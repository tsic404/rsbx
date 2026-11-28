//go:build linux

package sandbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"rsbx/internal/proto"
)

// GatewayRequestSock is created on the sandbox's private minimal /dev before
// the launcher remounts /dev readonly. No environment value selects this socket.
const GatewayRequestSock = "/dev/.rsbx-exec.sock"

const (
	// The binary request preserves kernel bytes; 16 MiB leaves headroom for
	// raised-stack exec payloads without weakening the explicit frame bound.
	maxGatewayRequestSize = 16 << 20
	maxGatewayErrorSize   = 1024
	gatewayIOTimeout      = 10 * time.Second
	gatewayStatusOK       = byte(0)
	gatewayStatusError    = byte(1)
)

// gatewayServer serves exactly one immutable captured exec per registered PID.
// A consumed entry remains registered until Forget, preventing republication
// while that gateway process still exists.
type gatewayServer struct {
	listener *net.UnixListener
	uid, gid uint32
	mu       sync.Mutex
	requests map[int][]byte
	conns    map[*net.UnixConn]struct{}
	closed   bool
	wg       sync.WaitGroup
	once     sync.Once
	closeErr error
}

func newGatewayServer(path string) (*gatewayServer, error) {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen for captured gateway requests: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, fmt.Errorf("protect gateway request socket: %w", err)
	}
	server := &gatewayServer{
		listener: listener,
		uid:      uint32(os.Getuid()),
		gid:      uint32(os.Getgid()),
		requests: make(map[int][]byte),
		conns:    make(map[*net.UnixConn]struct{}),
	}
	server.wg.Add(1)
	go server.accept()
	return server, nil
}

// Publish must complete before the supervisor resumes this gateway PID. The
// encoded bytes, not the caller's mutable request or slices, are registered.
func (s *gatewayServer) Publish(pid int, req *proto.ExecReq) error {
	if pid <= 0 {
		return fmt.Errorf("invalid gateway PID %d", pid)
	}
	if err := validateGatewayRequest(req); err != nil {
		return err
	}
	// Bound byte strings and their vector length prefixes before encoding.
	// The final encoded-size check includes the protocol's fixed fields.
	size := len(req.Target) + len(req.Dir) + len(req.Session)
	if size > maxGatewayRequestSize {
		return fmt.Errorf("gateway request exceeds %d bytes", maxGatewayRequestSize)
	}
	for _, list := range [2][]string{req.Argv, req.Env} {
		for _, value := range list {
			if len(value) > maxGatewayRequestSize-size-4 {
				return fmt.Errorf("gateway request exceeds %d bytes", maxGatewayRequestSize)
			}
			size += len(value) + 4
		}
	}
	body := req.Encode()
	if len(body) > maxGatewayRequestSize {
		return fmt.Errorf("gateway request exceeds %d bytes", maxGatewayRequestSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("gateway request server is closed")
	}
	if _, exists := s.requests[pid]; exists {
		return fmt.Errorf("gateway PID %d already has a captured request", pid)
	}
	s.requests[pid] = body
	return nil
}

func (s *gatewayServer) Forget(pid int) {
	s.mu.Lock()
	delete(s.requests, pid)
	s.mu.Unlock()
}

func (s *gatewayServer) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			s.shutdown(fmt.Errorf("accept gateway request: %w", err))
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serve(conn)
	}
}

func (s *gatewayServer) serve(conn *net.UnixConn) {
	defer s.wg.Done()
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()
	if err := conn.SetWriteDeadline(time.Now().Add(gatewayIOTimeout)); err != nil {
		return
	}
	peer, err := gatewayPeerCredentials(conn)
	var body []byte
	if err == nil {
		body, err = s.takeRequest(peer)
	}
	if err != nil {
		message := []byte(err.Error())
		if len(message) > maxGatewayErrorSize {
			message = message[:maxGatewayErrorSize]
		}
		writeGatewayFrame(conn, gatewayStatusError, message)
		return
	}
	writeGatewayFrame(conn, gatewayStatusOK, body)
}

func gatewayPeerCredentials(conn *net.UnixConn) (*unix.Ucred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("access gateway peer credentials: %w", err)
	}
	var peer *unix.Ucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		peer, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, fmt.Errorf("read gateway peer credentials: %w", err)
	}
	if credentialErr != nil {
		return nil, fmt.Errorf("read gateway peer credentials: %w", credentialErr)
	}
	return peer, nil
}

func (s *gatewayServer) takeRequest(peer *unix.Ucred) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("gateway request server is closed")
	}
	if peer == nil || peer.Pid <= 0 || peer.Uid != s.uid || peer.Gid != s.gid {
		return nil, fmt.Errorf("gateway peer credentials do not match the supervisor")
	}
	pid := int(peer.Pid)
	body, exists := s.requests[pid]
	if !exists {
		return nil, fmt.Errorf("gateway PID %d has no captured execution request", pid)
	}
	if body == nil {
		return nil, fmt.Errorf("gateway PID %d already consumed its execution request", pid)
	}
	s.requests[pid] = nil
	return body, nil
}

// shutdown does not join: it is also called by the accept worker on a fatal
// listener error. Closing all streams prevents a stalled peer from leaking a
// worker. Registration and shutdown share the lock with every WaitGroup Add.
func (s *gatewayServer) shutdown(cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.closeErr = cause
	s.requests = nil
	if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) && s.closeErr == nil {
		s.closeErr = fmt.Errorf("close gateway request listener: %w", err)
	}
	for conn := range s.conns {
		conn.Close()
	}
}

// Close cancels active connections and joins both accept and response workers.
func (s *gatewayServer) Close() error {
	s.once.Do(func() {
		s.shutdown(nil)
		s.wg.Wait()
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

// A response is a status byte followed by a big-endian uint32 payload length.
// Errors have their own small bound; all reads are exact, including EOF cases.
func writeGatewayFrame(w io.Writer, status byte, body []byte) error {
	limit := maxGatewayRequestSize
	switch status {
	case gatewayStatusOK:
	case gatewayStatusError:
		limit = maxGatewayErrorSize
	default:
		return fmt.Errorf("invalid gateway response status %d", status)
	}
	if len(body) == 0 || len(body) > limit {
		return fmt.Errorf("gateway response size %d is outside 1..%d bytes", len(body), limit)
	}
	var header [5]byte
	header[0] = status
	binary.BigEndian.PutUint32(header[1:], uint32(len(body)))
	for _, buffer := range [2][]byte{header[:], body} {
		for len(buffer) > 0 {
			n, err := w.Write(buffer)
			if err != nil {
				return err
			}
			if n <= 0 || n > len(buffer) {
				return io.ErrShortWrite
			}
			buffer = buffer[n:]
		}
	}
	return nil
}

func readGatewayFrame(r io.Reader) (*proto.ExecReq, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("read gateway response header: %w", err)
	}
	limit := uint32(maxGatewayRequestSize)
	switch header[0] {
	case gatewayStatusOK:
	case gatewayStatusError:
		limit = maxGatewayErrorSize
	default:
		return nil, fmt.Errorf("invalid gateway response status %d", header[0])
	}
	size := binary.BigEndian.Uint32(header[1:])
	if size == 0 || size > limit {
		return nil, fmt.Errorf("gateway response size %d is outside 1..%d bytes", size, limit)
	}
	body := make([]byte, int(size))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read gateway response body: %w", err)
	}
	if header[0] == gatewayStatusError {
		return nil, fmt.Errorf("gateway supervisor refused request: %s", body)
	}
	req, err := proto.DecodeExecReq(body)
	if err != nil {
		return nil, fmt.Errorf("decode captured gateway request: %w", err)
	}
	if err := validateGatewayRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

func validateGatewayRequest(req *proto.ExecReq) error {
	if req == nil {
		return fmt.Errorf("missing captured gateway request")
	}
	if err := validateExecFields(req.Target, req.Argv, req.Env); err != nil {
		return fmt.Errorf("invalid captured gateway request: %w", err)
	}
	if !filepath.IsAbs(req.Dir) || strings.IndexByte(req.Dir, 0) >= 0 {
		return fmt.Errorf("captured gateway directory must be a NUL-free absolute path")
	}
	return nil
}

// ReadGatewayRequest obtains only the supervisor's captured request. A missing
// publication is an explicit error, never a fallback to argv, env or /proc.
func ReadGatewayRequest() (*proto.ExecReq, error) {
	conn, err := net.DialTimeout("unix", GatewayRequestSock, gatewayIOTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to captured gateway request socket: %w", err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(gatewayIOTimeout)); err != nil {
		return nil, fmt.Errorf("bound gateway request read: %w", err)
	}
	return readGatewayFrame(conn)
}
