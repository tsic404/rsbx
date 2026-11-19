// Package rpc is the client side of the daemon connection: one multiplexed
// control connection for filesystem requests, plus one connection per exec
// session (so a long running process never head-of-line blocks stat calls).
package rpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"rsbx/internal/proto"
)

// Target describes how to reach the daemon.
type Target struct {
	// Socket is a unix socket path, used when Command is empty.
	Socket string
	// Command, when set, starts a stdio daemon (e.g. an ssh invocation).
	Command   []string
	Address   string
	TLSConfig *tls.Config
}

// DialContext connects to the daemon. For a command transport, ctx owns the
// subprocess for the lifetime of the connection, not just while it starts.
func (t Target) DialContext(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t.Address != "" {
		if t.TLSConfig == nil {
			return nil, fmt.Errorf("network transport requires authenticated TLS")
		}
		dialer := tls.Dialer{Config: t.TLSConfig, NetDialer: &net.Dialer{Timeout: 15 * time.Second}}
		return dialer.DialContext(ctx, "tcp", t.Address)
	}
	if len(t.Command) == 0 {
		var d net.Dialer
		return d.DialContext(ctx, "unix", t.Socket)
	}
	cmd := exec.CommandContext(ctx, t.Command[0], t.Command[1:]...)
	childIn, stdin, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stdout, childOut, err := os.Pipe()
	if err != nil {
		childIn.Close()
		stdin.Close()
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = childIn, childOut, os.Stderr
	s := &stdioConn{r: stdout, w: stdin, cmd: cmd, done: make(chan struct{})}
	cmd.Cancel = s.stop
	if err := cmd.Start(); err != nil {
		childIn.Close()
		stdin.Close()
		stdout.Close()
		childOut.Close()
		return nil, err
	}
	childIn.Close()
	childOut.Close()
	// Own the pipes instead of using Cmd.StdoutPipe: Wait must not close
	// stdout before a normal EOF has drained the daemon's final response.
	go func() {
		cmd.Wait()
		close(s.done)
	}()
	if err := ctx.Err(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// stdioConn exposes a pair of pipes as a net.Conn.
type stdioConn struct {
	r       io.ReadCloser
	w       io.WriteCloser
	cmd     *exec.Cmd
	done    chan struct{}
	once    sync.Once
	stopErr error
}

func (s *stdioConn) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *stdioConn) Write(p []byte) (int, error) { return s.w.Write(p) }

// stop is also Cmd.Cancel, so cancellation unblocks both pipes before reaping
// the transport process. It deliberately does not wait: Cmd.Wait calls Cancel.
func (s *stdioConn) stop() error {
	s.once.Do(func() {
		s.w.Close()
		s.r.Close()
		s.stopErr = s.cmd.Process.Kill()
	})
	return s.stopErr
}

func (s *stdioConn) Close() error {
	err := s.stop()
	<-s.done
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

// CloseWrite sends EOF without discarding the daemon's remaining output.
func (s *stdioConn) CloseWrite() error    { return s.w.Close() }
func (s *stdioConn) CloseRead() error     { return s.r.Close() }
func (s *stdioConn) LocalAddr() net.Addr  { return nil }
func (s *stdioConn) RemoteAddr() net.Addr { return nil }

func (s *stdioConn) SetDeadline(t time.Time) error {
	return errors.Join(s.SetReadDeadline(t), s.SetWriteDeadline(t))
}

func (s *stdioConn) SetReadDeadline(t time.Time) error {
	if r, ok := s.r.(interface{ SetReadDeadline(time.Time) error }); ok {
		return r.SetReadDeadline(t)
	}
	return errors.ErrUnsupported
}

func (s *stdioConn) SetWriteDeadline(t time.Time) error {
	if w, ok := s.w.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return w.SetWriteDeadline(t)
	}
	return errors.ErrUnsupported
}

// FS is a multiplexed filesystem client whose lifetime ends permanently at Close.
type FS struct {
	dial      func(context.Context) (net.Conn, error)
	ctx       context.Context
	cancel    context.CancelFunc
	connectMu sync.Mutex // serializes lazy dialing without blocking Close
	mu        sync.Mutex
	conn      net.Conn
	gen       uint64 // connection generation; bumped whenever conn changes
	closed    bool
	wmu       sync.Mutex
	next      uint32
	pending   map[uint32]chan fxResult
	closeOnce sync.Once
	closeErr  error
}

// fxResult is one request's outcome. The error travels with the reply so a
// request failed by a dying connection reports that connection's cause instead
// of a bare disconnect that hides a rejected handshake.
type fxResult struct {
	resp *proto.FxResp
	err  error
}

// connectionCauseWait bounds how long a failed write waits for the reader's
// verdict. It only elapses when the peer sent nothing readable, so it costs a
// failing request a fifth of a second at worst and never delays a live one.
const connectionCauseWait = 200 * time.Millisecond

// NewFS returns a session client that connects lazily until Close is called.
func NewFS(t Target) *FS {
	ctx, cancel := context.WithCancel(context.Background())
	return &FS{dial: t.DialContext, ctx: ctx, cancel: cancel, pending: make(map[uint32]chan fxResult)}
}

// Do performs one filesystem request.
func (c *FS) Do(req *proto.FxReq) (*proto.FxResp, error) {
	ch, id, conn, gen, err := c.register()
	if err != nil {
		return nil, err
	}
	req.ID = id
	c.wmu.Lock()
	if c.ctx.Err() != nil {
		c.wmu.Unlock()
		return nil, net.ErrClosed
	}
	werr := proto.WriteFrame(conn, proto.TFxReq, req.Encode())
	c.wmu.Unlock()
	if werr != nil {
		// A refused peer says why in its last readable bytes, so give the
		// reader a moment to deliver that verdict for this request before the
		// connection is torn down. Otherwise the caller sees only the write
		// symptom (a reset or a broken pipe), which names no cause.
		if res, ok := c.readerVerdict(ch); ok {
			if c.ctx.Err() != nil {
				return nil, net.ErrClosed
			}
			return nil, res
		}
		c.dropConn(conn, gen, werr)
		if c.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		return nil, fmt.Errorf("rsbx: filesystem connection lost: %w", werr)
	}
	select {
	case <-c.ctx.Done():
		return nil, net.ErrClosed
	case res, ok := <-ch:
		if !ok {
			if c.ctx.Err() != nil {
				return nil, net.ErrClosed
			}
			return nil, errors.New("rsbx: filesystem connection lost")
		}
		if res.err != nil {
			return nil, res.err
		}
		resp := res.resp
		if resp.Kind == proto.KErr || resp.Errno != 0 {
			errno := syscall.Errno(resp.Errno)
			if errno == 0 {
				errno = errnoOf(resp.Err)
			}
			return resp, errno
		}
		return resp, nil
	}
}

// errnoOf maps a daemon error string onto a syscall.Errno.
func errnoOf(s string) syscall.Errno {
	for _, e := range []syscall.Errno{
		syscall.EPERM, syscall.ENOENT, syscall.EACCES, syscall.EEXIST,
		syscall.ENOTDIR, syscall.EISDIR, syscall.EINVAL, syscall.ENOSPC,
		syscall.EROFS, syscall.ENAMETOOLONG, syscall.ENOTEMPTY, syscall.EBUSY,
		syscall.EXDEV, syscall.EIO,
	} {
		if e.Error() == s {
			return e
		}
	}
	return syscall.EIO
}

func (c *FS) register() (chan fxResult, uint32, net.Conn, uint64, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, 0, nil, 0, net.ErrClosed
	}
	if c.conn != nil {
		ch, id, conn, gen := c.registerLocked()
		c.mu.Unlock()
		return ch, id, conn, gen, nil
	}
	c.mu.Unlock()

	c.connectMu.Lock()
	defer c.connectMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, 0, nil, 0, net.ErrClosed
	}
	if c.conn == nil {
		c.mu.Unlock()
		conn, err := c.dial(c.ctx)
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			if conn != nil {
				conn.Close()
			}
			return nil, 0, nil, 0, net.ErrClosed
		}
		if err != nil {
			c.mu.Unlock()
			return nil, 0, nil, 0, fmt.Errorf("rsbx: connect to daemon: %w", err)
		}
		c.conn = conn
		c.gen++
		go c.readLoop(conn, c.gen)
	}
	ch, id, conn, gen := c.registerLocked()
	c.mu.Unlock()
	return ch, id, conn, gen, nil
}

// registerLocked records the waiter atomically with selecting its connection.
func (c *FS) registerLocked() (chan fxResult, uint32, net.Conn, uint64) {
	c.next++
	id := c.next
	ch := make(chan fxResult, 1)
	c.pending[id] = ch
	return ch, id, c.conn, c.gen
}

func (c *FS) readLoop(conn net.Conn, gen uint64) {
	for {
		f, err := proto.ReadFrame(conn)
		if err != nil {
			// Only the reader of the current generation may reset the
			// connection; a stale reader from a replaced connection must not
			// fail requests that belong to the newer one.
			c.dropConn(conn, gen, err)
			return
		}
		if f.Type != proto.TFxResp {
			continue
		}
		resp, err := proto.DecodeFxResp(f.Payload)
		if err != nil {
			continue
		}
		c.mu.Lock()
		if c.conn != conn || c.gen != gen {
			c.mu.Unlock()
			return
		}
		ch := c.pending[resp.ID]
		delete(c.pending, resp.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- fxResult{resp: resp}
		}
	}
}

// readerVerdict waits briefly for this request's failure verdict. A refused
// peer reports why in its last readable bytes, and that reason is the one the
// caller needs; the write symptom is only a fallback.
func (c *FS) readerVerdict(ch chan fxResult) (error, bool) {
	select {
	case res := <-ch:
		if res.err != nil {
			return res.err, true
		}
		return nil, false
	case <-time.After(connectionCauseWait):
		return nil, false
	}
}

// dropConn fails requests from this connection only. A stale reader or writer
// must not tear down a replacement connection. A later Do may reconnect, but
// the failed request itself is never retried. Each failed request carries the
// connection's cause, so a rejected handshake surfaces as itself.
func (c *FS) dropConn(conn net.Conn, gen uint64, cause error) {
	c.mu.Lock()
	if c.conn != conn || c.gen != gen {
		c.mu.Unlock()
		return
	}
	c.conn = nil
	c.gen++
	for id, ch := range c.pending {
		delete(c.pending, id)
		ch <- fxResult{err: fmt.Errorf("rsbx: filesystem connection lost: %w", cause)}
	}
	c.mu.Unlock()
	conn.Close()
}

// Close permanently shuts the session down. It cancels dialing and fails all
// requests before closing the connection to interrupt blocked reads and writes.
func (c *FS) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.cancel()
		conn := c.conn
		c.conn = nil
		c.gen++
		pending := c.pending
		c.pending = nil
		c.mu.Unlock()
		for _, ch := range pending {
			close(ch)
		}
		if conn != nil {
			c.closeErr = conn.Close()
		}
	})
	return c.closeErr
}

// ReadFile fetches a whole remote file body via handle open/read/close.
func (c *FS) ReadFile(p string) ([]byte, proto.Attr, error) {
	resp, err := c.Do(&proto.FxReq{
		Op:    proto.FxOpen,
		Path:  p,
		Flags: uint32(syscall.O_RDONLY),
	})
	if err != nil {
		return nil, proto.Attr{}, err
	}
	if resp.Kind == proto.KNone {
		return nil, proto.Attr{}, os.ErrNotExist
	}
	if resp.Kind != proto.KHandle || resp.Handle == 0 {
		return nil, proto.Attr{}, syscall.EIO
	}
	h := resp.Handle
	defer c.Do(&proto.FxReq{Op: proto.FxClose, Handle: h})

	st, err := c.Do(&proto.FxReq{Op: proto.FxFstat, Handle: h})
	if err != nil {
		return nil, proto.Attr{}, err
	}
	attr := st.Attr

	var buf []byte
	for off := int64(0); ; {
		r, err := c.Do(&proto.FxReq{
			Op:     proto.FxPread,
			Handle: h,
			Offset: off,
			Size:   proto.MaxIO,
		})
		if err != nil {
			return nil, proto.Attr{}, err
		}
		n := int64(len(r.Data))
		if r.Count > 0 && int64(r.Count) < n {
			n = int64(r.Count)
		}
		if n == 0 {
			break
		}
		buf = append(buf, r.Data[:n]...)
		off += n
		if n < proto.MaxIO {
			break
		}
	}
	return buf, attr, nil
}

// Stat reports whether the daemon has an entry at p. It opens the path
// read-only, which fails with os.ErrNotExist when the daemon does not have it.
func (c *FS) Stat(p string) (proto.Attr, error) {
	resp, err := c.Do(&proto.FxReq{
		Op:    proto.FxOpen,
		Path:  p,
		Flags: uint32(syscall.O_RDONLY),
	})
	if err != nil {
		return proto.Attr{}, err
	}
	if resp.Kind == proto.KNone {
		return proto.Attr{}, os.ErrNotExist
	}
	if resp.Kind != proto.KHandle || resp.Handle == 0 {
		return proto.Attr{}, syscall.EIO
	}
	h := resp.Handle
	defer c.Do(&proto.FxReq{Op: proto.FxClose, Handle: h})
	st, err := c.Do(&proto.FxReq{Op: proto.FxFstat, Handle: h})
	if err != nil {
		return proto.Attr{}, err
	}
	return st.Attr, nil
}

// WriteFile replaces a remote file body via handle open/write/close.
func (c *FS) WriteFile(p string, data []byte) error {
	resp, err := c.Do(&proto.FxReq{
		Op:    proto.FxOpen,
		Path:  p,
		Flags: uint32(syscall.O_WRONLY | syscall.O_CREAT | syscall.O_TRUNC),
		Mode:  0o644,
	})
	if err != nil {
		return err
	}
	if resp.Kind != proto.KHandle || resp.Handle == 0 {
		return syscall.EIO
	}
	h := resp.Handle
	defer c.Do(&proto.FxReq{Op: proto.FxClose, Handle: h})

	for off := 0; off < len(data); {
		end := off + proto.MaxIO
		if end > len(data) {
			end = len(data)
		}
		if _, err := c.Do(&proto.FxReq{
			Op:     proto.FxPwrite,
			Handle: h,
			Offset: int64(off),
			Data:   data[off:end],
		}); err != nil {
			return err
		}
		off = end
	}
	return nil
}
