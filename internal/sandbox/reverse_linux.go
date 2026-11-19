//go:build linux && (amd64 || arm64)

package sandbox

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"rsbx/internal/proto"
	"rsbx/internal/rpc"
)

type reverseJob struct {
	request *proto.ExecReq
	reply   chan reverseResult
}

type reverseResult struct {
	stdout *os.File
	stderr *os.File
	stdin  *os.File
	status <-chan int
	pid    int
	err    error
}

type reverseListener struct {
	listener net.Listener
	token    string
	jobs     chan reverseJob
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

func newReverseListener(listener net.Listener, token string, jobs chan reverseJob) *reverseListener {
	ctx, cancel := context.WithCancel(context.Background())
	reverse := &reverseListener{listener: listener, token: token, jobs: jobs, ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{}}
	reverse.wg.Add(1)
	go reverse.accept()
	return reverse
}

func (reverse *reverseListener) accept() {
	defer reverse.wg.Done()
	for {
		conn, err := reverse.listener.Accept()
		if err != nil {
			return
		}
		reverse.mu.Lock()
		if reverse.ctx.Err() != nil || len(reverse.conns) >= 32 {
			reverse.mu.Unlock()
			conn.Close()
			continue
		}
		reverse.conns[conn] = struct{}{}
		reverse.wg.Add(1)
		reverse.mu.Unlock()
		go func() {
			defer reverse.wg.Done()
			defer conn.Close()
			defer func() { reverse.mu.Lock(); delete(reverse.conns, conn); reverse.mu.Unlock() }()
			reverse.serve(conn)
		}()
	}
}

func (reverse *reverseListener) Close() {
	reverse.cancel()
	reverse.listener.Close()
	reverse.mu.Lock()
	for conn := range reverse.conns {
		conn.Close()
	}
	reverse.mu.Unlock()
	reverse.wg.Wait()
}

func (reverse *reverseListener) serve(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	presented := make([]byte, 64)
	if _, err := io.ReadFull(conn, presented); err != nil {
		return
	}
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if subtle.ConstantTimeCompare(presented, []byte(reverse.token)) != 1 {
		proto.WriteFrame(conn, proto.TErr, []byte("invalid session capability"))
		proto.WriteFrame(conn, proto.TExit, proto.ExitPayload(126))
		return
	}
	frame, err := proto.ReadFrame(conn)
	if err != nil || frame.Type != proto.TExec || len(frame.Payload) > 1<<20 {
		return
	}
	req, err := proto.DecodeExecReq(frame.Payload)
	if err != nil {
		return
	}
	job := reverseJob{request: req, reply: make(chan reverseResult, 1)}
	select {
	case reverse.jobs <- job:
	case <-reverse.ctx.Done():
		return
	}
	var result reverseResult
	select {
	case result = <-job.reply:
	case <-reverse.ctx.Done():
		return
	}
	if result.err != nil {
		proto.WriteFrame(conn, proto.TErr, []byte(result.err.Error()))
		proto.WriteFrame(conn, proto.TExit, proto.ExitPayload(126))
		return
	}
	conn.SetDeadline(time.Time{})
	peerClose := context.AfterFunc(reverse.ctx, func() { conn.Close() })
	defer peerClose()
	bridgeReverse(conn, result)
}

func bridgeReverse(conn net.Conn, result reverseResult) {
	defer result.stdout.Close()
	defer result.stderr.Close()
	defer result.stdin.Close()
	var writeMu sync.Mutex
	send := func(typ byte, payload []byte) bool {
		writeMu.Lock()
		defer writeMu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		return proto.WriteFrame(conn, typ, payload) == nil
	}
	cancel := func() {
		syscall.Kill(-result.pid, syscall.SIGKILL)
		result.stdin.Close()
		result.stdout.Close()
		result.stderr.Close()
		conn.Close()
	}
	var readers sync.WaitGroup
	readers.Add(2)
	for typ, reader := range map[byte]*os.File{proto.TStdout: result.stdout, proto.TStderr: result.stderr} {
		go func(typ byte, reader *os.File) {
			defer readers.Done()
			buf := make([]byte, 32<<10)
			for {
				count, err := reader.Read(buf)
				if count > 0 && !send(typ, buf[:count]) {
					cancel()
					return
				}
				if err != nil {
					return
				}
			}
		}(typ, reader)
	}
	done := make(chan struct{})
	input := make(chan []byte, 64)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for {
			select {
			case <-done:
				return
			case data := <-input:
				if data == nil {
					result.stdin.Close()
					return
				}
				if _, err := result.stdin.Write(data); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			frame, err := proto.ReadFrame(conn)
			if err != nil {
				select {
				case <-done:
					return
				default:
					cancel()
					return
				}
			}
			switch frame.Type {
			case proto.TStdin:
				if len(frame.Payload) > 64<<10 {
					cancel()
					return
				}
				select {
				case input <- frame.Payload:
				case <-done:
					return
				default:
					cancel()
					return
				}
			case proto.TSig:
				if len(frame.Payload) != 4 {
					cancel()
					return
				}
				signal := int32(binary.BigEndian.Uint32(frame.Payload))
				if signal <= 0 || signal > 64 {
					cancel()
					return
				}
				syscall.Kill(-result.pid, syscall.Signal(signal))
			case proto.TWinch:
			default:
				cancel()
				return
			}
		}
	}()
	code := <-result.status
	close(done)
	// The child is gone, so both output pipes end after the bytes it wrote
	// last. Waiting for the readers before the exit frame keeps output that
	// arrives just as it exits, and keeps the frame order the caller expects.
	// A descendant that inherited a pipe can hold it open indefinitely, so the
	// wait is bounded and the remainder is dropped rather than stalling the
	// session.
	finished := make(chan struct{})
	go func() {
		readers.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
	}
	send(proto.TExit, proto.ExitPayload(code))
	result.stdin.Close()
	cancel()
	workers.Wait()
}

type ReverseClient struct {
	Address string
	Token   string
}

func (client *ReverseClient) RunLocal(ctx context.Context, req *proto.ExecReq, stream net.Conn) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", client.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if _, err = io.WriteString(conn, client.Token); err != nil {
		return err
	}
	if err = proto.WriteFrame(conn, proto.TExec, req.Encode()); err != nil {
		return err
	}
	conn.SetWriteDeadline(time.Time{})
	return rpc.RelayFrames(ctx, stream, conn)
}

func reverseToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func reverseTarget(spec *launchSpec, req *proto.ExecReq) (string, error) {
	if err := validateExecFields(req.Target, req.Argv, req.Env); err != nil {
		return "", err
	}
	if req.Dir != "" && (!filepath.IsAbs(req.Dir) || strings.IndexByte(req.Dir, 0) >= 0) {
		return "", fmt.Errorf("invalid callback working directory")
	}
	if req.TTY {
		return "", fmt.Errorf("reverse PTY requests are not supported")
	}
	for _, entry := range req.Env {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "LD_") || name == "GLIBC_TUNABLES" || name == "GCONV_PATH" {
			return "", fmt.Errorf("unsafe loader environment: %s", name)
		}
	}
	if filepath.IsAbs(req.Target) {
		target := filepath.Clean(req.Target)
		for _, allowed := range spec.ReverseAllow {
			if target == allowed {
				return target, nil
			}
		}
	}
	return "", fmt.Errorf("local execution refused: %s is not in local.allow", req.Target)
}
