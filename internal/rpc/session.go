package rpc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"rsbx/internal/proto"
	"rsbx/internal/pty"
)

// RunSession executes req on the daemon and bridges the caller's stdio.
// It returns the remote exit status and owns a background session context.
// req must carry the non-argv Target plus a nonempty command vector.
//
// Signals and terminal resizes are forwarded to the remote process group
// while the session lives, so Ctrl-C and a window resize act on the command
// that actually runs. The local process does not terminate on those signals:
// the daemon reports the real status, and that is what the caller exits with.
func RunSession(t Target, req *proto.ExecReq, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	return RunSessionContext(context.Background(), t, req, stdin, stdout, stderr)
}

// RunSessionContext is RunSession with caller-owned cancellation. Canceling ctx
// closes the connection and terminates and reaps any stdio transport process.
func RunSessionContext(ctx context.Context, t Target, req *proto.ExecReq, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	return runSession(ctx, t.DialContext, req, stdin, stdout, stderr)
}

func runSession(ctx context.Context, dial func(context.Context) (net.Conn, error), req *proto.ExecReq, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if req == nil || req.Target == "" || len(req.Argv) == 0 {
		return 127, errors.New("rsbx: exec request requires a target and command")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	conn, err := dial(ctx)
	if err != nil {
		return 127, fmt.Errorf("connect to daemon: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer conn.Close()
	if err := proto.WriteFrame(conn, proto.TExec, req.Encode()); err != nil {
		if ctx.Err() != nil {
			return 127, ctx.Err()
		}
		return 127, err
	}

	// A failed write means that frame did not reach the daemon; it does not
	// mean the reply is gone. The daemon may already have written the exit
	// frame, and closing here would discard it before the read loop sees it.
	// The sender that failed stops, and the loop ends on its own EOF.
	var wmu sync.Mutex
	send := func(typ byte, p []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return proto.WriteFrame(conn, typ, p)
	}

	// done prevents further session I/O after teardown. An arbitrary io.Reader
	// cannot be canceled, so only the owned stdin reader is joined.
	done := make(chan struct{})
	var stdinWg sync.WaitGroup
	var signalWg sync.WaitGroup

	// File-backed stdin is duplicated and polled together with a wake pipe.
	// Cancellation never closes or changes the caller's descriptor.
	src, cancelRead, releaseRead, joinable, err := cancellableReader(stdin)
	if err != nil {
		return 127, fmt.Errorf("rsbx: prepare stdin: %w", err)
	}
	stdinWg.Add(1)
	go func() {
		defer stdinWg.Done()
		defer releaseRead()
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			select {
			case <-done:
				return
			default:
			}
			if n > 0 {
				if send(proto.TStdin, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					conn.Close()
					return
				}
				send(proto.TStdin, nil)
				return
			}
			select {
			case <-done:
				return
			default:
			}
		}
	}()

	// Forward signals and terminal resizes. sigc is selected against done, so
	// the worker exits when the session ends even though signal.Stop does not
	// close the channel.
	sigc := make(chan os.Signal, 16)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT,
		syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH)
	signalWg.Add(1)
	go func() {
		defer signalWg.Done()
		var b [4]byte
		for {
			select {
			case <-done:
				return
			case s := <-sigc:
				if s == syscall.SIGWINCH {
					if f, ok := stdin.(*os.File); ok {
						if rows, cols := pty.GetWinsize(f); rows != 0 || cols != 0 {
							var w [4]byte
							binary.BigEndian.PutUint16(w[0:], rows)
							binary.BigEndian.PutUint16(w[2:], cols)
							if send(proto.TWinch, w[:]) != nil {
								return
							}
						}
					}
					continue
				}
				sig, ok := s.(syscall.Signal)
				if !ok {
					continue
				}
				binary.BigEndian.PutUint32(b[:], uint32(int32(sig)))
				if send(proto.TSig, b[:]) != nil {
					return
				}
			}
		}
	}()

	finish := func() {
		close(done)
		signal.Stop(sigc)
		cancelRead()
		cancel()
		// Workers may be parked in send, so close the transport before joining.
		conn.Close()
		signalWg.Wait()
		if joinable {
			stdinWg.Wait()
		}
	}
	defer finish()

	ttyOut := req.TTY
	for {
		f, err := proto.ReadFrame(conn)
		if err != nil {
			if ctx.Err() != nil {
				return 127, ctx.Err()
			}
			return 127, fmt.Errorf("rsbx: daemon disconnected before exit: %w", err)
		}
		switch f.Type {
		case proto.TReady:
		case proto.TStdout:
			if _, err := stdout.Write(f.Payload); err != nil {
				return 127, err
			}
		case proto.TStderr:
			w := stderr
			if ttyOut {
				w = stdout
			}
			if _, err := w.Write(f.Payload); err != nil {
				return 127, err
			}
		case proto.TTty:
			if _, err := stdout.Write(f.Payload); err != nil {
				return 127, err
			}
		case proto.TErr:
			if _, err := fmt.Fprintf(stderr, "%s\n", f.Payload); err != nil {
				return 127, err
			}
		case proto.TExit:
			return proto.ParseExit(f.Payload), nil
		}
	}
}

// cancellableReader gives file-backed stdin an owned duplicate and a wake pipe.
// Polling avoids a blocking Read on a duplicate that Close cannot interrupt on
// Linux. cancel wakes the reader; release closes descriptors after Read returns.
// An arbitrary reader remains caller-owned and cannot safely be canceled.
func cancellableReader(r io.Reader) (reader io.Reader, cancel, release func(), joinable bool, err error) {
	f, ok := r.(*os.File)
	if !ok {
		return r, func() {}, func() {}, false, nil
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, nil, nil, false, err
	}
	dupFD := -1
	var dupErr error
	ctlErr := rc.Control(func(fd uintptr) {
		dupFD, dupErr = unix.Dup(int(fd))
		if dupErr == nil {
			syscall.CloseOnExec(dupFD)
		}
	})
	if ctlErr != nil || dupErr != nil || dupFD < 0 {
		if dupFD >= 0 {
			syscall.Close(dupFD)
		}
		if ctlErr != nil {
			return nil, nil, nil, false, ctlErr
		}
		if dupErr != nil {
			return nil, nil, nil, false, dupErr
		}
		return nil, nil, nil, false, syscall.EBADF
	}
	wakeR, wakeW, err := os.Pipe()
	if err != nil {
		syscall.Close(dupFD)
		return nil, nil, nil, false, err
	}
	p := &pollStdin{fd: dupFD, wakeFD: int(wakeR.Fd()), wakeR: wakeR, wakeW: wakeW}
	return p, p.cancel, p.release, true, nil
}

type pollStdin struct {
	fd          int
	wakeFD      int
	wakeR       *os.File
	wakeW       *os.File
	cancelOnce  sync.Once
	releaseOnce sync.Once
}

func (p *pollStdin) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	fds := [2]unix.PollFd{
		{Fd: int32(p.fd), Events: unix.POLLIN},
		{Fd: int32(p.wakeFD), Events: unix.POLLIN},
	}
	for {
		_, err := unix.Poll(fds[:], -1)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if fds[1].Revents != 0 || fds[0].Revents&unix.POLLNVAL != 0 {
			return 0, os.ErrClosed
		}
		if fds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) == 0 {
			continue
		}
		n, err := syscall.Read(p.fd, buf)
		if err == syscall.EINTR || err == syscall.EAGAIN {
			continue
		}
		if n < 0 {
			n = 0
		}
		if n == 0 && err == nil {
			err = io.EOF
		}
		return n, err
	}
}

func (p *pollStdin) cancel() {
	p.cancelOnce.Do(func() { p.wakeW.Close() })
}

func (p *pollStdin) release() {
	p.releaseOnce.Do(func() {
		p.cancel()
		syscall.Close(p.fd)
		p.wakeR.Close()
	})
}
