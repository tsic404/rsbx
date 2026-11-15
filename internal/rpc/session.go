package rpc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"rsbx/internal/proto"
	"rsbx/internal/pty"
)

// RunSession executes req on the daemon and bridges the caller's stdio.
// It returns the remote exit status.
//
// Signals and terminal resizes are forwarded to the remote process group
// while the session lives, so Ctrl-C and a window resize act on the command
// that actually runs. The local process does not terminate on those signals:
// the daemon reports the real status, and that is what the caller exits with.
func RunSession(t Target, req *proto.ExecReq, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	conn, err := t.Dial()
	if err != nil {
		return 127, fmt.Errorf("connect to daemon: %w", err)
	}
	defer conn.Close()
	if err := proto.WriteFrame(conn, proto.TExec, req.Encode()); err != nil {
		return 127, err
	}

	var wmu sync.Mutex
	send := func(typ byte, p []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return proto.WriteFrame(conn, typ, p)
	}

	// done ends every helper goroutine. It is closed once when the read loop
	// returns, so nothing lingers and blocks.
	done := make(chan struct{})
	// stdin worker: joined only when stdin is cancellable, abandoned otherwise
	// (an un-interruptible Read would block teardown forever).
	var stdinWg sync.WaitGroup
	// signal worker: always joined, it selects on done.
	var signalWg sync.WaitGroup

	// local stdin -> daemon. EOF is forwarded as a zero-length stdin frame so
	// the remote child sees end of input.
	//
	// A plain io.Reader can block in Read forever, so cancellation needs real
	// ownership. When stdin is an *os.File we read from a dup and close the dup
	// on cancel: the duplicate's close interrupts a parked Read without ever
	// touching the caller's descriptor. For any other reader there is no safe
	// way to interrupt Read, so that worker is not joined on teardown — it
	// carries no session state and cannot block the session from finishing.
	src, cancelRead, joinable := cancellableReader(stdin, done)
	stdinWg.Add(1)
	go func() {
		defer stdinWg.Done()
		defer cancelRead()
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if send(proto.TStdin, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
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
		// The signal worker always selects on done, so it is joined. The stdin
		// worker is joined only when its reader is interruptible; otherwise it
		// is abandoned (it owns no connection state) instead of blocking the
		// session on a Read that can never be interrupted.
		signalWg.Wait()
		if joinable {
			stdinWg.Wait()
		}
	}

	ttyOut := req.TTY
	for {
		f, err := proto.ReadFrame(conn)
		if err != nil {
			finish()
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
				return 127, nil
			}
			return 127, err
		}
		switch f.Type {
		case proto.TReady:
		case proto.TStdout:
			if _, err := stdout.Write(f.Payload); err != nil {
				finish()
				return 127, err
			}
		case proto.TStderr:
			w := stderr
			if ttyOut {
				w = stdout
			}
			if _, err := w.Write(f.Payload); err != nil {
				finish()
				return 127, err
			}
		case proto.TTty:
			if _, err := stdout.Write(f.Payload); err != nil {
				finish()
				return 127, err
			}
		case proto.TErr:
			fmt.Fprintf(stderr, "%s\n", f.Payload)
		case proto.TExit:
			finish()
			return proto.ParseExit(f.Payload), nil
		}
	}
}

// cancellableReader returns the reader RunSession reads stdin from, a close
// function to release any duplicate descriptor, and whether the reader can be
// unblocked on cancel (and therefore joined safely).
//
// A *os.File is dup'd so closing the duplicate interrupts a pending Read
// without closing the caller's FD. Every other reader has no interruptible
// Read, so it is returned as-is and reported unjoinable: the worker is
// abandoned rather than waited on, which prevents a permanent block.
func cancellableReader(r io.Reader, done <-chan struct{}) (io.Reader, func(), bool) {
	f, ok := r.(*os.File)
	if !ok {
		return r, func() {}, false
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return r, func() {}, false
	}
	var dupErr error
	var dup *os.File
	if ctlErr := rc.Control(func(fd uintptr) {
		nfd, err := syscall.Dup(int(fd))
		if err != nil {
			dupErr = err
			return
		}
		syscall.CloseOnExec(nfd)
		dup = os.NewFile(uintptr(nfd), "rsbx-stdin-dup")
	}); ctlErr != nil || dupErr != nil || dup == nil {
		if dup != nil {
			dup.Close()
		}
		return r, func() {}, false
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-stop:
		}
		dup.Close()
	}()
	return dup, func() { close(stop) }, true
}
