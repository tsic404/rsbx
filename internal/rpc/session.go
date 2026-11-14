package rpc

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"rsbx/internal/proto"
)

// RunSession executes req on the daemon and bridges the caller's stdio.
// It returns the remote exit status.
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

	// local stdin -> daemon. EOF is forwarded as a zero-length stdin frame so
	// the remote child sees end of input while the session stays alive; the
	// local read side is then drained to keep the loopback from spinning.
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := stdin.Read(buf)
			if n > 0 {
				if send(proto.TStdin, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				send(proto.TStdin, nil)
				io.Copy(io.Discard, stdin)
				return
			}
		}
	}()

	ttyOut := req.TTY
	for {
		f, err := proto.ReadFrame(conn)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
				return 127, nil
			}
			return 127, err
		}
		switch f.Type {
		case proto.TReady:
		case proto.TStdout:
			stdout.Write(f.Payload)
		case proto.TStderr:
			if ttyOut {
				stdout.Write(f.Payload)
			} else {
				stderr.Write(f.Payload)
			}
		case proto.TTty:
			stdout.Write(f.Payload)
		case proto.TErr:
			fmt.Fprintf(stderr, "%s\n", f.Payload)
		case proto.TExit:
			return proto.ParseExit(f.Payload), nil
		}
	}
}

var _ = os.Stdout
