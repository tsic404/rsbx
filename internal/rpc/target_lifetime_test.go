package rpc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRPCTransportHelperProcess(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "rsbx-rpc-helper" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "hold":
		fmt.Fprintln(os.Stdout, "ready")
		for {
			time.Sleep(time.Hour)
		}
	case "echo":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			os.Exit(2)
		}
		if _, err := os.Stdout.Write(data); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

func helperStdio(t *testing.T, mode string) (*stdioConn, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	target := Target{Command: []string{os.Args[0], "-test.run=^TestRPCTransportHelperProcess$", "--", "rsbx-rpc-helper", mode}}
	conn, err := target.DialContext(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	s := conn.(*stdioConn)
	t.Cleanup(func() { cancel(); s.Close() })
	return s, cancel
}

func readHelperReady(t *testing.T, s *stdioConn) {
	t.Helper()
	if err := s.SetReadDeadline(time.Now().Add(rpcLifetimeTimeout)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(s).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("helper startup = (%q, %v)", line, err)
	}
	if err := s.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestStdioCloseAndCancellationUnblockPipesAndReap(t *testing.T) {
	for _, how := range []string{"Close", "context cancellation"} {
		t.Run(how, func(t *testing.T) {
			s, cancel := helperStdio(t, "hold")
			readHelperReady(t, s)
			readStarted, writeStarted := make(chan struct{}), make(chan struct{})
			readDone, writeDone := make(chan error, 1), make(chan error, 1)
			go func() {
				close(readStarted)
				_, err := s.Read(make([]byte, 1))
				readDone <- err
			}()
			go func() {
				close(writeStarted)
				// The helper never reads its stdin; this cannot fit in a pipe.
				_, err := s.Write(make([]byte, 1<<20))
				writeDone <- err
			}()
			awaitRPC(t, readStarted)
			awaitRPC(t, writeStarted)
			closed := make(chan error, 1)
			if how == "context cancellation" {
				cancel()
				go func() {
					<-s.done
					closed <- s.Close()
				}()
			} else {
				go func() { closed <- s.Close() }()
			}
			if err := awaitRPC(t, readDone); err == nil {
				t.Fatal("stopped transport left Read successful")
			}
			if err := awaitRPC(t, writeDone); err == nil {
				t.Fatal("stopped transport left Write successful")
			}
			awaitRPC(t, s.done)
			if s.cmd.ProcessState == nil {
				t.Fatal("transport was not reaped")
			}
			if err := s.cmd.Process.Signal(syscall.Signal(0)); !errors.Is(err, os.ErrProcessDone) {
				t.Fatalf("transport still exists after Wait: %v", err)
			}
			if err := awaitRPC(t, closed); err != nil {
				t.Fatalf("Close: %v", err)
			}
		})
	}
}

func TestStdioHalfCloseDrainsOutputAfterProcessExit(t *testing.T) {
	s, _ := helperStdio(t, "echo")
	const payload = "final daemon response"
	if _, err := io.WriteString(s, payload); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// Wait has already reaped the child, but buffered stdout still belongs to
	// the connection and must not have been closed by Cmd.Wait.
	awaitRPC(t, s.done)
	if err := s.SetReadDeadline(time.Now().Add(rpcLifetimeTimeout)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(s)
	if err != nil || string(got) != payload {
		t.Fatalf("final stdout = (%q, %v), want %q", got, err, payload)
	}
}

type rpcNopWriteCloser struct{ io.Writer }

func (rpcNopWriteCloser) Close() error { return nil }

func TestStdioUnsupportedDeadlinesReturnErrors(t *testing.T) {
	s := &stdioConn{r: io.NopCloser(strings.NewReader("")), w: rpcNopWriteCloser{io.Discard}}
	for _, set := range []func(time.Time) error{s.SetReadDeadline, s.SetWriteDeadline, s.SetDeadline} {
		if err := set(time.Now()); !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("unsupported deadline returned %v", err)
		}
	}
}

func TestStdioPipeDeadlinesAreEnforced(t *testing.T) {
	s, _ := helperStdio(t, "hold")
	readHelperReady(t, s)
	past := time.Now().Add(-time.Second)
	if err := s.SetReadDeadline(past); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired read deadline returned %v", err)
	}
	if err := s.SetWriteDeadline(past); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(make([]byte, 1<<20)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired write deadline returned %v", err)
	}
	if err := s.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestDialContextAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := (Target{Command: []string{"must-not-be-started"}}).DialContext(ctx)
	if conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial = (%v, %v)", conn, err)
	}
}
