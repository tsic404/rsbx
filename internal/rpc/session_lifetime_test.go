package rpc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"rsbx/internal/proto"
)

type sessionLifetimeResult struct {
	code int
	err  error
}

type sessionErrorWriter struct{ err error }

func (w sessionErrorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestSessionClosesTransportBeforeJoiningBlockedStdin(t *testing.T) {
	writeErr := errors.New("output failed")
	for _, tc := range []struct {
		name    string
		typ     byte
		payload []byte
		stdout  io.Writer
		code    int
		err     error
	}{
		{"exit", proto.TExit, proto.ExitPayload(23), io.Discard, 23, nil},
		{"output error", proto.TStdout, []byte("output"), sessionErrorWriter{writeErr}, 127, writeErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, daemon := net.Pipe()
			t.Cleanup(func() { daemon.Close() })
			in, input, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { input.Close(); in.Close() })
			if _, err := io.WriteString(input, "blocked stdin"); err != nil {
				t.Fatal(err)
			}
			served := make(chan error, 1)
			go func() {
				frame, err := proto.ReadFrame(daemon)
				if err != nil {
					served <- err
					return
				}
				if frame.Type != proto.TExec {
					served <- fmt.Errorf("first frame type = %d", frame.Type)
					return
				}
				var header [5]byte
				if _, err := io.ReadFull(daemon, header[:]); err != nil {
					served <- err
					return
				}
				if header[4] != proto.TStdin || binary.BigEndian.Uint32(header[:4]) == 0 {
					served <- fmt.Errorf("expected a nonempty stdin frame, got %v", header)
					return
				}
				// Leave the stdin payload unread and keep the connection open.
				// Teardown, not this fake daemon's EOF, must release the writer.
				served <- proto.WriteFrame(daemon, tc.typ, tc.payload)
			}()
			result := make(chan sessionLifetimeResult, 1)
			go func() {
				code, err := runSession(context.Background(), func(context.Context) (net.Conn, error) {
					return client, nil
				}, &proto.ExecReq{Target: "example", Argv: []string{"example"}, Dir: "/"}, in, tc.stdout, io.Discard)
				result <- sessionLifetimeResult{code: code, err: err}
			}()
			got := awaitRPC(t, result)
			if got.code != tc.code || !errors.Is(got.err, tc.err) {
				t.Fatalf("session = (%d, %v), want (%d, %v)", got.code, got.err, tc.code, tc.err)
			}
			if err := awaitRPC(t, served); err != nil {
				t.Fatal(err)
			}
			if _, err := in.Stat(); err != nil {
				t.Fatalf("session closed the caller's stdin: %v", err)
			}
			closed := make(chan error, 1)
			go func() {
				_, err := daemon.Read(make([]byte, 1))
				closed <- err
			}()
			if err := awaitRPC(t, closed); !errors.Is(err, io.EOF) {
				t.Fatalf("session did not close its connection: %v", err)
			}
		})
	}
}

func TestSessionCancellationWakesOwnedStdin(t *testing.T) {
	client, daemon := net.Pipe()
	t.Cleanup(func() { daemon.Close() })
	in, input, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close(); in.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	seen := make(chan error, 1)
	go func() {
		_, err := proto.ReadFrame(daemon)
		seen <- err
	}()
	result := make(chan sessionLifetimeResult, 1)
	go func() {
		code, err := runSession(ctx, func(context.Context) (net.Conn, error) { return client, nil },
			&proto.ExecReq{Target: "example", Argv: []string{"example"}}, in, io.Discard, io.Discard)
		result <- sessionLifetimeResult{code: code, err: err}
	}()
	if err := awaitRPC(t, seen); err != nil {
		t.Fatal(err)
	}
	cancel()
	got := awaitRPC(t, result)
	if got.code != 127 || !errors.Is(got.err, context.Canceled) {
		t.Fatalf("canceled session = (%d, %v)", got.code, got.err)
	}
	if err := in.SetReadDeadline(time.Now().Add(rpcLifetimeTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(input, "caller"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("caller"))
	if _, err := io.ReadFull(in, buf); err != nil || string(buf) != "caller" {
		t.Fatalf("caller stdin after cancellation = (%q, %v)", buf, err)
	}
}

func TestSessionDisconnectBeforeExitIsAnError(t *testing.T) {
	client, daemon := net.Pipe()
	t.Cleanup(func() { daemon.Close() })
	served := make(chan error, 1)
	go func() {
		_, err := proto.ReadFrame(daemon)
		daemon.Close()
		served <- err
	}()
	result := make(chan sessionLifetimeResult, 1)
	go func() {
		code, err := runSession(context.Background(), func(context.Context) (net.Conn, error) { return client, nil },
			&proto.ExecReq{Target: "example", Argv: []string{"example"}}, strings.NewReader(""), io.Discard, io.Discard)
		result <- sessionLifetimeResult{code: code, err: err}
	}()
	got := awaitRPC(t, result)
	if got.code != 127 || got.err == nil {
		t.Fatalf("disconnect reported (%d, %v), want 127 and an error", got.code, got.err)
	}
	if err := awaitRPC(t, served); err != nil {
		t.Fatal(err)
	}
}

func TestCancellableFileReaderWakesWithoutClosingOriginal(t *testing.T) {
	in, input, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close(); in.Close() })
	// Closing a duplicate does not interrupt a blocking Linux read. Exercise
	// that descriptor mode explicitly instead of relying on Go's pipe poller.
	if err := syscall.SetNonblock(int(in.Fd()), false); err != nil {
		t.Fatal(err)
	}
	reader, cancel, release, joinable, err := cancellableReader(in)
	if err != nil || !joinable {
		t.Fatalf("cancellableReader = (joinable %v, %v)", joinable, err)
	}
	t.Cleanup(release)
	started, done := make(chan struct{}), make(chan error, 1)
	go func() {
		defer release()
		close(started)
		_, err := reader.Read(make([]byte, 1))
		done <- err
	}()
	awaitRPC(t, started)
	cancel()
	cancel()
	if err := awaitRPC(t, done); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("canceled file read = %v", err)
	}
	if _, err := io.WriteString(input, "owned"); err != nil {
		t.Fatal(err)
	}
	readBack := make(chan error, 1)
	go func() {
		buf := make([]byte, len("owned"))
		_, err := io.ReadFull(in, buf)
		if err == nil && string(buf) != "owned" {
			err = fmt.Errorf("read %q, want owned", buf)
		}
		readBack <- err
	}()
	if err := awaitRPC(t, readBack); err != nil {
		t.Fatalf("original descriptor was changed or closed: %v", err)
	}
}

func TestCancellableReaderClosedFileFails(t *testing.T) {
	in, input, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	input.Close()
	in.Close()
	_, _, _, _, err = cancellableReader(in)
	if err == nil {
		t.Fatal("closed stdin silently became an uninterruptible reader")
	}
}

func TestSessionRejectsMissingTargetBeforeDial(t *testing.T) {
	for _, req := range []*proto.ExecReq{
		nil,
		{Argv: []string{"argv-zero"}},
		{Target: "example"},
	} {
		dialed := false
		code, err := runSession(context.Background(), func(context.Context) (net.Conn, error) {
			dialed = true
			return nil, errors.New("unexpected dial")
		}, req, strings.NewReader(""), io.Discard, io.Discard)
		if dialed || code != 127 || err == nil {
			t.Fatalf("invalid request dialed=%v, result=(%d, %v)", dialed, code, err)
		}
	}
}
