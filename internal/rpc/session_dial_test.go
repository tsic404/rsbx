package rpc

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"rsbx/internal/proto"
)

// A daemon that cannot be reached fails the session at establishment and says
// so. The dial seam is the only place this path can be exercised without a
// second machine, so it is asserted here rather than left to a carrier.
func TestSessionDialFailureIsExplicit(t *testing.T) {
	dialErr := errors.New("dial unix /run/rsbx/daemon.sock: connect: no such file or directory")
	dials := 0
	code, err := runSession(context.Background(), func(context.Context) (net.Conn, error) {
		dials++
		return nil, dialErr
	}, &proto.ExecReq{
		Target: "/bin/true",
		Argv:   []string{"/bin/true"},
	}, strings.NewReader(""), io.Discard, io.Discard)

	if dials != 1 {
		t.Fatalf("dial called %d times, want exactly 1", dials)
	}
	if code != 127 {
		t.Errorf("exit status = %d, want 127", code)
	}
	if err == nil {
		t.Fatal("an unreachable daemon was reported as a successful session")
	}
	if !errors.Is(err, dialErr) {
		t.Errorf("failure lost its cause: %v", err)
	}
	if !strings.Contains(err.Error(), "connect to daemon") {
		t.Errorf("failure does not name the connection: %v", err)
	}
}

// Cancelling the caller's context aborts a dial that is still in flight, and
// the session reports the cancellation rather than a half-built connection.
func TestSessionDialCanceledByContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, err := runSession(ctx, func(ctx context.Context) (net.Conn, error) {
		return nil, ctx.Err()
	}, &proto.ExecReq{
		Target: "/bin/true",
		Argv:   []string{"/bin/true"},
	}, strings.NewReader(""), io.Discard, io.Discard)

	if code != 127 {
		t.Errorf("exit status = %d, want 127", code)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want a canceled context", err)
	}
}
