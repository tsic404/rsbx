package rpc

import (
	"context"
	"errors"

	"net"
	"strings"
	"testing"
	"time"

	"rsbx/internal/proto"
)

// scriptedConn answers reads with one fixed error and writes with another, so
// the request path is exercised without a kernel transport whose timing would
// decide the assertion.
type scriptedConn struct {
	readErr  error
	writeErr error
	closed   chan struct{}
}

func (c *scriptedConn) Read([]byte) (int, error) { return 0, c.readErr }
func (c *scriptedConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}
func (c *scriptedConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *scriptedConn) LocalAddr() net.Addr              { return nil }
func (c *scriptedConn) RemoteAddr() net.Addr             { return nil }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

func newScriptedFS(t *testing.T, conn *scriptedConn) *FS {
	t.Helper()
	fs := NewFS(Target{})
	fs.dial = func(ctx context.Context) (net.Conn, error) { return conn, nil }
	t.Cleanup(func() { fs.Close() })
	return fs
}

// A connection whose reader fails with a certificate error must fail the
// waiting request with that cause. Reporting a bare disconnect instead sends
// the operator looking for a network fault when the peer rejected the
// certificate.
func TestRequestReportsReaderCause(t *testing.T) {
	rejection := errors.New("remote error: tls: bad certificate")
	fs := newScriptedFS(t, &scriptedConn{readErr: rejection, closed: make(chan struct{})})
	_, err := fs.Do(&proto.FxReq{Op: proto.FxStat, Path: "/"})
	if err == nil {
		t.Fatal("a connection that failed was reported as usable")
	}
	if !strings.Contains(err.Error(), "bad certificate") {
		t.Fatalf("the failure lost the reader's cause: %v", err)
	}
}

// A write that fails after the reader already saw the cause must report that
// cause: the write symptom (a reset or broken pipe) says nothing about why the
// peer went away.
func TestFailedWriteReportsReaderCause(t *testing.T) {
	rejection := errors.New("remote error: tls: certificate required")
	conn := &scriptedConn{
		readErr:  rejection,
		writeErr: errors.New("write: broken pipe"),
		closed:   make(chan struct{}),
	}
	fs := NewFS(Target{})
	fs.dial = func(ctx context.Context) (net.Conn, error) { return conn, nil }
	t.Cleanup(func() { fs.Close() })

	// The first request arms the connection; the reader fails immediately, so
	// by the time the second write runs the cause is recorded.
	fs.Do(&proto.FxReq{Op: proto.FxStat, Path: "/"})
	_, err := fs.Do(&proto.FxReq{Op: proto.FxStat, Path: "/"})
	if err == nil {
		t.Fatal("a write to a dead connection was reported as usable")
	}
	if !strings.Contains(err.Error(), "certificate required") {
		t.Fatalf("the failure lost the reader's cause: %v", err)
	}
}
