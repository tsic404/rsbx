package rpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"rsbx/internal/proto"
)

const rpcLifetimeTimeout = 5 * time.Second

func awaitRPC[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(rpcLifetimeTimeout):
		t.Fatal("timed out waiting for RPC lifetime event")
		var zero T
		return zero
	}
}

type fsLifetimeReply struct {
	resp *proto.FxResp
	err  error
}

func startFSRequest(fs *FS, path string) <-chan fsLifetimeReply {
	out := make(chan fsLifetimeReply, 1)
	go func() {
		resp, err := fs.Do(&proto.FxReq{Op: proto.FxReadlink, Path: path})
		out <- fsLifetimeReply{resp: resp, err: err}
	}()
	return out
}

func newLifetimeFS(t *testing.T, dial func(context.Context) (net.Conn, error)) *FS {
	t.Helper()
	fs := NewFS(Target{})
	fs.dial = dial
	t.Cleanup(func() { fs.Close() })
	return fs
}

func closeFSWithin(t *testing.T, fs *FS) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fs.Close() }()
	if err := awaitRPC(t, done); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestFSCloseReleasesPendingAndRejectsReconnect(t *testing.T) {
	client, daemon := net.Pipe()
	t.Cleanup(func() { daemon.Close() })
	var dials atomic.Int32
	fs := newLifetimeFS(t, func(context.Context) (net.Conn, error) {
		dials.Add(1)
		return client, nil
	})
	seen := make(chan error, 1)
	go func() {
		_, err := proto.ReadFrame(daemon)
		seen <- err
	}()
	out := startFSRequest(fs, "/waiting")
	if err := awaitRPC(t, seen); err != nil {
		t.Fatal(err)
	}

	closeFSWithin(t, fs)
	reply := awaitRPC(t, out)
	if reply.resp != nil || !errors.Is(reply.err, net.ErrClosed) {
		t.Fatalf("pending request = (%v, %v), want closed error", reply.resp, reply.err)
	}
	if resp, err := fs.Do(&proto.FxReq{Op: proto.FxStat, Path: "/after-close"}); resp != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("post-close request = (%v, %v), want closed error", resp, err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dialed %d times, want exactly one", got)
	}
}

type fsWriteNoticeConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *fsWriteNoticeConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestFSCloseReleasesBlockedWrite(t *testing.T) {
	client, daemon := net.Pipe()
	t.Cleanup(func() { daemon.Close() })
	conn := &fsWriteNoticeConn{Conn: client, started: make(chan struct{})}
	fs := newLifetimeFS(t, func(context.Context) (net.Conn, error) { return conn, nil })
	out := startFSRequest(fs, "/blocked-write")
	// The daemon never reads: a net.Pipe write cannot complete before Close.
	awaitRPC(t, conn.started)
	closeFSWithin(t, fs)
	reply := awaitRPC(t, out)
	if reply.resp != nil || !errors.Is(reply.err, net.ErrClosed) {
		t.Fatalf("blocked write = (%v, %v), want closed error", reply.resp, reply.err)
	}
}

// A lost connection is reported before any later request notices. The
// filesystem view turns that signal into dropping its retained results; without
// it a query that the view answered locally would keep succeeding after the
// daemon is gone.
func TestFSReportsLostConnection(t *testing.T) {
	client, daemon := net.Pipe()
	fs := newLifetimeFS(t, func(context.Context) (net.Conn, error) { return client, nil })
	lost := make(chan struct{})
	var once sync.Once
	fs.OnLost(func() { once.Do(func() { close(lost) }) })

	out := startFSRequest(fs, "/lost")
	if _, err := proto.ReadFrame(daemon); err != nil {
		t.Fatalf("read request: %v", err)
	}
	daemon.Close()
	if reply := awaitRPC(t, out); reply.err == nil {
		t.Fatal("the request on a closed connection succeeded")
	}
	awaitRPC(t, lost)
}

func TestFSCloseCancelsDial(t *testing.T) {
	started := make(chan struct{})
	var dials atomic.Int32
	fs := newLifetimeFS(t, func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	out := startFSRequest(fs, "/during-dial")
	awaitRPC(t, started)
	closeFSWithin(t, fs)
	if reply := awaitRPC(t, out); reply.resp != nil || !errors.Is(reply.err, net.ErrClosed) {
		t.Fatalf("dialing request = (%v, %v), want closed error", reply.resp, reply.err)
	}
	if reply := awaitRPC(t, startFSRequest(fs, "/after-dial-cancel")); !errors.Is(reply.err, net.ErrClosed) {
		t.Fatalf("post-close request error = %v", reply.err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dialed %d times after cancellation", got)
	}
}

func TestFSCloseRejectsRequestsWhileCanceledDialUnwinds(t *testing.T) {
	client, daemon := net.Pipe()
	t.Cleanup(func() { daemon.Close() })
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseDial := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseDial)
	fs := newLifetimeFS(t, func(ctx context.Context) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		// A connection returned after cancellation must never enter the session.
		return client, nil
	})
	out := startFSRequest(fs, "/unwinding-dial")
	awaitRPC(t, started)
	closeFSWithin(t, fs)
	awaitRPC(t, canceled)
	if reply := awaitRPC(t, startFSRequest(fs, "/after-close")); !errors.Is(reply.err, net.ErrClosed) {
		t.Fatalf("post-close request error = %v", reply.err)
	}
	releaseDial()
	if reply := awaitRPC(t, out); !errors.Is(reply.err, net.ErrClosed) {
		t.Fatalf("late dial result error = %v", reply.err)
	}
	closed := make(chan error, 1)
	go func() {
		_, err := daemon.Read(make([]byte, 1))
		closed <- err
	}()
	if err := awaitRPC(t, closed); !errors.Is(err, io.EOF) {
		t.Fatalf("late connection was left open: %v", err)
	}
}

func TestFSConcurrentResponsesStayWithTheirRequests(t *testing.T) {
	client, daemon := net.Pipe()
	t.Cleanup(func() { daemon.Close() })
	fs := newLifetimeFS(t, func(context.Context) (net.Conn, error) { return client, nil })
	served := make(chan error, 1)
	go func() {
		var reqs [2]*proto.FxReq
		for i := range reqs {
			frame, err := proto.ReadFrame(daemon)
			if err != nil {
				served <- err
				return
			}
			reqs[i], err = proto.DecodeFxReq(frame.Payload)
			if err != nil {
				served <- err
				return
			}
		}
		if reqs[0].ID == reqs[1].ID {
			served <- fmt.Errorf("concurrent requests share ID %d", reqs[0].ID)
			return
		}
		for i := len(reqs) - 1; i >= 0; i-- {
			resp := &proto.FxResp{ID: reqs[i].ID, Kind: proto.KLink, Data: []byte(reqs[i].Path)}
			if err := proto.WriteFrame(daemon, proto.TFxResp, resp.Encode()); err != nil {
				served <- err
				return
			}
		}
		served <- nil
	}()
	first := startFSRequest(fs, "/first")
	second := startFSRequest(fs, "/second")
	for _, want := range []struct {
		path string
		out  <-chan fsLifetimeReply
	}{{"/first", first}, {"/second", second}} {
		reply := awaitRPC(t, want.out)
		if reply.err != nil || reply.resp == nil || string(reply.resp.Data) != want.path {
			t.Fatalf("response for %s = (%v, %v)", want.path, reply.resp, reply.err)
		}
	}
	if err := awaitRPC(t, served); err != nil {
		t.Fatal(err)
	}
}

func TestFSDroppedConnectionReconnectsOnlyForNextRequest(t *testing.T) {
	firstClient, firstDaemon := net.Pipe()
	secondClient, secondDaemon := net.Pipe()
	t.Cleanup(func() { firstDaemon.Close(); secondDaemon.Close() })
	var dials atomic.Int32
	fs := newLifetimeFS(t, func(context.Context) (net.Conn, error) {
		switch dials.Add(1) {
		case 1:
			return firstClient, nil
		case 2:
			return secondClient, nil
		default:
			return nil, errors.New("unexpected retry")
		}
	})
	firstRead := make(chan error, 1)
	go func() {
		_, err := proto.ReadFrame(firstDaemon)
		firstDaemon.Close()
		firstRead <- err
	}()
	failed := awaitRPC(t, startFSRequest(fs, "/lost"))
	if failed.err == nil || failed.resp != nil {
		t.Fatalf("disconnected request = (%v, %v)", failed.resp, failed.err)
	}
	if err := awaitRPC(t, firstRead); err != nil {
		t.Fatal(err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("failed request retried: %d dials", got)
	}
	served := make(chan error, 1)
	go func() {
		frame, err := proto.ReadFrame(secondDaemon)
		if err != nil {
			served <- err
			return
		}
		req, err := proto.DecodeFxReq(frame.Payload)
		if err != nil {
			served <- err
			return
		}
		resp := &proto.FxResp{ID: req.ID, Kind: proto.KLink, Data: []byte("second")}
		served <- proto.WriteFrame(secondDaemon, proto.TFxResp, resp.Encode())
	}()
	reply := awaitRPC(t, startFSRequest(fs, "/next"))
	if reply.err != nil || reply.resp == nil || string(reply.resp.Data) != "second" {
		t.Fatalf("reconnected request = (%v, %v)", reply.resp, reply.err)
	}
	if err := awaitRPC(t, served); err != nil {
		t.Fatal(err)
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("dialed %d times, want two", got)
	}
}
