package sandbox

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"rsbx/internal/rpc"
)

const brokerLifetimeTimeout = 5 * time.Second

func awaitRelay[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(brokerLifetimeTimeout):
		t.Fatal("timed out waiting for broker lifetime event")
		var zero T
		return zero
	}
}

type relayPipeListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *relayPipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *relayPipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *relayPipeListener) Addr() net.Addr { return nil }

func newPipeRelay(t *testing.T, dial func(context.Context) (net.Conn, error)) (*broker, *relayPipeListener) {
	t.Helper()
	listener := &relayPipeListener{conns: make(chan net.Conn), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	b := &broker{listener: listener, dir: t.TempDir(), dial: dial, ctx: ctx, cancel: cancel, conns: make(map[net.Conn]struct{})}
	b.wg.Add(1)
	go b.accept()
	t.Cleanup(func() { b.Close() })
	return b, listener
}

func injectRelay(t *testing.T, listener *relayPipeListener, conn net.Conn) {
	t.Helper()
	select {
	case listener.conns <- conn:
	case <-time.After(brokerLifetimeTimeout):
		conn.Close()
		t.Fatal("broker did not accept the pipe")
	}
}

func closeBrokerWithin(t *testing.T, b *broker) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- b.Close() }()
	if err := awaitRelay(t, done); err != nil {
		t.Fatalf("broker Close: %v", err)
	}
}

func expectRelayPeerClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	read := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		read <- err
	}()
	if err := awaitRelay(t, read); !errors.Is(err, io.EOF) {
		t.Fatalf("broker left a peer open: %v", err)
	}
}

type relayNoticeConn struct {
	net.Conn
	readStarted  chan struct{}
	writeStarted chan struct{}
	closed       chan struct{}
	readOnce     sync.Once
	writeOnce    sync.Once
	closeOnce    sync.Once
}

func noticeRelayConn(conn net.Conn) *relayNoticeConn {
	return &relayNoticeConn{Conn: conn, readStarted: make(chan struct{}), writeStarted: make(chan struct{}), closed: make(chan struct{})}
}

func (c *relayNoticeConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	return c.Conn.Read(p)
}

func (c *relayNoticeConn) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	return c.Conn.Write(p)
}

func (c *relayNoticeConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return err
}

func beginRelayWrite(conn net.Conn, data string) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := io.WriteString(conn, data)
		done <- err
	}()
	return done
}

func readRelayMessage(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(brokerLifetimeTimeout)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != want {
		t.Fatalf("relayed bytes = (%q, %v), want %q", buf, err, want)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestBrokerCloseReleasesStalledRelay(t *testing.T) {
	upstream, daemon := net.Pipe()
	t.Cleanup(func() { daemon.Close() })
	up := noticeRelayConn(upstream)
	b, listener := newPipeRelay(t, func(context.Context) (net.Conn, error) { return up, nil })
	client, downstream := net.Pipe()
	t.Cleanup(func() { client.Close() })
	injectRelay(t, listener, downstream)
	awaitRelay(t, up.readStarted)
	written := beginRelayWrite(client, "stalled")
	// No daemon reader exists. The relay has consumed the downstream bytes
	// and is now trying a net.Pipe write that cannot finish normally.
	awaitRelay(t, up.writeStarted)
	if err := awaitRelay(t, written); err != nil {
		t.Fatal(err)
	}
	closeBrokerWithin(t, b)
	expectRelayPeerClosed(t, client)
	expectRelayPeerClosed(t, daemon)
	awaitRelay(t, up.closed)

	lateClient, lateServer := net.Pipe()
	t.Cleanup(func() { lateClient.Close() })
	b.startRelay(lateServer)
	expectRelayPeerClosed(t, lateClient)
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("post-close Accept = %v", err)
	}
	closeBrokerWithin(t, b)
}

func TestBrokerCloseCancelsDial(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan error, 1)
	b, listener := newPipeRelay(t, func(ctx context.Context) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		canceled <- ctx.Err()
		return nil, ctx.Err()
	})
	client, downstream := net.Pipe()
	t.Cleanup(func() { client.Close() })
	injectRelay(t, listener, downstream)
	awaitRelay(t, started)
	closeBrokerWithin(t, b)
	if err := awaitRelay(t, canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("dial cancellation = %v", err)
	}
	expectRelayPeerClosed(t, client)
}

func TestBrokerClosesUpstreamReturnedDuringShutdown(t *testing.T) {
	upstream, daemon := net.Pipe()
	t.Cleanup(func() { daemon.Close() })
	started := make(chan struct{})
	b, listener := newPipeRelay(t, func(ctx context.Context) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return upstream, nil
	})
	client, downstream := net.Pipe()
	t.Cleanup(func() { client.Close() })
	injectRelay(t, listener, downstream)
	awaitRelay(t, started)
	closeBrokerWithin(t, b)
	expectRelayPeerClosed(t, client)
	expectRelayPeerClosed(t, daemon)
}

type relayReadErrorConn struct {
	net.Conn
	err error
}

func (c relayReadErrorConn) Read([]byte) (int, error) { return 0, c.err }

func TestBrokerRelayErrorClosesBothDirections(t *testing.T) {
	upstream, daemon := net.Pipe()
	t.Cleanup(func() { daemon.Close() })
	b, listener := newPipeRelay(t, func(context.Context) (net.Conn, error) {
		return relayReadErrorConn{Conn: upstream, err: errors.New("upstream failed")}, nil
	})
	client, downstream := net.Pipe()
	t.Cleanup(func() { client.Close() })
	injectRelay(t, listener, downstream)
	expectRelayPeerClosed(t, client)
	expectRelayPeerClosed(t, daemon)
	closeBrokerWithin(t, b)
}

func TestBrokerKeepsSimultaneousClientsSeparate(t *testing.T) {
	type upstreamPair struct {
		daemon net.Conn
		conn   *relayNoticeConn
	}
	pairs := make(chan upstreamPair, 2)
	b, listener := newPipeRelay(t, func(context.Context) (net.Conn, error) {
		upstream, daemon := net.Pipe()
		conn := noticeRelayConn(upstream)
		pairs <- upstreamPair{daemon: daemon, conn: conn}
		return conn, nil
	})
	first, firstDownstream := net.Pipe()
	t.Cleanup(func() { first.Close() })
	injectRelay(t, listener, firstDownstream)
	firstUp := awaitRelay(t, pairs)
	t.Cleanup(func() { firstUp.daemon.Close() })
	second, secondDownstream := net.Pipe()
	t.Cleanup(func() { second.Close() })
	injectRelay(t, listener, secondDownstream)
	secondUp := awaitRelay(t, pairs)
	t.Cleanup(func() { secondUp.daemon.Close() })

	firstWrite, secondWrite := beginRelayWrite(first, "first"), beginRelayWrite(second, "second")
	readRelayMessage(t, firstUp.daemon, "first")
	readRelayMessage(t, secondUp.daemon, "second")
	if err := awaitRelay(t, firstWrite); err != nil {
		t.Fatal(err)
	}
	if err := awaitRelay(t, secondWrite); err != nil {
		t.Fatal(err)
	}
	firstReply, secondReply := beginRelayWrite(firstUp.daemon, "alpha"), beginRelayWrite(secondUp.daemon, "beta")
	readRelayMessage(t, first, "alpha")
	readRelayMessage(t, second, "beta")
	if err := awaitRelay(t, firstReply); err != nil {
		t.Fatal(err)
	}
	if err := awaitRelay(t, secondReply); err != nil {
		t.Fatal(err)
	}

	first.Close()
	firstUp.daemon.Close()
	awaitRelay(t, firstUp.conn.closed)
	stillLive := beginRelayWrite(second, "still live")
	readRelayMessage(t, secondUp.daemon, "still live")
	if err := awaitRelay(t, stillLive); err != nil {
		t.Fatal(err)
	}
	closeBrokerWithin(t, b)
	expectRelayPeerClosed(t, second)
	expectRelayPeerClosed(t, secondUp.daemon)
}

func TestBrokerHalfClosePreservesFinalReply(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	upstream, err := net.Listen("unix", filepath.Join(dir, "up.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { upstream.Close() })
	served := make(chan error, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(brokerLifetimeTimeout)); err != nil {
			served <- err
			return
		}
		data, err := io.ReadAll(conn)
		if err == nil {
			_, err = io.WriteString(conn, "reply:"+string(data))
		}
		served <- err
	}()
	b, err := newBroker(rpc.Target{Socket: filepath.Join(dir, "up.sock")}, filepath.Join(dir, "broker"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	conn, err := net.Dial("unix", b.HostSockPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(brokerLifetimeTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "request"); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	if err != nil || string(data) != "reply:request" {
		t.Fatalf("half-closed reply = (%q, %v)", data, err)
	}
	if err := awaitRelay(t, served); err != nil {
		t.Fatal(err)
	}
}
