package sandbox

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"rsbx/internal/rpc"
)

// broker is a private unix listener that relays every accepted connection to
// the daemon via rpc.Target.DialContext.
//
// It lives outside the sandbox root. Only its directory is bound in, at
// BrokerDir, so the trampoline inside reaches the daemon without the host
// socket directory, ssh binary or credentials being visible at all: for the
// ssh transport the broker process is the one that starts ssh, in the host
// mount and network context.
type broker struct {
	listener net.Listener
	dir      string
	dial     func(context.Context) (net.Conn, error)
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	once     sync.Once
	closeErr error
}

// newBroker creates the private relay directory and starts accepting.
func newBroker(target rpc.Target, dir string) (*broker, error) {
	// The directory must be private to this user: it is the only host path
	// the sandbox can touch, and it answers filesystem requests with the
	// caller's full authority.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "daemon.sock")
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &broker{listener: ln, dir: dir, dial: target.DialContext, ctx: ctx, cancel: cancel, conns: make(map[net.Conn]struct{})}
	b.wg.Add(1)
	go b.accept()
	return b, nil
}

// HostDir is the host directory to bind at BrokerDir inside the sandbox.
func (b *broker) HostDir() string { return b.dir }

// Socket is the socket path as the sandbox sees it.
func (b *broker) Socket() string { return BrokerSock }

// accept relays every connection until the broker is stopped.
func (b *broker) accept() {
	defer b.wg.Done()
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			select {
			case <-b.ctx.Done():
				return
			default:
				continue
			}
		}
		b.startRelay(conn)
	}
}

// startRelay takes ownership before starting the goroutine. Its Add and the
// closed check share a lock, so Close cannot miss a just-accepted connection.
func (b *broker) startRelay(client net.Conn) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		client.Close()
		return
	}
	b.conns[client] = struct{}{}
	b.wg.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.wg.Done()
		b.relay(client)
	}()
}

func (b *broker) track(conn net.Conn) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.conns[conn] = struct{}{}
	return true
}

func (b *broker) release(conn net.Conn) {
	conn.Close()
	b.mu.Lock()
	delete(b.conns, conn)
	b.mu.Unlock()
}

// relay pipes one sandbox connection to its own daemon connection. A direction
// that ends half-closes its destination, so the peer reads every byte before
// EOF. The two directions settle independently: a daemon that has already
// finished still owes its final frame to the sandbox, so a failed write toward
// it must not tear down the other stream. Only a sandbox-side read failure, a
// sandbox-side write failure, or a broker shutdown closes both.
func (b *broker) relay(client net.Conn) {
	defer b.release(client)
	upstream, err := b.dial(b.ctx)
	if err != nil {
		return
	}
	if !b.track(upstream) {
		upstream.Close()
		return
	}
	defer b.release(upstream)
	type direction struct {
		fromClient bool
		write      bool
		err        error
	}
	results := make(chan direction, 2)
	copyStream := func(dst, src net.Conn, fromClient bool) {
		result := direction{fromClient: fromClient}
		buf := make([]byte, 32<<10)
		for {
			n, rerr := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					result.err, result.write = werr, true
					break
				}
			}
			if rerr != nil {
				if !errors.Is(rerr, io.EOF) {
					result.err = rerr
				}
				break
			}
		}
		if result.err == nil {
			if c, ok := dst.(interface{ CloseWrite() error }); ok {
				result.err = c.CloseWrite()
				result.write = result.err != nil
			}
		}
		results <- result
	}
	go copyStream(upstream, client, true)
	go copyStream(client, upstream, false)
	for range 2 {
		result := <-results
		if b.ctx.Err() != nil {
			client.Close()
			upstream.Close()
			continue
		}
		if result.err == nil {
			continue
		}
		// A write failure toward the daemon means that connection is finished:
		// it may still hold the session's last frame for the sandbox, and that
		// stream is the only one that may end the sandbox side.
		if result.fromClient && result.write {
			continue
		}
		client.Close()
		upstream.Close()
	}
}

// Stop is the no-result shutdown used by callers that do not need cleanup errors.
func (b *broker) Stop() { b.Close() }

// Close cancels dialing and closes every stream before waiting for relays.
func (b *broker) Close() error {
	b.once.Do(func() {
		b.mu.Lock()
		b.closed = true
		b.cancel()
		conns := b.conns
		b.conns = nil
		b.mu.Unlock()
		b.listener.Close()
		for conn := range conns {
			conn.Close()
		}
		b.wg.Wait()
		b.closeErr = os.RemoveAll(b.dir)
	})
	return b.closeErr
}

// HostSockPath returns the host-side socket path for the bind mount source.
func (b *broker) HostSockPath() string { return filepath.Join(b.dir, "daemon.sock") }
