package sandbox

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"rsbx/internal/rpc"
)

// broker is a private unix listener that relays every accepted connection to
// the daemon via rpc.Target.Dial.
//
// It lives outside the sandbox root. Only its directory is bound in, at
// BrokerDir, so the trampoline inside reaches the daemon without the host
// socket directory, ssh binary or credentials being visible at all: for the
// ssh transport the broker process is the one that starts ssh, in the host
// mount and network context.
type broker struct {
	listener net.Listener
	dir      string
	target   rpc.Target
	wg       sync.WaitGroup
	once     sync.Once
	done     chan struct{}
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
	b := &broker{listener: ln, dir: dir, target: target, done: make(chan struct{})}
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
			case <-b.done:
				return
			default:
				continue
			}
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			b.relay(conn)
		}()
	}
}

// relay pipes one sandbox connection to a fresh daemon connection.
func (b *broker) relay(client net.Conn) {
	defer client.Close()
	upstream, err := b.target.Dial()
	if err != nil {
		return
	}
	defer upstream.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(upstream, client)
		// Half-close so the daemon sees end-of-request even when the
		// transport is a command's stdio rather than a real socket.
		if c, ok := upstream.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(client, upstream)
		if c, ok := client.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
	}()
	wg.Wait()
}

// Stop closes the listener, waits for live relays and removes the directory.
func (b *broker) Stop() {
	b.once.Do(func() { close(b.done) })
	b.listener.Close()
	b.wg.Wait()
	os.RemoveAll(b.dir)
}

// Close stops the broker (alias for Stop, used by Plan.Run defer).
func (b *broker) Close() error { b.Stop(); return nil }

// HostSockPath returns the host-side socket path for the bind mount source.
func (b *broker) HostSockPath() string { return filepath.Join(b.dir, "daemon.sock") }
