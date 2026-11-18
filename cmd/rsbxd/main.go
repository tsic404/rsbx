// Command rsbxd is the daemon: it runs commands and owns the remote tree. Its
// own root is the remote filesystem; there is no -root override and no jail.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"rsbx/internal/rpc"
	"syscall"
	"time"

	"rsbx/internal/daemon"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	showVer := flag.Bool("version", false, "print the version and exit")
	sock := flag.String("socket", "", "unix socket to listen on (empty = stdio)")
	stdio := flag.Bool("stdio", false, "serve a single session over stdin/stdout")
	listen := flag.String("listen", "", "authenticated TCP address")
	ca := flag.String("tls-ca", "", "client certificate CA")
	cert := flag.String("tls-cert", "", "server certificate")
	key := flag.String("tls-key", "", "server key")
	skipVerify := flag.Bool("tls-skip-verify", false, "local test only")
	flag.Parse()

	if *showVer {
		fmt.Println("rsbxd", version)
		return
	}
	srv := &daemon.Server{}
	if *listen != "" {
		config, err := rpc.TLSConfig(*ca, *cert, *key, "", true, *skipVerify)
		if err != nil {
			log.Fatal(err)
		}
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		for {
			raw, err := ln.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go serveTLS(srv, raw, config)
		}
	}

	if *stdio || *sock == "" {
		srv.ServeConn(stdioConn{})
		return
	}
	if dir := filepath.Dir(*sock); dir != "" {
		os.MkdirAll(dir, 0o700)
	}
	// One daemon per socket, enforced rather than assumed.
	//
	// Unlinking the socket path before listening lets a second daemon start
	// alongside the first: both are listening, only one path exists, and the
	// two accept loops race for each connection. A client then stalls whenever
	// its connection lands on the wrong side — which reads as "the daemon
	// hangs" and is nearly impossible to see from the outside. An exclusive
	// file lock makes the second start fail with a reason instead.
	unlock, err := lockInstance(*sock + ".lock")
	if err != nil {
		log.Fatalf("rsbxd: %v", err)
	}
	defer unlock()
	os.Remove(*sock)
	ln, err := net.Listen("unix", *sock)
	if err != nil {
		log.Fatal(err)
	}
	os.Chmod(*sock, 0o600)
	log.Printf("rsbxd: socket=%s", *sock)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("rsbxd: accept: %v", err)
			continue
		}
		go srv.ServeConn(c)
	}
}

// serveTLS completes the handshake before serving, and on a refused handshake
// drains what the peer already sent before closing. Closing a socket with
// unread data makes the kernel send RST, which can discard the TLS alert that
// carries the real reason; the peer would then report a reset instead of the
// rejected certificate. Draining keeps the alert deliverable.
func serveTLS(srv *daemon.Server, raw net.Conn, config *tls.Config) {
	conn := tls.Server(raw, config)
	if err := conn.Handshake(); err != nil {
		// The tls.Conn refuses further reads once its handshake failed, so
		// the drain has to happen on the raw socket: unread bytes at close
		// make the kernel answer with RST, which discards the alert.
		raw.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		io.Copy(io.Discard, raw)
		conn.Close()
		return
	}
	srv.ServeConn(conn)
}

// lockInstance takes an exclusive advisory lock so only one daemon serves a
// socket. The lock is released when the process exits, including on a crash,
// because the kernel drops it with the descriptor.
func lockInstance(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another rsbxd already serves this socket (%s)", path)
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
