// Command rsbxd is the daemon: it runs commands and owns the remote tree.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"rsbx/internal/daemon"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	showVer := flag.Bool("version", false, "print the version and exit")
	sock := flag.String("socket", "", "unix socket to listen on (empty = stdio)")
	root := flag.String("root", "", "remote root directory")
	stdio := flag.Bool("stdio", false, "serve a single session over stdin/stdout")
	flag.Parse()

	if *showVer {
		fmt.Println("rsbxd", version)
		return
	}
	if *root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err)
		}
		*root = home
	}
	if err := os.MkdirAll(*root, 0o755); err != nil {
		log.Fatal(err)
	}
	srv := &daemon.Server{Root: *root}

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
	log.Printf("rsbxd: socket=%s root=%s", *sock, *root)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("rsbxd: accept: %v", err)
			continue
		}
		go srv.ServeConn(c)
	}
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
