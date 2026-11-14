// Command rsbxd is the daemon: it runs commands and owns the remote tree.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

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
