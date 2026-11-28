package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"rsbx/internal/proto"
	"rsbx/internal/rpc"
)

func main() { os.Exit(run()) }

func run() int {
	target, args, err := selectTarget(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-stub:", err)
		return 126
	}
	socket := os.Getenv("RSBX_STUB_SOCKET")
	if socket == "" {
		fmt.Fprintln(os.Stderr, "rsbx-stub: missing absolute RSBX_STUB_SOCKET (no active sandbox session): RSBX_STUB_SOCKET is not set")
		return 126
	}
	if !filepath.IsAbs(socket) {
		fmt.Fprintf(os.Stderr, "rsbx-stub: missing absolute RSBX_STUB_SOCKET (no active sandbox session): %q is not an absolute path\n", socket)
		return 126
	}
	if info, err := os.Stat(socket); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx-stub: no live sandbox session at %s: %v\n", socket, err)
		return 126
	} else if info.Mode()&os.ModeSocket == 0 {
		fmt.Fprintf(os.Stderr, "rsbx-stub: no live sandbox session at %s: not a unix socket\n", socket)
		return 126
	}
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 126
	}
	req := &proto.ExecReq{Target: target, Argv: args, Env: os.Environ(), Dir: dir}
	if len(req.Encode()) > 1<<20 {
		fmt.Fprintln(os.Stderr, "rsbx-stub: request too large")
		return 126
	}
	code, err := rpc.RunSessionContext(context.Background(), rpc.Target{Socket: socket}, req, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-stub:", err)
		return 126
	}
	if code < 0 {
		return 128 - code
	}
	return code
}

func selectTarget(args []string) (string, []string, error) {
	if len(args) == 0 {
		return "", nil, fmt.Errorf("missing invocation name")
	}
	name := args[0]
	if filepath.Base(name) == "rsbx-stub" {
		if len(args) < 2 {
			return "", nil, fmt.Errorf("usage: rsbx-stub PROGRAM [ARG ...]")
		}
		name = args[1]
		args = args[1:]
	}
	if name == "" || strings.IndexByte(name, 0) >= 0 {
		return "", nil, fmt.Errorf("invalid target")
	}
	if strings.ContainsRune(name, '/') && !filepath.IsAbs(name) {
		absolute, err := filepath.Abs(name)
		if err != nil {
			return "", nil, err
		}
		name = absolute
	}
	return name, append([]string(nil), args...), nil
}
