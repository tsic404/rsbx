// Command rsbx-tramp is served in place of every executable that must run on
// the daemon instead of locally.
//
// It learns which command it stands for from /proc/self/exe (the path the
// caller exec'd), then asks the daemon to run exactly that command and bridges
// stdio. Being statically linked is deliberate: it must work even when the
// program the user tried to run was itself static.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"rsbx/internal/proto"
	"rsbx/internal/rpc"
)

func main() {
	self, err := os.Readlink("/proc/self/exe")
	if err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-tramp: cannot identify itself:", err)
		os.Exit(127)
	}
	if os.Getenv("RSBX_TRAMP_SELFTEST") != "" {
		cwd, _ := os.Getwd()
		fmt.Printf("trampoline=%s argv=%v cwd=%s\n", self, os.Args, cwd)
		return
	}
	target := self
	if env := os.Getenv("RSBX_TARGET"); env != "" {
		target = env
	}
	// The transport is either a unix socket (daemon on this host) or a
	// command that speaks the protocol on its stdio (ssh).
	sock := os.Getenv("RSBX_TRAMP_SOCK")
	cmdSpec := os.Getenv("RSBX_TRAMP_CMD")
	if sock == "" && cmdSpec == "" {
		fmt.Fprintln(os.Stderr, "rsbx-tramp: no daemon transport in the environment")
		os.Exit(127)
	}
	req := &proto.ExecReq{
		Argv: append([]string{target}, os.Args[1:]...),
		Env:  os.Environ(),
		TTY:  isCharDevice(os.Stdin) && isCharDevice(os.Stdout),
	}
	// The daemon operates on its own root, not on the sandbox's mount path,
	// so the working directory travels as a sandbox-absolute path.
	// Inside bwrap the mount *is* /, so the cwd is already correct there.
	if cwd, err := os.Getwd(); err == nil {
		req.Dir = sandboxPath(cwd)
	}
	if root := os.Getenv("RSBX_ROOT"); root != "" {
		req.Env = append(req.Env, "RSBX_ROOT="+root)
	}
	transport := rpc.Target{Socket: sock}
	if cmdSpec != "" {
		transport = rpc.Target{Command: splitArgs(cmdSpec)}
	}
	code, err := rpc.RunSession(transport, req, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-tramp:", err)
		os.Exit(127)
	}
	// A command that failed while naming a local tree is the one case where
	// the remote view cannot satisfy it, and the raw ENOENT says nothing about
	// why. Say it instead of leaving the user to infer it.
	if code != 0 && os.Getenv("RSBX_LOCAL_TREES") != "" {
		if hit := firstLocalArg(req.Argv, os.Getenv("RSBX_LOCAL_TREES")); hit != "" {
			fmt.Fprintf(os.Stderr,
				"rsbx: %s ran on the daemon and cannot see the local tree %s; "+
					"add %s to local.allow to run it here instead\n",
				filepath.Base(req.Argv[0]), hit, req.Argv[0])
		}
	}
	os.Exit(code)
}

// firstLocalArg returns the first argument that lies inside one of the
// colon-separated local trees, or "" when there is none.
func firstLocalArg(argv []string, trees string) string {
	for _, a := range argv[1:] {
		if !strings.HasPrefix(a, "/") {
			continue
		}
		for _, tree := range strings.Split(trees, ":") {
			if tree == "" {
				continue
			}
			if a == tree || strings.HasPrefix(a, tree+"/") {
				return a
			}
		}
	}
	return ""
}

// sandboxPath strips the FUSE mount prefix so the daemon sees "/proj" rather
// than "/home/user/.rsbx/sandbox/proj".
func sandboxPath(p string) string {
	mount := os.Getenv("RSBX_SANDBOX_MOUNT")
	if mount == "" || !strings.HasPrefix(p, mount) {
		return p
	}
	rest := strings.TrimPrefix(p, mount)
	if rest == "" {
		return "/"
	}
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	return rest
}

// splitArgs splits a whitespace separated command line into argv.
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func isCharDevice(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

var _ = syscall.Getpid
