// Command rsbx-guard installs the Landlock exec allowlist and then runs the
// requested program.
//
// It runs inside the sandbox, after bwrap has built the view: bwrap itself
// needs mount and mkdir rights that the ruleset would deny, so the restriction
// cannot be installed before it.
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"rsbx/internal/sandbox"
)

func main() {
	if spec := os.Getenv("RSBX_LANDLOCK_EXEC"); spec != "" {
		if err := sandbox.ApplyLandlock(strings.Split(spec, ":")); err != nil && !isUnsupported(err) {
			fmt.Fprintln(os.Stderr, "rsbx-guard:", err)
			os.Exit(126)
		}
	}
	argv := os.Args[1:]
	if len(argv) == 0 {
		os.Exit(0)
	}
	if err := syscall.Exec(argv[0], argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx-guard: exec %s: %v\n", argv[0], err)
		os.Exit(127)
	}
}

// isUnsupported reports whether Landlock is missing from the running kernel, in
// which case the sandbox degrades to trampoline-only redirection.
func isUnsupported(err error) bool {
	s := err.Error()
	return strings.Contains(s, "function not implemented") ||
		strings.Contains(s, "operation not supported") ||
		strings.Contains(s, "invalid argument")
}
