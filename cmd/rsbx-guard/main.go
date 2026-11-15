// Command rsbx-guard installs the Landlock exec allowlist and then runs the
// requested program.
//
// It runs inside the sandbox, after the launcher has built the view and
// dropped every capability. The ruleset cannot be installed earlier: mounting
// and pivoting need rights the ruleset would deny, so the restriction lands
// between root setup and the first instruction of the entry.
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"rsbx/internal/sandbox"
)

func main() {
	argv := os.Args[1:]
	if len(argv) == 0 {
		os.Exit(0)
	}
	if spec := os.Getenv("RSBX_LANDLOCK_EXEC"); spec != "" {
		if err := sandbox.ApplyLandlock(strings.Split(spec, ":")); err != nil && !isUnsupported(err) {
			fmt.Fprintln(os.Stderr, "rsbx-guard:", err)
			os.Exit(126)
		}
	}
	if err := syscall.Exec(argv[0], argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx-guard: exec %s: %v\n", argv[0], err)
		os.Exit(127)
	}
}

// isUnsupported reports whether Landlock is missing from the running kernel,
// in which case the sandbox degrades to trampoline-only redirection.
func isUnsupported(err error) bool {
	s := err.Error()
	return strings.Contains(s, "function not implemented") ||
		strings.Contains(s, "operation not supported")
}
