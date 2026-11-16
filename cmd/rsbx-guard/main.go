// Command rsbx-guard installs the mandatory execution restrictions on the
// pinned thread that execs the entry program. Go runtime siblings may already
// exist; they are trusted helper code and are destroyed by exec. The target,
// argv, environment and exact Landlock paths arrive only in a sealed spec.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"

	"rsbx/internal/sandbox"
)

func main() {
	runtime.LockOSThread()
	if err := checkGuardArgs(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-guard:", err)
		os.Exit(126)
	}
	spec, err := sandbox.ReadGuardSpec(3)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-guard:", err)
		os.Exit(127)
	}
	if err := readGuardGate(4); err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-guard:", err)
		os.Exit(126)
	}
	if err := sandbox.DropExecutionPrivileges(); err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-guard:", err)
		os.Exit(126)
	}
	if err := sandbox.ApplyLandlock(spec.ExecPaths); err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-guard:", err)
		os.Exit(126)
	}
	if err := sandbox.InstallExecSeccomp(); err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-guard:", err)
		os.Exit(126)
	}
	if err := syscall.Exec(spec.Target, spec.Argv, spec.Env); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx-guard: exec %s: %v\n", spec.Target, err)
		os.Exit(127)
	}
}

func checkGuardArgs(argv []string) error {
	if len(argv) != 5 || argv[0] == "" || argv[1] != "-rsbx-guard-spec-fd" || argv[2] != "3" ||
		argv[3] != "-rsbx-guard-gate-fd" || argv[4] != "4" {
		return fmt.Errorf("expected -rsbx-guard-spec-fd 3 -rsbx-guard-gate-fd 4")
	}
	return nil
}

// The supervisor writes one release byte and closes its pipe end. Waiting for
// EOF also rejects extra bytes instead of treating a malformed gate as release.
func readGuardGate(fd int) error {
	if fd < 0 {
		return fmt.Errorf("invalid guard gate descriptor %d", fd)
	}
	f := os.NewFile(uintptr(fd), "rsbx-guard-gate")
	if f == nil {
		return fmt.Errorf("invalid guard gate descriptor %d", fd)
	}
	defer f.Close()
	var gate [2]byte
	n, err := io.ReadFull(f, gate[:])
	if n == 1 && gate[0] == '1' && errors.Is(err, io.ErrUnexpectedEOF) {
		return nil
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("read guard launch gate: %w", err)
	}
	return fmt.Errorf("guard launch gate must contain exactly byte '1', got %q", gate[:n])
}
