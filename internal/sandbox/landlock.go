package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LandlockRuleset builds a ruleset that permits execve only for the listed
// paths plus the dynamic loaders.
//
// The paths are interpreted inside the sandbox, after bwrap has built the view,
// which is why they are sandbox-absolute ("/usr/bin/bash") rather than host
// paths: the guard runs where the kernel resolves them that way.
func LandlockRuleset(paths []string) (int, error) {
	attr := unix.LandlockRulesetAttr{Access_fs: unix.LANDLOCK_ACCESS_FS_EXECUTE}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return 0, fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	ruleset := int(fd)
	for _, p := range append(append([]string(nil), paths...), loaderPaths()...) {
		if err := addPathBeneath(ruleset, p); err != nil {
			unix.Close(ruleset)
			return 0, err
		}
	}
	return ruleset, nil
}

func addPathBeneath(ruleset int, path string) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		// A path that cannot be opened cannot be executed either. Skipping it
		// keeps one missing entry from disabling the whole sandbox.
		return nil
	}
	defer unix.Close(fd)
	attr := unix.LandlockPathBeneathAttr{
		Allowed_access: unix.LANDLOCK_ACCESS_FS_EXECUTE,
		Parent_fd:      int32(fd),
	}
	_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset),
		uintptr(unix.LANDLOCK_RULE_PATH_BENEATH), uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("landlock_add_rule %s: %w", path, errno)
	}
	return nil
}

// loaderPaths lists the dynamic loaders relative to a sandbox root. Every
// dynamically linked ELF is executed through one, so denying it would deny the
// allowlist too.
func loaderPaths() []string {
	paths := []string{
		"/lib64/ld-linux-x86-64.so.2",
		"/lib/ld-linux-x86-64.so.2",
		"/lib/ld-linux-aarch64.so.1",
		"/lib64/ld-linux-aarch64.so.1",
		"/lib/ld-musl-x86_64.so.1",
		"/lib/ld-musl-aarch64.so.1",
		"/usr/lib/ld-linux-x86-64.so.2",
		"/usr/lib64/ld-linux-x86-64.so.2",
	}
	// Debian and Ubuntu keep the loader under a multiarch directory, which
	// cannot be enumerated without knowing the triplet.
	for _, triplet := range []string{"x86_64-linux-gnu", "aarch64-linux-gnu", "i386-linux-gnu", "riscv64-linux-gnu"} {
		paths = append(paths,
			"/usr/lib/"+triplet+"/ld-linux-x86-64.so.2",
			"/usr/lib/"+triplet+"/ld-linux-aarch64.so.1")
	}
	return paths
}

// ApplyLandlock installs the ruleset on the calling process, so every child
// inherits it. no_new_privs prevents the process from lifting it again.
func ApplyLandlock(paths []string) error {
	ruleset, err := LandlockRuleset(paths)
	if err != nil {
		return err
	}
	defer unix.Close(ruleset)
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

var _ = filepath.Join
var _ = os.Getenv
