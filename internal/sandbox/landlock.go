package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LandlockRuleset builds a ruleset that permits execve only for the listed
// paths plus the dynamic loaders.
//
// The paths are interpreted inside the sandbox, after the launcher has built
// the view, which is why they are sandbox-absolute ("/usr/bin/bash") rather
// than host paths: the guard runs where the kernel resolves them that way.
func LandlockRuleset(paths []string) (int, error) {
	attr := unix.LandlockRulesetAttr{Access_fs: unix.LANDLOCK_ACCESS_FS_EXECUTE}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return 0, fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	ruleset := int(fd)
	all := append(append([]string(nil), paths...), loaderPaths()...)
	for _, p := range all {
		if err := addPathBeneath(ruleset, p); err != nil {
			unix.Close(ruleset)
			return 0, err
		}
	}
	return ruleset, nil
}

func addPathBeneath(ruleset int, path string) error {
	fd, err := openForRule(path)
	if err != nil {
		// A path that is genuinely absent cannot be executed either, so
		// skipping it keeps one missing entry from disabling the whole sandbox.
		// Anything else is a real failure and must be reported: dropping a rule
		// because the filesystem was momentarily busy silently narrowed the
		// allowlist, and the entry program was then refused by the kernel with
		// EACCES that pointed at nothing.
		if err == unix.ENOENT || err == unix.ENOTDIR {
			return nil
		}
		return fmt.Errorf("landlock grant %s: %w", path, err)
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

// loaderPaths lists the dynamic loaders relative to the sandbox root. Every
// dynamically linked ELF is executed through one, so denying it would deny the
// allowlist too. The list is the set of interpreters, not a grant for the
// library trees around them.
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
		// Alpine keeps /lib and /lib64 as symlinks into /usr/lib, so the
		// loader's only real path is the one below. With just the link,
		// opening it in the sandbox view answers ENOENT and the grant is
		// dropped, which then refuses the entry with EACCES.
		"/usr/lib/ld-musl-x86_64.so.1",
		"/usr/lib/ld-musl-aarch64.so.1",
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
var _ = strings.HasPrefix

// openForRule resolves a path for a Landlock rule. The path is read through the
// sandbox's own filesystem, which under load can answer a transient error for a
// file that is plainly there, so a failure is retried on a short delay before it
// is believed.
func openForRule(path string) (int, error) {
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for attempt := 0; ; attempt++ {
		var fd int
		fd, err = unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err == nil {
			return fd, nil
		}
		if time.Now().After(deadline) {
			break
		}
		// ENOENT is retried like any other error. The path is read through the
		// sandbox filesystem, which answers "no such file" for a moment while a
		// dentry is being resolved; believing it dropped the rule, and the
		// loader then had no execute grant at all. Every session that lost
		// /lib/ld-linux-x86-64.so.2 this way failed the entry with
		// "exec /bin/sh: permission denied", which points at nothing.
		//
		// The delay grows, because the window is a directory being built rather
		// than a lost race: the second attempt is what most sessions need.
		d := time.Duration(attempt+1) * 4 * time.Millisecond
		if d > 100*time.Millisecond {
			d = 100 * time.Millisecond
		}
		time.Sleep(d)
	}
	return -1, err
}
