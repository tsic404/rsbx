//go:build linux

package sandbox

// Landlock restricts execution to exactly the paths the controller computed:
// the allowlisted local programs with their aliases resolved, the runtime
// assets the policy recorded (the dynamic loader and interpreter files those
// programs need), and the two native helpers. Every path in the list is
// required: the controller resolved them all before launch, so a path that
// cannot be opened or granted here is a mounting or policy failure and aborts
// the session rather than silently narrowing the sandbox.
//
// There is no unsupported-kernel fallback. A kernel without Landlock refuses
// the first syscall, the launcher reports it, and the entry never starts:
// running with only redirection in place would be a weaker sandbox than the
// configuration asked for.
import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LandlockRuleset builds a ruleset permitting execve only for the listed
// paths. The paths are sandbox-absolute: they are opened after the launcher
// pivoted into the final view, where the kernel resolves them that way.
// Every entry must resolve and accept the rule; any failure is returned.
func LandlockRuleset(paths []string) (int, error) {
	if len(paths) == 0 {
		return 0, fmt.Errorf("Landlock execution paths are empty")
	}
	attr := unix.LandlockRulesetAttr{Access_fs: unix.LANDLOCK_ACCESS_FS_EXECUTE}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return 0, fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	ruleset := int(fd)
	for _, p := range paths {
		if err := addPathBeneath(ruleset, p); err != nil {
			unix.Close(ruleset)
			return 0, err
		}
	}
	return ruleset, nil
}

func addPathBeneath(ruleset int, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("Landlock execution grant is not absolute: %q", path)
	}
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("landlock grant %s: %w", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat Landlock grant %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("Landlock execution grant %s is not an exact regular file", path)
	}
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

// ApplyLandlock installs the ruleset on the calling thread. The pinned guard
// sets no_new_privs and drops all privilege before this call; its subsequent
// exec and every descendant inherit this exact-inode ruleset.
func ApplyLandlock(paths []string) error {
	ruleset, err := LandlockRuleset(paths)
	if err != nil {
		return err
	}
	defer unix.Close(ruleset)
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}
