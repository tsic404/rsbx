//go:build linux

package sandbox

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A process may borrow a terminal as stdio without owning its controlling
// session. Only the actual owner changes foreground pgids. The controller
// records/restores host-namespace ids; PID 1 supplies its entry's private-id
// pgid to the ioctl, which the kernel translates in the calling namespace.
func terminalOwnership(fd int) (int, bool, error) {
	if !isTerminal(fd) {
		return 0, false, nil
	}
	ttySession, err := unix.IoctlGetInt(fd, unix.TIOCGSID)
	if err != nil {
		return 0, false, nil
	}
	session, err := unix.Getsid(0)
	if err != nil {
		return 0, false, err
	}
	if ttySession != session {
		return 0, false, nil
	}
	group, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil {
		return 0, false, err
	}
	return group, true, nil
}

// tcsetpgrp from a background group normally generates SIGTTOU. Block that
// signal on this pinned calling thread only, then restore its exact mask.
// This prevents restoration from stopping the controller or changing global
// signal dispositions used by the caller's own terminal handling.
func setTerminalGroup(fd, group int) error {
	mask := uint64(1) << uint(unix.SIGTTOU-1)
	var old uint64
	_, _, errno := unix.RawSyscall6(unix.SYS_RT_SIGPROCMASK, unix.SIG_BLOCK, uintptr(unsafe.Pointer(&mask)), uintptr(unsafe.Pointer(&old)), 8, 0, 0)
	if errno != 0 {
		return fmt.Errorf("block terminal job-control signal: %w", errno)
	}
	ioctlErr := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, group)
	_, _, restoreErr := unix.RawSyscall6(unix.SYS_RT_SIGPROCMASK, unix.SIG_SETMASK, uintptr(unsafe.Pointer(&old)), 0, 8, 0, 0)
	if ioctlErr != nil {
		return ioctlErr
	}
	if restoreErr != 0 {
		return fmt.Errorf("restore terminal signal mask: %w", restoreErr)
	}
	return nil
}
