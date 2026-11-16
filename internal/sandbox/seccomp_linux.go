//go:build linux && (amd64 || arm64)

package sandbox

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const forbiddenCloneFlags uint32 = unix.CLONE_UNTRACED | unix.CLONE_PTRACE |
	unix.CLONE_NEWCGROUP | unix.CLONE_NEWIPC | unix.CLONE_NEWNET | unix.CLONE_NEWNS |
	unix.CLONE_NEWPID | unix.CLONE_NEWTIME | unix.CLONE_NEWUSER | unix.CLONE_NEWUTS

const seccompPrctlSyscall = unix.SYS_PRCTL

// The filter is plain BPF on the executing thread: execve and execveat use
// SECCOMP_RET_TRACE, while ordinary I/O syscalls remain allowed. It requires
// the supervisor to have installed PTRACE_O_TRACESECCOMP and process events
// before releasing the launch gate. It does not use user notification, is not
// a replacement for ptrace capture, and relies on a readonly proc mount plus
// sealed stdio to exclude writable proc-mem FDs.
var execSeccompFilter = [...]unix.SockFilter{
	{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4}, // seccomp_data.arch
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: execSeccompAuditArch},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
	{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, // seccomp_data.nr
	// x32 shares the amd64 audit arch but sets bit 30. Neither native ABI
	// has syscalls in this range; reject x32 and negative syscall numbers.
	{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 1, K: 0x40000000},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},

	// The supervisor observes every exec attempt without syscall-stop I/O.
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_EXECVE},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_TRACE},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_EXECVEAT},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_TRACE},

	// Each denied syscall is an adjacent comparator/deny pair: a matching
	// syscall returns EPERM, and every other syscall falls through to the
	// next comparator with the syscall number still in the accumulator.
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_PTRACE},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_PROCESS_VM_READV},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_PROCESS_VM_WRITEV},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_PIDFD_GETFD},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_USERFAULTFD},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_IO_URING_SETUP},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_IO_URING_REGISTER},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_IO_URING_ENTER},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_IO_SETUP},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_IO_SUBMIT},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_IO_CANCEL},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_SECCOMP},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_BPF},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_PERF_EVENT_OPEN},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 6, K: seccompPrctlSyscall},
	{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 20}, // args[0], high word
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: 0},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16}, // args[0], low word
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.PR_SET_SECCOMP},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	// The prctl block inspected args[0]; restore the accumulator to the
	// syscall number before the remaining namespace comparators.
	{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, // seccomp_data.nr
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_UNSHARE},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_SETNS},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_MOUNT},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_UMOUNT2},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_PIVOT_ROOT},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_CHROOT},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},

	// clone3's pointed-to flags cannot be inspected with classic BPF. ENOSYS
	// lets libc fall back to clone, whose flags are inspected below.
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_CLONE3},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 3, K: unix.SYS_CLONE},
	// Every prohibited clone flag is in this word on both supported ABIs.
	{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16}, // args[0], low word
	{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jf: 1, K: forbiddenCloneFlags},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
}

// InstallExecSeccomp restricts only the calling thread. It must remain pinned
// until exec, when the new program inherits this filter and all siblings die.
// DropExecutionPrivileges must already have established no_new_privs.
func InstallExecSeccomp() error {
	nnp, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("get no_new_privs before exec seccomp: %w", errno)
	}
	if nnp != 1 {
		return fmt.Errorf("exec seccomp requires no_new_privs")
	}
	program := unix.SockFprog{Len: uint16(len(execSeccompFilter)), Filter: &execSeccompFilter[0]}
	_, _, errno = unix.Syscall6(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&program)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("install exec seccomp filter: %w", errno)
	}
	return nil
}
