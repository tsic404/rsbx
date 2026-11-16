//go:build linux && (amd64 || arm64)

package sandbox

import (
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

// Evaluate the installed plain-BPF program without changing test-process
// privileges or relying on a particular kernel's seccomp configuration.
func evaluateExecSeccomp(t *testing.T, arch, nr uint32, argument0 uint64) uint32 {
	t.Helper()
	var data [64]byte
	binary.LittleEndian.PutUint32(data[0:4], nr)
	binary.LittleEndian.PutUint32(data[4:8], arch)
	binary.LittleEndian.PutUint64(data[16:24], argument0)
	var accumulator uint32
	for pc := 0; pc < len(execSeccompFilter); pc++ {
		instruction := execSeccompFilter[pc]
		switch instruction.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			if instruction.K > uint32(len(data)-4) {
				t.Fatalf("invalid load offset %d", instruction.K)
			}
			accumulator = binary.LittleEndian.Uint32(data[instruction.K : instruction.K+4])
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if accumulator == instruction.K {
				pc += int(instruction.Jt)
			} else {
				pc += int(instruction.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
			if accumulator >= instruction.K {
				pc += int(instruction.Jt)
			} else {
				pc += int(instruction.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			if accumulator&instruction.K != 0 {
				pc += int(instruction.Jt)
			} else {
				pc += int(instruction.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return instruction.K
		default:
			t.Fatalf("unsupported BPF instruction %#x", instruction.Code)
		}
	}
	t.Fatal("filter fell through without returning")
	return 0
}

func TestExecSeccompRejectsCompatAndX32(t *testing.T) {
	for _, arch := range []uint32{unix.AUDIT_ARCH_I386, unix.AUDIT_ARCH_ARM, execSeccompAuditArch ^ 0x80000000} {
		if got := evaluateExecSeccomp(t, arch, unix.SYS_EXECVE, 0); got != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatalf("compat architecture %#x returned %#x", arch, got)
		}
	}
	for _, nr := range []uint32{0x40000000 | unix.SYS_EXECVE, 0x40000000 | unix.SYS_PTRACE, 0xffffffff} {
		if got := evaluateExecSeccomp(t, execSeccompAuditArch, nr, 0); got != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatalf("non-native syscall %#x returned %#x", nr, got)
		}
	}
}

func TestExecSeccompDeniesMemoryTracingAndNamespaceEscapes(t *testing.T) {
	for _, nr := range []uint32{
		unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
		unix.SYS_PIDFD_GETFD, unix.SYS_USERFAULTFD,
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_REGISTER, unix.SYS_IO_URING_ENTER,
		unix.SYS_IO_SETUP, unix.SYS_IO_SUBMIT, unix.SYS_IO_CANCEL,
		unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_MOUNT, unix.SYS_UMOUNT2,
		unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT,
	} {
		t.Run(fmt.Sprint(nr), func(t *testing.T) {
			want := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
			if got := evaluateExecSeccomp(t, execSeccompAuditArch, nr, 0); got != want {
				t.Fatalf("denied syscall %d returned %#x, want %#x", nr, got, want)
			}
		})
	}
}

func TestExecSeccompTracesExecAndPreventsFilterReplacement(t *testing.T) {
	for _, nr := range []uint32{unix.SYS_EXECVE, unix.SYS_EXECVEAT} {
		if got := evaluateExecSeccomp(t, execSeccompAuditArch, nr, 0); got != unix.SECCOMP_RET_TRACE {
			t.Fatalf("exec syscall %d returned %#x, want SECCOMP_RET_TRACE", nr, got)
		}
	}
	want := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
	if got := evaluateExecSeccomp(t, execSeccompAuditArch, unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER); got != want {
		t.Fatalf("seccomp syscall returned %#x", got)
	}
	if got := evaluateExecSeccomp(t, execSeccompAuditArch, unix.SYS_SECCOMP, 1<<32); got != want {
		t.Fatalf("seccomp syscall bypass returned %#x", got)
	}
	if got := evaluateExecSeccomp(t, execSeccompAuditArch, unix.SYS_PRCTL, unix.PR_SET_SECCOMP); got != want {
		t.Fatalf("PR_SET_SECCOMP returned %#x", got)
	}
	if got := evaluateExecSeccomp(t, execSeccompAuditArch, unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS); got != unix.SECCOMP_RET_ALLOW {
		t.Fatalf("ordinary prctl returned %#x", got)
	}
}

func TestExecSeccompInspectsCloneAndReturnsClone3ENOSYS(t *testing.T) {
	for _, flags := range []uint64{
		unix.CLONE_UNTRACED, unix.CLONE_PTRACE, unix.CLONE_NEWCGROUP,
		unix.CLONE_NEWIPC, unix.CLONE_NEWNET, unix.CLONE_NEWNS, unix.CLONE_NEWPID,
		unix.CLONE_NEWTIME, unix.CLONE_NEWUSER, unix.CLONE_NEWUTS,
	} {
		want := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
		if got := evaluateExecSeccomp(t, execSeccompAuditArch, unix.SYS_CLONE, flags); got != want {
			t.Fatalf("clone flags %#x returned %#x, want %#x", flags, got, want)
		}
	}
	for _, flags := range []uint64{0, unix.CLONE_CLEAR_SIGHAND, uint64(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD)} {
		if got := evaluateExecSeccomp(t, execSeccompAuditArch, unix.SYS_CLONE, flags); got != unix.SECCOMP_RET_ALLOW {
			t.Fatalf("ordinary clone flags %#x returned %#x", flags, got)
		}
		want := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.ENOSYS)
		if got := evaluateExecSeccomp(t, execSeccompAuditArch, unix.SYS_CLONE3, flags); got != want {
			t.Fatalf("clone3 returned %#x, want %#x", got, want)
		}
	}
}

func TestExecSeccompAllowsOrdinaryIOAndInspection(t *testing.T) {
	for _, nr := range []uint32{unix.SYS_READ, unix.SYS_WRITE, unix.SYS_OPENAT, unix.SYS_FUTEX, unix.SYS_RT_SIGACTION, unix.SYS_GETTID} {
		if got := evaluateExecSeccomp(t, execSeccompAuditArch, nr, 0); got != unix.SECCOMP_RET_ALLOW {
			t.Fatalf("ordinary syscall %d returned %#x", nr, got)
		}
	}
}
