//go:build linux && arm64

package sandbox

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

const traceAuditArch = unix.AUDIT_ARCH_AARCH64

var traceSyscallInstruction = []byte{0x01, 0x00, 0x00, 0xd4}

type traceRegs struct{ raw unix.PtraceRegs }

func readTraceRegs(pid int) (traceRegs, error) {
	var r traceRegs
	err := unix.PtraceGetRegs(pid, &r.raw)
	return r, err
}

func writeTraceRegs(pid int, r traceRegs) error { return unix.PtraceSetRegs(pid, &r.raw) }

func (r traceRegs) ip() uint64 { return r.raw.Pc }

func (r traceRegs) call(nr uint64, a [6]uint64) traceRegs {
	r.raw.Regs[8] = nr
	copy(r.raw.Regs[:6], a[:])
	return r
}

func replaceEntry(pid int, r traceRegs, nr uint64, args [6]uint64) error {
	if err := writeTraceRegs(pid, r.call(nr, args)); err != nil {
		return err
	}
	// At an arm64 syscall-entry stop the kernel already cached x8. Changing
	// the general registers alone does not replace that cached syscallno.
	// NT_ARM_SYSTEM_CALL is the authoritative per-thread syscall regset.
	number := int32(nr)
	iov := unix.Iovec{Base: (*byte)(unsafe.Pointer(&number))}
	iov.SetLen(4)
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_SETREGSET, uintptr(pid), 0x404, uintptr(unsafe.Pointer(&iov)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func replayCall(pid int, r traceRegs, nr uint64, args [6]uint64) error {
	r = r.call(nr, args)
	r.raw.Pc -= uint64(len(traceSyscallInstruction))
	return writeTraceRegs(pid, r)
}

func restoreResult(pid int, r traceRegs, result int64) error {
	r.raw.Regs[0] = uint64(result)
	return writeTraceRegs(pid, r)
}
