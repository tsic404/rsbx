//go:build linux && amd64

package sandbox

import "golang.org/x/sys/unix"

const traceAuditArch = unix.AUDIT_ARCH_X86_64

var traceSyscallInstruction = []byte{0x0f, 0x05}

type traceRegs struct{ raw unix.PtraceRegs }

func readTraceRegs(pid int) (traceRegs, error) {
	var r traceRegs
	err := unix.PtraceGetRegs(pid, &r.raw)
	return r, err
}

func writeTraceRegs(pid int, r traceRegs) error { return unix.PtraceSetRegs(pid, &r.raw) }

func (r traceRegs) ip() uint64 { return r.raw.Rip }

func (r traceRegs) call(nr uint64, a [6]uint64) traceRegs {
	r.raw.Orig_rax = nr
	r.raw.Rax = nr
	r.raw.Rdi, r.raw.Rsi, r.raw.Rdx = a[0], a[1], a[2]
	r.raw.R10, r.raw.R8, r.raw.R9 = a[3], a[4], a[5]
	return r
}

func replaceEntry(pid int, r traceRegs, nr uint64, args [6]uint64) error {
	return writeTraceRegs(pid, r.call(nr, args))
}

func replayCall(pid int, r traceRegs, nr uint64, args [6]uint64) error {
	r = r.call(nr, args)
	r.raw.Rip -= uint64(len(traceSyscallInstruction))
	return writeTraceRegs(pid, r)
}

func restoreResult(pid int, r traceRegs, result int64) error {
	r.raw.Rax = uint64(result)
	return writeTraceRegs(pid, r)
}
