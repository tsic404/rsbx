//go:build linux && (amd64 || arm64)

package sandbox

import (
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSeccompInfoRecognizesNativeABIAndEntries(t *testing.T) {
	info := traceSyscallInfo{Op: unix.PTRACE_SYSCALL_INFO_SECCOMP, Arch: traceAuditArch}
	info.Data[0] = unix.SYS_EXECVE
	if info.Op != unix.PTRACE_SYSCALL_INFO_SECCOMP || info.Arch != traceAuditArch || info.number() != unix.SYS_EXECVE {
		t.Fatal("native exec seccomp stop not recognized")
	}
	info.Data[0] = unix.SYS_EXECVEAT
	if info.number() != unix.SYS_EXECVEAT {
		t.Fatal("native execveat seccomp stop not recognized")
	}
}

func TestTraceReaderRejectsCorruptMemory(t *testing.T) {
	reader := traceReader{pid: 1 << 30, remaining: maxExecBytes}
	if got, err := reader.vector(0); err != nil || got != nil {
		t.Fatalf("null vector = %v, %v", got, err)
	}
	reader = traceReader{pid: 1 << 30, remaining: maxExecBytes}
	if _, err := reader.string(1, maxExecPath); err == nil {
		t.Fatal("unmapped trace memory read accepted")
	}
}

func TestCommittedImageBounds(t *testing.T) {
	if _, err := imageBounds([]byte("1234 (odd)comm)) S")); err == nil {
		t.Fatal("short process stat accepted")
	}
	// /proc/PID/stat fields: 1 pid, 2 comm, 3 state, ... 48 arg_start,
	// 49 arg_end, 50 env_start, 51 env_end. The parser strips the pid and
	// parenthesised comm, so its index 0 is kernel field 3 and its indexes
	// 45..48 are kernel fields 48..51.
	//
	// This fixture keeps the combined "pid (comm)" prefix at index 0, so
	// fixture index k holds kernel field k+2: kernel field 48 lands at
	// fixture index 46, not 45.
	fields := []string{"42 (a)b)c)"}
	for i := 3; i <= 51; i++ {
		fields = append(fields, fmt.Sprint(i))
	}
	if len(fields)-1 < 49 {
		t.Fatalf("fixture has %d post-comm fields, need at least 49", len(fields)-1)
	}
	fields[46], fields[47], fields[48], fields[49] = "1000", "1100", "2000", "2100"
	bounds, err := imageBounds([]byte(strings.Join(fields, " ")))
	if err != nil {
		t.Fatal(err)
	}
	if bounds != [4]uint64{1000, 1100, 2000, 2100} {
		t.Fatalf("bounds %v", bounds)
	}
	// A record that stops before arg_start must be rejected rather than
	// reading zero-valued bounds out of a shorter field list.
	if _, err := imageBounds([]byte(strings.Join(fields[:46], " "))); err == nil {
		t.Fatal("stat truncated before the argument bounds accepted")
	}
}

func TestNULVectorPreservesEmptyFields(t *testing.T) {
	got, err := nulVector([]byte("\x00\xff\x00end\x00"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"", "\xff", "end"}) {
		t.Fatalf("vector %q", got)
	}
	if _, err := nulVector([]byte("unterminated")); err == nil {
		t.Fatal("unterminated vector accepted")
	}
}

func TestExecMemoryPreservesKernelVectors(t *testing.T) {
	argv := []string{"custom-zero", "a\xffb", ""}
	memory, err := newExecMemory("/project/tool", argv, nil)
	if err != nil {
		t.Fatal(err)
	}
	zero := uint64(1 << 40)
	memory.relocate(zero, argv, nil)
	if got := string(memory.bytes[:len("/project/tool")]); got != "/project/tool" {
		t.Fatalf("path %q", got)
	}
	if got := binary.LittleEndian.Uint64(memory.bytes[memory.argvOffset:]); got != zero+uint64(memory.envOffset)+8 {
		t.Fatalf("argv0 address %#x", got)
	}
	if binary.LittleEndian.Uint64(memory.bytes[memory.argvOffset+3*8:]) != 0 ||
		binary.LittleEndian.Uint64(memory.bytes[memory.envOffset:]) != 0 {
		t.Fatal("vector terminators are missing")
	}
	if err := memory.retarget(1<<30, "/x"); err == nil {
		t.Fatal("untraceable retarget accepted")
	}
	if _, err := newExecMemory(string(make([]byte, maxExecPath)), nil, nil); err != unix.ENAMETOOLONG {
		t.Fatalf("oversized path error %v", err)
	}
}

func TestATFDCWDKernelArgument(t *testing.T) {
	// unix.AT_FDCWD is -100. The kernel takes the sign-extended 64-bit
	// two's-complement form, which is ^uint64(99); convert at run time so
	// the negative value is never a compile-time uint64 constant.
	var cwd = int64(unix.AT_FDCWD)
	if atFDCWDArgument != uint64(cwd) || atFDCWDArgument>>63 == 0 {
		t.Fatalf("AT_FDCWD argument %#x", atFDCWDArgument)
	}
}

func TestNativeSyscallInstructionEncoding(t *testing.T) {
	if len(traceSyscallInstruction) == 0 || len(traceSyscallInstruction) > 4 {
		t.Fatal("syscall instruction encoding must be one native instruction")
	}
	if os.Getpagesize() < 4096 {
		t.Fatal("page assumption does not hold")
	}
}

func TestStrayInjectionEventKeepsSignalDeliveries(t *testing.T) {
	// A stop whose signal is not SIGTRAP carries no ptrace event code, which
	// TrapCause reports as a negative value. SIGURG and the other ordinary
	// signals a busy session receives must restart the injected call rather
	// than fail the launch; they are queued for the next resume instead.
	for _, cause := range []int{-1, -2, 0} {
		if strayInjectionEvent(cause) {
			t.Fatalf("cause %d treated as a stray ptrace event", cause)
		}
	}
	// A real ptrace event other than PTRACE_EVENT_STOP means a second event
	// arrived while the injected call was in flight, which is fatal.
	for _, cause := range []int{unix.PTRACE_EVENT_SECCOMP, unix.PTRACE_EVENT_EXEC, unix.PTRACE_EVENT_FORK} {
		if !strayInjectionEvent(cause) {
			t.Fatalf("ptrace event %d accepted during injection", cause)
		}
	}
	if strayInjectionEvent(unix.PTRACE_EVENT_STOP) {
		t.Fatal("PTRACE_EVENT_STOP treated as a stray ptrace event")
	}
}

func TestEntryBootstrapExecNeedsEntryGroupAndNoDecision(t *testing.T) {
	decision := execDecision{expected: execAsset{Path: GuardPath}}
	// The supervisor's own exec of the guard is reported for the entry group
	// before any decision exists. It is the only such report accepted.
	tracer := &tracer{entry: 11, decisions: map[int]execDecision{}}
	if !tracer.entryBootstrapExec(11) {
		t.Fatal("bootstrap exec of the entry group rejected")
	}
	if tracer.entryBootstrapExec(12) {
		t.Fatal("exec of a non-entry group accepted as the bootstrap exec")
	}
	// Once a decision is recorded for the entry group, the same report shape
	// is the guard's own exec of the entry program and must be validated
	// against that decision, never waved through.
	tracer.decisions[11] = decision
	if tracer.entryBootstrapExec(11) {
		t.Fatal("exec with a recorded decision accepted as the bootstrap exec")
	}
}
