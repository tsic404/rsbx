//go:build linux && (amd64 || arm64)

package sandbox

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	maxExecPath  = 4096
	maxExecBytes = 8 << 20
)

// PTRACE_GET_SYSCALL_INFO is authoritative about entry/exit stops. A toggled
// userspace boolean cannot describe restarted syscalls, seccomp stops, or a
// nonleader thread changing its TID during exec.
type traceSyscallInfo struct {
	Op     uint8
	Pad    [3]byte
	Arch   uint32
	IP, SP uint64
	Data   [8]uint64
}

func readSyscallInfo(pid int) (traceSyscallInfo, error) {
	var info traceSyscallInfo
	n, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_GET_SYSCALL_INFO, uintptr(pid), unsafe.Sizeof(info), uintptr(unsafe.Pointer(&info)), 0, 0)
	if errno != 0 {
		return info, fmt.Errorf("ptrace syscall info: %w", errno)
	}
	if n < 24 || info.Arch != traceAuditArch {
		return info, fmt.Errorf("unsupported or incomplete tracee syscall ABI %#x", info.Arch)
	}
	if (info.Op == unix.PTRACE_SYSCALL_INFO_ENTRY || info.Op == unix.PTRACE_SYSCALL_INFO_SECCOMP) && n < 80 {
		return info, fmt.Errorf("incomplete syscall entry information")
	}
	return info, nil
}

func (i traceSyscallInfo) number() uint64 { return i.Data[0] }
func (i traceSyscallInfo) args() [6]uint64 {
	var out [6]uint64
	copy(out[:], i.Data[1:7])
	return out
}

// All callers hold every descendant at a ptrace stop while capturing these
// bytes. The optional bulk read and PEEKDATA read have the same authority;
// falling back from a filtered bulk-read syscall never weakens confinement.
type traceReader struct {
	pid       int
	remaining int
	buf       [4096]byte
}

func traceRead(pid int, addr uint64, dst []byte) error {
	if len(dst) == 0 {
		return nil
	}
	local := unix.Iovec{Base: &dst[0]}
	local.SetLen(len(dst))
	n, err := unix.ProcessVMReadv(pid, []unix.Iovec{local}, []unix.RemoteIovec{{Base: uintptr(addr), Len: len(dst)}}, 0)
	if err == nil && n == len(dst) {
		return nil
	}
	n, err = unix.PtracePeekData(pid, uintptr(addr), dst)
	if err != nil || n != len(dst) {
		return unix.EFAULT
	}
	return nil
}

func (r *traceReader) string(addr uint64, limit int) (string, error) {
	if addr == 0 {
		return "", unix.EFAULT
	}
	var out []byte
	page := uint64(os.Getpagesize())
	for len(out) < limit {
		n := min(len(r.buf), limit-len(out), int(page-(addr%page)))
		if err := traceRead(r.pid, addr, r.buf[:n]); err != nil {
			return "", err
		}
		if end := bytes.IndexByte(r.buf[:n], 0); end >= 0 {
			out = append(out, r.buf[:end]...)
			return string(out), nil
		}
		out = append(out, r.buf[:n]...)
		addr += uint64(n)
	}
	return "", unix.E2BIG
}

func (r *traceReader) vector(addr uint64) ([]string, error) {
	if addr == 0 {
		return nil, nil
	}
	var out []string
	var pointer [8]byte
	for r.remaining >= 8 {
		if err := traceRead(r.pid, addr, pointer[:]); err != nil {
			return nil, err
		}
		addr += 8
		r.remaining -= 8
		p := binary.LittleEndian.Uint64(pointer[:])
		if p == 0 {
			return out, nil
		}
		s, err := r.string(p, min(32*os.Getpagesize(), r.remaining))
		if err != nil {
			return nil, err
		}
		r.remaining -= len(s) + 1
		out = append(out, s)
	}
	return nil, unix.E2BIG
}

type execInvocation struct {
	path      string
	argv, env []string
	cwd       string
	dirfd     int
	flags     int
	execveat  bool
}

func captureInvocation(pid int, info traceSyscallInfo) (execInvocation, error) {
	a := info.args()
	out := execInvocation{dirfd: unix.AT_FDCWD}
	path, argv, env := a[0], a[1], a[2]
	if info.number() == unix.SYS_EXECVEAT {
		out.execveat = true
		out.dirfd, out.flags = int(int32(a[0])), int(a[4])
		path, argv, env = a[1], a[2], a[3]
		if out.flags & ^(unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW) != 0 {
			return out, unix.EINVAL
		}
	} else if info.number() != unix.SYS_EXECVE {
		return out, unix.EINVAL
	}
	r := traceReader{pid: pid, remaining: maxExecBytes}
	var err error
	out.path, err = r.string(path, maxExecPath)
	if err != nil {
		return out, err
	}
	if out.path == "" && (!out.execveat || out.flags&unix.AT_EMPTY_PATH == 0) {
		return out, unix.ENOENT
	}
	out.argv, err = r.vector(argv)
	if err != nil {
		return out, err
	}
	// Linux normalizes an empty argv vector to one empty argv[0]. Preserve
	// the observable exec image rather than inventing a target-based argv0.
	if len(out.argv) == 0 {
		out.argv = []string{""}
	}
	out.env, err = r.vector(env)
	if err != nil {
		return out, err
	}
	out.cwd, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return out, unix.ENOENT
	}
	if !strings.HasPrefix(out.cwd, "/") || strings.HasSuffix(out.cwd, " (deleted)") {
		return out, unix.ENOENT
	}
	return out, nil
}

// The injected mapping is newly allocated, anonymous, private, and then made
// read-only. It never shares a user-supplied pathname/argv page. Descendants
// stay stopped until exec commits (or the syscall error has been restored).
type execMemory struct {
	bytes                              []byte
	base                               uint64
	argvOffset, envOffset, emptyOffset int
}

func newExecMemory(path string, argv, env []string) (*execMemory, error) {
	if len(path) >= maxExecPath {
		return nil, unix.ENAMETOOLONG
	}
	m := &execMemory{emptyOffset: maxExecPath, argvOffset: maxExecPath + 8}
	m.envOffset = m.argvOffset + (len(argv)+1)*8
	offset := m.envOffset + (len(env)+1)*8
	size := offset
	for _, vector := range [][]string{argv, env} {
		for _, s := range vector {
			size += len(s) + 1
		}
	}
	if size > maxExecBytes+maxExecPath+32 {
		return nil, unix.E2BIG
	}
	m.bytes = make([]byte, size)
	copy(m.bytes, path)
	for _, vector := range [][]string{argv, env} {
		for _, s := range vector {
			copy(m.bytes[offset:], s)
			offset += len(s) + 1
		}
	}
	return m, nil
}

func (m *execMemory) relocate(base uint64, argv, env []string) {
	m.base = base
	offset := m.envOffset + (len(env)+1)*8
	for v, vector := range [][]string{argv, env} {
		start := m.argvOffset
		if v == 1 {
			start = m.envOffset
		}
		for i, s := range vector {
			binary.LittleEndian.PutUint64(m.bytes[start+i*8:], base+uint64(offset))
			offset += len(s) + 1
		}
	}
}

func (m *execMemory) pathAddr() uint64  { return m.base }
func (m *execMemory) emptyAddr() uint64 { return m.base + uint64(m.emptyOffset) }
func (m *execMemory) argvAddr() uint64  { return m.base + uint64(m.argvOffset) }
func (m *execMemory) envAddr() uint64   { return m.base + uint64(m.envOffset) }

func (m *execMemory) retarget(pid int, path string) error {
	if len(path) >= maxExecPath {
		return unix.ENAMETOOLONG
	}
	clear(m.bytes[:maxExecPath])
	copy(m.bytes, path)
	n, err := unix.PtracePokeData(pid, uintptr(m.base), m.bytes[:maxExecPath])
	if err != nil || n != maxExecPath {
		return fmt.Errorf("write immutable exec path: %w", err)
	}
	return nil
}

func imageBounds(data []byte) ([4]uint64, error) {
	var out [4]uint64
	line := string(data)
	i := strings.LastIndex(line, ") ")
	if i < 0 {
		return out, fmt.Errorf("malformed process stat")
	}
	fields := strings.Fields(line[i+2:])
	if len(fields) < 49 {
		return out, fmt.Errorf("short process stat")
	}
	for j, field := range []int{45, 46, 47, 48} {
		value, err := strconv.ParseUint(fields[field], 10, 64)
		if err != nil {
			return out, err
		}
		out[j] = value
	}
	if out[1] < out[0] || out[3] < out[2] || out[1]-out[0]+out[3]-out[2] > maxExecBytes {
		return out, fmt.Errorf("invalid committed argument/environment range")
	}
	return out, nil
}

func nulVector(block []byte) ([]string, error) {
	if len(block) == 0 {
		return nil, nil
	}
	if block[len(block)-1] != 0 {
		return nil, fmt.Errorf("unterminated committed exec vector")
	}
	return strings.Split(string(block[:len(block)-1]), "\x00"), nil
}

func committedVectors(pid int) (argv, env []string, err error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil, nil, err
	}
	ranges, err := imageBounds(data)
	if err != nil {
		return nil, nil, err
	}
	vectors := [2][]string{}
	for i := range 2 {
		start, end := ranges[i*2], ranges[i*2+1]
		block := make([]byte, int(end-start))
		if err := traceRead(pid, start, block); err != nil {
			return nil, nil, err
		}
		vectors[i], err = nulVector(block)
		if err != nil {
			return nil, nil, err
		}
	}
	return vectors[0], vectors[1], nil
}

func threadGroupID(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "Tgid:" {
			group, err := strconv.Atoi(fields[1])
			if err != nil || group <= 0 {
				return 0, fmt.Errorf("invalid thread group in proc status")
			}
			return group, nil
		}
	}
	return 0, fmt.Errorf("proc status has no thread group")
}
