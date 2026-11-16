//go:build linux

package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// Raised-stack Linux executions may carry several MiB of argv/env, and the
// base64 byte-vector encoding expands them. The ceiling remains explicit.
const maxGuardSpecSize = 16 << 20

// GuardSpec is the immutable launch record supplied by the supervisor. Target
// is the execve pathname, not argv[0]; Env and Argv are passed through unchanged.
// The launcher has already installed the captured working directory.
type GuardSpec struct {
	Target    string   `json:"target"`
	Argv      []string `json:"argv"`
	Env       []string `json:"env"`
	ExecPaths []string `json:"exec_paths"`
}

// Target, argv and env are kernel byte strings, not necessarily UTF-8. The
// JSON byte-vector representation uses base64 and never replaces caller bytes.
type guardSpecWire struct {
	Target    []byte   `json:"target"`
	Argv      [][]byte `json:"argv"`
	Env       [][]byte `json:"env"`
	ExecPaths []string `json:"exec_paths"`
}

func (spec GuardSpec) MarshalJSON() ([]byte, error) {
	if err := validateGuardSpec(&spec); err != nil {
		return nil, err
	}
	body, err := json.Marshal(guardSpecWire{
		Target:    []byte(spec.Target),
		Argv:      guardByteVector(spec.Argv),
		Env:       guardByteVector(spec.Env),
		ExecPaths: spec.ExecPaths,
	})
	if err != nil {
		return nil, err
	}
	if len(body) > maxGuardSpecSize {
		return nil, fmt.Errorf("guard spec exceeds %d bytes", maxGuardSpecSize)
	}
	return body, nil
}

func (spec *GuardSpec) UnmarshalJSON(body []byte) error {
	if spec == nil {
		return fmt.Errorf("nil guard spec receiver")
	}
	if len(body) > maxGuardSpecSize {
		return fmt.Errorf("guard spec exceeds %d bytes", maxGuardSpecSize)
	}
	var wire guardSpecWire
	if err := decodeGuardJSON(body, &wire); err != nil {
		return err
	}
	candidate := GuardSpec{
		Target:    string(wire.Target),
		Argv:      guardStringVector(wire.Argv),
		Env:       guardStringVector(wire.Env),
		ExecPaths: wire.ExecPaths,
	}
	if err := validateGuardSpec(&candidate); err != nil {
		return err
	}
	*spec = candidate
	return nil
}

func guardByteVector(values []string) [][]byte {
	if values == nil {
		return nil
	}
	vector := make([][]byte, len(values))
	for i, value := range values {
		vector[i] = []byte(value)
	}
	return vector
}

func guardStringVector(values [][]byte) []string {
	if values == nil {
		return nil
	}
	vector := make([]string, len(values))
	for i, value := range values {
		vector[i] = string(value)
	}
	return vector
}

func validateGuardSpec(spec *GuardSpec) error {
	if err := validateExecFields(spec.Target, spec.Argv, spec.Env); err != nil {
		return fmt.Errorf("invalid guard spec: %w", err)
	}
	if len(spec.ExecPaths) == 0 {
		return fmt.Errorf("invalid guard spec: empty execution allowlist")
	}
	for i, path := range spec.ExecPaths {
		if !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 || !utf8.ValidString(path) {
			return fmt.Errorf("invalid guard spec: execution path %d is not a NUL-free absolute UTF-8 path", i)
		}
	}
	return nil
}

// ReadGuardSpec consumes and closes fd. It reads from offset zero, independent
// of the inherited file offset, and requires a fully sealed, bounded record.
func ReadGuardSpec(fd int) (*GuardSpec, error) {
	if fd < 0 {
		return nil, fmt.Errorf("invalid guard spec descriptor %d", fd)
	}
	f := os.NewFile(uintptr(fd), "rsbx-guard-spec")
	if f == nil {
		return nil, fmt.Errorf("invalid guard spec descriptor %d", fd)
	}
	defer f.Close()

	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil {
		return nil, fmt.Errorf("read guard spec seals: %w", err)
	}
	const requiredSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if seals&requiredSeals != requiredSeals {
		return nil, fmt.Errorf("guard spec is not fully sealed: seals %#x, require %#x", seals, requiredSeals)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("stat guard spec: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("guard spec is not a regular sealed file")
	}
	if st.Size <= 0 || st.Size > maxGuardSpecSize {
		return nil, fmt.Errorf("guard spec size %d is outside 1..%d bytes", st.Size, maxGuardSpecSize)
	}
	data := make([]byte, int(st.Size))
	if _, err := f.ReadAt(data, 0); err != nil {
		return nil, fmt.Errorf("read guard spec: %w", err)
	}
	var spec GuardSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("decode guard spec: %w", err)
	}
	return &spec, nil
}

// decodeGuardJSON accepts exactly one record, with no unknown fields or trailing
// JSON. Exec strings are byte vectors; execution paths remain UTF-8 strings.
func decodeGuardJSON(data []byte, record any) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("record contains invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(record); err != nil {
		return err
	}
	if len(bytes.TrimSpace(data[dec.InputOffset():])) != 0 {
		return fmt.Errorf("trailing JSON data after guard record")
	}
	return nil
}

func validateExecFields(target string, argv, env []string) error {
	if target == "" || strings.IndexByte(target, 0) >= 0 {
		return fmt.Errorf("target must be nonempty and NUL-free")
	}
	if len(argv) == 0 {
		return fmt.Errorf("empty argv")
	}
	// An empty or non-path argv[0] is valid execve input. It never selects the
	// target, and must not be rewritten by either helper.
	for i, arg := range argv {
		if strings.IndexByte(arg, 0) >= 0 {
			return fmt.Errorf("argv[%d] is not NUL-free", i)
		}
	}
	for i, entry := range env {
		if strings.IndexByte(entry, 0) >= 0 {
			return fmt.Errorf("env[%d] is not NUL-free", i)
		}
	}
	return nil
}

const (
	secureNoRoot       = 1 << 0
	secureNoRootLocked = 1 << 1
)

// DropExecutionPrivileges irreversibly removes execution privileges from the
// calling thread. The caller must keep this thread pinned through Landlock,
// seccomp and exec. Trusted Go runtime siblings can exist before exec; they do
// not carry this thread's restrictions and are destroyed by exec.
func DropExecutionPrivileges() error {
	securebits, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_SECUREBITS, 0, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("get execution securebits: %w", errno)
	}
	const requiredSecurebits = secureNoRoot | secureNoRootLocked
	if securebits&requiredSecurebits != requiredSecurebits {
		if err := unix.Prctl(unix.PR_SET_SECUREBITS, securebits|requiredSecurebits, 0, 0, 0); err != nil {
			return fmt.Errorf("lock SECURE_NOROOT: %w", err)
		}
	}

	// Bounding-set removal needs CAP_SETPCAP, so it precedes clearing the
	// effective and permitted sets. Read each kernel-supported capability;
	// never treat EPERM or an unsupported capability ABI as success.
	for capability := uintptr(0); ; capability++ {
		present, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_CAPBSET_READ, capability, 0, 0, 0, 0)
		if errno == unix.EINVAL {
			break
		}
		if errno != 0 {
			return fmt.Errorf("read bounding capability %d: %w", capability, errno)
		}
		if capability >= 64 {
			return fmt.Errorf("capability %d exceeds the supported capability ABI", capability)
		}
		if present != 0 && present != 1 {
			return fmt.Errorf("invalid bounding capability %d value %d", capability, present)
		}
		if present == 1 {
			if err := unix.Prctl(unix.PR_CAPBSET_DROP, capability, 0, 0, 0); err != nil {
				return fmt.Errorf("drop bounding capability %d: %w", capability, err)
			}
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var capabilities [2]unix.CapUserData
	if err := unix.Capset(&header, &capabilities[0]); err != nil {
		return fmt.Errorf("clear effective, permitted and inheritable capabilities: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}

	if err := unix.Capget(&header, &capabilities[0]); err != nil {
		return fmt.Errorf("verify execution capabilities: %w", err)
	}
	for _, capability := range capabilities {
		if capability.Effective != 0 || capability.Permitted != 0 || capability.Inheritable != 0 {
			return fmt.Errorf("execution capabilities remain after dropping privileges")
		}
	}
	securebits, _, errno = unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_SECUREBITS, 0, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("verify execution securebits: %w", errno)
	}
	if securebits&requiredSecurebits != requiredSecurebits {
		return fmt.Errorf("SECURE_NOROOT is not locked")
	}
	nnp, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("verify no_new_privs: %w", errno)
	}
	if nnp != 1 {
		return fmt.Errorf("no_new_privs is not set")
	}
	status, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return fmt.Errorf("read executing thread privileges: %w", err)
	}
	return verifyExecutionStatus(status)
}

func verifyExecutionStatus(status []byte) error {
	var seen uint8
	for line := range bytes.SplitSeq(status, []byte{'\n'}) {
		name, value, ok := bytes.Cut(line, []byte{':'})
		if !ok {
			continue
		}
		var bit uint8
		switch string(name) {
		case "CapInh":
			bit = 1 << 0
		case "CapPrm":
			bit = 1 << 1
		case "CapEff":
			bit = 1 << 2
		case "CapBnd":
			bit = 1 << 3
		case "CapAmb":
			bit = 1 << 4
		case "NoNewPrivs":
			bit = 1 << 5
		default:
			continue
		}
		if seen&bit != 0 {
			return fmt.Errorf("duplicate executing thread status field %s", name)
		}
		seen |= bit
		value = bytes.TrimSpace(value)
		if bit == 1<<5 {
			if !bytes.Equal(value, []byte{'1'}) {
				return fmt.Errorf("executing thread NoNewPrivs is not 1")
			}
			continue
		}
		capability, err := strconv.ParseUint(string(value), 16, 64)
		if err != nil {
			return fmt.Errorf("invalid executing thread %s: %w", name, err)
		}
		if capability != 0 {
			return fmt.Errorf("executing thread %s is not zero", name)
		}
	}
	if seen != (1<<6)-1 {
		return fmt.Errorf("executing thread status is missing capability or no_new_privs fields")
	}
	return nil
}
