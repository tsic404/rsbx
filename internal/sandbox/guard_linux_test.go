//go:build linux

package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const guardTestSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

func guardTestFD(t *testing.T, body []byte, seals int) int {
	t.Helper()
	fd, err := unix.MemfdCreate("rsbx-guard-test", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 0 {
		n, err := unix.Write(fd, body)
		if err != nil || n != len(body) {
			unix.Close(fd)
			t.Fatalf("write spec: n=%d err=%v", n, err)
		}
	}
	if seals != 0 {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
			unix.Close(fd)
			t.Fatal(err)
		}
	}
	return fd
}

func guardTestSpec() GuardSpec {
	return GuardSpec{
		Target: "/bin/entry",
		Argv:   []string{"not-the-target", "", "argument with spaces", "\xff\xfe"},
		Env: []string{
			"PATH=/captured", "RSBX_GUARD_ARGV=4:evil", "RSBX_LANDLOCK_EXEC=/evil",
			"RSBX_TRAMP_TARGET=/evil", "RSBX_TRAMP_CMD=evil", "RSBX_TRAMP_SELFTEST=1",
			"BYTES=\xff\xfe",
		},
		ExecPaths: []string{"/bin/entry", "/lib/ld-linux.so"},
	}
}

func TestGuardSpecJSONPreservesKernelBytesAndEmptyEnvironment(t *testing.T) {
	for _, env := range [][]string{nil, {}, {"", "BYTES=\xff\xfe"}} {
		want := guardTestSpec()
		want.Target = "/entry/\xff"
		want.Env = env
		body, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		var wire guardSpecWire
		if err := json.Unmarshal(body, &wire); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(wire.Target, []byte(want.Target)) {
			t.Fatalf("target was not encoded as exact bytes: %q", wire.Target)
		}
		got, err := ReadGuardSpec(guardTestFD(t, body, guardTestSeals))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, &want) {
			t.Fatalf("guard byte codec changed request: got %#v, want %#v", got, want)
		}
	}
}

func TestGuardSpecMarshalRejectsInvalidExecutionPaths(t *testing.T) {
	for _, path := range []string{"", "relative", "/bad\x00path", "/bad/\xff"} {
		spec := guardTestSpec()
		spec.ExecPaths = []string{path}
		if _, err := json.Marshal(spec); err == nil {
			t.Fatalf("invalid execution path %q was serialized", path)
		}
	}
}

func TestReadGuardSpecPreservesCapturedFieldsAndOffset(t *testing.T) {
	t.Setenv("RSBX_GUARD_ARGV", "4:evil")
	t.Setenv("RSBX_LANDLOCK_EXEC", "/evil")
	t.Setenv("RSBX_TRAMP_TARGET", "/evil")
	want := guardTestSpec()
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	fd := guardTestFD(t, body, guardTestSeals)
	// Writing left the inherited offset at EOF; ReadGuardSpec must use zero.
	got, err := ReadGuardSpec(fd)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, &want) {
		t.Fatalf("captured spec changed: got %#v, want %#v", got, want)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("spec descriptor was not consumed: %v", err)
	}
}

func TestReadGuardSpecAllowsEmptyArgvZeroWithoutInferringTarget(t *testing.T) {
	spec := guardTestSpec()
	spec.Argv[0] = ""
	body, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadGuardSpec(guardTestFD(t, body, guardTestSeals))
	if err != nil {
		t.Fatal(err)
	}
	if got.Target != spec.Target || got.Argv[0] != "" {
		t.Fatalf("target or argv[0] changed: %#v", got)
	}
}

func TestReadGuardSpecRequiresEverySeal(t *testing.T) {
	body, err := json.Marshal(guardTestSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, seal := range []int{unix.F_SEAL_WRITE, unix.F_SEAL_GROW, unix.F_SEAL_SHRINK, unix.F_SEAL_SEAL} {
		t.Run(strings.TrimPrefix(sealName(seal), "F_SEAL_"), func(t *testing.T) {
			fd := guardTestFD(t, body, guardTestSeals&^seal)
			if _, err := ReadGuardSpec(fd); err == nil || !strings.Contains(err.Error(), "not fully sealed") {
				t.Fatalf("missing seal %#x accepted: %v", seal, err)
			}
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Fatalf("rejected spec descriptor remains open: %v", err)
			}
		})
	}
}

func sealName(seal int) string {
	switch seal {
	case unix.F_SEAL_WRITE:
		return "F_SEAL_WRITE"
	case unix.F_SEAL_GROW:
		return "F_SEAL_GROW"
	case unix.F_SEAL_SHRINK:
		return "F_SEAL_SHRINK"
	default:
		return "F_SEAL_SEAL"
	}
}

func TestReadGuardSpecRejectsMalformedRecords(t *testing.T) {
	wire := guardSpecWire{
		Target:    []byte("/bin/entry"),
		Argv:      [][]byte{[]byte("different")},
		Env:       [][]byte{},
		ExecPaths: []string{"/bin/entry"},
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(encoded)
	cases := []struct {
		name, body string
	}{
		{"empty", ""},
		{"null", "null"},
		{"truncated", valid[:len(valid)-1]},
		{"trailing_record", valid + " {}"},
		{"trailing_garbage", valid + " garbage"},
		{"unknown_field", strings.Replace(valid, `"env":[]`, `"env":[],"cwd":"/evil"`, 1)},
		{"invalid_base64", strings.Replace(valid, `"target":"L2Jpbi9lbnRyeQ=="`, `"target":"!"`, 1)},
		{"wrong_argv_type", strings.Replace(valid, `"argv":["ZGlmZmVyZW50"]`, `"argv":"different"`, 1)},
		{"invalid_json_utf8", strings.Replace(valid, "/bin/entry", "/bin/\xffentry", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadGuardSpec(guardTestFD(t, []byte(tc.body), guardTestSeals)); err == nil {
				t.Fatal("malformed spec accepted")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*guardSpecWire)
	}{
		{"missing_target", func(w *guardSpecWire) { w.Target = nil }},
		{"nul_target", func(w *guardSpecWire) { w.Target = []byte("/bin/\x00entry") }},
		{"empty_argv", func(w *guardSpecWire) { w.Argv = [][]byte{} }},
		{"null_argv", func(w *guardSpecWire) { w.Argv = nil }},
		{"nul_argv", func(w *guardSpecWire) { w.Argv = [][]byte{[]byte("bad\x00arg")} }},
		{"nul_env", func(w *guardSpecWire) { w.Env = [][]byte{[]byte("BAD=\x00")} }},
		{"empty_paths", func(w *guardSpecWire) { w.ExecPaths = nil }},
		{"relative_path", func(w *guardSpecWire) { w.ExecPaths = []string{"bin/entry"} }},
		{"nul_path", func(w *guardSpecWire) { w.ExecPaths = []string{"/bad\x00path"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := wire
			tc.mutate(&bad)
			body, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ReadGuardSpec(guardTestFD(t, body, guardTestSeals)); err == nil {
				t.Fatal("malformed byte-vector spec accepted")
			}
		})
	}
	if _, err := ReadGuardSpec(-1); err == nil {
		t.Fatal("negative descriptor accepted")
	}
}

func TestReadGuardSpecEnforcesExactSizeBound(t *testing.T) {
	body, err := json.Marshal(guardTestSpec())
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, bytes.Repeat([]byte{' '}, maxGuardSpecSize-len(body))...)
	if _, err := ReadGuardSpec(guardTestFD(t, body, guardTestSeals)); err != nil {
		t.Fatalf("record at limit rejected: %v", err)
	}
	fd := guardTestFD(t, nil, 0)
	if err := unix.Ftruncate(fd, maxGuardSpecSize+1); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, guardTestSeals); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	if _, err := ReadGuardSpec(fd); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("oversized record accepted: %v", err)
	}
}

func TestVerifyExecutionStatusRequiresAllZeroCapabilitySets(t *testing.T) {
	const status = "Name:\trsbx-guard\n" +
		"CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n" +
		"CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n" +
		"CapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"
	if err := verifyExecutionStatus([]byte(status)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		t.Run(field, func(t *testing.T) {
			line := field + ":\t0000000000000000\n"
			for _, bad := range []string{
				strings.Replace(status, line, field+":\t0000000000000001\n", 1),
				strings.Replace(status, line, "", 1),
				strings.Replace(status, line, field+":\tinvalid\n", 1),
				status + line,
			} {
				if err := verifyExecutionStatus([]byte(bad)); err == nil {
					t.Fatalf("invalid %s accepted", field)
				}
			}
		})
	}
	for _, bad := range []string{
		strings.Replace(status, "NoNewPrivs:\t1\n", "NoNewPrivs:\t0\n", 1),
		strings.Replace(status, "NoNewPrivs:\t1\n", "", 1),
		status + "NoNewPrivs:\t1\n",
	} {
		if err := verifyExecutionStatus([]byte(bad)); err == nil {
			t.Fatal("missing, unset or duplicated no_new_privs accepted")
		}
	}
}
