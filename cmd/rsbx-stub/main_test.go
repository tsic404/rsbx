package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each way of losing the capability has to be told apart and name what is
// wrong: no variable at all, a variable that is not an absolute path, and a
// path whose session is gone.
func TestRunRefusesWithDistinguishableReasons(t *testing.T) {
	deadDir := t.TempDir()
	deadSocket := filepath.Join(deadDir, "session.sock")
	if err := os.RemoveAll(deadDir); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		value  string
		set    bool
		want   []string
		absent string
	}{
		{
			name:   "unset",
			set:    false,
			want:   []string{"missing absolute RSBX_STUB_SOCKET", "not set"},
			absent: "",
		},
		{
			name:   "relative",
			value:  filepath.Join("run", "session.sock"),
			set:    true,
			want:   []string{"missing absolute RSBX_STUB_SOCKET", "not an absolute path", "run/session.sock"},
			absent: "no live sandbox session",
		},
		{
			name:   "dead",
			value:  deadSocket,
			set:    true,
			want:   []string{"no live sandbox session", deadSocket, "no such file"},
			absent: "missing absolute RSBX_STUB_SOCKET",
		},
	}

	seen := map[string]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setStubEnv(t, tc.value, tc.set)
			code, stderr := runStub(t)
			if code != 126 {
				t.Fatalf("exit = %d, want 126 (stderr %q)", code, stderr)
			}
			for _, want := range tc.want {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr %q does not name %q", stderr, want)
				}
			}
			if tc.absent != "" && strings.Contains(stderr, tc.absent) {
				t.Errorf("stderr %q wrongly claims %q", stderr, tc.absent)
			}
			reason := strings.TrimSuffix(strings.TrimSpace(stderr), "\n")
			if prev, ok := seen[reason]; ok {
				t.Errorf("case %q repeats the reason of %q: %q", tc.name, prev, reason)
			}
			seen[reason] = tc.name
		})
	}
}

// A CLI path installed as the reverse stub has no session capability in a
// local agent session. The refusal has to name the installation mistake:
// telling the caller only that the variable is unset sends the operator to
// the handshake, where there was no session in the first place.
func TestRunNamesMisinstalledCLI(t *testing.T) {
	setStubEnv(t, "", false)
	code, stderr := runStubWithArgs(t, []string{"/opt/agent/multica", "--help"})
	if code != 126 {
		t.Fatalf("exit = %d, want 126 (stderr %q)", code, stderr)
	}
	for _, want := range []string{"rsbx-stub is not a general-purpose CLI", "RSBX_STUB_SOCKET", "install the real multica CLI at MULTICA_CLI_PATH"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q does not name %q", stderr, want)
		}
	}
}

// A daemon-side forwarding alias is a valid way to install the stub. When its
// session capability is missing, the reason is the absent capability, not a
// CLI installation: telling the operator to replace the alias hides the
// failure the acceptance carrier is checking.
func TestRunKeepsMissingCapabilityForForwardingAlias(t *testing.T) {
	setStubEnv(t, "", false)
	code, stderr := runStubWithArgs(t, []string{"tc17-echo", "PAYLOAD"})
	if code != 126 {
		t.Fatalf("exit = %d, want 126 (stderr %q)", code, stderr)
	}
	for _, want := range []string{"rsbx-stub: missing absolute RSBX_STUB_SOCKET", "RSBX_STUB_SOCKET is not set"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q does not name %q", stderr, want)
		}
	}
	if strings.Contains(stderr, "not a general-purpose CLI") || strings.Contains(stderr, "install the real multica CLI") {
		t.Errorf("stderr %q wrongly claims a CLI installation mistake", stderr)
	}
}

func setStubEnv(t *testing.T, value string, set bool) {
	t.Helper()
	prev, had := os.LookupEnv("RSBX_STUB_SOCKET")
	if set {
		if err := os.Setenv("RSBX_STUB_SOCKET", value); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Unsetenv("RSBX_STUB_SOCKET"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			os.Setenv("RSBX_STUB_SOCKET", prev)
			return
		}
		os.Unsetenv("RSBX_STUB_SOCKET")
	})
}

func runStub(t *testing.T) (int, string) {
	t.Helper()
	return runStubWithArgs(t, []string{"rsbx-stub", "/usr/bin/true"})
}

func runStubWithArgs(t *testing.T, args []string) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldArgs, oldStderr := os.Args, os.Stderr
	os.Args = args
	os.Stderr = w
	defer func() {
		os.Args, os.Stderr = oldArgs, oldStderr
	}()
	code := run()
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	return code, string(out)
}
