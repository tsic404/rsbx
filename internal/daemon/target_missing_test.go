package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rsbx/internal/proto"
)

// A target that does not exist on the daemon is an executability error, not a
// silent retry somewhere else. The request names an absolute path, so neither
// PATH lookup nor an interpreter can turn it into a different program.
func TestExecMissingTargetIsAnExecutabilityError(t *testing.T) {
	target := filepath.Join(t.TempDir(), "no-such-target")
	frames, err := runClient(t, &proto.ExecReq{
		Target: target,
		Argv:   []string{target},
	}, nil)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	code, ok := exitStatus(frames)
	if !ok || code == 0 {
		t.Fatalf("a missing target exited %d (found=%v), want a non-zero status", code, ok)
	}
	if !frameType(frames, proto.TErr) {
		t.Fatalf("a missing target produced no error frame: %v", frames)
	}
	for _, f := range frames {
		if f.Type != proto.TErr {
			continue
		}
		if !strings.Contains(string(f.Payload), "no such file") {
			t.Errorf("the error does not name the missing file: %q", f.Payload)
		}
	}
}

// A target that exists but is not executable is refused as well: "the file is
// there" is not the criterion, "the file can be executed" is.
func TestExecNonExecutableTargetIsRefused(t *testing.T) {
	target := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(target, []byte("not a program"), 0o644); err != nil {
		t.Fatal(err)
	}
	frames, err := runClient(t, &proto.ExecReq{
		Target: target,
		Argv:   []string{target},
	}, nil)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	code, ok := exitStatus(frames)
	if !ok || code == 0 {
		t.Fatalf("a non-executable target exited %d (found=%v), want a non-zero status", code, ok)
	}
	if !frameType(frames, proto.TErr) {
		t.Fatalf("a non-executable target produced no error frame: %v", frames)
	}
}
