package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"rsbx/internal/paths"
	"rsbx/internal/policy"
)

// A directory holding the allowlist must stay served by FUSE, because that is
// where every non-granted name becomes a trampoline. Binding the host tree over
// it would hand the sandbox the real binaries.
func TestPolicyDirsAreNotBound(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	tool := filepath.Join(dir, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.New([]string{tool})
	if err != nil {
		t.Fatal(err)
	}
	local, err := paths.New([]string{dir}, false)
	if err != nil {
		t.Fatal(err)
	}
	plan := &Plan{Exec: pol, Local: local, Cfg: testCfg(), Mount: "/mnt/x"}
	args := plan.BwrapArgs([]string{"/bin/true"})
	for i := 0; i+2 < len(args); i++ {
		if (args[i] == "--bind" || args[i] == "--ro-bind") && args[i+1] == dir {
			t.Fatalf("policy directory bound from the host: %v", args[i:i+3])
		}
	}
}

// tempDirOutsideTmp creates a scratch directory that is not under /tmp. The
// sandbox replaces /tmp with a tmpfs, so trees living there are served by FUSE
// rather than bound, which would invalidate the bind tests below.
func tempDirOutsideTmp(t *testing.T) string {
	t.Helper()
	base := os.Getenv("RSBX_TEST_SCRATCH")
	if base == "" {
		base = "/var/tmp"
	}
	dir, err := os.MkdirTemp(base, "rsbx-test-")
	if err != nil {
		t.Skipf("no writable scratch outside /tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
