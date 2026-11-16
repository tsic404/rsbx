package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"rsbx/internal/paths"
	"rsbx/internal/policy"
)

// An allowlisted command in an exec directory must resolve to the host file,
// not to the gateway. Otherwise every tool an agent shells out to is
// redirected, and `stat` of a local tree fails with "no such file".
func TestAllowlistedCommandIsNotTrapped(t *testing.T) {
	base := tempDirOutsideTmp(t)
	binDir := filepath.Join(base, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(binDir, "allowed")
	other := filepath.Join(binDir, "other")
	for _, p := range []string{allowed, other} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pol, err := policy.New([]string{allowed})
	if err != nil {
		t.Fatal(err)
	}
	local, err := paths.New([]string{binDir}, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testCfg()
	plan := &Plan{Cfg: cfg, Exec: pol, Local: local, Mount: cfg.Sandbox.Mount}
	lay := plan.Layout()
	if !lay.LocalExec(allowed) {
		t.Errorf("allowlisted %s reported not local", allowed)
	}
	if lay.LocalExec(other) {
		t.Errorf("non-allowlisted %s reported local", other)
	}
	// The exact allowlist, aliases included, is what the immutable overlay
	// binds and what Landlock grants; data directories never appear.
	found := false
	for _, p := range lay.ExecPaths {
		if p == allowed {
			found = true
		}
	}
	if !found {
		t.Errorf("exec directory %s not arbitrated: %v", binDir, lay.ExecPaths)
	}
	for _, p := range lay.ExecPaths {
		if p == binDir {
			t.Errorf("directory %s became an execution grant", binDir)
		}
	}
}
