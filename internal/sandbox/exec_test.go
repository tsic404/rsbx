package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"rsbx/internal/paths"
	"rsbx/internal/policy"
)

// An allowlisted command in an exec directory must resolve to the host file,
// not to the trampoline. Otherwise every tool an agent shells out to is
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
	lay := (&Plan{Exec: pol, Local: local}).Layout()
	if lay.LocalExec == nil {
		t.Fatal("LocalExec not wired")
	}
	if !lay.LocalExec(allowed) {
		t.Errorf("allowlisted %s reported not local", allowed)
	}
	if lay.LocalExec(other) {
		t.Errorf("non-allowlisted %s reported local", other)
	}
}
