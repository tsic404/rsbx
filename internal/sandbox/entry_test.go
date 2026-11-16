package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

// The entry program is started by the session, so it runs locally by
// definition. Requiring it in local.allow as well only ever produced an
// execvp failure at start-up.
func TestEntryProgramIsAllowedImplicitly(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	entry := filepath.Join(dir, "entry")
	if err := os.WriteFile(entry, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, helper := range []string{"rsbx-tramp", "rsbx-guard"} {
		if err := os.WriteFile(filepath.Join(dir, helper), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	cfg := testCfg()
	cfg.Local.Allow = []string{}
	cfg.Local.Entry = entry
	cfg.Local.Paths = []string{dir}
	cfg.Sandbox.Mount = filepath.Join(dir, "mnt")
	cfg.Sandbox.Cache = filepath.Join(dir, "cache")

	plan, err := Prepare(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Exec.IsLocal(entry) {
		t.Errorf("entry %s not allowed to run locally", entry)
	}
	// and it must survive Landlock, or the session cannot start at all
	found := false
	for _, p := range plan.SandboxExecPaths() {
		if p == entry {
			found = true
		}
	}
	if !found {
		t.Errorf("entry %s missing from the Landlock allowlist: %v", entry, plan.SandboxExecPaths())
	}
}

// A relative entry cannot be resolved inside the sandbox, so it is rejected
// rather than silently failing at exec time.
func TestRelativeEntryRejected(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	for _, helper := range []string{"rsbx-tramp", "rsbx-guard"} {
		if err := os.WriteFile(filepath.Join(dir, helper), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := testCfg()
	cfg.Local.Allow = []string{"/usr/bin/true"}
	cfg.Local.Entry = "bash"
	cfg.Sandbox.Mount = filepath.Join(dir, "mnt")
	cfg.Sandbox.Cache = filepath.Join(dir, "cache")
	if _, err := Prepare(cfg, dir); err == nil {
		t.Fatal("relative entry accepted")
	}
}
