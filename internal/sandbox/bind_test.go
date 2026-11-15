package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"rsbx/internal/config"
	"rsbx/internal/paths"
	"rsbx/internal/policy"
)

// planFor builds a Plan the way Prepare would, without touching a mount.
func planFor(t *testing.T, dir string, allow []string, localTrees []string) *Plan {
	t.Helper()
	pol, err := policy.New(allow)
	if err != nil {
		t.Fatal(err)
	}
	local, err := paths.New(localTrees, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Sandbox.Mount = "/mnt/x"
	cfg.Sandbox.Cache = filepath.Join(dir, "cache")
	return &Plan{
		Cfg:   cfg,
		Exec:  pol,
		Local: local,
		Mount: cfg.Sandbox.Mount,
	}
}

// The layout must reserve every internal bind target as synthetic. The
// launcher creates these itself; if FUSE forwarded one to the daemon it would
// materialise a stray file or directory in the daemon tree.
func TestReservedPathsAreSynthetic(t *testing.T) {
	plan := planFor(t, tempDirOutsideTmp(t), []string{"/bin/sh"}, nil)
	lay := plan.Layout()
	synthetic := map[string]bool{}
	for _, s := range lay.Synthetic {
		synthetic[s] = true
	}
	for _, want := range []string{BrokerDir, OldRootPath, "/proc", "/dev"} {
		if !synthetic[want] {
			t.Errorf("%s not reserved as a synthetic mount point", want)
		}
	}
	for _, f := range lay.SyntheticFiles {
		if f != GuardPath && f != TrampolinePath {
			t.Errorf("unexpected synthetic file %s", f)
		}
	}
}

// The broker directory is the only host directory the launcher binds. Nothing
// else may appear as a host passthrough that the policy did not grant.
func TestOnlyBrokerIsHostBound(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	plan := planFor(t, dir, []string{"/bin/sh"}, []string{dir})
	lay := plan.Layout()
	// HostDirs is the ancestor closure of the local trees; nothing outside
	// them may appear there.
	for d := range lay.HostDirs {
		if d == "/" {
			// The root is the view itself, not a host passthrough.
			continue
		}
		if !plan.Local.IsLocal(d) && !isAncestorOf(d, plan.Local.Roots()) {
			t.Errorf("%s is not part of any local tree", d)
		}
	}
	if lay.SystemLinks != nil && len(lay.SystemLinks) != 0 {
		t.Errorf("host system links leaked into the layout: %v", lay.SystemLinks)
	}
}

func isAncestorOf(dir string, roots []string) bool {
	for _, r := range roots {
		if r == dir || len(dir) < len(r) && r[len(dir)] == '/' && r[:len(dir)] == dir {
			return true
		}
	}
	return false
}

// The launcher spec is the only thing crossing the process boundary. It must
// never carry host credentials: the daemon transport is dialled by the broker
// outside the root, so the spec has no socket path, no ssh command and no
// environment of its own beyond what the entry already has.
func TestLaunchSpecCarriesNoDaemonTransport(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	cfg := config.Default()
	cfg.Daemon.Transport = "ssh"
	cfg.Daemon.Command = `ssh host rsbxd --socket /x`
	plan := planFor(t, dir, []string{"/bin/sh"}, nil)
	plan.Cfg = cfg
	plan.Target = targetOf(cfg)
	b, err := newBroker(plan.Target, filepath.Join(dir, "broker"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	spec := plan.launchSpec([]string{"/bin/sh"}, b)
	if spec.Mount != plan.Mount || spec.BrokerDir != b.HostDir() {
		t.Errorf("spec mispoints the root or broker: %+v", spec)
	}
	for _, kv := range spec.Env {
		if kv == "RSBX_TRAMP_SOCK=" || kv == "RSBX_TRAMP_CMD=" {
			t.Errorf("spec leaks trampoline transport: %q", kv)
		}
	}
}

// A working directory the sandbox cannot have must not be carried into the
// launcher: /tmp stays the daemon's directory, so starting there means the
// entry starts at / instead.
func TestHiddenCwdFallsBackToRoot(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	plan := planFor(t, dir, []string{"/bin/sh"}, []string{dir})
	b, err := newBroker(plan.Target, filepath.Join(dir, "broker"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	// /tmp is the daemon's directory, so it is reachable through the view;
	// it must never be treated as a host tree the launcher replaces.
	if !plan.hasPath("/tmp") {
		t.Error("daemon /tmp must stay visible in the view")
	}
	if plan.Local.IsLocal("/tmp") || plan.Local.IsLocal("/tmp/anything") {
		t.Error("/tmp must not be served as a local tree")
	}
	spec := plan.launchSpec([]string{"/bin/sh"}, b)
	if spec.Cwd == "/tmp" || filepath.HasPrefix(spec.Cwd, "/tmp/") {
		t.Errorf("cwd %q cannot exist in the sandbox view", spec.Cwd)
	}
}

// tempDirOutsideTmp creates a scratch directory that is not under /tmp. The
// sandbox keeps /tmp as daemon content, so trees living there would be served
// by FUSE rather than from the host, which would invalidate these tests.
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
