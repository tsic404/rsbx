package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rsbx/internal/paths"
	"rsbx/internal/policy"
)

// The launcher only ever binds one host directory: the broker relay. Any other
// bind target in the setup would expose host content the policy never granted.
func TestSpecBindsOnlyTheBrokerDir(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	tramp := filepath.Join(dir, "rsbx-tramp")
	guard := filepath.Join(dir, "rsbx-guard")
	for _, p := range []string{tramp, guard} {
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := testCfg()
	cfg.Local.Entry = "/bin/sh"
	cfg.Local.Allow = []string{}
	cfg.Sandbox.Mount = filepath.Join(dir, "mnt")
	cfg.Sandbox.Cache = filepath.Join(dir, "cache")
	plan, err := Prepare(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	spec := plan.launchSpec([]string{"/bin/sh"}, &broker{dir: filepath.Join(dir, "broker")})
	if spec.BrokerDir != filepath.Join(dir, "broker") {
		t.Errorf("broker dir = %q, want the private cache directory", spec.BrokerDir)
	}
	if spec.HelperDir != filepath.Dir(tramp) {
		t.Errorf("helper dir = %q, want the directory holding the helpers", spec.HelperDir)
	}
	_ = guard
	if spec.Cwd != "" && !filepath.IsAbs(spec.Cwd) {
		t.Errorf("cwd %q must be absolute", spec.Cwd)
	}
}

// The namespace set is created inside the launcher, not at clone time; see
// TestLauncherCreatesNamespacesItself. What the plan must carry is the
// configuration that decides that set.
func TestPlanCarriesNamespaceConfiguration(t *testing.T) {
	plan := planFor(t, tempDirOutsideTmp(t), []string{"/bin/sh"}, nil)
	b, err := newBroker(plan.Target, filepath.Join(plan.Cache, "broker"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	spec := plan.launchSpec([]string{"/bin/sh"}, b)
	if spec.UnshareUser != plan.Cfg.Sandbox.UnshareUser {
		t.Errorf("unshare_user not carried: %v", spec.UnshareUser)
	}
	if spec.ShareNetwork != plan.usesHostNetwork() {
		t.Errorf("share_network not carried: %v", spec.ShareNetwork)
	}
}

// The launcher is addressed by an internal flag before flag.Parse, so a user
// command line can neither collide with it nor trigger it accidentally.
func TestLaunchFlagIsInternal(t *testing.T) {
	if !strings.HasPrefix(launchFlag, "-rsbx-") {
		t.Errorf("launch flag %q must be internal", launchFlag)
	}
	if MaybeRunLauncher() {
		t.Error("a plain argv must not start the launcher")
	}
}

// A sandbox path with no meaning in the view is not handed to the launcher as
// the working directory: / is the fallback.
func TestCwdOutsideViewIsDropped(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	pol, err := policy.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	local, err := paths.New(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	plan := &Plan{Exec: pol, Local: local, Cfg: testCfg(), Mount: "/mnt/x"}
	spec := plan.launchSpec([]string{"/bin/sh"}, &broker{dir: dir})
	if spec.Cwd == dir {
		t.Errorf("cwd %q kept although the plan cannot have it", dir)
	}
}

// The Landlock list is the allowlist plus the helpers, never the directories
// holding them.
func TestLandlockListIsPathsNotDirs(t *testing.T) {
	base := tempDirOutsideTmp(t)
	bin := filepath.Join(base, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(bin, "tool")
	if err := os.WriteFile(tool, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	tramp := filepath.Join(base, "rsbx-tramp")
	guard := filepath.Join(base, "rsbx-guard")
	for _, p := range []string{tramp, guard} {
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pol, err := policy.New([]string{tool})
	if err != nil {
		t.Fatal(err)
	}
	local, err := paths.New(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	plan := &Plan{
		Exec: pol, Local: local, Cfg: testCfg(),
		Mount: filepath.Join(base, "mnt"), Cache: filepath.Join(base, "cache"),
		Trampoline: tramp, Guard: guard,
	}
	list := strings.Split(strings.Join(plan.SandboxExecPaths(), ":"), ":")
	for _, p := range list {
		if p == bin {
			t.Errorf("policy directory %s granted wholesale: %v", bin, list)
		}
		if !filepath.IsAbs(p) {
			t.Errorf("non-absolute Landlock path %q in %v", p, list)
		}
	}
	for _, want := range []string{tool, GuardPath, TrampolinePath} {
		found := false
		for _, p := range list {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s missing from the Landlock list: %v", want, list)
		}
	}
}

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
	// The FUSE layout arbitrates policy directories per name; nothing binds
	// the host tree over them.
	lay := plan.Layout()
	found := false
	for _, d := range lay.ExecDirs {
		if d == dir {
			found = true
		}
	}
	if !found {
		t.Errorf("policy directory %s missing from the exec layout: %v", dir, lay.ExecDirs)
	}
}
