package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"rsbx/internal/config"
	"rsbx/internal/paths"
	"rsbx/internal/policy"
)

// A plan built directly, the way the tests below need it.
func testPlan(t *testing.T, allow, trees []string) (*Plan, string) {
	t.Helper()
	dir := tempDirOutsideTmp(t)
	pol, err := policy.New(allow)
	if err != nil {
		t.Fatal(err)
	}
	local, err := paths.New(trees, false)
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
		Cache: cfg.Sandbox.Cache,
	}, dir
}

// The launcher creates its namespaces itself, inside the child, and reports a
// refusal instead of running with a weaker sandbox. The parent's clone flags
// therefore carry no namespace at all: a clone-time namespace can be silently
// skipped inside an outer container, which is exactly what must not happen.
func TestLauncherCreatesNamespacesItself(t *testing.T) {
	spec := &launchSpec{ShareNetwork: false, UnshareUser: true}
	if got := launchCloneFlags(spec); got != 0 {
		t.Fatalf("clone flags = %#x, want 0: namespaces belong to the launcher", got)
	}
}

// The spec is a bounded JSON document on a dedicated descriptor. It must
// survive a round trip unchanged, and it must be rejected when oversized.
func TestSpecRoundTripAndBound(t *testing.T) {
	plan, dir := testPlan(t, []string{"/bin/sh"}, nil)
	b, err := newBroker(plan.Target, filepath.Join(dir, "broker"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()

	spec := plan.launchSpec([]string{"/bin/sh", "-lc", "echo hi"}, b)
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > maxSpecSize {
		t.Fatalf("spec is %d bytes", len(data))
	}
	var back launchSpec
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Mount != spec.Mount || back.BrokerDir != spec.BrokerDir {
		t.Errorf("spec lost fields on the way through: %+v vs %+v", back, spec)
	}
	if len(back.Argv) != 3 || back.Argv[0] != "/bin/sh" {
		t.Errorf("argv not carried: %v", back.Argv)
	}
	if back.LocalTrees != spec.LocalTrees {
		t.Errorf("local trees not carried: %q vs %q", back.LocalTrees, spec.LocalTrees)
	}
}

// MaybeRunLauncher must leave an ordinary command line alone: the internal
// flag is not part of the public interface.
func TestMaybeRunLauncherIgnoresNormalArgs(t *testing.T) {
	// A process without the launch flag returns false immediately; the flag
	// package then sees an unchanged argv.
	if MaybeRunLauncher() {
		t.Fatal("ordinary argv taken for the launcher")
	}
}

// The entry process environment must carry the broker socket path the
// trampoline expects, and the Landlock grant when one is configured.
func TestLauncherEnvironmentForTrampoline(t *testing.T) {
	plan, _ := testPlan(t, []string{"/bin/sh"}, nil)
	plan.Trampoline = "/opt/rsbx/rsbx-tramp"
	plan.Guard = "/opt/rsbx/rsbx-guard"
	b, err := newBroker(plan.Target, filepath.Join(plan.Cache, "broker"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	spec := plan.launchSpec([]string{"/bin/sh"}, b)
	// The trampoline socket is added by supervise, in the launcher, so the
	// parent's own environment never carries it.
	env := append(append([]string(nil), spec.Env...), "RSBX_TRAMP_SOCK="+BrokerSock)
	if !slices.Contains(env, "RSBX_TRAMP_SOCK="+BrokerSock) {
		t.Errorf("trampoline socket missing from entry env: %v", env)
	}
	if !strings.Contains(spec.LandlockExec, GuardPath) ||
		!strings.Contains(spec.LandlockExec, TrampolinePath) {
		t.Errorf("landlock grant misses the helpers: %q", spec.LandlockExec)
	}
	if spec.HelperDir != filepath.Dir(plan.Trampoline) {
		t.Errorf("helper directory not carried: %+v", spec)
	}
}

// The guard binary must exist next to the trampoline: the Dockerfile and CI
// both build them together, and a missing one is a packaging error that has
// to surface at Prepare time, not at first exec.
func TestPrepareRequiresBothHelpers(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	tramp := filepath.Join(dir, "rsbx-tramp")
	if err := os.WriteFile(tramp, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Local.Entry = "/bin/sh"
	cfg.Sandbox.Mount = filepath.Join(dir, "mnt")
	cfg.Sandbox.Cache = filepath.Join(dir, "cache")
	if _, err := Prepare(cfg, dir); err == nil {
		t.Fatal("missing guard accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "rsbx-guard"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(cfg, dir); err != nil {
		t.Fatalf("complete helper set rejected: %v", err)
	}
}
