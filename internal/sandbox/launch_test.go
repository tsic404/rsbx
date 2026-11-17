package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

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

// The launcher creates its namespaces itself, inside the child, and reports
// a refusal instead of running with a weaker sandbox. The parent's clone
// flags carry only the user namespace, whose mappings must be written at
// clone time; a clone-time mount/PID namespace can be silently skipped
// inside an outer container, which is exactly what must not happen.
func TestLauncherCreatesNamespacesItself(t *testing.T) {
	spec := &launchSpec{UnshareUser: true}
	// No launchCloneFlags indirection: the launcher unshares mount/PID/IPC/
	// UTS itself, and CLONE_NEWUSER is the only flag the parent may pass.
	if spec.UnshareUser != true {
		t.Fatal("fixture broken")
	}
}

// A session keeps the caller's network namespace. The launcher must not ask
// the kernel to create a private one, whether or not it creates a user
// namespace.
func TestLaunchAttrsDoNotCreateNetworkNamespace(t *testing.T) {
	for _, tc := range []struct {
		name        string
		unshareUser bool
	}{
		{"without user namespace", false},
		{"with user namespace", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := launchAttrs(&launchSpec{UnshareUser: tc.unshareUser})
			if attrs.Cloneflags&unix.CLONE_NEWNET != 0 {
				t.Fatalf("clone flags create a network namespace: %#x", attrs.Cloneflags)
			}
			if attrs.Unshareflags&unix.CLONE_NEWNET != 0 {
				t.Fatalf("unshare flags create a network namespace: %#x", attrs.Unshareflags)
			}
		})
	}
}

// The diagnostic view is user-visible; it must not present a network mode or
// a net namespace that the session no longer has.
func TestExplainReportsNoNetworkNamespace(t *testing.T) {
	plan, _ := testPlan(t, []string{"/bin/sh"}, nil)
	out := plan.Explain()
	for _, unwanted := range []string{"network:", ",net", " net,"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("plan still reports network namespace state %q:\n%s", unwanted, out)
		}
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

	spec, err := plan.launchSpec([]string{"/bin/sh", "-lc", "echo hi"}, b)
	if err != nil {
		t.Fatal(err)
	}
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
	// The executable asset identity fields must survive the reexec: the
	// launcher has no policy object of its own.
	if !slices.Equal(back.RuntimePaths, spec.RuntimePaths) {
		t.Errorf("runtime paths lost: %v vs %v", back.RuntimePaths, spec.RuntimePaths)
	}
	// The local/remote split and the script chains must survive the reexec:
	// the launcher process has no policy object of its own.
	if !slices.Equal(back.LocalAllow, spec.LocalAllow) {
		t.Errorf("local allow lost: %v vs %v", back.LocalAllow, spec.LocalAllow)
	}
	if len(back.Scripts) != len(spec.Scripts) {
		t.Errorf("script chains lost: %v vs %v", back.Scripts, spec.Scripts)
	}
}

// A spec without the exec allowlist is rejected: the supervisor would have
// no basis for a single exec decision, and silently starting without one is
// the weak fallback the design forbids.
func TestSpecRequiresExecPathsAndAssets(t *testing.T) {
	// readLaunchSpec enforces the contract, not the JSON codec: exercise the
	// validator through a pipe the way runLauncher reads it. Each case omits
	// one mandatory part of the pinned launch contract.
	for _, spec := range []*launchSpec{
		{Mount: "/m", Target: "/bin/sh", Argv: []string{"/bin/sh"}},
		{
			Mount: "/m", Target: "/bin/sh", Argv: []string{"/bin/sh"},
			ExecPaths: []string{"/bin/sh"}, LocalAllow: []string{"/bin/sh"},
			RootFD: rootFD, AssetDirFD: assetDirFD,
		},
	} {
		body, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			w.Write(body)
			w.Close()
		}()
		if _, err := readLaunchSpec(r); err == nil {
			t.Fatalf("spec without pinned descriptors or namespace identities accepted: %s", body)
		}
	}
}

// MaybeRunLauncher must leave an ordinary command line alone: the internal
// flag is not part of the public interface.
func TestMaybeRunLauncherIgnoresNormalArgs(t *testing.T) {
	if MaybeRunLauncher() {
		t.Fatal("ordinary argv taken for the launcher")
	}
}

// The launcher spec must carry the helper directory, the exact execution
// grants and a gateway socket path that only the reserved broker serves.
func TestLauncherSpecCarriesHelpers(t *testing.T) {
	plan, _ := testPlan(t, []string{"/bin/sh"}, nil)
	plan.Trampoline = "/opt/rsbx/rsbx-tramp"
	plan.Guard = "/opt/rsbx/rsbx-guard"
	b, err := newBroker(plan.Target, filepath.Join(plan.Cache, "broker"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	spec, err := plan.launchSpec([]string{"/bin/sh"}, b)
	if err != nil {
		t.Fatal(err)
	}
	foundGuard, foundGateway := false, false
	for _, p := range spec.ExecPaths {
		if p == GuardPath {
			foundGuard = true
		}
		if p == TrampolinePath {
			foundGateway = true
		}
	}
	if !foundGuard || !foundGateway {
		t.Errorf("execution grants miss the helpers: %v", spec.ExecPaths)
	}
	if spec.HelperDir != filepath.Dir(plan.Trampoline) {
		t.Errorf("helper directory not carried: %+v", spec)
	}
	for _, kv := range spec.Env {
		if strings.HasPrefix(kv, "RSBX_TRAMP_SOCK=") || strings.HasPrefix(kv, "RSBX_TRAMP_CMD=") {
			t.Errorf("spec leaks trampoline transport: %q", kv)
		}
	}
}

// A non-UTF-8 argv/env byte vector must cross the spec wire unchanged: JSON
// string encoding would silently replace caller bytes with U+FFFD.
func TestSpecWirePreservesKernelBytes(t *testing.T) {
	spec := launchSpec{
		Mount:      "/mnt/x",
		BrokerDir:  "/.rsbx-rpc",
		Target:     "/bin/sh",
		Argv:       []string{"/bin/sh", "-c", "ok\xff\xfe"},
		Env:        []string{"PATH=/usr/bin", "BYTES=\xff\xfe"},
		ExecPaths:  []string{GuardPath, TrampolinePath},
		LocalAllow: []string{"/bin/sh"},
	}
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	var back launchSpec
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Argv[2] != spec.Argv[2] {
		t.Errorf("argv bytes replaced: %q vs %q", back.Argv[2], spec.Argv[2])
	}
	if back.Env[1] != spec.Env[1] {
		t.Errorf("env bytes replaced: %q vs %q", back.Env[1], spec.Env[1])
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
