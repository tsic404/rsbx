//go:build linux && (amd64 || arm64)

package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// assetFor pins a real file's identity the way the launcher's asset capture
// does, so the exec policy sees kernel-true dev/ino pairs.
func assetFor(t *testing.T, path, kind string) execAsset {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return execAsset{Path: path, Kind: kind, Dev: uint64(st.Dev), Ino: st.Ino, Size: st.Size}
}

// The exec policy treats exactly the configured allowlist as local, and
// nothing else — runtime assets are executable (Landlock) but never a user's
// local program, and a path that merely shares a directory with an allowed
// program stays remote.
func TestExecPolicyLocalSplit(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "tool")
	interpreter := filepath.Join(dir, "python3")
	envTool := filepath.Join(dir, "node-tool")
	envCommand := filepath.Join(dir, "node")
	// Classification is tested directly: asset identity verification is
	// exercised separately, so the helpers are pinned from real temporary
	// inodes while recording the reserved logical paths they must carry.
	for _, p := range []string{script, interpreter, envTool, envCommand} {
		if err := os.WriteFile(p, []byte("#!/bin/x\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	helperAsset := func(kind, path string) execAsset {
		f, err := os.CreateTemp(dir, "helper-")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		a := assetFor(t, f.Name(), kind)
		a.Path = path
		return a
	}
	spec := &launchSpec{
		LocalAllow:   []string{script, envTool},
		RuntimePaths: []string{interpreter, envCommand},
		Scripts: []scriptChain{
			{Script: script, Interp: interpreter, Spelling: interpreter, InterpArgs: []string{"-E"}},
			{Script: envTool, Interp: envCommand, Spelling: envCommand, Env: true, EnvInterp: envCommand, EnvArgs: []string{envCommand}},
		},
	}
	spec.Assets = []execAsset{
		assetFor(t, script, "local"), assetFor(t, envTool, "local"),
		assetFor(t, interpreter, "runtime"), assetFor(t, envCommand, "runtime"),
		helperAsset("guard", GuardPath), helperAsset("gateway", TrampolinePath),
	}
	policy, err := newExecPolicy(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.local) != 2 {
		t.Errorf("local set is %v", policy.local)
	}
	if c, ok := policy.scripts[assetID(policy.paths[script])]; !ok || c.Interp != interpreter || len(c.InterpArgs) != 1 {
		t.Errorf("script metadata lost: %+v", c)
	}
	if _, ok := policy.scripts[assetID(policy.paths[interpreter])]; ok {
		t.Error("runtime interpreter became a script")
	}
	if policy.guard.Path != GuardPath || policy.gateway.Path != TrampolinePath {
		t.Errorf("helpers misidentified: %s %s", policy.guard.Path, policy.gateway.Path)
	}
}

// Script metadata is only valid when it names a pinned policy asset; a chain
// attached to a missing or non-policy path must fail closed.
func TestScriptMetadataRequiresPinnedAssets(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "tool")
	interpreter := filepath.Join(dir, "python3")
	guard, gateway := filepath.Join(dir, "rsbx-guard"), filepath.Join(dir, "rsbx-tramp")
	for _, p := range []string{script, interpreter, guard, gateway} {
		if err := os.WriteFile(p, []byte("#!/bin/x\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A runtime script may carry interpreter metadata for kernel recursion,
	// but that never makes its inode a local program; the failing cases are a
	// chain whose script asset is absent and one whose interpreter is absent.
	for _, tc := range []struct {
		name   string
		assets []execAsset
	}{
		{"missing script asset", []execAsset{assetFor(t, interpreter, "runtime"), assetFor(t, guard, "guard"), assetFor(t, gateway, "gateway")}},
		{"missing interpreter snapshot", []execAsset{assetFor(t, script, "local"), assetFor(t, guard, "guard"), assetFor(t, gateway, "gateway")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := &launchSpec{
				Scripts: []scriptChain{{Script: script, Interp: interpreter, Spelling: interpreter}},
				Assets:  tc.assets,
			}
			if _, err := pinnedExecPolicy(spec); err == nil {
				t.Fatal("invalid script metadata accepted")
			}
		})
	}
}

// Kernel script recursion prepends only a small interpreter prefix. The
// pinned plan must reproduce that argv shape, including literal spellings,
// and reject a kernel argv that drops or reorders the user's arguments.
func TestScriptPlanFollowsKernelRecursion(t *testing.T) {
	p := &execPolicy{
		paths: map[string]execAsset{
			"/p/tool":      {Path: "/p/tool", Kind: "local", Dev: 1, Ino: 1},
			"/bin/python":  {Path: "/bin/python", Kind: "runtime", Dev: 2, Ino: 2},
			"/bin/python2": {Path: "/bin/python2", Kind: "runtime", Dev: 3, Ino: 3},
		},
		scripts: map[executableID]scriptChain{
			{1, 1}: {Script: "/p/tool", Interp: "/bin/python", Spelling: "/bin/python", InterpArgs: []string{"-E"}},
			{2, 2}: {Script: "/bin/python", Interp: "/bin/python2", Spelling: "/bin/python2"},
		},
	}
	plan, err := p.scriptPlan(executableID{1, 1}, "/p/tool", []string{"/p/tool", "a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	// Kernel recursion keeps every intermediate interpreter as the next
	// script's argv[0] slot: the innermost spelling comes first, then the
	// outer spelling and its optional argument, then the requested script.
	if !slices.Equal(plan.prefix, []string{"/bin/python2", "/bin/python", "-E", "/p/tool"}) {
		t.Fatalf("interpreter prefix wrong: %v", plan.prefix)
	}
	if got := assetID(plan.image); got != (executableID{3, 3}) {
		t.Fatalf("final image is %v", got)
	}
	want := []string{"/bin/python2", "/bin/python", "-E", "/p/tool", "a", "b"}
	if !plan.matches(want) {
		t.Error("correct kernel argv rejected")
	}
	for _, bad := range [][]string{
		{"/bin/python2", "/bin/python", "-X", "/p/tool", "a", "b"},
		{"/bin/python2", "/bin/python", "-E", "/p/tool", "a"},
		{"/bin/python2", "/bin/python", "-E", "/p/tool", "a", "b", "c"},
		{"/bin/python2", "-E", "/p/tool", "a", "b"},
	} {
		if plan.matches(bad) {
			t.Errorf("mutated argv %v accepted", bad)
		}
	}
}

// An env-shebang chain adds one exact env command hop after the kernel loads
// the script; the one-shot permit must match exactly that committed shape.
func TestScriptPlanEnvTransition(t *testing.T) {
	p := &execPolicy{
		paths: map[string]execAsset{
			"/p/tool":   {Path: "/p/tool", Kind: "local", Dev: 1, Ino: 1},
			"/bin/sh":   {Path: "/bin/sh", Kind: "runtime", Dev: 2, Ino: 2},
			"/bin/real": {Path: "/bin/real", Kind: "runtime", Dev: 3, Ino: 3},
		},
		scripts: map[executableID]scriptChain{
			{1, 1}: {Script: "/p/tool", Interp: "/bin/sh", Spelling: "/bin/sh", Env: true, EnvInterp: "/bin/real", EnvArgs: []string{"/bin/real"}},
		},
	}
	plan, err := p.scriptPlan(executableID{1, 1}, "/p/tool", []string{"/p/tool", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.permit == nil {
		t.Fatal("env chain produced no permit")
	}
	if got := assetID(plan.permit.image); got != (executableID{3, 3}) {
		t.Fatalf("permit image is %v", got)
	}
	if !plan.permit.matches([]string{"/bin/real", "/p/tool", "x"}) {
		t.Error("env permit rejected the committed env argv")
	}
	if plan.permit.matches([]string{"/bin/real", "/other", "x"}) {
		t.Error("env permit accepted a different script path")
	}
}

// The gateway path the supervisor substitutes must be the reserved helper
// path, not anything the tracee can name.
func TestGatewayIsReservedHelper(t *testing.T) {
	if !strings.HasPrefix(TrampolinePath, HelperDir+"/") {
		t.Errorf("gateway %s is not under the bound helper dir %s", TrampolinePath, HelperDir)
	}
	if filepath.Dir(TrampolinePath) != HelperDir || filepath.Dir(GuardPath) != HelperDir {
		t.Error("helpers must share the bound helper directory")
	}
}
