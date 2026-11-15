package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rsbx/internal/paths"
	"rsbx/internal/policy"
)

// bwrap only offers a -try form for user and cgroup namespaces. Asking for
// --unshare-net-try made every non-ssh sandbox fail to start, so the argument
// list must never contain it.
func TestNoUnsupportedBwrapTryFlags(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	pol, _ := policy.New([]string{"/usr/bin/true"})
	local, _ := paths.New([]string{dir}, false)
	plan := &Plan{Exec: pol, Local: local, Cfg: testCfg(), Mount: "/mnt/x"}
	args := plan.BwrapArgs([]string{"/bin/true"})
	allowed := map[string]bool{
		"--unshare-user-try": true, "--unshare-cgroup-try": true,
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--unshare-") && strings.HasSuffix(a, "-try") && !allowed[a] {
			t.Errorf("bwrap does not accept %s", a)
		}
	}
}

// The caller's directory is only used when the sandbox will have it; /tmp is
// replaced by a tmpfs, so starting there must fall back instead of failing.
func TestChdirSkippedForPathsHiddenByTmpfs(t *testing.T) {
	pol, _ := policy.New([]string{"/usr/bin/true"})
	local, _ := paths.New(nil, false)
	plan := &Plan{Exec: pol, Local: local, Cfg: testCfg(), Mount: "/mnt/x"}
	if plan.hasPath("/tmp/anything") {
		t.Error("/tmp path reported reachable; it is a tmpfs")
	}
	if plan.hasPath("/some/daemon/path") {
		t.Error("unknown path reported reachable")
	}
	if !plan.hasPath("/proc") {
		t.Error("synthetic path reported unreachable")
	}
}

// Local trees are served by FUSE, never bound: a bind would make bwrap create
// the intermediate directories, and that creation replaces the FUSE entries at
// the same paths, leaving the tree empty inside the sandbox.
func TestLocalTreesAreNeverBound(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	if err := os.WriteFile(filepath.Join(dir, "notes.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, _ := policy.New([]string{"/usr/bin/true"})
	local, _ := paths.New([]string{dir}, false)
	plan := &Plan{Exec: pol, Local: local, Cfg: testCfg(), Mount: "/mnt/x"}
	args := plan.BwrapArgs([]string{"/bin/true"})
	for i := 0; i+2 < len(args); i++ {
		if args[i] != "--bind" && args[i] != "--ro-bind" && args[i] != "--bind-try" && args[i] != "--ro-bind-try" {
			continue
		}
		if args[i+1] == dir || args[i+2] == dir {
			t.Fatalf("local tree bound from the host: %v", args[i:i+3])
		}
	}
}

// A local tree can live deep in the host filesystem. Its ancestors must be
// present in the view as plain directories, and the root itself must not be
// turned into an empty placeholder, or the tree appears with no contents.
func TestDeepLocalTreeIsReachable(t *testing.T) {
	base := tempDirOutsideTmp(t)
	deep := filepath.Join(base, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, _ := policy.New([]string{"/usr/bin/true"})
	local, _ := paths.New([]string{deep}, false)
	plan := &Plan{Exec: pol, Local: local, Cfg: testCfg(), Mount: "/mnt/x"}
	lay := plan.Layout()

	for _, dir := range []string{filepath.Dir(deep), filepath.Dir(filepath.Dir(deep))} {
		if !lay.HostDirs[dir] {
			t.Errorf("ancestor %s missing from HostDirs", dir)
		}
		found := false
		for _, s := range lay.Synthetic {
			if s == dir {
				found = true
			}
		}
		if !found {
			t.Errorf("ancestor %s not reserved as a mount point", dir)
		}
	}
	for _, s := range lay.Synthetic {
		if s == deep {
			t.Errorf("local tree root %s served as an empty placeholder", deep)
		}
	}
	if !plan.hasPath(deep) {
		t.Errorf("local tree %s reported unreachable", deep)
	}
	if !plan.hasPath(filepath.Dir(deep)) {
		t.Errorf("ancestor %s reported unreachable", filepath.Dir(deep))
	}
}

// The trampoline needs the local tree list to explain a failure. Without it the
// user only sees a bare ENOENT and has to infer the cause.
func TestLocalTreesReachTheSandbox(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	pol, _ := policy.New([]string{"/usr/bin/true"})
	local, _ := paths.New([]string{dir}, false)
	plan := &Plan{Exec: pol, Local: local, Cfg: testCfg(), Mount: "/mnt/x"}
	args := plan.BwrapArgs([]string{"/bin/true"})
	found := false
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--setenv" && args[i+1] == "RSBX_LOCAL_TREES" && args[i+2] == dir {
			found = true
		}
	}
	if !found {
		t.Fatalf("RSBX_LOCAL_TREES not passed to the sandbox: %v", args)
	}
}
