package sandbox

import (
	"strings"
	"testing"

	"rsbx/internal/paths"
	"rsbx/internal/policy"
)

// A bind whose destination shares a parent with an exec-policy directory would
// make bwrap create that parent, hiding the FUSE entries below it. This is the
// bug that emptied /usr/bin.
func TestBindsThroughPolicyDirRejected(t *testing.T) {
	roots := []string{"/usr/bin"}
	cases := map[string]bool{
		"/usr/lib":     true,  // shares /usr
		"/usr/share":   true,  // shares /usr
		"/usr/libexec": true,  // shares /usr
		"/etc":         false, // unrelated top-level tree
		"/work":        false,
		"/usr/bin":     true, // the policy dir itself
		"/usr/bin/sub": true, // inside it
	}
	for p, want := range cases {
		if got := bindsThrough(p, roots); got != want {
			t.Errorf("bindsThrough(%s) = %v, want %v", p, got, want)
		}
	}
}

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
