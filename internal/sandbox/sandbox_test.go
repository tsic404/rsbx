package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rsbx/internal/config"
	"rsbx/internal/paths"
)

// Multiple invocations of the same configuration must neither replace each
// other's broker/cache nor delete the operator's files during cleanup.
func TestSessionsOwnDisjointResources(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Sandbox.Mount = filepath.Join(dir, "mounts")
	cfg.Sandbox.Cache = filepath.Join(dir, "cache")
	a, b := &Plan{Cfg: cfg}, &Plan{Cfg: cfg}
	if err := a.allocateSession(); err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := b.allocateSession(); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if a.Mount == b.Mount || a.Cache == b.Cache {
		t.Fatal("concurrent sessions share a runtime directory")
	}
	files := []string{
		filepath.Join(a.Cache, "owned-a"),
		filepath.Join(b.Cache, "owned-b"),
		filepath.Join(cfg.Sandbox.Cache, "operator-file"),
	}
	for _, name := range files {
		if err := os.WriteFile(name, []byte("keep ownership"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(files[0]); !os.IsNotExist(err) {
		t.Fatalf("closed session's private file remains: %v", err)
	}
	for _, name := range files[1:] {
		data, err := os.ReadFile(name)
		if err != nil || string(data) != "keep ownership" {
			t.Fatalf("closing one session damaged %s: %q, %v", name, data, err)
		}
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(files[2]); err != nil {
		t.Fatalf("cleanup removed unowned cache content: %v", err)
	}
}

func TestSessionControlCannotBeExposedThroughLocalSymlink(t *testing.T) {
	dir := t.TempDir()
	control := filepath.Join(dir, "control")
	if err := os.Mkdir(control, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "agent-config")
	if err := os.Symlink(control, alias); err != nil {
		t.Fatal(err)
	}
	local, err := paths.New([]string{alias}, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Sandbox.Cache = filepath.Join(control, "cache")
	cfg.Sandbox.Mount = filepath.Join(dir, "mounts")
	plan := &Plan{Cfg: cfg, Local: local}
	if err := plan.allocateSession(); err == nil {
		defer plan.Close()
		t.Fatal("agent configuration alias exposes the controller's broker/cache")
	}
	if _, err := os.Stat(cfg.Sandbox.Cache); !os.IsNotExist(err) {
		t.Fatalf("rejected configuration still allocated control resources: %v", err)
	}
}

// A sibling that merely shares a name prefix is not inside the root, and the
// filesystem root contains every absolute path rather than only "//" children.
func TestWithinRootBoundary(t *testing.T) {
	cases := []struct {
		filename, root string
		want           bool
	}{
		{"/a/b", "/a", true},
		{"/a", "/a", true},
		{"/ab", "/a", false},
		{"/a/b", "/a/", true},
		{"/x", "/", true},
		{"relative", "/", false},
	}
	for _, c := range cases {
		if got := within(c.filename, c.root); got != c.want {
			t.Errorf("within(%q, %q) = %v, want %v", c.filename, c.root, got, c.want)
		}
	}
}

// A failed worker must not turn cleanup into a false success, and it must not
// remove directories this session does not own.
func TestCloseReportsFailureAndKeepsForeignPaths(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Sandbox.Mount = filepath.Join(dir, "mounts")
	cfg.Sandbox.Cache = filepath.Join(dir, "cache")
	plan := &Plan{Cfg: cfg}
	if err := plan.allocateSession(); err != nil {
		t.Fatal(err)
	}
	sessionDir, mountDir := plan.sessionDir, plan.mountDir
	foreignMount := filepath.Join(cfg.Sandbox.Mount, "session-other")
	if err := os.Mkdir(foreignMount, 0o700); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	close(done)
	plan.filesystem = &filesystemWorker{done: done, waitErr: errors.New("worker failed")}
	err := plan.Close()
	if err == nil || !strings.Contains(err.Error(), "worker failed") {
		t.Fatalf("failed worker reported as clean shutdown: %v", err)
	}
	for _, owned := range []string{sessionDir, mountDir} {
		if _, err := os.Stat(owned); !os.IsNotExist(err) {
			t.Errorf("owned path %s survived cleanup: %v", owned, err)
		}
	}
	if _, err := os.Stat(foreignMount); err != nil {
		t.Fatalf("cleanup removed another session's directory: %v", err)
	}
	// A second Close has nothing left to release and must not report again.
	if err := plan.Close(); err != nil {
		t.Fatalf("repeated Close reported cleanup failure: %v", err)
	}
}

// The filesystem worker releases this session's own directories after it
// unmounts, even when the controller dies before its deferred Close. This
// drives the worker's exact authenticated-cleanup steps without FUSE: only the
// allocated mount/cache directories may disappear, and the configuration
// bases, the persistent asset cache, and other sessions' directories must not.
func TestFilesystemWorkerReleasesOnlyOwnedSessionResources(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg()
	cfg.Sandbox.Mount = filepath.Join(dir, "mounts")
	cfg.Sandbox.Cache = filepath.Join(dir, "cache")
	plan := &Plan{Cfg: cfg}
	if err := plan.allocateSession(); err != nil {
		t.Fatal(err)
	}
	// The controller dies here: it never calls Close.
	resources, err := plan.filesystemResources()
	if err != nil {
		t.Fatal(err)
	}
	foreignMount := filepath.Join(cfg.Sandbox.Mount, "session-other")
	foreignCache := filepath.Join(cfg.Sandbox.Cache, "session-other")
	assetCache := filepath.Join(cfg.Sandbox.Cache, "exec-assets", "asset")
	for _, name := range []string{foreignMount, foreignCache, filepath.Dir(assetCache), plan.Cache} {
		if err := os.MkdirAll(name, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The session's scratch content is disposable and goes with its own tree.
	if err := os.WriteFile(filepath.Join(plan.Cache, "scratch"), []byte("dispose"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(assetCache, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := filesystemSpec{
		Config: *cfg, Mount: plan.Mount, Cache: plan.Cache,
		SessionID: plan.sessionID, Resources: resources,
	}
	// The worker re-authenticates the pinned paths itself.
	authenticated, err := spec.ownedSessionResources()
	if err != nil {
		t.Fatal(err)
	}
	if err := removeSessionResources(authenticated); err != nil {
		t.Fatal(err)
	}
	for _, owned := range []string{plan.mountDir, plan.sessionDir} {
		if _, err := os.Stat(owned); !os.IsNotExist(err) {
			t.Errorf("worker left its own session directory %s behind: %v", owned, err)
		}
	}
	for _, kept := range []string{foreignMount, foreignCache, assetCache, cfg.Sandbox.Mount, cfg.Sandbox.Cache} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("worker removed unowned path %s: %v", kept, err)
		}
	}
	// The controller's own cleanup is idempotent with the worker's.
	if err := plan.Close(); err != nil {
		t.Fatalf("controller cleanup after the worker's: %v", err)
	}
}

// A live mount point is never emptied: if unmount failed and the directory
// still holds kernel-visible content, cleanup reports the failure and leaves
// the directory in place instead of deleting it or its scratch tree.
func TestSessionResourceRefusesToRemoveLiveMount(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg()
	cfg.Sandbox.Mount = filepath.Join(dir, "mounts")
	cfg.Sandbox.Cache = filepath.Join(dir, "cache")
	plan := &Plan{Cfg: cfg}
	if err := plan.allocateSession(); err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	resources, err := plan.filesystemResources()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plan.Mount, "entry"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = removeSessionResources(resources)
	if err == nil || !strings.Contains(err.Error(), plan.Mount) {
		t.Fatalf("nonempty mount point reported as released: %v", err)
	}
	if _, err := os.Stat(filepath.Join(plan.Mount, "entry")); err != nil {
		t.Fatalf("cleanup removed content under a live mount: %v", err)
	}
}

// Cleanup refuses paths it did not allocate: a session name under a different
// base, a non-session directory in the base, and a replacement directory that
// reused the name after the original was moved away.
func TestSessionResourceRefusesForeignAndReplacedPaths(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg()
	cfg.Sandbox.Mount = filepath.Join(dir, "mounts")
	cfg.Sandbox.Cache = filepath.Join(dir, "cache")
	plan := &Plan{Cfg: cfg}
	if err := plan.allocateSession(); err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	resources, err := plan.filesystemResources()
	if err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedSessionDir(cfg.Sandbox.Cache, filepath.Join(cfg.Sandbox.Cache, "exec-assets"), true); err == nil {
		t.Fatal("cleanup accepted a non-session cache directory")
	}
	otherBase := filepath.Join(dir, "elsewhere")
	if err := os.Mkdir(otherBase, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedSessionDir(otherBase, plan.Mount, false); err == nil {
		t.Fatal("cleanup accepted a session name outside its allocated base")
	}
	// Replace the mount directory with a same-named directory: the pinned
	// identity no longer matches, so removal must fail and spare it.
	moved := plan.Mount + ".moved"
	if err := os.Rename(plan.Mount, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(plan.Mount, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removeSessionResources(resources[:1]); err == nil {
		t.Fatal("cleanup removed a replacement directory that reused the session name")
	}
	if _, err := os.Stat(plan.Mount); err != nil {
		t.Fatalf("cleanup removed the replacement directory: %v", err)
	}
}

// The worker will not accept a spec that names a different session, a foreign
// base, or a resource whose identity no longer matches: the controller is the
// only party allowed to say what this session allocated.
func TestFilesystemSpecRejectsUnownedResources(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg()
	cfg.Sandbox.Mount = filepath.Join(dir, "mounts")
	cfg.Sandbox.Cache = filepath.Join(dir, "cache")
	plan := &Plan{Cfg: cfg}
	if err := plan.allocateSession(); err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	resources, err := plan.filesystemResources()
	if err != nil {
		t.Fatal(err)
	}
	good := filesystemSpec{
		Config: *cfg, Mount: plan.Mount, Cache: plan.Cache,
		SessionID: plan.sessionID, Resources: resources,
	}
	if _, err := good.ownedSessionResources(); err != nil {
		t.Fatalf("authentic spec rejected: %v", err)
	}
	for name, mutate := range map[string]func(*filesystemSpec){
		"foreign session id": func(s *filesystemSpec) { s.SessionID = "session-other" },
		"empty session id":   func(s *filesystemSpec) { s.SessionID = "" },
		"missing resources":  func(s *filesystemSpec) { s.Resources = nil },
		"cache as a mount":   func(s *filesystemSpec) { s.Resources[1].Tree = false },
		"foreign base":       func(s *filesystemSpec) { s.Resources[0].Base = dir },
		"foreign name":       func(s *filesystemSpec) { s.Resources[0].Name = "session-other" },
		"foreign identity":   func(s *filesystemSpec) { s.Resources[0].Ino++ },
	} {
		spec := good
		spec.Resources = append([]sessionResource(nil), resources...)
		mutate(&spec)
		if _, err := spec.ownedSessionResources(); err == nil {
			t.Errorf("%s was accepted by the filesystem worker", name)
		}
	}
}
