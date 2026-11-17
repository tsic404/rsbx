package workspace_test

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"rsbx/internal/daemon"
	"rsbx/internal/paths"
	"rsbx/internal/rpc"
	"rsbx/internal/workspace"
)

// daemonFS serves the real filesystem protocol on a socket, so these tests
// observe what the daemon actually does to the tree rather than a stub.
func daemonFS(t *testing.T) *rpc.FS {
	t.Helper()
	dir, err := os.MkdirTemp("", "rws")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &daemon.Server{Logf: func(string, ...any) {}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.ServeConn(c)
		}
	}()
	fs := rpc.NewFS(rpc.Target{Socket: sock})
	t.Cleanup(func() { fs.Close() })
	return fs
}

func seedTree(t *testing.T) string {
	t.Helper()
	seed := t.TempDir()
	write := func(rel, content string, mode os.FileMode) {
		t.Helper()
		p := filepath.Join(seed, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("AGENTS.md", "task instructions\n", 0o644)
	write("src/main.go", "package task\n", 0o644)
	write("run.sh", "#!/bin/sh\necho seeded\n", 0o755)
	if err := os.Mkdir(filepath.Join(seed, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("AGENTS.md", filepath.Join(seed, "current")); err != nil {
		t.Fatal(err)
	}
	return seed
}

func TestEnsureWritesSeedIntoTheDaemonTree(t *testing.T) {
	fs := daemonFS(t)
	remote := t.TempDir()
	seed := seedTree(t)
	ws := filepath.Join(remote, "tasks", "t1")

	if err := workspace.Ensure(fs, workspace.Spec{Path: ws, Seed: seed}); err != nil {
		t.Fatalf("initialize workspace: %v", err)
	}
	for rel, want := range map[string]string{
		"AGENTS.md":   "task instructions\n",
		"src/main.go": "package task\n",
		"run.sh":      "#!/bin/sh\necho seeded\n",
	} {
		got, err := os.ReadFile(filepath.Join(ws, rel))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
	fi, err := os.Stat(filepath.Join(ws, "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("seeded executable lost its mode: %v", fi.Mode())
	}
	if fi, err := os.Stat(filepath.Join(ws, "empty")); err != nil || !fi.IsDir() {
		t.Errorf("empty seed directory not created: %v, %v", fi, err)
	}
	target, err := os.Readlink(filepath.Join(ws, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "AGENTS.md" {
		t.Errorf("seed symlink = %q, want AGENTS.md", target)
	}
	// The initialization writes below the workspace and nowhere else.
	ents, err := os.ReadDir(remote)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "tasks" {
		t.Errorf("initialization wrote outside the workspace: %v", ents)
	}
}

func TestEnsureCopiesFilesLargerThanOneChunk(t *testing.T) {
	fs := daemonFS(t)
	seed := t.TempDir()
	big := make([]byte, 2*1024*1024+123)
	for i := range big {
		big[i] = byte(i % 251)
	}
	if err := os.WriteFile(filepath.Join(seed, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(t.TempDir(), "ws")
	if err := workspace.Ensure(fs, workspace.Spec{Path: ws, Seed: seed}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(ws, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(big) || string(got) != string(big) {
		t.Fatalf("large seed file differs: %d bytes stored, %d sent", len(got), len(big))
	}
}

func TestEnsureKeepsAgentProductsAndRestoresSeed(t *testing.T) {
	fs := daemonFS(t)
	seed := seedTree(t)
	ws := filepath.Join(t.TempDir(), "ws")
	spec := workspace.Spec{Path: ws, Seed: seed}
	if err := workspace.Ensure(fs, spec); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "product.txt"), []byte("agent work\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "AGENTS.md"), []byte("edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := workspace.Ensure(fs, spec); err != nil {
		t.Fatalf("re-initialize: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(ws, "product.txt"))
	if err != nil || string(got) != "agent work\n" {
		t.Errorf("agent product lost on re-initialization: %q, %v", got, err)
	}
	got, err = os.ReadFile(filepath.Join(ws, "AGENTS.md"))
	if err != nil || string(got) != "task instructions\n" {
		t.Errorf("seed content not restored: %q, %v", got, err)
	}
}

// A read-only seeded file must not make the next initialization fail: the
// seed's own mode is applied after the write, so a rerun has to reopen it.
func TestEnsureRewritesReadOnlySeededFile(t *testing.T) {
	fs := daemonFS(t)
	seed := t.TempDir()
	if err := os.WriteFile(filepath.Join(seed, "readonly.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(seed, "readonly.txt"), 0o444); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(t.TempDir(), "ws")
	for i := 0; i < 2; i++ {
		if err := workspace.Ensure(fs, workspace.Spec{Path: ws, Seed: seed}); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	got, err := os.ReadFile(filepath.Join(ws, "readonly.txt"))
	if err != nil || string(got) != "one\n" {
		t.Fatalf("read-only seed file = %q, %v", got, err)
	}
	fi, err := os.Stat(filepath.Join(ws, "readonly.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o444 {
		t.Errorf("mode = %v, want 0444", fi.Mode().Perm())
	}
}

// A directory seeded read-only must accept children added by a later seed:
// the seed's mode is a final state, not a barrier to initialization.
func TestEnsureAddsChildrenToReadOnlySeededDirectories(t *testing.T) {
	fs := daemonFS(t)
	seed := t.TempDir()
	locked := filepath.Join(seed, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "first.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	ws := filepath.Join(t.TempDir(), "ws")
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(ws, "locked"), 0o755) })
	spec := workspace.Spec{Path: ws, Seed: seed}
	if err := workspace.Ensure(fs, spec); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := os.Chmod(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "second.txt"), []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := workspace.Ensure(fs, spec); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(ws, "locked", "second.txt")); err != nil || string(got) != "two\n" {
		t.Fatalf("new child = %q, %v", got, err)
	}
	fi, err := os.Stat(filepath.Join(ws, "locked"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o555 {
		t.Errorf("directory mode = %v, want 0555", fi.Mode().Perm())
	}
}

// A seed path may itself be a symlink to the directory; that symlink names
// the seed, while links inside the seed are still copied as links.
func TestEnsureFollowsSeedRootSymlink(t *testing.T) {
	fs := daemonFS(t)
	real := seedTree(t)
	alias := filepath.Join(t.TempDir(), "task")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(t.TempDir(), "ws")
	if err := workspace.Ensure(fs, workspace.Spec{Path: ws, Seed: alias}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(ws)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatalf("workspace is a %v, not a directory", fi.Mode())
	}
	if got, err := os.ReadFile(filepath.Join(ws, "AGENTS.md")); err != nil || string(got) != "task instructions\n" {
		t.Fatalf("seed content = %q, %v", got, err)
	}
	target, err := os.Readlink(filepath.Join(ws, "current"))
	if err != nil || target != "AGENTS.md" {
		t.Fatalf("seed link = %q, %v", target, err)
	}
}

func TestEnsureRefusesLocalPrivateMaterial(t *testing.T) {
	fs := daemonFS(t)
	private := t.TempDir()
	seed := filepath.Join(private, "task")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seed, "AGENTS.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	local, err := paths.New([]string{private}, false)
	if err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(t.TempDir(), "ws")
	err = workspace.Ensure(fs, workspace.Spec{Path: ws, Seed: seed, Local: local})
	if err == nil || !strings.Contains(err.Error(), "local") {
		t.Fatalf("private seed not refused: %v", err)
	}
	if _, err := os.Stat(ws); !os.IsNotExist(err) {
		t.Fatalf("refused seed wrote a workspace: %v", err)
	}
}

func TestEnsureRefusesLocalTreeInsideSeed(t *testing.T) {
	fs := daemonFS(t)
	seed := t.TempDir()
	nested := filepath.Join(seed, ".multica")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "state.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	local, err := paths.New([]string{nested}, false)
	if err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(t.TempDir(), "ws")
	err = workspace.Ensure(fs, workspace.Spec{Path: ws, Seed: seed, Local: local})
	if err == nil || !strings.Contains(err.Error(), "local") {
		t.Fatalf("seed containing a local tree not refused: %v", err)
	}
}

func TestEnsureResolvesLocalTreeAliases(t *testing.T) {
	fs := daemonFS(t)
	private := t.TempDir()
	aliasDir := t.TempDir()
	alias := filepath.Join(aliasDir, "agent")
	if err := os.Symlink(private, alias); err != nil {
		t.Fatal(err)
	}
	local, err := paths.New([]string{alias}, false)
	if err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(t.TempDir(), "ws")
	err = workspace.Ensure(fs, workspace.Spec{Path: ws, Seed: private, Local: local})
	if err == nil || !strings.Contains(err.Error(), "local") {
		t.Fatalf("aliased private seed not refused: %v", err)
	}
}

func TestEnsureRefusesWorkspaceInLocalTree(t *testing.T) {
	fs := daemonFS(t)
	private := t.TempDir()
	local, err := paths.New([]string{private}, false)
	if err != nil {
		t.Fatal(err)
	}
	err = workspace.Ensure(fs, workspace.Spec{Path: filepath.Join(private, "ws"), Local: local})
	if err == nil || !strings.Contains(err.Error(), "local") {
		t.Fatalf("local workspace not refused: %v", err)
	}
}

func TestEnsureRefusesMissingStartDirectory(t *testing.T) {
	fs := daemonFS(t)
	ws := filepath.Join(t.TempDir(), "absent")
	err := workspace.Ensure(fs, workspace.Spec{Path: ws})
	if err == nil || !strings.Contains(err.Error(), "no such directory") {
		t.Fatalf("missing start directory not refused: %v", err)
	}
	if _, statErr := os.Stat(ws); !os.IsNotExist(statErr) {
		t.Fatalf("a refused start directory was created: %v", statErr)
	}
}

func TestEnsureRefusesNonDirectoryStart(t *testing.T) {
	fs := daemonFS(t)
	ws := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(ws, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := workspace.Ensure(fs, workspace.Spec{Path: ws})
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("non-directory start not refused: %v", err)
	}
}

func TestEnsureRefusesSpecialFiles(t *testing.T) {
	fs := daemonFS(t)
	seed := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(seed, "pipe"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	err := workspace.Ensure(fs, workspace.Spec{Path: filepath.Join(t.TempDir(), "ws"), Seed: seed})
	if err == nil || !strings.Contains(err.Error(), "only files, directories and symlinks") {
		t.Fatalf("special seed file not refused: %v", err)
	}
}

func TestEnsureDoesNotFollowSeedSymlinks(t *testing.T) {
	fs := daemonFS(t)
	seed := t.TempDir()
	if err := os.Symlink("/etc/passwd", filepath.Join(seed, "secret")); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(t.TempDir(), "ws")
	if err := workspace.Ensure(fs, workspace.Spec{Path: ws, Seed: seed}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(ws, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("seed symlink was materialized as a %v", fi.Mode())
	}
	target, err := os.Readlink(filepath.Join(ws, "secret"))
	if err != nil || target != "/etc/passwd" {
		t.Fatalf("link text = %q, %v", target, err)
	}
}

func TestEnsureRefusesRelativePaths(t *testing.T) {
	fs := daemonFS(t)
	for _, spec := range []workspace.Spec{
		{Path: "relative/ws"},
		{Path: filepath.Join(t.TempDir(), "ws"), Seed: "relative/seed"},
		{Path: ""},
	} {
		if err := workspace.Ensure(fs, spec); err == nil {
			t.Errorf("spec %+v accepted", spec)
		}
	}
}

// The daemon's tree and this machine's tree are different filesystems. Their
// paths must never be compared: the same spelling, or one containing the
// other, says nothing about whether the content is the same.
func TestValidateKeepsTheTwoMachinesApart(t *testing.T) {
	base := t.TempDir()
	seed := filepath.Join(base, "tasks", "17")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		seed,
		filepath.Join(seed, "ws"),
		base,
	} {
		if err := workspace.Validate(workspace.Spec{Path: path, Seed: seed}); err != nil {
			t.Errorf("daemon path %s rejected because of the client seed: %v", path, err)
		}
	}
}

// A daemon path is not resolved through this machine's filesystem: only the
// written path decides which source the sandbox view serves.
func TestValidateDoesNotResolveTheDaemonPath(t *testing.T) {
	private := t.TempDir()
	alias := filepath.Join(t.TempDir(), "agent")
	if err := os.Symlink(private, alias); err != nil {
		t.Fatal(err)
	}
	local, err := paths.New([]string{private}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := workspace.Validate(workspace.Spec{Path: filepath.Join(alias, "ws"), Local: local}); err != nil {
		t.Fatalf("client symlink decided the daemon path: %v", err)
	}
}

// Initialization terminates even when the names nest on one machine: the
// seed listing is fixed before the daemon's tree changes.
func TestEnsureAcceptsWorkspaceNestedUnderTheSeedName(t *testing.T) {
	fs := daemonFS(t)
	seed := t.TempDir()
	if err := os.WriteFile(filepath.Join(seed, "AGENTS.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(seed, "ws")
	if err := workspace.Ensure(fs, workspace.Spec{Path: ws, Seed: seed}); err != nil {
		t.Fatalf("nested workspace name: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(ws, "AGENTS.md")); err != nil || string(got) != "seed\n" {
		t.Fatalf("seed content = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(ws, "ws")); !os.IsNotExist(err) {
		t.Fatalf("initialization followed its own output: %v", err)
	}
}
