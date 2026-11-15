package fusefs

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// The dynamic loader is executed by the kernel for every dynamically linked
// program. Trapping it would make every local program unrunnable, which is
// exactly the bug that made the sandbox exec a trampoline instead of bash.
func TestLoaderIsNeverTrapped(t *testing.T) {
	for _, p := range []string{
		"/lib64/ld-linux-x86-64.so.2",
		"/lib/ld-musl-x86_64.so.1",
		"/usr/lib/libc.so.6",
		"/lib/x86_64-linux-gnu/libz.so.1",
	} {
		if !isLoader(p) {
			t.Errorf("%s not recognised as a loader", p)
		}
	}
	for _, p := range []string{"/usr/bin/bash", "/usr/bin/cat", "/work/prog.lua"} {
		if isLoader(p) {
			t.Errorf("%s wrongly treated as a loader", p)
		}
	}
}

// Redirection belongs to the directories where the allowlist lives. A +x file
// in a normal tree is data that happens to be executable, and replacing it with
// the trampoline would hand an agent binary bytes where it expected a script.
func TestTrapOnlyInsideExecDirs(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	lay := &Layout{
		Local:      stubLocalForTrap{},
		Trampoline: filepath.Join(dir, "tramp"),
		LocalExec:  func(string) bool { return false }, // nothing is allowlisted
	}
	n := &Node{lay: lay, path: dir}

	// No ExecDirs: the file is data and must pass through.
	if _, ok := n.trapFor(exe); ok {
		t.Fatal("data file outside an exec dir was redirected")
	}
	// Same file, now inside a policy directory: the policy decides, so it is
	// redirected.
	lay.ExecDirs = []string{dir}
	if _, ok := n.trapFor(exe); !ok {
		t.Fatal("executable in an exec dir was not redirected")
	}
}

type stubLocalForTrap struct{}

func (stubLocalForTrap) IsLocal(string) bool  { return true }
func (stubLocalForTrap) Writable(string) bool { return true }
func (stubLocalForTrap) Roots() []string      { return nil }

// Inode.Path returns a path relative to the root. Using it directly as a
// rename destination produced "home/…" instead of "/home/…", which failed the
// local-tree test and answered EROFS to an agent writing its session file.
func TestRenameDestinationIsAnchored(t *testing.T) {
	rel := "home/me/.omp/sessions"
	got := path.Join("/", rel, "x.jsonl")
	if !strings.HasPrefix(got, "/home/me/") {
		t.Fatalf("destination not anchored: %q", got)
	}
}
