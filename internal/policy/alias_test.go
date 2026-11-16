package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// An allowlisted alias must expose the file the kernel actually loads: a
// distribution that keeps /bin/sh as a symlink to dash would otherwise leave
// the entry unexecutable behind Landlock.
func TestExecPathsResolveAliases(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "dash-1.0")
	link := filepath.Join(dir, "sh")
	if err := os.WriteFile(real, []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	p, err := New([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	paths := p.ExecPaths()
	foundLink, foundReal := false, false
	for _, e := range paths {
		switch e {
		case link:
			foundLink = true
		case real:
			foundReal = true
		}
	}
	if !foundLink {
		t.Errorf("alias %s missing from %v", link, paths)
	}
	if !foundReal {
		t.Errorf("real target %s missing from %v", real, paths)
	}
	// The grant covers the executable only. Its directory must not appear.
	for _, e := range paths {
		if e == dir {
			t.Errorf("directory %s granted alongside the binary", dir)
		}
	}
}

// Directory rules enumerate only concrete executable files at construction.
func TestExecPathsSnapshotDirectoryRules(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "tool")
	if err := os.WriteFile(executable, []byte("program"), 0o755); err != nil {
		t.Fatal(err)
	}
	p, err := New([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsLocal(executable) || p.IsLocal(dir) {
		t.Fatalf("directory did not compile to its exact executable: %v", p.ExecPaths())
	}
	later := filepath.Join(dir, "created-later")
	if err := os.WriteFile(later, []byte("program"), 0o755); err != nil {
		t.Fatal(err)
	}
	if p.IsLocal(later) || p.IsAliasTarget(later) {
		t.Fatal("a file created after construction inherited directory execute permission")
	}
	for _, filename := range p.ExecPaths() {
		if filename == dir || filename == later {
			t.Fatalf("directory grant or late file in snapshot: %v", p.ExecPaths())
		}
	}
}

// IsAliasTarget answers for the real file behind an allowlisted alias even
// though the alias is the configured name.
func TestIsAliasTarget(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "realbin")
	link := filepath.Join(dir, "alias")
	os.WriteFile(real, []byte("ELF"), 0o755)
	os.Symlink(real, link)
	p, _ := New([]string{link})
	if !p.IsAliasTarget(real) {
		t.Error("real target of an allowlisted alias is not recognised")
	}
	if p.IsAliasTarget(filepath.Join(dir, "other")) {
		t.Error("unrelated file recognised as an alias target")
	}
	// The alias itself stays the ordinary case.
	if !p.IsLocal(link) {
		t.Error("allowlisted alias reported not local")
	}
}
