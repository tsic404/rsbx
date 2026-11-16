package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsLocalUsesExactExecutableNames(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "tool")
	if err := os.WriteFile(tool, []byte("program"), 0o755); err != nil {
		t.Fatal(err)
	}
	p, err := New([]string{tool})
	if err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{tool + "ful", filepath.Join(tool, "child"), dir, "relative/path"} {
		if p.IsLocal(filename) {
			t.Errorf("non-exact path %q may execute locally", filename)
		}
	}
	if !p.IsLocal(tool) {
		t.Fatal("configured executable is not local")
	}
}

func TestGlobExpandsExistingExecutableFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"tool-one", "tool-two"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("program"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p, err := New([]string{filepath.Join(dir, "tool-*")})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Local) != 2 {
		t.Fatalf("glob snapshot = %v", p.Local)
	}
	for _, filename := range p.ExecPaths() {
		if !filepath.IsAbs(filename) {
			t.Errorf("entry is not absolute: %q", filename)
		}
	}
}

func TestMissingDependencyFailsPolicyConstruction(t *testing.T) {
	file := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(file, []byte("#!/nonexistent-rsbx-interpreter\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New([]string{file}); err == nil {
		t.Fatal("missing shebang interpreter was silently accepted")
	}
}
