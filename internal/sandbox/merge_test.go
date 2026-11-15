package sandbox

import (
	"testing"

	"rsbx/internal/paths"
)

// Merging the writable and read-only trees must keep every root, and keep the
// read-only flag of each. Losing /usr/bin here means the allowlisted commands
// inside it are no longer local, and an agent cannot inspect its own tree.
func TestMergeKeepsAllRoots(t *testing.T) {
	w, err := paths.New([]string{"/e2e/localrw"}, false)
	if err != nil {
		t.Fatal(err)
	}
	r, err := paths.New([]string{"/usr/bin", "/usr/lib", "/usr/share", "/etc"}, true)
	if err != nil {
		t.Fatal(err)
	}
	m := mergePaths(w, r)
	roots := m.Roots()
	for _, want := range []string{"/usr/bin", "/usr/lib", "/usr/share", "/etc", "/e2e/localrw"} {
		found := false
		for _, got := range roots {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("root %s lost from %v", want, roots)
		}
	}
	if !m.Writable("/e2e/localrw") {
		t.Error("writable tree became read-only")
	}
	if m.Writable("/usr/bin") {
		t.Error("read-only tree became writable")
	}
}
