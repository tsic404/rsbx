package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rsbx/internal/config"
)

// A local program whose runtime dependency cannot be resolved fails the
// session before any connection exists. Prepare is the only place the session
// can be refused as a whole: once it returns a plan, the caller has a mount
// and a daemon connection, and a program that cannot be snapshotted would have
// to be run somewhere else.
func TestPrepareRejectsUnresolvableRuntimeDependency(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	prog := filepath.Join(dir, "bad-interpreter")
	if err := os.WriteFile(prog, []byte("#!/nonexistent-rsbx-interpreter\necho RAN\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Local.Allow = []string{prog}
	cfg.Local.Entry = ""
	cfg.Sandbox.Mount = filepath.Join(dir, "mnt")
	cfg.Sandbox.Cache = filepath.Join(dir, "cache")

	_, err := Prepare(cfg, dir)
	if err == nil {
		t.Fatal("a program with an unresolvable dependency produced a session plan")
	}
	// The failure has to name the dependency; a generic refusal would be
	// indistinguishable from a configuration error and could not be reported
	// as its own failure class.
	if !strings.Contains(err.Error(), "interpreter") && !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("the refusal does not name the unresolved dependency: %v", err)
	}
}
