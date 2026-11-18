package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"rsbx/internal/config"
	"rsbx/internal/paths"
)

// Both control bases — the mount base and the cache base — are refused when
// they sit inside a declared local tree. Either one exposes the controller's
// session directories to local content, so the check is symmetric.
//
// The alias case is the one a name comparison would miss: the local tree and
// the control base are spelled differently but resolve to the same place.
func TestSessionControlRejectsEachBaseInsideLocalTree(t *testing.T) {
	for _, base := range []string{"mount", "cache"} {
		for _, spelling := range []string{"direct", "alias"} {
			t.Run(base+"/"+spelling, func(t *testing.T) {
				dir := t.TempDir()
				tree := filepath.Join(dir, "agent")
				if err := os.Mkdir(tree, 0o700); err != nil {
					t.Fatal(err)
				}
				// The declared local root is either the tree itself or a
				// symlink that resolves to it.
				declared := tree
				if spelling == "alias" {
					declared = filepath.Join(dir, "agent-config")
					if err := os.Symlink(tree, declared); err != nil {
						t.Fatal(err)
					}
				}
				local, err := paths.New([]string{declared}, false)
				if err != nil {
					t.Fatal(err)
				}
				cfg := config.Default()
				cfg.Sandbox.Mount = filepath.Join(dir, "mounts")
				cfg.Sandbox.Cache = filepath.Join(dir, "cache")
				switch base {
				case "mount":
					cfg.Sandbox.Mount = filepath.Join(tree, "session-mount")
				case "cache":
					cfg.Sandbox.Cache = filepath.Join(tree, "session-cache")
				}
				plan := &Plan{Cfg: cfg, Local: local}
				if err := plan.allocateSession(); err == nil {
					defer plan.Close()
					t.Fatalf("%s base inside the local tree was accepted", base)
				}
				// A rejected configuration must not have allocated anything on
				// the way to the refusal.
				if _, err := os.Stat(cfg.Sandbox.Mount); err == nil && base == "mount" {
					t.Errorf("rejected mount base was created on disk")
				}
				if _, err := os.Stat(cfg.Sandbox.Cache); err == nil && base == "cache" {
					t.Errorf("rejected cache base was created on disk")
				}
			})
		}
	}
}
