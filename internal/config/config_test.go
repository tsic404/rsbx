package config

import (
	"strings"
	"testing"
)

const sample = `
# comment line
[daemon]
transport = "unix"
socket    = "/tmp/rsbx.sock"

[local]
allow = ["/usr/bin", "/bin", "/opt/my tools/bin"]
paths = ["/work", "/home/u/repos"]
read_only_paths = ["/usr"]
entry = "/usr/bin/bash"

[remote]
root = "/srv/work"

[sandbox]
mount = "/home/u/.rsbx/sandbox"
`

func TestParse(t *testing.T) {
	cfg, err := Parse(sample)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Daemon.Transport != "unix" || cfg.Daemon.Socket != "/tmp/rsbx.sock" {
		t.Fatalf("daemon: %+v", cfg.Daemon)
	}
	if cfg.Local.Entry != "/usr/bin/bash" {
		t.Errorf("entry = %q", cfg.Local.Entry)
	}
	wantAllow := []string{"/usr/bin", "/bin", "/opt/my tools/bin"}
	if strings.Join(cfg.Local.Allow, "|") != strings.Join(wantAllow, "|") {
		t.Errorf("allow = %v, want %v", cfg.Local.Allow, wantAllow)
	}
	if cfg.Remote.Root != "/srv/work" {
		t.Errorf("root = %q", cfg.Remote.Root)
	}
	if len(cfg.Local.Paths) != 2 || len(cfg.Local.ReadOnlyPaths) != 1 {
		t.Errorf("paths = %v read-only = %v", cfg.Local.Paths, cfg.Local.ReadOnlyPaths)
	}
}

func TestParseRejectsUnknownKey(t *testing.T) {
	if _, err := Parse("[local]\nnope = \"x\"\n"); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestParseRejectsUnterminatedTable(t *testing.T) {
	if _, err := Parse("[local\nallow = []\n"); err == nil {
		t.Fatal("unterminated table accepted")
	}
}

func TestMissingFileYieldsDefaults(t *testing.T) {
	cfg, err := Load("/nonexistent/rsbx/config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Daemon.Transport == "" {
		t.Fatal("defaults not applied")
	}
}
