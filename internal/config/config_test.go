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

// The shipped example uses multi-line arrays, because a long allowlist is
// unreadable on one line. The parser has to accept that form.
func TestParseMultiLineArray(t *testing.T) {
	src := `
[local]
allow = [
  "/usr/bin/bash",   # a comment after an element
  "/usr/bin/env",
]
paths = [
  "/work",
]
`
	cfg, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/bin/bash", "/usr/bin/env"}
	if strings.Join(cfg.Local.Allow, ",") != strings.Join(want, ",") {
		t.Errorf("allow = %v, want %v", cfg.Local.Allow, want)
	}
	if len(cfg.Local.Paths) != 1 || cfg.Local.Paths[0] != "/work" {
		t.Errorf("paths = %v", cfg.Local.Paths)
	}
}

func TestParseRejectsUnterminatedArray(t *testing.T) {
	if _, err := Parse("[local]\nallow = [\n  \"/a\",\n"); err == nil {
		t.Fatal("unterminated array accepted")
	}
}

func TestBalancedIgnoresBracketsInStrings(t *testing.T) {
	if !balanced(`["[a]"]`) {
		t.Error("brackets inside a string counted")
	}
	if balanced(`["a"`) {
		t.Error("unclosed array seen as balanced")
	}
}

func TestParseShareNetwork(t *testing.T) {
	cfg, err := Parse("[sandbox]\nshare_network = true\n")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Sandbox.ShareNetwork {
		t.Fatal("share_network not applied")
	}
	if _, err := Parse("[sandbox]\nshare_network = yes\n"); err == nil {
		t.Fatal("non-boolean accepted")
	}
}

func TestParseUnshareUser(t *testing.T) {
	cfg, err := Parse("[sandbox]\nunshare_user = false\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sandbox.UnshareUser {
		t.Fatal("unshare_user = false not applied")
	}
	d := Default()
	if !d.Sandbox.UnshareUser {
		t.Fatal("unshare_user must default to true")
	}
}
