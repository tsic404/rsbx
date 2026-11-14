package policy

import "testing"

func TestIsLocal(t *testing.T) {
	p, err := New([]string{"/usr/bin/bash", "/opt/tools"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/usr/bin/bash", true},
		{"/usr/bin/bashful", false}, // prefix must end at a path separator
		{"/opt/tools/git", true},
		{"/opt/tools-extra/git", false},
		{"/usr/bin/ls", false},
		{"relative/path", false},
	}
	for _, c := range cases {
		if got := p.IsLocal(c.path); got != c.want {
			t.Errorf("IsLocal(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestGlobExpandsToExistingFiles(t *testing.T) {
	p, err := New([]string{"/usr/bin/bash*"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Local) == 0 {
		t.Skip("no /usr/bin/bash* on this host")
	}
	for _, e := range p.Local {
		if !IsAbs(e) {
			t.Errorf("entry is not absolute: %q", e)
		}
	}
}

func IsAbs(p string) bool { return len(p) > 0 && p[0] == '/' }
