package paths

import "testing"

func TestMatchNestedTakesPrecedence(t *testing.T) {
	ro, err := New([]string{"/usr"}, true)
	if err != nil {
		t.Fatal(err)
	}
	rw, err := New([]string{"/work"}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p        string
		local    bool
		writable bool
	}{
		{"/usr/bin/gcc", true, false},
		{"/usr", true, false},
		{"/work", true, true},
		{"/work/src/a.c", true, true},
		{"/usalike/x", false, false},  // a prefix must end at a separator
		{"/etc/passwd", false, false}, // unlisted: answered by the daemon
	} {
		got := ro.IsLocal(c.p) || rw.IsLocal(c.p)
		writable := ro.Writable(c.p) || rw.Writable(c.p)
		if got != c.local || writable != c.writable {
			t.Errorf("%s: local=%v writable=%v, want %v/%v", c.p, got, writable, c.local, c.writable)
		}
	}
}

func TestRelativeRejected(t *testing.T) {
	if _, err := New([]string{"relative/path"}, false); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestMissingEntryStillMatches(t *testing.T) {
	s, err := New([]string{"/does/not/exist"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsLocal("/does/not/exist/later") {
		t.Fatal("absent entry stopped matching")
	}
}

// WithReadOnly keeps the longest-prefix order, so a writable subtree inside a
// read-only tree stays writable.
func TestWithReadOnlyKeepsPrecedence(t *testing.T) {
	s, err := New([]string{"/usr", "/usr/local/work"}, false)
	if err != nil {
		t.Fatal(err)
	}
	s = s.WithReadOnly(map[string]bool{"/usr": true})
	if !s.Writable("/usr/local/work/x") {
		t.Error("writable subtree became read-only")
	}
	if s.Writable("/usr/bin/gcc") {
		t.Error("read-only tree became writable")
	}
}
