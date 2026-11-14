package sandbox

import "testing"

// A bind whose destination shares a parent with an exec-policy directory would
// make bwrap create that parent, hiding the FUSE entries below it. This is the
// bug that emptied /usr/bin.
func TestBindsThroughPolicyDirRejected(t *testing.T) {
	roots := []string{"/usr/bin"}
	cases := map[string]bool{
		"/usr/lib":     true,  // shares /usr
		"/usr/share":   true,  // shares /usr
		"/usr/libexec": true,  // shares /usr
		"/etc":         false, // unrelated top-level tree
		"/work":        false,
		"/usr/bin":     true, // the policy dir itself
		"/usr/bin/sub": true, // inside it
	}
	for p, want := range cases {
		if got := bindsThrough(p, roots); got != want {
			t.Errorf("bindsThrough(%s) = %v, want %v", p, got, want)
		}
	}
}
