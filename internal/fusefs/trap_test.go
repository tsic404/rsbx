package fusefs

import (
	"os"
	"path/filepath"
	"testing"

	"rsbx/internal/proto"
)

// A program that exists only on the daemon, named from a directory the policy
// reserves for programs, has to resolve to the trampoline.
//
// The decision used to be "is there a local file that the policy declined?", so
// a name with no local file answered ENOENT and the session could not run
// anything that was only installed on the other side — which is the whole point
// of a remote shell.
func TestDaemonOnlyProgramInExecDirIsTrapped(t *testing.T) {
	dir := t.TempDir()
	tramp := filepath.Join(dir, "tramp")
	if err := os.WriteFile(tramp, []byte("\x7fELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	remote := &stubRemote{
		found: true,
		attr:  proto.Attr{Mode: proto.SIFREG | 0o755, Size: 100},
	}
	lay := &Layout{
		Remote:     remote,
		Local:      stubLocal{},
		ExecDirs:   []string{"/opt/tools"},
		Trampoline: tramp,
		// The policy allows nothing, so anything that does exist would be
		// redirected; the case under test is the name that does not exist.
		LocalExec: func(string) bool { return false },
	}
	n := &Node{lay: lay, path: "/opt/tools"}

	if trap, ok := n.trapFor("/opt/tools/remote-tool"); !ok || trap != tramp {
		t.Fatalf("daemon-only program resolved to %q, ok=%v; want the trampoline", trap, ok)
	}
}

// A directory on the daemon must stay a directory. Resolving it to the
// trampoline would make the file itself a trampoline and every child
// unreachable with "Not a directory".
func TestDaemonDirectoryInExecDirIsNotTrapped(t *testing.T) {
	dir := t.TempDir()
	tramp := filepath.Join(dir, "tramp")
	if err := os.WriteFile(tramp, []byte("\x7fELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	remote := &stubRemote{
		found: true,
		attr:  proto.Attr{Mode: proto.SIFDIR | 0o755},
	}
	lay := &Layout{
		Remote:     remote,
		Local:      stubLocal{},
		ExecDirs:   []string{"/opt/tools"},
		Trampoline: tramp,
		LocalExec:  func(string) bool { return false },
	}
	n := &Node{lay: lay, path: "/opt"}

	if trap, ok := n.trapFor("/opt/tools"); ok {
		t.Fatalf("a daemon directory resolved to %q; it must stay a directory", trap)
	}
}

// A name the daemon does not have either stays missing, and the answer must not
// depend on the remote being consulted more than once per lookup.
func TestMissingEverywhereStaysMissing(t *testing.T) {
	dir := t.TempDir()
	tramp := filepath.Join(dir, "tramp")
	if err := os.WriteFile(tramp, []byte("\x7fELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	lay := &Layout{
		Remote:     &stubRemote{found: false},
		Local:      stubLocal{},
		ExecDirs:   []string{"/opt/tools"},
		Trampoline: tramp,
		LocalExec:  func(string) bool { return false },
	}
	n := &Node{lay: lay, path: "/opt/tools"}

	if trap, ok := n.trapFor("/opt/tools/nothing"); ok {
		t.Fatalf("missing name resolved to %q", trap)
	}
}
