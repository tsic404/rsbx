package fusefs

import (
	"os"
	"path/filepath"
	"testing"

	"rsbx/internal/proto"
)

// stubRemote answers stat with a fixed attribute, so trap decisions can be
// tested without a live daemon connection.
type stubRemote struct {
	attr  proto.Attr
	found bool
}

func (s *stubRemote) Do(req *proto.FxReq) (*proto.FxResp, error) {
	if req.Op != proto.FxStat {
		return &proto.FxResp{Kind: proto.KOk}, nil
	}
	if !s.found {
		return &proto.FxResp{Kind: proto.KNone}, nil
	}
	return &proto.FxResp{Kind: proto.KStat, Attr: s.attr}, nil
}

func (s *stubRemote) ReadFile(string) ([]byte, proto.Attr, error) {
	return nil, proto.Attr{}, os.ErrNotExist
}

func (s *stubRemote) WriteFile(string, []byte) error { return nil }

type stubLocal struct{}

func (stubLocal) IsLocal(string) bool  { return false }
func (stubLocal) Writable(string) bool { return false }
func (stubLocal) Roots() []string      { return nil }

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

// A newly created file in an exec directory is not a program.
//
// Every new file is absent locally until it is written, so "the host does not
// have this name" is the ordinary state of a file the session just made. Treating
// that as a daemon program made stat report the trampoline's size and any read
// return its bytes: creating an empty file in an allowlisted directory handed
// back a 3 MB copy of rsbx-tramp.
func TestNewFileInExecDirIsNotTrapped(t *testing.T) {
	dir := t.TempDir()
	tramp := filepath.Join(dir, "tramp")
	if err := os.WriteFile(tramp, []byte("\x7fELF-trampoline"), 0o755); err != nil {
		t.Fatal(err)
	}
	remote := &stubRemote{
		found: true,
		// a regular file, as a just-created empty file would be
		attr: proto.Attr{Mode: proto.SIFREG | 0o644, Size: 0},
	}
	lay := &Layout{
		Remote:     remote,
		Local:      stubLocal{},
		ExecDirs:   []string{"/opt/tools"},
		Trampoline: tramp,
		LocalExec:  func(string) bool { return false },
	}
	n := &Node{lay: lay, path: "/opt/tools"}

	if trap, ok := n.trapFor("/opt/tools/new.txt"); ok {
		t.Fatalf("a data file resolved to %q; it must stay data", trap)
	}
}

// A daemon file that is not executable is data, whatever its name.
func TestNonExecutableDaemonFileIsNotTrapped(t *testing.T) {
	dir := t.TempDir()
	tramp := filepath.Join(dir, "tramp")
	if err := os.WriteFile(tramp, []byte("\x7fELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	remote := &stubRemote{
		found: true,
		attr:  proto.Attr{Mode: proto.SIFREG | 0o600, Size: 10},
	}
	lay := &Layout{
		Remote:     remote,
		Local:      stubLocal{},
		ExecDirs:   []string{"/opt/tools"},
		Trampoline: tramp,
		LocalExec:  func(string) bool { return false },
	}
	n := &Node{lay: lay, path: "/opt/tools"}

	if trap, ok := n.trapFor("/opt/tools/notes.txt"); ok {
		t.Fatalf("a non-executable file resolved to %q", trap)
	}
}

// A transport failure is not a verdict about the name. Treating a dropped
// connection as "the daemon has no such program" turned a redirected name into
// ENOENT under load, so the same exec failed on one call and worked on the next.
func TestUnansweredDaemonIsNotAbsence(t *testing.T) {
	dir := t.TempDir()
	tramp := filepath.Join(dir, "tramp")
	if err := os.WriteFile(tramp, []byte("\x7fELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	lay := &Layout{
		Remote:     &failingRemote{},
		Local:      stubLocal{},
		ExecDirs:   []string{"/opt/tools"},
		Trampoline: tramp,
		LocalExec:  func(string) bool { return false },
	}
	n := &Node{lay: lay, path: "/opt/tools"}
	if isProc, answered := n.remoteIsProgram("/opt/tools/tool"); answered {
		t.Fatalf("a transport error was reported as answered (isProgram=%v)", isProc)
	}
	// And the lookup must not claim the name does not exist.
	if _, ok := n.trapFor("/opt/tools/tool"); ok {
		t.Fatal("redirected a name whose remote state is unknown")
	}
}

// failingRemote fails every request, the way a dropped connection does.
type failingRemote struct{}

func (failingRemote) Do(*proto.FxReq) (*proto.FxResp, error) {
	return nil, os.ErrClosed
}

func (failingRemote) ReadFile(string) ([]byte, proto.Attr, error) {
	return nil, proto.Attr{}, os.ErrClosed
}

func (failingRemote) WriteFile(string, []byte) error { return os.ErrClosed }
