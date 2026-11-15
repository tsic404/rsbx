package fsremote

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rsbx/internal/proto"
)

func newServer(t *testing.T) (*Server, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("remote-body"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Server{Root: root}, root
}

func TestResolveStaysInsideRoot(t *testing.T) {
	s, root := newServer(t)
	// ".." segments are normalised away, so a traversal attempt resolves to a
	// path inside the root rather than escaping it.
	for _, p := range []string{"/../etc/passwd", "/sub/../../etc/passwd", "/../../../../etc/shadow"} {
		got, ok := s.Resolve(p)
		if !ok {
			t.Fatalf("%q rejected", p)
		}
		if !strings.HasPrefix(got, root+"/") {
			t.Fatalf("%q escaped the root: %s", p, got)
		}
	}
	if _, ok := s.Resolve("/a.txt"); !ok {
		t.Fatal("legitimate path rejected")
	}
}

func TestReadAndWrite(t *testing.T) {
	s, root := newServer(t)
	resp := s.Handle(&proto.FxReq{Op: proto.FxRead, Path: "/a.txt"})
	if resp.Kind != proto.KFile || string(resp.Data) != "remote-body" {
		t.Fatalf("read returned kind=%d data=%q", resp.Kind, resp.Data)
	}
	// A write must land under the root, not beside it.
	resp = s.Handle(&proto.FxReq{Op: proto.FxWrite, Path: "/new/file.txt", Data: []byte("x")})
	if resp.Kind == proto.KErr {
		t.Fatalf("write failed: %s", resp.Err)
	}
	if _, err := os.Stat(filepath.Join(root, "new", "file.txt")); err != nil {
		t.Fatalf("write did not land in the root: %v", err)
	}
}

func TestMissingPathIsNone(t *testing.T) {
	s, _ := newServer(t)
	if resp := s.Handle(&proto.FxReq{Op: proto.FxStat, Path: "/nope"}); resp.Kind != proto.KNone {
		t.Fatalf("missing path returned kind=%d", resp.Kind)
	}
}

func TestListReportsType(t *testing.T) {
	s, _ := newServer(t)
	resp := s.Handle(&proto.FxReq{Op: proto.FxList, Path: "/"})
	if resp.Kind != proto.KDir {
		t.Fatalf("list kind=%d", resp.Kind)
	}
	seen := map[string]uint32{}
	for _, e := range resp.Ents {
		seen[e.Name] = e.Mode
	}
	if seen["sub"]&proto.SIFDIR == 0 {
		t.Errorf("sub not reported as a directory: %o", seen["sub"])
	}
	if seen["a.txt"]&proto.SIFREG == 0 {
		t.Errorf("a.txt not reported as a file: %o", seen["a.txt"])
	}
}

func TestWriteAtPlacesBytes(t *testing.T) {
	s, root := newServer(t)
	// Create first: a positioned write writes to a file, it does not bring one
	// into existence. Reaching for O_CREATE here made every write a create,
	// which put back a file whose name its owner had already removed.
	if resp := s.Handle(&proto.FxReq{Op: proto.FxWrite, Path: "/at.txt", Data: nil}); resp.Kind == proto.KErr {
		t.Fatalf("create failed: %s", resp.Err)
	}
	if resp := s.Handle(&proto.FxReq{Op: proto.FxWriteAt, Path: "/at.txt", Arg: "0", Data: []byte("hello")}); resp.Kind == proto.KErr {
		t.Fatalf("write failed: %s", resp.Err)
	}
	if resp := s.Handle(&proto.FxReq{Op: proto.FxWriteAt, Path: "/at.txt", Arg: "5", Data: []byte("-world")}); resp.Kind == proto.KErr {
		t.Fatalf("write failed: %s", resp.Err)
	}
	got, err := os.ReadFile(filepath.Join(root, "at.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello-world" {
		t.Fatalf("positioned write misplaced bytes: %q", got)
	}
}

// A positioned write to a name that does not exist is an error, not an implicit
// create. Otherwise a program that removes its scratch file and keeps writing
// leaves the file behind with a tail of its writes in it.
func TestWriteAtDoesNotCreate(t *testing.T) {
	s, root := newServer(t)
	resp := s.Handle(&proto.FxReq{Op: proto.FxWriteAt, Path: "/gone.txt", Arg: "0", Data: []byte("x")})
	if resp.Kind != proto.KErr {
		t.Fatalf("write to a missing file returned kind %d, want an error", resp.Kind)
	}
	if _, err := os.Stat(filepath.Join(root, "gone.txt")); !os.IsNotExist(err) {
		t.Fatalf("the write created the file: %v", err)
	}
}
