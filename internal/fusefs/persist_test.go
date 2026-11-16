package fusefs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
)

// newLocalLayout builds a layout whose only tree is a scratch directory, so the
// handle operations below exercise the local path.
func newLocalLayout(t *testing.T, dir string) *Layout {
	t.Helper()
	return &Layout{
		Local: fixedLocal(dir),
	}
}

type fixedLocal string

func (f fixedLocal) IsLocal(p string) bool {
	d := string(f)
	return p == d || len(p) > len(d) && p[:len(d)+1] == d+"/"
}
func (fixedLocal) Writable(string) bool { return true }
func (f fixedLocal) Roots() []string    { return []string{string(f)} }

// An agent appends to its own log and transcript. WriteAt is invalid on a file
// opened with O_APPEND, so an O_APPEND handle must write through Write. Getting
// this wrong surfaced as EIO on every append and made sessions non-durable.
func TestAppendHandleDoesNotUseWriteAt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log.txt")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	h := &handle{fd: f, path: p, lay: newLocalLayout(t, dir), appendOnly: true}
	n := &Node{lay: h.lay, path: p}

	for _, line := range []string{"one\n", "two\n", "three\n"} {
		if _, errno := n.Write(nil, h, []byte(line), 0); errno != 0 {
			t.Fatalf("append %q failed: %v", line, errno)
		}
	}

	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "one\ntwo\nthree\n" {
		t.Fatalf("appends lost or reordered: %q", got)
	}
}

// SQLite, and every editor that writes then flushes, calls fsync. Without an
// implementation the kernel answers EOPNOTSUPP, which agents surface as
// "EIO: i/o error, write" and retry forever.
func TestFsyncSucceedsForLocalFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "db.sqlite")
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	h := &handle{fd: f, path: p, lay: newLocalLayout(t, dir)}
	n := &Node{lay: h.lay, path: p}

	if errno := n.Fsync(nil, h, 0); errno != 0 {
		t.Fatalf("node fsync failed: %v", errno)
	}
	if errno := h.Fsync(nil, 0); errno != 0 {
		t.Fatalf("handle fsync failed: %v", errno)
	}

	// go-fuse forwards FSYNC to whichever handler implements the interface, so
	// both must provide it: a node that only had the handle method would leave
	// the kernel answering EOPNOTSUPP.
	var _ fs.NodeFsyncer = n
	var _ fs.FileFsyncer = h
}
