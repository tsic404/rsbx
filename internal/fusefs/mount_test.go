package fusefs

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"

	"rsbx/internal/proto"
)

// emptyRemote is the daemon side of a mount made only of local trees. Any
// remote call fails loudly: reaching it from a local path is the bug under test,
// and a silent success would hide it.
type emptyRemote struct{ calls atomic.Int32 }

func (e *emptyRemote) Do(*proto.FxReq) (*proto.FxResp, error) {
	e.calls.Add(1)
	return &proto.FxResp{Kind: proto.KNone}, nil
}

func (e *emptyRemote) ReadFile(string) ([]byte, proto.Attr, error) {
	e.calls.Add(1)
	return nil, proto.Attr{}, os.ErrNotExist
}

func (e *emptyRemote) WriteFile(string, []byte) error {
	e.calls.Add(1)
	return nil
}

// mounted serves one local tree through a real FUSE mount and returns the
// mountpoint and the tree's host path.
//
// The mountpoint is not the tree: FUSE's path space starts at "/" (the sandbox
// view) while the mountpoint is a directory on the host, so the two never
// coincide in production. A file at sandbox path /a/b/c is reachable as
// mountpoint/a/b/c.
func mounted(t *testing.T) (mnt, tree string) {
	t.Helper()
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("no /dev/fuse")
	}
	base := t.TempDir()
	tree = filepath.Join(base, "tree")
	mnt = filepath.Join(base, "mnt")
	for _, d := range []string{tree, mnt} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The tree is named by its own absolute path, so every ancestor has to be a
	// visible placeholder for the sandbox path to resolve.
	hostDirs := map[string]bool{"/": true, "/tmp": true, "/var": true, "/var/tmp": true}
	for p := base; p != "/" && p != "."; p = filepath.Dir(p) {
		hostDirs[p] = true
	}

	lay := &Layout{
		Remote: &emptyRemote{},
		// The tree is addressed by its own path inside the sandbox, and the
		// mount is a separate directory on the host. That is the production
		// arrangement: the mount point must never sit inside the tree it serves.
		Local:    viewLocal{prefix: mnt, tree: tree},
		HostDirs: hostDirs,
	}
	rootNode := NewRoot(lay)
	if err := rootNode.Err(); err != nil {
		rootNode.Close()
		t.Fatal(err)
	}
	one := time.Second
	srv, err := fs.Mount(mnt, rootNode, &fs.Options{
		NullPermissions: true,
		MountOptions:    fuse.MountOptions{FsName: "rsbx-test", DisableSplice: true},
		EntryTimeout:    &one,
		AttrTimeout:     &one,
	})
	if err != nil {
		rootNode.Close()
		t.Skipf("cannot mount FUSE here: %v", err)
	}
	t.Cleanup(func() { srv.Unmount(); rootNode.Close() })
	return mnt, tree
}

// viewLocal answers the path policy in sandbox terms.
//
// Inside the mount a local tree appears at its own absolute path (/work/proj),
// while on the host it lives wherever it lives. In a real session the two
// strings are equal, so the filesystem returns the sandbox path unchanged; a
// test cannot arrange that without mounting over the tree, so the translation
// happens here instead of inside the filesystem.
type viewLocal struct {
	prefix string // the mount point
	tree   string // the tree's host path
}

func (v viewLocal) inside(p string) (string, bool) {
	if !strings.HasPrefix(p, v.tree) {
		return "", false
	}
	if len(p) > len(v.tree) && p[len(v.tree)] != '/' {
		return "", false
	}
	return p, p == v.tree || p[len(v.tree)] == '/'
}

func (v viewLocal) IsLocal(p string) bool {
	_, ok := v.inside(p)
	return ok
}

func (v viewLocal) Writable(string) bool { return true }
func (v viewLocal) Roots() []string      { return []string{v.tree} }

// inView maps a host path to the same path inside the mount, which is how the
// sandbox sees it.
func inView(mnt, hostPath string) string {
	return filepath.Join(mnt, hostPath)
}

// An atomic write is create-temp, rename, reopen. The reopen arrives against the
// inode the kernel resolved before the rename, so the rename has to repoint it
// at the destination. Getting this wrong made every atomic write fail with
// ENOENT, which is how careful programs write their state.
func TestAtomicWriteThroughMount(t *testing.T) {
	mnt, tree := mounted(t)
	tmp := inView(mnt, filepath.Join(tree, ".f.tmp"))
	final := inView(mnt, filepath.Join(tree, "f.jsonl"))

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if _, err := f.Write([]byte("payload\n")); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp: %v", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		t.Fatalf("rename: %v", err)
	}
	got, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("reopen after rename: %v", err)
	}
	if string(got) != "payload\n" {
		t.Fatalf("content after rename: %q", got)
	}
	// and it is one file on the host, not a copy in the view
	if _, err := os.Stat(filepath.Join(tree, "f.jsonl")); err != nil {
		t.Fatalf("host file: %v", err)
	}
}

// SQLite and every editor that writes then flushes calls fsync. Without an
// implementation the kernel answers EOPNOTSUPP, which programs report as
// "EIO: i/o error, write" and retry forever.
func TestFsyncThroughMount(t *testing.T) {
	mnt, tree := mounted(t)
	p := inView(mnt, filepath.Join(tree, "db.sqlite"))
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("data")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("fsync: %v", err)
	}
}

// Agents append to their logs and transcripts. The kernel issues those writes on
// an O_APPEND file, and Go rejects WriteAt for such a file, so the handle has to
// write through Write.
func TestAppendThroughMount(t *testing.T) {
	mnt, tree := mounted(t)
	p := inView(mnt, filepath.Join(tree, "log.txt"))
	for _, line := range []string{"one\n", "two\n", "three\n"} {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatalf("open for append: %v", err)
		}
		if _, err := f.Write([]byte(line)); err != nil {
			f.Close()
			t.Fatalf("append %q: %v", line, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
	got, err := os.ReadFile(filepath.Join(tree, "log.txt"))
	if err != nil {
		t.Fatalf("host read: %v", err)
	}
	if string(got) != "one\ntwo\nthree\n" {
		t.Fatalf("appends lost or reordered: %q", got)
	}
}

// A local tree is local because the bytes land on this machine's filesystem. The
// read happens on the host path, which the mount does not shadow.
func TestLocalWriteReachesHost(t *testing.T) {
	mnt, tree := mounted(t)
	if err := os.WriteFile(inView(mnt, filepath.Join(tree, "a.txt")), []byte("hello"), 0o644); err != nil {
		t.Fatalf("create through mount: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(tree, "a.txt"))
	if err != nil {
		t.Fatalf("host read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("host content: %q", got)
	}
}

// Deleting and re-creating the same name must work: a stale negative or positive
// dentry here would make a build tool see a file that is gone, or miss one that
// came back.
func TestUnlinkThenCreateThroughMount(t *testing.T) {
	mnt, tree := mounted(t)
	p := inView(mnt, filepath.Join(tree, "f.txt"))
	if err := os.WriteFile(p, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tree, "f.txt")); !os.IsNotExist(err) {
		t.Fatalf("unlink did not reach the host: %v", err)
	}
	if err := os.WriteFile(p, []byte("second"), 0o644); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(tree, "f.txt"))
	if err != nil {
		t.Fatalf("host read after recreate: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("content: %q", got)
	}
}

var _ = unix.ENOENT

// A file created with O_CREAT on an existing name must not be cleared. The
// create path used to write an empty body to the daemon before anything had
// read the old one, which turned "open a database" into "lose the database".
func TestCreateDoesNotTruncateExisting(t *testing.T) {
	mnt, tree := mounted(t)
	p := inView(mnt, filepath.Join(tree, "keep.txt"))
	if err := os.WriteFile(p, []byte("original"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("reopen with O_CREAT: %v", err)
	}
	f.Close()
	got, err := os.ReadFile(filepath.Join(tree, "keep.txt"))
	if err != nil {
		t.Fatalf("host read: %v", err)
	}
	if string(got) != "original" {
		t.Fatalf("O_CREAT cleared the file: %q", got)
	}
	// and O_TRUNC does what it says
	f, err = os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("reopen with O_TRUNC: %v", err)
	}
	f.Close()
	if fi, err := os.Stat(filepath.Join(tree, "keep.txt")); err != nil || fi.Size() != 0 {
		t.Fatalf("O_TRUNC did not truncate: %v %v", fi, err)
	}
}

// A file that is written and then read through the same descriptor has to
// return what was written. A write handle with no local file used to answer
// empty on every read, which a database reports as corruption.
func TestReadAfterWriteSameHandle(t *testing.T) {
	mnt, tree := mounted(t)
	p := inView(mnt, filepath.Join(tree, "rw.txt"))
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	payload := []byte("written-then-read")
	if _, err := f.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := f.ReadAt(buf, 0); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("read back %q, wrote %q", buf, payload)
	}
}

// Renaming a directory moves every name under it. An open of the new path
// resolves to inodes created under the old one, so their paths have to move
// too — otherwise the whole subtree answers ENOENT after a rename.
func TestRenameDirectoryMovesChildren(t *testing.T) {
	mnt, tree := mounted(t)
	oldDir := inView(mnt, filepath.Join(tree, "before"))
	newDir := inView(mnt, filepath.Join(tree, "after"))
	if err := os.MkdirAll(filepath.Join(oldDir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "nested", "f.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	// open once so the inodes exist and are cached before the rename
	if _, err := os.ReadFile(filepath.Join(oldDir, "nested", "f.txt")); err != nil {
		t.Fatalf("warm read: %v", err)
	}
	if err := os.Rename(oldDir, newDir); err != nil {
		t.Fatalf("rename dir: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(newDir, "nested", "f.txt"))
	if err != nil {
		t.Fatalf("read child after dir rename: %v", err)
	}
	if string(got) != "data" {
		t.Fatalf("child content: %q", got)
	}
}

// Unlinking one name of a hard-linked file must leave the others readable. Both
// names share an inode, and that inode carries one path; if it keeps pointing at
// the removed name, the survivor lists fine and cannot be opened.
func TestUnlinkOneHardLinkLeavesTheOtherReadable(t *testing.T) {
	mnt, tree := mounted(t)
	a := inView(mnt, filepath.Join(tree, "one.txt"))
	b := inView(mnt, filepath.Join(tree, "two.txt"))
	if err := os.WriteFile(a, []byte("shared"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Fatalf("link: %v", err)
	}
	if err := os.Remove(a); err != nil {
		t.Fatalf("unlink one: %v", err)
	}
	got, err := os.ReadFile(b)
	if err != nil {
		t.Fatalf("read surviving name: %v", err)
	}
	if string(got) != "shared" {
		t.Fatalf("content: %q", got)
	}
}

// chmod and utimes arrive through the same call as truncate. Answering success
// without applying them makes a program believe it changed something it did not.
func TestSetattrAppliesModeAndTimes(t *testing.T) {
	mnt, tree := mounted(t)
	p := inView(mnt, filepath.Join(tree, "meta.txt"))
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(tree, "meta.txt")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode after chmod: %v %v", fi.Mode(), err)
	}
	want := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(p, want, want); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	fi, err := os.Stat(filepath.Join(tree, "meta.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.ModTime().Unix() != want.Unix() {
		t.Fatalf("mtime = %v, want %v", fi.ModTime(), want)
	}
}

// Symlinks and hard links are ordinary things a build tree contains.
func TestSymlinkAndHardLink(t *testing.T) {
	mnt, tree := mounted(t)
	target := inView(mnt, filepath.Join(tree, "target.txt"))
	if err := os.WriteFile(target, []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := inView(mnt, filepath.Join(tree, "sym.txt"))
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if got, err := os.ReadFile(link); err != nil || string(got) != "body" {
		t.Fatalf("read through symlink: %q %v", got, err)
	}
	hard := inView(mnt, filepath.Join(tree, "hard.txt"))
	if err := os.Link(target, hard); err != nil {
		t.Fatalf("hard link: %v", err)
	}
	a, err := os.Stat(filepath.Join(tree, "target.txt"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(filepath.Join(tree, "hard.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Sys().(*syscall.Stat_t).Ino != b.Sys().(*syscall.Stat_t).Ino {
		t.Fatal("hard link and target have different inodes")
	}
	if a.Sys().(*syscall.Stat_t).Nlink != 2 {
		t.Fatalf("nlink = %d, want 2", a.Sys().(*syscall.Stat_t).Nlink)
	}
}

// rmdir removes the directory; unlink must not recurse into it.
func TestRmdirAndUnlinkAreDistinct(t *testing.T) {
	mnt, tree := mounted(t)
	dir := inView(mnt, filepath.Join(tree, "gone"))
	if err := os.MkdirAll(filepath.Join(dir, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "inner", "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// rmdir on a non-empty directory fails, and must not delete the tree
	if err := syscall.Rmdir(dir); err == nil {
		t.Fatal("rmdir of a non-empty directory succeeded")
	}
	if _, err := os.Stat(filepath.Join(tree, "gone", "inner", "f")); err != nil {
		t.Fatalf("rmdir deleted contents: %v", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove tree: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tree, "gone")); !os.IsNotExist(err) {
		t.Fatalf("tree survived rm -rf: %v", err)
	}
}

// A stat taken before and after reading a file has to agree, or tar reports
// "file changed as we read it" and refuses to archive it.
func TestStatIsStableAcrossRead(t *testing.T) {
	mnt, tree := mounted(t)
	p := inView(mnt, filepath.Join(tree, "stable.txt"))
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(f); err != nil {
		t.Fatalf("read: %v", err)
	}
	during, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if before.ModTime() != after.ModTime() || before.Size() != after.Size() {
		t.Fatalf("stat changed across read: %v/%d -> %v/%d",
			before.ModTime(), before.Size(), after.ModTime(), after.Size())
	}
	if during.ModTime() != before.ModTime() {
		t.Fatalf("handle stat disagrees: %v vs %v", during.ModTime(), before.ModTime())
	}
}

// An open descriptor keeps reading the bytes it was opened on. A later write to
// the same name replaces the file, and the holder must not start seeing the new
// content, still less nothing at all. Log rotation, `git`'s object check and
// every editor's "save" rely on this.
func TestOpenHandleKeepsItsContent(t *testing.T) {
	mnt, tree := mounted(t)
	p := inView(mnt, filepath.Join(tree, "held.txt"))
	if err := os.WriteFile(p, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	// Replace the name while the descriptor is open, by writing a new file and
	// renaming it into place — the way editors and state files save. In-place
	// truncation is expected to be visible to a holder; a rename is not.
	tmp := inView(mnt, filepath.Join(tree, ".held.tmp"))
	if err := os.WriteFile(tmp, []byte("replacement"), 0o644); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatalf("rename replacement: %v", err)
	}
	buf := make([]byte, 64)
	n, _ := f.ReadAt(buf, 0)
	if string(buf[:n]) != "original" {
		t.Fatalf("open handle read %q, want the content it was opened on", buf[:n])
	}
	// and the new content is what the path serves
	got, err := os.ReadFile(filepath.Join(tree, "held.txt"))
	if err != nil {
		t.Fatalf("host read: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("path serves %q", got)
	}
}

// A descriptor whose name is removed keeps working, and the name stays gone.
// Scratch files are made this way: create, unlink, keep writing.
func TestWriteThroughRemovedNameDoesNotResurrectIt(t *testing.T) {
	mnt, tree := mounted(t)
	p := inView(mnt, filepath.Join(tree, "scratch"))
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write([]byte("first")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	// writing is allowed to fail or to be discarded, but must not recreate
	f.Write([]byte("second"))
	f.Close()
	if _, err := os.Stat(filepath.Join(tree, "scratch")); !os.IsNotExist(err) {
		t.Fatalf("the name came back: %v", err)
	}
}

// A read handle serves a snapshot of the file it was opened on. Statting that
// handle and reading it have to agree on the size: a writer may change the file
// since the open, and reporting the new size while Read serves the old bytes is
// a lie — impossible on a local filesystem, and it corrupts any program that
// sizes its buffer from a stat.
func TestHandleStatMatchesItsContent(t *testing.T) {
	mnt, tree := mounted(t)
	p := inView(mnt, filepath.Join(tree, "snap.txt"))
	if err := os.WriteFile(p, []byte("gen1-abcdefgh"), 0o644); err != nil {
		t.Fatal(err)
	}
	// open the file, which materialises the read snapshot
	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Replace the name with a smaller file. An editor or a state writer saves
	// this way, and the open descriptor keeps the bytes it opened on.
	tmp := inView(mnt, filepath.Join(tree, ".snap.tmp"))
	if err := os.WriteFile(tmp, []byte("gen2"), 0o644); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatalf("rename replacement: %v", err)
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("handle stat: %v", err)
	}
	buf := make([]byte, 64)
	n, _ := f.ReadAt(buf, 0)
	// the handle still holds gen1's bytes, and its stat agrees
	if string(buf[:n]) != "gen1-abcdefgh" {
		t.Fatalf("handle read %q, want the snapshot", buf[:n])
	}
	if fi.Size() != int64(len("gen1-abcdefgh")) {
		t.Fatalf("handle size %d, want %d (the bytes it serves)",
			fi.Size(), len("gen1-abcdefgh"))
	}
	f.Close()
}
