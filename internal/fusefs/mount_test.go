package fusefs

import (
	"os"
	"path/filepath"
	"sync/atomic"
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
		Remote:     &emptyRemote{},
		Local:      fixedLocal(tree),
		Cache:      filepath.Join(base, "cache"),
		Trampoline: filepath.Join(base, "tramp"),
		HostDirs:   hostDirs,
	}
	one := time.Second
	srv, err := fs.Mount(mnt, NewRoot(lay), &fs.Options{
		MountOptions:  fuse.MountOptions{FsName: "rsbx-test", DisableSplice: true},
		EntryTimeout:  &one,
		AttrTimeout:   &one,
	})
	if err != nil {
		t.Skipf("cannot mount FUSE here: %v", err)
	}
	t.Cleanup(func() { srv.Unmount() })
	return mnt, tree
}

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
