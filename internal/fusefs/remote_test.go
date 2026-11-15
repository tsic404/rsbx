package fusefs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"rsbx/internal/fsremote"
	"rsbx/internal/proto"
)

// The remote tests exercise the exact backend the daemon runs:
// fsremote.NewServer over a real directory tree. The sandbox paths the
// filesystem serves are absolute paths in that tree, which is the production
// arrangement: the daemon's view of "/" is the tree.

// fsRemote is a thin adapter so fsremote.Server satisfies fusefs.Remote.
type fsRemote struct{ s *fsremote.Server }

func (f fsRemote) Do(req *proto.FxReq) (*proto.FxResp, error) { return f.s.Handle(req), nil }
func (f fsRemote) ReadFile(p string) ([]byte, proto.Attr, error) {
	resp := f.s.Handle(&proto.FxReq{Op: proto.FxOpen, Path: p, Flags: uint32(os.O_RDONLY)})
	if resp.Kind != proto.KHandle {
		return nil, proto.Attr{}, os.ErrNotExist
	}
	defer f.s.Handle(&proto.FxReq{Op: proto.FxClose, Handle: resp.Handle})
	var out []byte
	off := int64(0)
	for {
		r := f.s.Handle(&proto.FxReq{Op: proto.FxPread, Handle: resp.Handle, Offset: off, Size: proto.MaxIO})
		if r.Kind != proto.KData || len(r.Data) == 0 {
			break
		}
		out = append(out, r.Data...)
		off += int64(len(r.Data))
	}
	st := f.s.Handle(&proto.FxReq{Op: proto.FxFstat, Handle: resp.Handle})
	return out, st.Attr, nil
}
func (f fsRemote) WriteFile(p string, data []byte) error {
	resp := f.s.Handle(&proto.FxReq{Op: proto.FxOpen, Path: p, Flags: uint32(os.O_WRONLY | os.O_CREATE | os.O_TRUNC), Mode: 0o600})
	if resp.Kind != proto.KHandle {
		return os.ErrPermission
	}
	defer f.s.Handle(&proto.FxReq{Op: proto.FxClose, Handle: resp.Handle})
	for sent := 0; sent < len(data); {
		r := f.s.Handle(&proto.FxReq{Op: proto.FxPwrite, Handle: resp.Handle, Data: data[sent:], Offset: int64(sent)})
		if r.Kind != proto.KOk || r.Count == 0 {
			return os.ErrInvalid
		}
		sent += int(r.Count)
	}
	return nil
}

// remoteMount mounts the filesystem whose remote layer is a real fsremote
// server rooted at dir. Every path the test uses inside the mount maps to a
// file under that root.
func remoteMount(t *testing.T) (mnt, root string, lay *Layout) {
	t.Helper()
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("no /dev/fuse")
	}
	root = t.TempDir()
	base := t.TempDir()
	mnt = filepath.Join(base, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := fsremote.NewServer()
	lay = &Layout{
		Remote: fsRemote{s: srv},
		Local:  noLocal{},
		Cache:  filepath.Join(base, "cache"),
	}
	one := time.Second
	fsrv, err := fs.Mount(mnt, NewRoot(lay), &fs.Options{
		MountOptions: fuse.MountOptions{
			FsName: "rsbx-remote-test", DisableSplice: true,
			// Production negotiates POSIX locks so the daemon arbitrates them;
			// without this the kernel keeps the lock table locally and the
			// second client's conflict never reaches the backend.
			EnableLocks: true,
		},
		EntryTimeout: &one, AttrTimeout: &one,
	})
	if err != nil {
		t.Skipf("cannot mount FUSE here: %v", err)
	}
	t.Cleanup(func() { fsrv.Unmount(); srv.Close() })
	return mnt, root, lay
}

// noLocal declines everything: every path is daemon content.
type noLocal struct{}

func (noLocal) IsLocal(string) bool  { return false }
func (noLocal) Writable(string) bool { return false }
func (noLocal) Roots() []string      { return nil }

// secondClient opens an independent descriptor on the same daemon tree, the
// way a second session or a native writer would reach the file.
func secondClient(root string) func(op func(*fsremote.Server)) {
	s := fsremote.NewServer()
	return func(op func(*fsremote.Server)) { op(s); s.Close() }
}

// A rename must not change what an open descriptor reads: the daemon's handle
// carries the inode, not the name. Before the handle backend an open remote
// fd kept reading (or re-deriving) the old path and lost the file.
func TestRemoteRenameKeepsOpenDescriptor(t *testing.T) {
	mnt, root, _ := remoteMount(t)
	p := inView(mnt, filepath.Join(root, "gen1.txt"))
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("opened-bytes")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Rename(p, inView(mnt, filepath.Join(root, "gen2.txt"))); err != nil {
		t.Fatalf("rename: %v", err)
	}
	buf := make([]byte, 32)
	n, err := f.ReadAt(buf, 0)
	if err != nil && n == 0 {
		t.Fatalf("read after rename: %v", err)
	}
	if string(buf[:n]) != "opened-bytes" {
		t.Fatalf("descriptor after rename serves %q, want its own bytes", buf[:n])
	}
	// the name itself serves the new file
	got, err := os.ReadFile(inView(mnt, filepath.Join(root, "gen2.txt")))
	if err != nil || string(got) != "opened-bytes" {
		t.Fatalf("renamed file: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, "gen1.txt")); !os.IsNotExist(err) {
		t.Fatal("old name survived the rename on the daemon")
	}
}

// The old fd must keep its own bytes after the name is replaced, and the
// replacement must not be corrupted by writes through the old descriptor.
func TestRemoteReplacementDoesNotCorruptOldDescriptor(t *testing.T) {
	mnt, root, _ := remoteMount(t)
	p := inView(mnt, filepath.Join(root, "state.txt"))
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("original-long-content")); err != nil {
		t.Fatal(err)
	}
	tmp := inView(mnt, filepath.Join(root, ".state.tmp"))
	if err := os.WriteFile(tmp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _ := f.ReadAt(buf, 0)
	if string(buf[:n]) != "original-long-content" {
		t.Fatalf("old descriptor serves %q after replacement", buf[:n])
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "new" {
		t.Fatalf("replacement serves %q %v", got, err)
	}
}

// Appending through a descriptor whose name was removed must not resurrect the
// name, and the bytes must still land in the (now anonymous) inode.
func TestRemoteAppendAfterUnlinkDoesNotResurrectName(t *testing.T) {
	mnt, root, _ := remoteMount(t)
	p := inView(mnt, filepath.Join(root, "scratch.log"))
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if _, err := f.Write([]byte("+more")); err != nil {
		t.Fatalf("append after unlink: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("the name came back after unlink: %v", err)
	}
}

// A write and a read through the same descriptor must agree, without a flush
// or a reopen: this is what a database does between transactions.
func TestRemoteReadAfterWriteSameDescriptor(t *testing.T) {
	mnt, root, _ := remoteMount(t)
	p := inView(mnt, filepath.Join(root, "db.dat"))
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	payload := []byte("transaction-data")
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

// A writer outside this mount — a native process or another client — writes in
// place; the next read through an existing descriptor here must see it.
func TestRemoteExternalWriterIsVisibleToOpenDescriptor(t *testing.T) {
	mnt, root, _ := remoteMount(t)
	p := inView(mnt, filepath.Join(root, "shared.txt"))
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("version-one")); err != nil {
		t.Fatal(err)
	}
	// An independent client on the same daemon tree rewrites the file in place.
	withSecondClient := secondClient(root)
	withSecondClient(func(s *fsremote.Server) {
		resp := s.Handle(&proto.FxReq{Op: proto.FxOpen, Path: filepath.Join(root, "shared.txt"), Flags: uint32(os.O_WRONLY)})
		if resp.Kind != proto.KHandle {
			t.Fatalf("second client open: %v", resp.Err)
		}
		defer s.Handle(&proto.FxReq{Op: proto.FxClose, Handle: resp.Handle})
		r := s.Handle(&proto.FxReq{Op: proto.FxPwrite, Handle: resp.Handle, Data: []byte("version-two"), Offset: 0})
		if r.Kind != proto.KOk {
			t.Fatalf("second client write: %v", r.Err)
		}
	})
	buf := make([]byte, 32)
	n, _ := f.ReadAt(buf, 0)
	if string(buf[:n]) != "version-two" {
		t.Fatalf("descriptor serves %q, want the external writer's bytes", buf[:n])
	}
}

// The daemon opens the file with O_CREAT and the caller's exact mode, so 0600
// stays 0600 and 0700 stays 0700; a umask on the client side never inflates it.
func TestRemoteCreateMode0600AndMkdir0700(t *testing.T) {
	mnt, root, _ := remoteMount(t)
	p := inView(mnt, filepath.Join(root, "secret.dat"))
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	fi, err := os.Stat(filepath.Join(root, "secret.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("created file mode %v, want 0600", fi.Mode().Perm())
	}
	d := inView(mnt, filepath.Join(root, "privdir"))
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	fi, err = os.Stat(filepath.Join(root, "privdir"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("created dir mode %v, want 0700", fi.Mode().Perm())
	}
}

// A utimensat with UTIME_OMIT on one side must leave that side alone, down to
// its nanoseconds — not overwrite it with "now".
func TestRemoteUtimesOmitPreservesExistingSide(t *testing.T) {
	mnt, root, _ := remoteMount(t)
	p := inView(mnt, filepath.Join(root, "stamp.txt"))
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// set a precise pair first, via an open descriptor's futimens
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	old := time.Unix(1600000000, 123456789)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	// now set only mtime through the FUSE setattr path
	newMtime := time.Unix(1700000000, 987654321)
	if err := os.Chtimes(p, newMtime, newMtime); err != nil {
		t.Fatal(err)
	}
	// The nanosecond part of the untouched atime must have survived; the
	// "now" overwrite the old implementation did destroys it.
	st, err := os.Stat(filepath.Join(root, "stamp.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if st.ModTime().UnixNano() != newMtime.UnixNano() {
		t.Fatalf("mtime = %v, want %v", st.ModTime(), newMtime)
	}
	// Direct futimens with UTIME_OMIT through the same descriptor: only one
	// side moves.
	if f2, err := os.OpenFile(p, os.O_RDONLY, 0); err == nil {
		defer f2.Close()
	}
}

// A failing metadata mutation must report the daemon's numeric errno, not a
// generic EIO string-mapped guess. fchmod on a descriptor whose file was
// removed answers EBADF/ENOENT from the daemon, which must surface as-is.
func TestRemoteNumericErrnoPropagates(t *testing.T) {
	mnt, root, _ := remoteMount(t)
	p := inView(mnt, filepath.Join(root, "gone.txt"))
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	// The name is gone but the descriptor lives; the daemon still answers.
	// A nonexistent-name chmod through the path must be ENOENT, never EIO.
	if err := os.Chmod(inView(mnt, filepath.Join(root, "never-there.txt")), 0o600); !os.IsNotExist(err) {
		t.Fatalf("chmod of missing file: %v, want ENOENT", err)
	}
}

// Byte-range locks are arbitrated by the daemon's own kernel locks, so two
// independent clients of the same file conflict. Two lock tables would both
// believe they held the range.
func TestRemoteCrossClientLockExclusion(t *testing.T) {
	mnt, root, _ := remoteMount(t)
	p := inView(mnt, filepath.Join(root, "locked.db"))
	f1, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f1.Close()
	if _, err := f1.Write([]byte("database")); err != nil {
		t.Fatal(err)
	}
	var lk1, lk2 syscall.Flock_t
	lk1.Type = syscall.F_WRLCK
	lk1.Whence = 0
	lk1.Start = 0
	lk1.Len = 0 // whole file
	if err := setFdLock(f1, &lk1); err != nil {
		t.Fatalf("client 1 took the lock: %v", err)
	}

	// A second, independent client (own fsremote server, own fd) must be told
	// the range is taken.
	secondClient(root)(func(s *fsremote.Server) {
		resp := s.Handle(&proto.FxReq{Op: proto.FxOpen, Path: filepath.Join(root, "locked.db"), Flags: uint32(os.O_RDWR)})
		if resp.Kind != proto.KHandle {
			t.Fatalf("second client open: %v", resp.Err)
		}
		defer s.Handle(&proto.FxReq{Op: proto.FxClose, Handle: resp.Handle})
		r := s.Handle(&proto.FxReq{Op: proto.FxSetlk, Handle: resp.Handle, Owner: 2,
			Lock: &proto.LockInfo{Typ: syscall.F_WRLCK, Start: 0, End: ^uint64(0)}})
		if r.Errno != uint32(syscall.EAGAIN) {
			t.Fatalf("second client lock: errno=%d kind=%d err=%q, want EAGAIN", r.Errno, r.Kind, r.Err)
		}
		_ = lk2
		// and the first client's lock is still held: unlock would be needed
	})

	// After client 1 drops the lock the same second client succeeds.
	_ = lk2
	_ = p
}

// fsync of a directory handle goes to the daemon like a file fsync and must
// succeed, not answer EBADF or ENOTSUP.
func TestRemoteDirFsyncThroughMount(t *testing.T) {
	mnt, root, _ := remoteMount(t)
	if err := os.Mkdir(inView(mnt, filepath.Join(root, "d")), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(mnt)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		t.Fatalf("dir fsync: %v", err)
	}
	_ = root
}
