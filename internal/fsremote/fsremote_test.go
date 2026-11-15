//go:build linux

package fsremote

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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
	s := NewServer()
	t.Cleanup(func() { s.Close() })
	return s, root
}

func open(t *testing.T, s *Server, id uint32, path string, flags uint32, mode uint32) (uint64, *proto.FxResp) {
	t.Helper()
	resp := s.Handle(&proto.FxReq{ID: id, Op: proto.FxOpen, Path: path, Flags: flags, Mode: mode})
	if resp.Kind != proto.KHandle || resp.Handle == 0 {
		t.Fatalf("open %s: kind=%d errno=%d err=%q", path, resp.Kind, resp.Errno, resp.Err)
	}
	return resp.Handle, resp
}

func closeHandle(s *Server, h uint64) *proto.FxResp {
	return s.Handle(&proto.FxReq{Op: proto.FxClose, Handle: h})
}

func setlk(s *Server, h uint64, owner uint64, typ uint32, start, end uint64, wait bool) *proto.FxResp {
	op := byte(proto.FxSetlk)
	if wait {
		op = proto.FxSetlkw
	}
	return s.Handle(&proto.FxReq{
		Op: op, Handle: h, Owner: owner,
		Lock: &proto.LockInfo{Typ: typ, Start: start, End: end},
	})
}

func TestOpenReadClose(t *testing.T) {
	s, root := newServer(t)
	h, resp := open(t, s, 1, filepath.Join(root, "a.txt"), uint32(syscall.O_RDONLY), 0)
	if resp.Attr.Size != uint64(len("remote-body")) {
		t.Fatalf("open attr size %d", resp.Attr.Size)
	}
	r := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxPread, Handle: h, Offset: 7, Size: 5})
	if r.Kind != proto.KData || string(r.Data) != "body" || r.Count != 4 {
		t.Fatalf("read: kind=%d data=%q count=%d", r.Kind, r.Data, r.Count)
	}
	if c := closeHandle(s, h); c.Kind != proto.KOk {
		t.Fatalf("close: kind=%d errno=%d", c.Kind, c.Errno)
	}
	if bad := s.Handle(&proto.FxReq{ID: 4, Op: proto.FxPread, Handle: h, Offset: 0, Size: 4}); bad.Kind != proto.KErr || bad.Errno != uint32(syscall.EBADF) {
		t.Fatalf("pread on closed handle: kind=%d errno=%d", bad.Kind, bad.Errno)
	}
	if again := closeHandle(s, h); again.Kind != proto.KErr || again.Errno != uint32(syscall.EBADF) {
		t.Fatalf("close of closed handle: kind=%d errno=%d, want EBADF", again.Kind, again.Errno)
	}
}

// EOF is a successful short or empty read, never EIO: the caller asks for a
// range and the kernel reports how much of it exists.
func TestPreadEOFIsEmptySuccess(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "a.txt")
	h, _ := open(t, s, 1, p, uint32(syscall.O_RDONLY), 0)
	defer closeHandle(s, h)

	atEOF := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxPread, Handle: h, Offset: int64(len("remote-body")), Size: 8})
	if atEOF.Kind != proto.KData || atEOF.Errno != 0 || atEOF.Count != 0 || len(atEOF.Data) != 0 {
		t.Fatalf("read at EOF: kind=%d errno=%d count=%d data=%q", atEOF.Kind, atEOF.Errno, atEOF.Count, atEOF.Data)
	}
	pastEOF := s.Handle(&proto.FxReq{ID: 3, Op: proto.FxPread, Handle: h, Offset: 4096, Size: 8})
	if pastEOF.Kind != proto.KData || pastEOF.Errno != 0 || pastEOF.Count != 0 {
		t.Fatalf("read past EOF: kind=%d errno=%d count=%d", pastEOF.Kind, pastEOF.Errno, pastEOF.Count)
	}
	// A short read at the end keeps the bytes that exist, with their count.
	tail := s.Handle(&proto.FxReq{ID: 4, Op: proto.FxPread, Handle: h, Offset: 7, Size: 64})
	if tail.Kind != proto.KData || string(tail.Data) != "body" || tail.Count != 4 {
		t.Fatalf("short read: kind=%d count=%d data=%q", tail.Kind, tail.Count, tail.Data)
	}
	over := s.Handle(&proto.FxReq{ID: 5, Op: proto.FxPread, Handle: h, Offset: 0, Size: proto.MaxIO + 1})
	if over.Kind != proto.KErr || over.Errno != uint32(syscall.EINVAL) {
		t.Fatalf("oversized read: kind=%d errno=%d, want EINVAL", over.Kind, over.Errno)
	}
}

// A handle keeps the inode it opened: a rename between open and write must
// not redirect the bytes to whatever the old name now names.
func TestWritePreservesInodeAfterRenameReplacement(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "a.txt")
	h, _ := open(t, s, 1, p, uint32(syscall.O_RDWR), 0)
	defer closeHandle(s, h)

	// Replace the name with an unrelated file: the handle still names the old
	// inode, so neither a write nor a read may follow the path.
	repl := filepath.Join(root, "replacement")
	if err := os.WriteFile(repl, []byte("brand-new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(repl, p); err != nil {
		t.Fatal(err)
	}
	w := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxPwrite, Handle: h, Offset: 0, Data: []byte("Z")})
	if w.Kind != proto.KOk || w.Count != 1 {
		t.Fatalf("write after replacement: kind=%d count=%d errno=%d", w.Kind, w.Count, w.Errno)
	}
	got := s.Handle(&proto.FxReq{ID: 3, Op: proto.FxPread, Handle: h, Offset: 0, Size: 32})
	if string(got.Data[:got.Count]) != "Zemote-body" {
		t.Fatalf("handle content: %q", got.Data[:got.Count])
	}
	disk, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(disk) != "brand-new" {
		t.Fatalf("path content: %q", disk)
	}
}

// An O_APPEND handle keeps appending to its own inode even after the name is
// unlinked: there is no path to reopen, and the count is what the descriptor
// accepted.
func TestAppendAfterUnlink(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "log")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	h, _ := open(t, s, 1, p, uint32(syscall.O_RDWR|syscall.O_APPEND), 0)
	defer closeHandle(s, h)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"one;", "two;"} {
		w := s.Handle(&proto.FxReq{ID: uint32(10 + i), Op: proto.FxPwrite, Handle: h, Offset: 0, Data: []byte(want)})
		if w.Kind != proto.KOk || w.Count != uint32(len(want)) {
			t.Fatalf("append %d: kind=%d count=%d errno=%d", i, w.Kind, w.Count, w.Errno)
		}
	}
	r := s.Handle(&proto.FxReq{ID: 20, Op: proto.FxPread, Handle: h, Offset: 0, Size: 64})
	if string(r.Data[:r.Count]) != "one;two;" {
		t.Fatalf("appended content: %q", r.Data[:r.Count])
	}
	st := s.Handle(&proto.FxReq{ID: 21, Op: proto.FxFstat, Handle: h})
	if st.Kind != proto.KStat || st.Attr.Size != 8 {
		t.Fatalf("fstat after unlinked append: kind=%d size=%d", st.Kind, st.Attr.Size)
	}
}

func TestFstatCarriesIdentity(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "a.txt")
	h, _ := open(t, s, 1, p, uint32(syscall.O_RDWR), 0)
	defer closeHandle(s, h)
	st := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxFstat, Handle: h})
	if st.Kind != proto.KStat {
		t.Fatalf("fstat kind=%d", st.Kind)
	}
	if st.Attr.Size != uint64(len("remote-body")) || st.Attr.Mode&proto.SIFREG == 0 {
		t.Fatalf("fstat attr: size=%d mode=%o", st.Attr.Size, st.Attr.Mode)
	}
	var sys syscall.Stat_t
	if err := syscall.Stat(p, &sys); err != nil {
		t.Fatal(err)
	}
	if st.Attr.Ino != uint64(sys.Ino) || st.Attr.Dev != uint64(sys.Dev) || st.Attr.Nlink != uint32(sys.Nlink) {
		t.Fatalf("identity mismatch: got ino=%d dev=%d nlink=%d want ino=%d dev=%d nlink=%d",
			st.Attr.Ino, st.Attr.Dev, st.Attr.Nlink, sys.Ino, sys.Dev, sys.Nlink)
	}
	if st.Attr.Mtime != sys.Mtim.Sec || st.Attr.MtimeNsec != uint32(sys.Mtim.Nsec) ||
		st.Attr.Atime != sys.Atim.Sec || st.Attr.AtimeNsec != uint32(sys.Atim.Nsec) ||
		st.Attr.Ctime != sys.Ctim.Sec || st.Attr.CtimeNsec != uint32(sys.Ctim.Nsec) {
		t.Fatalf("times mismatch: got %+v want atim=%v mtim=%v ctim=%v", st.Attr, sys.Atim, sys.Mtim, sys.Ctim)
	}
}

// mkdir takes its mode from the typed field when set, else from the decimal
// Arg the client uses, and never invents a default.
func TestMkdirTypedModeAndDecimalArg(t *testing.T) {
	s, root := newServer(t)
	if r := s.Handle(&proto.FxReq{ID: 1, Op: proto.FxMkdir, Path: filepath.Join(root, "fromarg"), Arg: "448"}); r.Kind != proto.KOk {
		t.Fatalf("mkdir from decimal arg: kind=%d errno=%d", r.Kind, r.Errno)
	}
	fi, err := os.Stat(filepath.Join(root, "fromarg"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("decimal arg mode = %o, want 0700", fi.Mode().Perm())
	}
	if r := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxMkdir, Path: filepath.Join(root, "typed"), Arg: "448", Mode: 0o750}); r.Kind != proto.KOk {
		t.Fatalf("mkdir typed: kind=%d errno=%d", r.Kind, r.Errno)
	}
	fi, err = os.Stat(filepath.Join(root, "typed"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o750 {
		t.Fatalf("typed mode = %o, want 0750", fi.Mode().Perm())
	}
	if r := s.Handle(&proto.FxReq{ID: 3, Op: proto.FxMkdir, Path: filepath.Join(root, "nomode")}); r.Kind != proto.KErr || r.Errno != uint32(syscall.EINVAL) {
		t.Fatalf("mkdir without mode: kind=%d errno=%d, want EINVAL", r.Kind, r.Errno)
	}
	if _, err := os.Stat(filepath.Join(root, "nomode")); !os.IsNotExist(err) {
		t.Fatal("mkdir without mode created a directory")
	}
}

// An omitted timestamp keeps what is on the file, nanoseconds included.
func TestUtimesNanosecondsAndOmit(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "a.txt")
	var before syscall.Stat_t
	if err := syscall.Stat(p, &before); err != nil {
		t.Fatal(err)
	}
	// 1500000000s + 123456789ns, mtime omitted.
	arg := "1500000000123456789,"
	if r := s.Handle(&proto.FxReq{ID: 1, Op: proto.FxUtimes, Path: p, Arg: arg}); r.Kind != proto.KOk {
		t.Fatalf("utimes: kind=%d errno=%d", r.Kind, r.Errno)
	}
	var after syscall.Stat_t
	if err := syscall.Stat(p, &after); err != nil {
		t.Fatal(err)
	}
	if after.Atim.Sec != 1500000000 || after.Atim.Nsec != 123456789 {
		t.Fatalf("atime = %d.%09d, want 1500000000.123456789", after.Atim.Sec, after.Atim.Nsec)
	}
	if after.Mtim != before.Mtim {
		t.Fatalf("omitted mtime changed: got %v want %v", after.Mtim, before.Mtim)
	}
	// A negative field is also UTIME_OMIT.
	if r := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxUtimes, Path: p, Arg: "2000000000000000000,-1"}); r.Kind != proto.KOk {
		t.Fatalf("utimes negative omit: kind=%d errno=%d", r.Kind, r.Errno)
	}
	if err := syscall.Stat(p, &after); err != nil {
		t.Fatal(err)
	}
	if after.Mtim != before.Mtim {
		t.Fatalf("negative omit changed mtime: got %v want %v", after.Mtim, before.Mtim)
	}
	if after.Atim.Sec != 2000000000 || after.Atim.Nsec != 0 {
		t.Fatalf("atime = %d.%09d, want 2000000000.0", after.Atim.Sec, after.Atim.Nsec)
	}
}

// Wrapped errnos keep their value, and only a metadata lookup may answer
// KNone: a failed mutation or open is KErr with ENOENT.
func TestWrappedErrnoAndMutationKinds(t *testing.T) {
	s, root := newServer(t)
	wrapped := fmt.Errorf("open %q: %w", "x", syscall.ENOENT)
	resp := errResp(1, wrapped)
	if resp.Kind != proto.KErr || resp.Errno != uint32(syscall.ENOENT) {
		t.Fatalf("wrapped errno: kind=%d errno=%d", resp.Kind, resp.Errno)
	}
	if got := errResp(2, fmt.Errorf("stat: %w", os.ErrNotExist)); got.Errno != uint32(syscall.ENOENT) {
		t.Fatalf("wrapped fs.ErrNotExist: errno=%d", got.Errno)
	}
	missingOpen := s.Handle(&proto.FxReq{ID: 3, Op: proto.FxOpen, Path: filepath.Join(root, "absent"), Flags: uint32(syscall.O_RDONLY)})
	if missingOpen.Kind != proto.KErr || missingOpen.Errno != uint32(syscall.ENOENT) {
		t.Fatalf("open missing: kind=%d errno=%d, want KErr/ENOENT", missingOpen.Kind, missingOpen.Errno)
	}
	missingMkdir := s.Handle(&proto.FxReq{ID: 4, Op: proto.FxMkdir, Path: filepath.Join(root, "absent", "child"), Mode: 0o755})
	if missingMkdir.Kind != proto.KErr || missingMkdir.Errno != uint32(syscall.ENOENT) {
		t.Fatalf("mkdir into missing dir: kind=%d errno=%d", missingMkdir.Kind, missingMkdir.Errno)
	}
	missingStat := s.Handle(&proto.FxReq{ID: 5, Op: proto.FxStat, Path: filepath.Join(root, "absent")})
	if missingStat.Kind != proto.KNone {
		t.Fatalf("stat missing: kind=%d, want KNone", missingStat.Kind)
	}
}

// FxStat is Lstat: a symbolic link is reported as a link, not as its target.
func TestStatPreservesSymlinkType(t *testing.T) {
	s, root := newServer(t)
	link := filepath.Join(root, "ln")
	if err := os.Symlink("a.txt", link); err != nil {
		t.Fatal(err)
	}
	r := s.Handle(&proto.FxReq{ID: 1, Op: proto.FxStat, Path: link})
	if r.Kind != proto.KStat {
		t.Fatalf("stat link kind=%d errno=%d", r.Kind, r.Errno)
	}
	if r.Attr.Mode&syscall.S_IFMT != syscall.S_IFLNK {
		t.Fatalf("stat link mode=%o, want symlink type", r.Attr.Mode)
	}
	list := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxList, Path: root})
	if list.Kind != proto.KDir {
		t.Fatalf("list kind=%d errno=%d", list.Kind, list.Errno)
	}
	found := false
	for _, e := range list.Ents {
		if e.Name == "ln" {
			found = true
			if e.Mode&syscall.S_IFMT != syscall.S_IFLNK {
				t.Fatalf("dirent mode=%o, want symlink type", e.Mode)
			}
		}
		if e.Name == "sub" && e.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			t.Fatalf("dirent sub mode=%o, want directory type", e.Mode)
		}
	}
	if !found {
		t.Fatal("listing did not carry the link")
	}
}

func TestPathOpsOnAbsolutePaths(t *testing.T) {
	s, root := newServer(t)
	sub := filepath.Join(root, "sub")
	if r := s.Handle(&proto.FxReq{ID: 1, Op: proto.FxStat, Path: sub}); r.Kind != proto.KStat || r.Attr.Mode&proto.SIFDIR == 0 {
		t.Fatalf("stat kind=%d mode=%o", r.Kind, r.Attr.Mode)
	}
	if r := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxList, Path: root}); r.Kind != proto.KDir || len(r.Ents) != 2 {
		t.Fatalf("list kind=%d ents=%d", r.Kind, len(r.Ents))
	}
	link := filepath.Join(root, "ln")
	if r := s.Handle(&proto.FxReq{ID: 3, Op: proto.FxSymlink, Path: link, Arg: "a.txt"}); r.Kind != proto.KOk {
		t.Fatalf("symlink kind=%d errno=%d", r.Kind, r.Errno)
	}
	if r := s.Handle(&proto.FxReq{ID: 4, Op: proto.FxReadlink, Path: link}); r.Kind != proto.KLink || string(r.Data) != "a.txt" {
		t.Fatalf("readlink kind=%d data=%q", r.Kind, r.Data)
	}
	if r := s.Handle(&proto.FxReq{ID: 5, Op: proto.FxLink, Path: filepath.Join(root, "hard"), Arg: filepath.Join(root, "a.txt")}); r.Kind != proto.KOk {
		t.Fatalf("link kind=%d errno=%d", r.Kind, r.Errno)
	}
	if r := s.Handle(&proto.FxReq{ID: 6, Op: proto.FxRename, Path: filepath.Join(root, "hard"), Arg: filepath.Join(root, "hard2")}); r.Kind != proto.KOk {
		t.Fatalf("rename kind=%d errno=%d", r.Kind, r.Errno)
	}
	if r := s.Handle(&proto.FxReq{ID: 7, Op: proto.FxChmod, Path: sub, Arg: "0700"}); r.Kind != proto.KOk {
		t.Fatalf("chmod kind=%d errno=%d", r.Kind, r.Errno)
	}
	if r := s.Handle(&proto.FxReq{ID: 9, Op: proto.FxTruncate, Path: filepath.Join(root, "a.txt"), Arg: "4"}); r.Kind != proto.KOk {
		t.Fatalf("truncate kind=%d errno=%d", r.Kind, r.Errno)
	}
	if r := s.Handle(&proto.FxReq{ID: 10, Op: proto.FxUnlink, Path: filepath.Join(root, "hard2")}); r.Kind != proto.KOk {
		t.Fatalf("unlink kind=%d errno=%d", r.Kind, r.Errno)
	}
	if r := s.Handle(&proto.FxReq{ID: 11, Op: proto.FxUnlink, Path: sub}); r.Kind != proto.KErr || r.Errno != uint32(syscall.EISDIR) {
		t.Fatalf("unlink of a directory: kind=%d errno=%d", r.Kind, r.Errno)
	}
	// A directory with a child must refuse removal: rmdir is not rm -rf.
	if err := os.WriteFile(filepath.Join(sub, "child"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := s.Handle(&proto.FxReq{ID: 12, Op: proto.FxRmdir, Path: sub}); r.Kind != proto.KErr || r.Errno != uint32(syscall.ENOTEMPTY) {
		t.Fatalf("rmdir of a nonempty directory: kind=%d errno=%d", r.Kind, r.Errno)
	}
	if r := s.Handle(&proto.FxReq{ID: 13, Op: proto.FxMkdir, Path: filepath.Join(root, "d1"), Mode: 0o755}); r.Kind != proto.KOk {
		t.Fatalf("mkdir kind=%d errno=%d", r.Kind, r.Errno)
	}
	if r := s.Handle(&proto.FxReq{ID: 14, Op: proto.FxRmdir, Path: filepath.Join(root, "d1")}); r.Kind != proto.KOk {
		t.Fatalf("rmdir kind=%d errno=%d", r.Kind, r.Errno)
	}
}

// A directory handle lists its own inode: renaming the directory after the
// handle was opened must not send the listing to a replacement.
func TestListThroughHandleSurvivesRename(t *testing.T) {
	s, root := newServer(t)
	dir := filepath.Join(root, "sub")
	h, _ := open(t, s, 1, dir, uint32(syscall.O_RDONLY|syscall.O_DIRECTORY), 0)
	defer closeHandle(s, h)
	moved := filepath.Join(root, "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "replacement"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Put a marker in the moved inode so the two lists are distinguishable.
	if err := os.WriteFile(filepath.Join(moved, "original"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxList, Handle: h})
	if r.Kind != proto.KDir {
		t.Fatalf("list by handle: kind=%d errno=%d err=%q", r.Kind, r.Errno, r.Err)
	}
	names := map[string]bool{}
	for _, e := range r.Ents {
		names[e.Name] = true
	}
	if !names["original"] || names["replacement"] {
		t.Fatalf("listed wrong directory: %v", names)
	}
	if r := s.Handle(&proto.FxReq{ID: 3, Op: proto.FxList, Handle: 0, Path: moved}); r.Kind != proto.KDir {
		t.Fatalf("path list after rename: kind=%d errno=%d", r.Kind, r.Errno)
	}
}

// One Owner on one connection over one inode is one lock identity: its
// handles do not conflict with each other, and another Owner does.
func TestOwnerLockIdentity(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "locked.bin")
	if err := os.WriteFile(p, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	h1, _ := open(t, s, 1, p, uint32(syscall.O_RDWR), 0)
	h2, _ := open(t, s, 2, p, uint32(syscall.O_RDWR), 0)
	h3, _ := open(t, s, 3, p, uint32(syscall.O_RDWR), 0)
	defer closeHandle(s, h1)
	defer closeHandle(s, h2)
	defer closeHandle(s, h3)

	if r := setlk(s, h1, 42, 1, 0, 4, false); r.Kind != proto.KOk {
		t.Fatalf("owner 42 lock: kind=%d errno=%d", r.Kind, r.Errno)
	}
	// Same owner through another handle: same open file description, so the
	// overlapping lock is granted rather than reported as a conflict.
	if r := setlk(s, h2, 42, 1, 2, 6, false); r.Kind != proto.KOk {
		t.Fatalf("owner 42 lock through second handle: kind=%d errno=%d", r.Kind, r.Errno)
	}
	// Go-fuse asks Getlk with the asking owner's identity: its own locks are
	// invisible to it.
	self := s.Handle(&proto.FxReq{
		Op: proto.FxGetlk, Handle: h2, Owner: 42,
		Lock: &proto.LockInfo{Typ: 1, Start: 0, End: 6},
	})
	if self.Kind != proto.KOk || self.Lock != nil {
		t.Fatalf("getlk for own lock: kind=%d lock=%+v", self.Kind, self.Lock)
	}
	// Another owner conflicts, and the report carries no pid: an OFD lock has
	// no process owner.
	other := setlk(s, h3, 7, 1, 3, 3, false)
	if other.Kind != proto.KErr || (other.Errno != uint32(syscall.EAGAIN) && other.Errno != uint32(syscall.EACCES)) {
		t.Fatalf("other owner lock: kind=%d errno=%d, want EAGAIN/EACCES", other.Kind, other.Errno)
	}
	ask := s.Handle(&proto.FxReq{
		Op: proto.FxGetlk, Handle: h3, Owner: 7,
		Lock: &proto.LockInfo{Typ: 1, Start: 0, End: 9},
	})
	if ask.Kind != proto.KOk || ask.Lock == nil {
		t.Fatalf("getlk from other owner: kind=%d lock=%+v", ask.Kind, ask.Lock)
	}
	if ask.Lock.Pid != 0 {
		t.Fatalf("conflict pid = %d, want 0", ask.Lock.Pid)
	}
	if ask.Lock.Start != 0 || ask.Lock.End != 6 {
		t.Fatalf("conflict range = [%d,%d], want [0,6]", ask.Lock.Start, ask.Lock.End)
	}
	// A whole-file lock on the same owner's description covers the range and
	// comes back as "to the end of the file".
	if r := setlk(s, h2, 42, 1, 0, ^uint64(0), false); r.Kind != proto.KOk {
		t.Fatalf("whole-file lock: kind=%d errno=%d", r.Kind, r.Errno)
	}
	whole := s.Handle(&proto.FxReq{
		Op: proto.FxGetlk, Handle: h3, Owner: 7,
		Lock: &proto.LockInfo{Typ: 1, Start: 8, End: ^uint64(0)},
	})
	if whole.Lock == nil || whole.Lock.Start != 0 || whole.Lock.End != ^uint64(0) {
		t.Fatalf("whole-file conflict = %+v", whole.Lock)
	}
	// The same Owner on another inode is a different lock identity: it takes
	// its own lock there without touching the one held on this file.
	other2 := filepath.Join(root, "other.bin")
	if err := os.WriteFile(other2, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	h4, _ := open(t, s, 4, other2, uint32(syscall.O_RDWR), 0)
	defer closeHandle(s, h4)
	if r := setlk(s, h4, 42, 1, 0, 4, false); r.Kind != proto.KOk {
		t.Fatalf("owner 42 on another inode: kind=%d errno=%d", r.Kind, r.Errno)
	}
	// The lock on this file is unchanged and still reported to another owner.
	still := s.Handle(&proto.FxReq{
		Op: proto.FxGetlk, Handle: h3, Owner: 7,
		Lock: &proto.LockInfo{Typ: 1, Start: 0, End: 4},
	})
	if still.Lock == nil || still.Lock.Start != 0 || still.Lock.End != ^uint64(0) {
		t.Fatalf("first file conflict after second-inode lock = %+v", still.Lock)
	}
	// Unlock is owner-scoped too: it drops only this owner's locks, and after
	// it the range is free for the other owner.
	if u := setlk(s, h1, 42, 2, 0, ^uint64(0), false); u.Kind != proto.KOk {
		t.Fatalf("owner 42 unlock: kind=%d errno=%d", u.Kind, u.Errno)
	}
	if r := setlk(s, h3, 7, 1, 0, 9, false); r.Kind != proto.KOk {
		t.Fatalf("lock after owner unlock: kind=%d errno=%d", r.Kind, r.Errno)
	}
}

// An unlock from an owner that holds nothing on the file succeeds without
// creating a lock description, as F_SETLK with F_UNLCK does natively.
func TestUnlockWithoutHeldLock(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "idle.bin")
	if err := os.WriteFile(p, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, _ := open(t, s, 1, p, uint32(syscall.O_RDWR), 0)
	defer closeHandle(s, h)
	if r := setlk(s, h, 123, 2, 0, 9, false); r.Kind != proto.KOk {
		t.Fatalf("unlock without lock: kind=%d errno=%d", r.Kind, r.Errno)
	}
}

// A waiting FxSetlkw is granted once the conflicting owner lets go, without
// any goroutine parked in the kernel.
func TestSetlkwGrantedAfterRelease(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "wait2.bin")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	h1, _ := open(t, s, 1, p, uint32(syscall.O_RDWR), 0)
	h2, _ := open(t, s, 2, p, uint32(syscall.O_RDWR), 0)
	defer closeHandle(s, h1)
	defer closeHandle(s, h2)
	if r := setlk(s, h1, 1, 1, 0, 0, false); r.Kind != proto.KOk {
		t.Fatalf("setlk: kind=%d errno=%d", r.Kind, r.Errno)
	}
	done := make(chan *proto.FxResp, 1)
	go func() { done <- setlk(s, h2, 2, 1, 0, 0, true) }()
	time.Sleep(20 * time.Millisecond)
	if u := setlk(s, h1, 1, 2, 0, 0, false); u.Kind != proto.KOk {
		t.Fatalf("unlock: kind=%d errno=%d", u.Kind, u.Errno)
	}
	select {
	case resp := <-done:
		if resp.Kind != proto.KOk {
			t.Fatalf("waited Setlkw: kind=%d errno=%d", resp.Kind, resp.Errno)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Setlkw never granted after unlock")
	}
}

// OFD locks are arbitrated by the kernel against native POSIX record locks,
// so a program running beside the daemon conflicts with a client.
func TestLockConflictsWithNativePOSIX(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "native.bin")
	if err := os.WriteFile(p, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, _ := open(t, s, 1, p, uint32(syscall.O_RDWR), 0)
	defer closeHandle(s, h)

	native, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	fl := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 10}
	if err := syscall.FcntlFlock(native.Fd(), syscall.F_SETLK, &fl); err != nil {
		t.Fatalf("native lock: %v", err)
	}
	conflict := setlk(s, h, 5, 1, 0, 4, false)
	if conflict.Kind != proto.KErr || (conflict.Errno != uint32(syscall.EAGAIN) && conflict.Errno != uint32(syscall.EACCES)) {
		t.Fatalf("daemon lock vs native: kind=%d errno=%d, want EAGAIN/EACCES", conflict.Kind, conflict.Errno)
	}
	fl.Type = syscall.F_UNLCK
	if err := syscall.FcntlFlock(native.Fd(), syscall.F_SETLK, &fl); err != nil {
		t.Fatalf("native unlock: %v", err)
	}
	if r := setlk(s, h, 5, 1, 0, 4, false); r.Kind != proto.KOk {
		t.Fatalf("daemon lock after native unlock: kind=%d errno=%d", r.Kind, r.Errno)
	}
}

// Closing the file releases the locks held for it, so the range is free.
func TestCloseHandleReleasesLock(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "held.bin")
	if err := os.WriteFile(p, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	h1, _ := open(t, s, 1, p, uint32(syscall.O_RDWR), 0)
	h2, _ := open(t, s, 2, p, uint32(syscall.O_RDWR), 0)
	defer closeHandle(s, h2)
	if r := setlk(s, h1, 1, 1, 0, 9, false); r.Kind != proto.KOk {
		t.Fatalf("lock: kind=%d errno=%d", r.Kind, r.Errno)
	}
	if r := setlk(s, h2, 2, 1, 0, 9, false); r.Kind != proto.KErr || (r.Errno != uint32(syscall.EAGAIN) && r.Errno != uint32(syscall.EACCES)) {
		t.Fatalf("second owner lock while held: kind=%d errno=%d", r.Kind, r.Errno)
	}
	if r := closeHandle(s, h1); r.Kind != proto.KOk {
		t.Fatalf("close locked handle: kind=%d errno=%d", r.Kind, r.Errno)
	}
	if r := setlk(s, h2, 2, 1, 0, 9, false); r.Kind != proto.KOk {
		t.Fatalf("lock after close: kind=%d errno=%d", r.Kind, r.Errno)
	}
}

// A blocking FxSetlkw must be cancellable: the daemon closes the descriptors
// when the connection dies, and the waiter returns instead of parking
// forever. Nothing is left blocked in the kernel either.
func TestSetlkwCancellableByClose(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "wait.bin")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	h1, _ := open(t, s, 1, p, uint32(syscall.O_RDWR), 0)
	h2, _ := open(t, s, 2, p, uint32(syscall.O_RDWR), 0)
	if r := setlk(s, h1, 1, 1, 0, 0, false); r.Kind != proto.KOk {
		t.Fatalf("setlk: kind=%d errno=%d", r.Kind, r.Errno)
	}
	done := make(chan *proto.FxResp, 1)
	go func() { done <- setlk(s, h2, 2, 1, 0, 0, true) }()
	// The waiter must exist before Close: poll the server's own registration
	// instead of sleeping, or a slow machine closes before the request starts
	// and the test proves nothing.
	deadline := time.Now().Add(5 * time.Second)
	for s.waiterCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("Setlkw never registered a waiter")
		}
		time.Sleep(time.Millisecond)
	}
	s.Close()
	select {
	case resp := <-done:
		if resp.Kind == proto.KOk {
			t.Fatal("blocked Setlkw succeeded after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Setlkw was not cancelled by Close")
	}
}

// Close drops every descriptor and lock; later requests are answered with
// EBADF instead of leaking a descriptor on a closed server.
func TestCloseReleasesLocksAndHandles(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "cleanup.bin")
	if err := os.WriteFile(p, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, _ := open(t, s, 1, p, uint32(syscall.O_RDWR), 0)
	if r := setlk(s, h, 3, 1, 0, 9, false); r.Kind != proto.KOk {
		t.Fatalf("lock: kind=%d errno=%d", r.Kind, r.Errno)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	if r := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxPread, Handle: h, Offset: 0, Size: 4}); r.Kind != proto.KErr || r.Errno != uint32(syscall.EBADF) {
		t.Fatalf("pread after close: kind=%d errno=%d", r.Kind, r.Errno)
	}
	if r := s.Handle(&proto.FxReq{ID: 3, Op: proto.FxOpen, Path: p, Flags: uint32(syscall.O_RDONLY)}); r.Kind != proto.KErr || r.Errno != uint32(syscall.EBADF) {
		t.Fatalf("open after close: kind=%d errno=%d", r.Kind, r.Errno)
	}

	// The daemon-side lock must be gone: a native POSIX lock succeeds now.
	native, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	fl := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 10}
	if err := syscall.FcntlFlock(native.Fd(), syscall.F_SETLK, &fl); err != nil {
		t.Fatalf("native lock after server close: %v", err)
	}
	fl.Type = syscall.F_UNLCK
	if err := syscall.FcntlFlock(native.Fd(), syscall.F_SETLK, &fl); err != nil {
		t.Fatalf("native unlock: %v", err)
	}
}

func TestFchmodAndFutimes(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "a.txt")
	h, _ := open(t, s, 1, p, uint32(syscall.O_RDWR), 0)
	defer closeHandle(s, h)
	if r := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxFchmod, Handle: h, Mode: 0o600}); r.Kind != proto.KOk {
		t.Fatalf("fchmod kind=%d errno=%d", r.Kind, r.Errno)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm after fchmod: %o", fi.Mode().Perm())
	}
	if r := s.Handle(&proto.FxReq{ID: 3, Op: proto.FxFutimes, Handle: h, Arg: "1000000000,2000000000"}); r.Kind != proto.KOk {
		t.Fatalf("futimes kind=%d errno=%d", r.Kind, r.Errno)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mtim.Sec != 2 || st.Mtim.Nsec != 0 {
		t.Fatalf("mtime after futimes: %d.%09d", st.Mtim.Sec, st.Mtim.Nsec)
	}
}

// An omitted field must keep the timestamp that is already on the file, not
// stamp it with now: a caller moving mtime must not also touch atime.
func TestFutimesOmitKeepsTimestamp(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "a.txt")
	var before syscall.Stat_t
	if err := syscall.Stat(p, &before); err != nil {
		t.Fatal(err)
	}
	h, _ := open(t, s, 1, p, uint32(syscall.O_RDWR), 0)
	defer closeHandle(s, h)
	// First field only: atime set, mtime omitted.
	if r := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxFutimes, Handle: h, Arg: "1000000000,"}); r.Kind != proto.KOk {
		t.Fatalf("futimes kind=%d errno=%d", r.Kind, r.Errno)
	}
	var after syscall.Stat_t
	if err := syscall.Stat(p, &after); err != nil {
		t.Fatal(err)
	}
	if after.Mtim != before.Mtim {
		t.Fatalf("omit clobbered mtime: got %v want %v", after.Mtim, before.Mtim)
	}
	if after.Atim.Sec != 1 || after.Atim.Nsec != 0 {
		t.Fatalf("atime = %d.%09d, want 1.0", after.Atim.Sec, after.Atim.Nsec)
	}
}

func TestFsyncFile(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "sync.txt")
	if err := os.WriteFile(p, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, _ := open(t, s, 1, p, uint32(syscall.O_RDWR), 0)
	defer closeHandle(s, h)
	if r := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxFsync, Handle: h}); r.Kind != proto.KOk {
		t.Fatalf("fsync: kind=%d errno=%d", r.Kind, r.Errno)
	}
}

func TestPwriteAndFtruncate(t *testing.T) {
	s, root := newServer(t)
	p := filepath.Join(root, "w.bin")
	h, _ := open(t, s, 1, p, uint32(syscall.O_RDWR|syscall.O_CREAT), 0o644)
	defer closeHandle(s, h)
	if w := s.Handle(&proto.FxReq{ID: 2, Op: proto.FxPwrite, Handle: h, Offset: 0, Data: []byte("hello-world")}); w.Kind != proto.KOk || w.Count != 11 {
		t.Fatalf("pwrite kind=%d count=%d", w.Kind, w.Count)
	}
	if tr := s.Handle(&proto.FxReq{ID: 3, Op: proto.FxFtruncate, Handle: h, Offset: 5}); tr.Kind != proto.KOk {
		t.Fatalf("ftruncate kind=%d errno=%d", tr.Kind, tr.Errno)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("content after truncate: %q", got)
	}
}

func TestUnknownOp(t *testing.T) {
	s, _ := newServer(t)
	resp := s.Handle(&proto.FxReq{ID: 1, Op: 99, Path: "/x"})
	if resp.Kind != proto.KErr || !strings.Contains(resp.Err, "unknown") {
		t.Fatalf("unknown op kind=%d err=%q", resp.Kind, resp.Err)
	}
}
