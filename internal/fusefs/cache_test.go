package fusefs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"rsbx/internal/fsremote"
	"rsbx/internal/proto"
)

// The cache windows this file judges are the ones the sandbox actually mounts
// with; `internal/sandbox` pins the same numbers in its own test, so a change
// there that is not mirrored here shows up as a failure rather than silent drift.
const (
	entryWindow = time.Second
	attrWindow  = time.Second
)

var errDaemonDown = errors.New("daemon unreachable")

// cacheRemote counts what the mount asks the daemon for, and can fail one
// operation to model a dropped connection.
type cacheRemote struct {
	server *fsremote.Server

	mu     sync.Mutex
	ops    map[byte]int
	byPath map[string]map[byte]int
	failOp byte
	down   bool
	lost   []func()
	// The session state the daemon would keep for this mount: the names the
	// session established, the mutation epoch, whether one of its commands is
	// running, and the views to announce command starts to.
	// created mirrors the daemon's ledger: each name this session established,
	// with the ledger generation that recorded it.
	created map[string]uint64
	ledger  uint64
	epoch   uint64
	running int
	// dirs mirrors the daemon's record of the directories this session's view
	// resolved while no command was running, with the children each had then.
	dirs   map[string]cacheDir
	forget []func([]string)
}

// cacheDir is one directory as a view last saw it.
type cacheDir struct {
	dev, ino uint64
	names    map[string]struct{}
}

func newCacheRemote() *cacheRemote {
	c := &cacheRemote{
		server: fsremote.NewServer(), ops: map[byte]int{}, byPath: map[string]map[byte]int{},
		created: map[string]uint64{}, dirs: map[string]cacheDir{},
	}
	c.server.UseSession(c)
	return c
}

// The daemon's session state, as the real one is kept there.
func (c *cacheRemote) Created(p string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.created[p]
	return ok
}

func (c *cacheRemote) MarkCreated(p string) {
	c.mu.Lock()
	c.ledger++
	c.created[p] = c.ledger
	c.mu.Unlock()
}

func (c *cacheRemote) LedgerSeq() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ledger
}

func (c *cacheRemote) ForgetCreated(p string, seq uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forgetCreatedLocked(p, seq)
}

func (c *cacheRemote) forgetCreatedLocked(p string, seq uint64) {
	if cur, ok := c.created[p]; ok && cur <= seq {
		delete(c.created, p)
	}
	for name, cur := range c.created {
		if cur <= seq && strings.HasPrefix(name, p+"/") {
			delete(c.created, name)
		}
	}
}

func (c *cacheRemote) MarkRemoved(p string) {
	c.mu.Lock()
	delete(c.created, p)
	c.mu.Unlock()
}

func (c *cacheRemote) State() (uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch, c.running > 0
}

// beginCommand models one of the session's commands starting on the daemon: a
// new mutation epoch and a window in which replies are not retainable.
func (c *cacheRemote) beginCommand() {
	c.mu.Lock()
	c.running++
	c.epoch++
	c.mu.Unlock()
}

// endCommand models the daemon's command-end reconciliation: the directories the
// view last saw are compared with the tree, and the names that disappeared are
// announced. A name that appeared is not attributed to the session: a directory
// comparison cannot tell which side created it.
func (c *cacheRemote) endCommand() {
	c.mu.Lock()
	c.running--
	done := c.running == 0
	c.mu.Unlock()
	if !done {
		return
	}
	forget := c.reconcile()
	if len(forget) == 0 {
		return
	}
	c.mu.Lock()
	fns := append([]func([]string){}, c.forget...)
	c.mu.Unlock()
	for _, fn := range fns {
		fn(forget)
	}
}

func (c *cacheRemote) MarkDir(p string, dev, ino uint64, names []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.dirs[p]; !ok && len(c.dirs) >= 256 {
		return
	}
	kids := make(map[string]struct{}, len(names))
	for _, name := range names {
		kids[name] = struct{}{}
	}
	c.dirs[p] = cacheDir{dev: dev, ino: ino, names: kids}
}

func (c *cacheRemote) OnForget(fn func([]string)) {
	c.mu.Lock()
	c.forget = append(c.forget, fn)
	c.mu.Unlock()
}

func (c *cacheRemote) reconcile() (forget []string) {
	c.mu.Lock()
	before := make(map[string]cacheDir, len(c.dirs))
	for p, d := range c.dirs {
		before[p] = d
	}
	seq := c.ledger
	c.mu.Unlock()
	after := make(map[string]cacheDir, len(before))
	var gone []string
	for p, had := range before {
		var st syscall.Stat_t
		err := syscall.Lstat(p, &st)
		if err != nil {
			forget = append(forget, p)
			// Only absence is evidence that the directory is gone. A permission
			// error means the comparison could not look: the entries may all
			// still be there, so the record below it must survive and the
			// snapshot is kept for the next comparison.
			if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) {
				gone = append(gone, p)
			} else {
				after[p] = had
			}
			continue
		}
		if uint64(st.Dev) != had.dev || st.Ino != had.ino {
			gone = append(gone, p)
			forget = append(forget, p)
			continue
		}
		des, err := os.ReadDir(p)
		if err != nil {
			if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ENOTDIR) {
				forget = append(forget, p)
				after[p] = had
			}
			continue
		}
		now := make(map[string]struct{}, len(des))
		for _, de := range des {
			now[de.Name()] = struct{}{}
		}
		for name := range had.names {
			if _, still := now[name]; !still {
				q := filepath.Join(p, name)
				gone = append(gone, q)
				forget = append(forget, q)
			}
		}
		after[p] = cacheDir{dev: had.dev, ino: had.ino, names: now}
	}
	c.mu.Lock()
	c.dirs = after
	// A name the command removed is gone; its record goes with it, bounded by the
	// generation read with the snapshots. A directory that merely could not be
	// read keeps its records: absence is the only evidence of removal.
	for _, p := range gone {
		c.forgetCreatedLocked(p, seq)
	}
	c.mu.Unlock()
	return forget
}

// command runs fn as one command of this session, the way the daemon runs a
// command it was asked to execute: the tree changes outside the view's
// callbacks.
func (c *cacheRemote) command(fn func()) {
	c.beginCommand()
	defer c.endCommand()
	fn()
}

func (c *cacheRemote) Do(req *proto.FxReq) (*proto.FxResp, error) {
	c.mu.Lock()
	c.ops[req.Op]++
	if req.Path != "" {
		if c.byPath[req.Path] == nil {
			c.byPath[req.Path] = map[byte]int{}
		}
		c.byPath[req.Path][req.Op]++
	}
	fail := c.failOp != 0 && req.Op == c.failOp
	down := c.down
	c.mu.Unlock()

	if fail || down {
		return nil, errDaemonDown
	}
	return c.server.Handle(req), nil
}

// OnLost records the view's invalidation hook, the same contract the real
// session client offers.
func (c *cacheRemote) OnLost(fn func()) {
	c.mu.Lock()
	c.lost = append(c.lost, fn)
	c.mu.Unlock()
}

// lose models a dropped daemon connection: every later request fails and the
// view is told that its retained results are no longer answerable.
func (c *cacheRemote) lose() {
	c.mu.Lock()
	c.down = true
	lost := append([]func(){}, c.lost...)
	c.mu.Unlock()
	for _, fn := range lost {
		fn()
	}
}

func (c *cacheRemote) recover() {
	c.mu.Lock()
	c.down = false
	c.mu.Unlock()
}

func (c *cacheRemote) ReadFile(p string) ([]byte, proto.Attr, error) {
	return fsRemote{s: c.server}.ReadFile(p)
}

func (c *cacheRemote) WriteFile(p string, data []byte) error {
	return fsRemote{s: c.server}.WriteFile(p, data)
}

func (c *cacheRemote) count(op byte) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ops[op]
}

func (c *cacheRemote) countPath(p string, op byte) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.byPath[p][op]
}

func (c *cacheRemote) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ops = map[byte]int{}
	c.byPath = map[string]map[byte]int{}
}

// waitFor polls a counted condition: the kernel releases a handle
// asynchronously, so a count observed immediately after close can still be zero.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (c *cacheRemote) fail(op byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failOp = op
}

// cacheMount mounts the daemon-side tree the way a session mounts it: the
// resolution window is decided per name by the filesystem, attributes are kept
// for one second, and a miss is never remembered.
func cacheMount(t *testing.T) (mnt, root string, remote *cacheRemote) {
	return cacheMountWith(t, func(string) LocalPaths { return noLocal{} })
}

// cacheMountWith mounts the daemon-side tree with a local policy derived from
// the tree's host path. A read-only local tree is how a session receives a
// mounted configuration tree; local answers are kept by the kernel, while
// daemon-derived answers are retained by the view.
func cacheMountWith(t *testing.T, local func(root string) LocalPaths) (mnt, root string, remote *cacheRemote) {
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
	remote = newCacheRemote()
	rootNode := NewRoot(&Layout{Remote: remote, Local: local(root)})
	if err := rootNode.Err(); err != nil {
		rootNode.Close()
		remote.server.Close()
		t.Fatal(err)
	}
	attr, negative := attrWindow, time.Duration(0)
	srv, err := fs.Mount(mnt, rootNode, &fs.Options{
		NullPermissions: true,
		MountOptions: fuse.MountOptions{
			FsName: "rsbx-cache-test", DisableSplice: true, EnableLocks: true,
		},
		EntryTimeout:    nil,
		AttrTimeout:     &attr,
		NegativeTimeout: &negative,
	})
	if err != nil {
		rootNode.Close()
		remote.server.Close()
		t.Skipf("cannot mount FUSE here: %v", err)
	}
	t.Cleanup(func() { srv.Unmount(); rootNode.Close(); remote.server.Close() })
	return mnt, root, remote
}

// readOnlyTree declares one read-only host tree: the shape a session gets for a
// mounted configuration or asset directory. The session never establishes names
// there, so the view may answer the next resolution from its own window.
type readOnlyTree struct{ prefix string }

func (r readOnlyTree) inside(p string) bool {
	return p == r.prefix || strings.HasPrefix(p, r.prefix+"/")
}

func (r readOnlyTree) IsLocal(p string) bool { return r.inside(p) }
func (r readOnlyTree) Writable(string) bool  { return false }
func (r readOnlyTree) Roots() []string       { return []string{r.prefix} }

func hostFile(t *testing.T, root, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// A path resolved once is answered from the view for the rest of the window:
// the second stat must not reach the daemon at all. This is the lower bound the
// contract states, and the behaviour a zero-cache mount cannot produce.
func TestRepeatResolveWithinWindowAsksDaemonNothing(t *testing.T) {
	mnt, root, remote := cacheMountWith(t, func(root string) LocalPaths { return readOnlyTree{prefix: root} })
	p := hostFile(t, root, "config.toml", []byte("setting = 1\n"), 0o644)
	view := inView(mnt, p)

	if _, err := os.Stat(view); err != nil {
		t.Fatalf("first stat: %v", err)
	}
	remote.reset()

	for i := 0; i < 5; i++ {
		st, err := os.Stat(view)
		if err != nil {
			t.Fatalf("repeat stat %d: %v", i, err)
		}
		if st.Size() != int64(len("setting = 1\n")) {
			t.Fatalf("repeat stat %d size = %d", i, st.Size())
		}
	}
	if n := remote.count(proto.FxStat); n != 0 {
		t.Fatalf("repeat resolution inside the window sent %d stat requests, want 0", n)
	}

	// The window is a bound, not a permanent answer: once it has passed the next
	// resolution has to ask again. An over-long window passes the assertion above
	// and fails here, which is the difference between a one-second retention and
	// a view that stops following the daemon.
	time.Sleep(entryWindow + 150*time.Millisecond)
	if _, err := os.Stat(view); err != nil {
		t.Fatalf("stat after the window: %v", err)
	}
	if n := remote.count(proto.FxStat); n == 0 {
		t.Fatal("the first resolution after the window was still answered from the view")
	}
}

// A miss is never remembered: each probe of a name that does not exist has to
// ask again, so a file created right after a failed lookup is visible at once.
//
// The count is taken from the second probe onwards, after the ancestors are
// already resolved: a first probe of the path also resolves every ancestor, and
// that traffic would make "zero repeat requests" look false for a reason that
// has nothing to do with the miss. The assertion that bites is the repeat: a
// remembered miss answers from the view and sends nothing, which is exactly the
// stale "not found" the contract forbids.
func TestMissingNameIsNeverRemembered(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	missing := filepath.Join(root, "absent.txt")
	view := inView(mnt, missing)

	if _, err := os.Stat(view); !os.IsNotExist(err) {
		t.Fatalf("first probe of a missing name: %v, want ENOENT", err)
	}
	remote.reset()
	for i := 0; i < 2; i++ {
		if _, err := os.Stat(view); !os.IsNotExist(err) {
			t.Fatalf("repeat probe %d of a missing name: %v, want ENOENT", i, err)
		}
	}
	if n := remote.count(proto.FxStat); n < 2 {
		t.Fatalf("2 repeat probes of a missing name sent %d requests, want one each (a miss is never remembered)", n)
	}

	// The shape the reasoning started from: the name appears right after the
	// failed lookups, and the next read has to find it.
	if err := os.WriteFile(missing, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(view)
	if err != nil {
		t.Fatalf("the name created after the failed lookups was still not visible: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("read back %q, want %q", got, "payload")
	}
}

// A name another client established is retained for one second even in a
// writable tree: the exception in C-19 covers names this session created, not
// every name in a tree the session may write. The window is a bound: the next
// resolution after it reaches the daemon again.
func TestExternalRemoteNameIsRetainedForOneSecond(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	p := hostFile(t, root, "project.txt", []byte("content"), 0o644)
	view := inView(mnt, p)

	if _, err := os.Stat(view); err != nil {
		t.Fatalf("first stat: %v", err)
	}
	remote.reset()
	for i := 0; i < 3; i++ {
		if _, err := os.Stat(view); err != nil {
			t.Fatalf("repeat stat %d: %v", i, err)
		}
	}
	if n := remote.countPath(p, proto.FxStat); n != 0 {
		t.Fatalf("a name established by another client sent %d repeat stat requests inside the window, want 0", n)
	}

	time.Sleep(entryWindow + 150*time.Millisecond)
	if _, err := os.Stat(view); err != nil {
		t.Fatalf("stat after the window: %v", err)
	}
	if n := remote.countPath(p, proto.FxStat); n == 0 {
		t.Fatal("the first resolution after the window was still answered from the view")
	}
}

// A name this session created is never retained. The daemon marks it on the
// reply, and every later resolution has to reach the daemon, so a delete or
// rename by this session is visible on the next query rather than a second
// later.
func TestSessionCreatedNameAsksDaemonOnEveryQuery(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	view := filepath.Join(mnt, root, "made.txt")
	if err := os.WriteFile(view, []byte("content"), 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}

	for i := 0; i < 3; i++ {
		remote.reset()
		if _, err := os.Stat(view); err != nil {
			t.Fatalf("stat %d: %v", i, err)
		}
		if n := remote.countPath(filepath.Join(root, "made.txt"), proto.FxStat); n == 0 {
			t.Fatalf("query %d of a name this session created was answered from the view", i)
		}
	}
}

// A retained result is not an answer after the daemon connection is gone.
// C-19 requires the local program's remote path access to fail explicitly,
// which is only possible because the view keeps daemon-derived results and
// drops them when the connection dies. A kernel-held entry has no such signal.
func TestRetainedRemoteResultIsNotAnsweredAfterDisconnect(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	p := hostFile(t, root, "warm.txt", []byte("bytes"), 0o644)
	view := inView(mnt, p)

	if _, err := os.Stat(view); err != nil {
		t.Fatalf("preheat stat: %v", err)
	}
	remote.reset()
	if _, err := os.Stat(view); err != nil {
		t.Fatalf("repeat stat inside the window: %v", err)
	}
	if n := remote.countPath(p, proto.FxStat); n != 0 {
		t.Fatalf("preheated name sent %d repeat requests, want 0", n)
	}

	remote.lose()
	if _, err := os.Stat(view); err == nil {
		t.Fatal("a stat after the daemon connection was lost was answered from a retained result")
	} else if os.IsNotExist(err) {
		t.Fatalf("a disconnected remote path reported ENOENT instead of the explicit failure C-19 requires: %v", err)
	}

	remote.recover()
	if _, err := os.Stat(view); err != nil {
		t.Fatalf("stat after the connection recovered: %v", err)
	}
}

// The same rule covers a structural ancestor whose attributes came from the
// daemon. Such a directory is locally known, but its mode, inode and size are
// remote facts; after a disconnect the query must fail rather than report the
// attributes the view obtained before it.
func TestUnionAncestorIsNotAnsweredAfterDisconnect(t *testing.T) {
	mnt, root, remote := cacheMountWith(t, func(root string) LocalPaths { return readOnlyTree{prefix: root} })
	ancestor := filepath.Dir(root)
	view := inView(mnt, ancestor)

	if _, err := os.Stat(view); err != nil {
		t.Fatalf("preheat stat of the structural ancestor: %v", err)
	}
	remote.reset()
	if _, err := os.Stat(view); err != nil {
		t.Fatalf("repeat stat inside the window: %v", err)
	}
	if n := remote.countPath(ancestor, proto.FxStat); n != 0 {
		t.Fatalf("structural ancestor sent %d repeat requests, want 0", n)
	}

	remote.lose()
	if _, err := os.Stat(view); err == nil {
		t.Fatal("a structural ancestor was answered from a retained remote attribute set after the connection was lost")
	} else if os.IsNotExist(err) {
		t.Fatalf("a disconnected structural ancestor reported ENOENT instead of an explicit failure: %v", err)
	}
}

// A directory enumeration is one result with one expiry. Re-enumerating inside
// the window reuses it and asks the daemon for no listing; after the window the
// next enumeration obtains a new result.
func TestRemoteDirectoryListingIsRetainedForOneSecond(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	dir := filepath.Join(root, "listed")
	hostFile(t, dir, "one.txt", []byte("one"), 0o644)
	hostFile(t, dir, "two.txt", []byte("two"), 0o644)
	view := inView(mnt, dir)

	if _, err := os.ReadDir(view); err != nil {
		t.Fatalf("first enumeration: %v", err)
	}
	remote.reset()
	if _, err := os.ReadDir(view); err != nil {
		t.Fatalf("repeat enumeration inside the window: %v", err)
	}
	if n := remote.count(proto.FxList); n != 0 {
		t.Fatalf("a repeat enumeration inside the window sent %d listing requests, want 0", n)
	}

	time.Sleep(entryWindow + 150*time.Millisecond)
	if _, err := os.ReadDir(view); err != nil {
		t.Fatalf("enumeration after the window: %v", err)
	}
	if n := remote.count(proto.FxList); n == 0 {
		t.Fatal("the first enumeration after the window was still answered from the view")
	}
}

// Child attributes that arrived with a listing expire with it. A stat of a
// listed child inside the window asks the daemon nothing; re-enumerating in the
// middle does not restart the window, so the same child reaches the daemon once
// the original listing is a second old.
func TestListedChildAttributesExpireWithTheListing(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	dir := filepath.Join(root, "children")
	child := hostFile(t, dir, "child.txt", []byte("bytes"), 0o644)
	viewDir, viewChild := inView(mnt, dir), inView(mnt, child)

	if _, err := os.ReadDir(viewDir); err != nil {
		t.Fatalf("first enumeration: %v", err)
	}
	remote.reset()
	if _, err := os.Stat(viewChild); err != nil {
		t.Fatalf("stat of a listed child: %v", err)
	}
	if n := remote.countPath(child, proto.FxStat); n != 0 {
		t.Fatalf("a listed child's attributes sent %d requests, want 0 (they share the listing's expiry)", n)
	}

	time.Sleep(600 * time.Millisecond)
	if _, err := os.ReadDir(viewDir); err != nil {
		t.Fatalf("mid-window enumeration: %v", err)
	}
	if n := remote.count(proto.FxList); n != 0 {
		t.Fatalf("a mid-window enumeration sent %d listing requests, want 0 (it must not renew the window)", n)
	}

	time.Sleep(550 * time.Millisecond)
	if _, err := os.Stat(viewChild); err != nil {
		t.Fatalf("stat after the listing window: %v", err)
	}
	if n := remote.countPath(child, proto.FxStat); n == 0 {
		t.Fatal("a child still answered from an expired listing: re-enumeration must not restart its expiry")
	}
}

// A change this session made has to be visible on the next query, not after a
// retention window. The session reaches the tree two ways: through this view,
// and through the commands it runs on the daemon. Both are exercised here,
// because only the first passes through the filesystem's own callbacks.
func TestSessionMutationsAreVisibleOnTheNextQuery(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	view := func(rel string) string { return filepath.Join(mnt, root, rel) }

	// Through the view: make a directory, remove it, ask whether it is gone.
	dir := view("made")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("stat after mkdir: %v", err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatalf("rmdir: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("stat right after rmdir = %v, want ENOENT", err)
	}

	// Through the view: create a name, unlink it, ask whether it is gone.
	file := view("gone.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("stat right after unlink = %v, want ENOENT", err)
	}

	// Through the view: rename, then ask about both names.
	before, after := view("before.txt"), view("after.txt")
	if err := os.WriteFile(before, []byte("moved"), 0o644); err != nil {
		t.Fatalf("create before rename: %v", err)
	}
	if err := os.Rename(before, after); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := os.Stat(before); !os.IsNotExist(err) {
		t.Fatalf("old name right after rename = %v, want ENOENT", err)
	}
	if got, err := os.ReadFile(after); err != nil || string(got) != "moved" {
		t.Fatalf("new name after rename = %q, %v", got, err)
	}

	// On the daemon: build a tree through this view, then let a session command
	// remove it. The view never sees the removal, so its own resolution has to be
	// gone before the next query.
	tree := view("work")
	if err := os.MkdirAll(filepath.Join(tree, "deep"), 0o755); err != nil {
		t.Fatalf("mkdir -p: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tree, "deep", "f"), []byte("q"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(tree); err != nil {
		t.Fatalf("stat before the daemon removed the tree: %v", err)
	}
	remote.command(func() {
		if err := os.RemoveAll(filepath.Join(root, "work")); err != nil {
			t.Fatalf("daemon-side removal: %v", err)
		}
	})
	if _, err := os.Stat(tree); !os.IsNotExist(err) {
		t.Fatalf("stat after a daemon-side removal = %v, want ENOENT", err)
	}

	// On the daemon: rename a tree the view already resolved. The old name has to
	// stop resolving on the next query and the new name has to read.
	src, dst := view("tree-a"), view("tree-b")
	if err := os.MkdirAll(filepath.Join(src, "x", "y"), 0o755); err != nil {
		t.Fatalf("mkdir tree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "x", "y", "f"), []byte("deep"), 0o644); err != nil {
		t.Fatalf("write tree: %v", err)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("stat tree before rename: %v", err)
	}
	remote.command(func() {
		if err := os.Rename(filepath.Join(root, "tree-a"), filepath.Join(root, "tree-b")); err != nil {
			t.Fatalf("daemon-side rename: %v", err)
		}
	})
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("old name after a daemon-side rename = %v, want ENOENT", err)
	}
	if got, err := os.ReadFile(filepath.Join(dst, "x", "y", "f")); err != nil || string(got) != "deep" {
		t.Fatalf("new name after a daemon-side rename = %q, %v", got, err)
	}
}

// A name removed by one of the session's own commands stops being answerable at
// once: the command never passes through the view, so the daemon reports the
// removal and the next query reaches it. A command that changes nothing must
// not cost the view the answers it already holds.
func TestDaemonCommandMutationIsVisibleOnTheNextQuery(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	p := filepath.Join(root, "built.txt")
	view := inView(mnt, p)

	// Control: a name another party established keeps its window across a
	// command that changed nothing. The command changed no directory, so the
	// daemon has nothing to attribute to it.
	other := hostFile(t, root, "other.txt", []byte("o"), 0o644)
	otherView := inView(mnt, other)
	if _, err := os.Stat(otherView); err != nil {
		t.Fatalf("stat of another party's name: %v", err)
	}
	remote.reset()
	remote.command(func() {})
	if _, err := os.Stat(otherView); err != nil {
		t.Fatalf("stat after a command that changed nothing: %v", err)
	}
	if n := remote.countPath(other, proto.FxStat); n != 0 {
		t.Fatalf("a command that changed nothing sent %d requests for another party's retained name", n)
	}

	remote.command(func() {
		if err := os.WriteFile(p, []byte("v1"), 0o644); err != nil {
			t.Fatalf("daemon-side create: %v", err)
		}
	})
	if _, err := os.Stat(view); err != nil {
		t.Fatalf("stat after the command created the name: %v", err)
	}

	remote.command(func() {
		if err := os.Remove(p); err != nil {
			t.Fatalf("daemon-side removal: %v", err)
		}
	})
	if _, err := os.Stat(view); !os.IsNotExist(err) {
		t.Fatalf("stat after the session's command removed the name = %v, want ENOENT", err)
	}
}

// A name one of the session's commands created is an ordinary positive entry:
// it is retained for one second counted from the moment the view obtained the
// result, and a later delete does not start a new window. The query after the
// original expiry must reach the daemon even though the delete happened less
// than a second before it.
func TestCommandCreatedNameExpiryStartsAtItsResult(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	p := filepath.Join(root, "built.txt")
	view := inView(mnt, p)

	// The command compares the directories the view last saw, so the parent has
	// to be listed first: without a recorded baseline the removal below has
	// nothing to be compared against and would go unannounced.
	if _, err := os.ReadDir(filepath.Join(mnt, root)); err != nil {
		t.Fatalf("list the parent: %v", err)
	}
	remote.command(func() {
		if err := os.WriteFile(p, []byte("v1"), 0o644); err != nil {
			t.Fatalf("daemon-side create: %v", err)
		}
	})
	// This query obtains the result; the window starts here.
	if _, err := os.Stat(view); err != nil {
		t.Fatalf("stat after the command created the name: %v", err)
	}
	remote.reset()
	if _, err := os.Stat(view); err != nil {
		t.Fatalf("repeat stat inside the window: %v", err)
	}
	if n := remote.countPath(p, proto.FxStat); n != 0 {
		t.Fatalf("a name the session's command created sent %d repeat requests inside the window, want 0", n)
	}

	// Delete well inside the window, then query after the original expiry but
	// less than a second after the delete. A view that restarted the window on
	// the delete would still answer here.
	time.Sleep(400 * time.Millisecond)
	remote.command(func() {
		if err := os.Remove(p); err != nil {
			t.Fatalf("daemon-side removal: %v", err)
		}
	})
	remote.reset()
	time.Sleep(entryWindow - 400*time.Millisecond + 150*time.Millisecond)
	if _, err := os.Stat(view); !os.IsNotExist(err) {
		t.Fatalf("stat after the original window = %v, want ENOENT", err)
	}
	if n := remote.countPath(p, proto.FxStat); n == 0 {
		t.Fatal("the query after the original expiry was answered from the view")
	}
}

// A name this session created loses its provenance once an observation finds it
// gone. The command that removed it can create the same spelling again, and what
// appears then is not the name this session established: it is an ordinary
// positive entry and keeps the one-second window. Without retiring the record on
// the confirmed absence, the re-created name would inherit it from the first one
// and ask the daemon on every query inside the window.
func TestRecreatedNameDoesNotInheritAnOldCreationRecord(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	p := filepath.Join(root, "made.txt")
	view := inView(mnt, p)

	// This session creates the name, so every query reaches the daemon.
	if err := os.WriteFile(view, []byte("first"), 0o644); err != nil {
		t.Fatalf("create through the view: %v", err)
	}
	for i := 0; i < 2; i++ {
		remote.reset()
		if _, err := os.Stat(view); err != nil {
			t.Fatalf("stat %d of the created name: %v", i, err)
		}
		if n := remote.countPath(p, proto.FxStat); n == 0 {
			t.Fatalf("query %d of a name this session created was answered from the view", i)
		}
	}

	// The command removes it; the next query observes the absence.
	remote.command(func() {
		if err := os.Remove(p); err != nil {
			t.Fatalf("daemon-side removal: %v", err)
		}
	})
	if _, err := os.Stat(view); !os.IsNotExist(err) {
		t.Fatalf("stat after the command removed the name = %v, want ENOENT", err)
	}

	// The command creates the same spelling again. That is a different name, so
	// it keeps the ordinary window: the first query asks the daemon, and a
	// repeat inside the window asks nothing.
	remote.command(func() {
		if err := os.WriteFile(p, []byte("second"), 0o644); err != nil {
			t.Fatalf("daemon-side recreate: %v", err)
		}
	})
	remote.reset()
	if _, err := os.Stat(view); err != nil {
		t.Fatalf("stat after the command recreated the name: %v", err)
	}
	if n := remote.countPath(p, proto.FxStat); n == 0 {
		t.Fatal("the re-created name was answered from the view on its first query")
	}
	remote.reset()
	for i := 0; i < 2; i++ {
		if _, err := os.Stat(view); err != nil {
			t.Fatalf("repeat stat %d of the re-created name: %v", i, err)
		}
	}
	if n := remote.countPath(p, proto.FxStat); n != 0 {
		t.Fatalf("the re-created name sent %d repeat requests inside the window, want 0", n)
	}
}

// A lookup that could not be answered is not a name that disappeared. A command
// that takes search permission off a parent directory makes the daemon's
// comparison see EACCES for a child that is still there; the record of a name
// this session created must survive that, so once the permission is back every
// query still reaches the daemon. A view that retired the record here would
// answer from its own cache and break the first C-19 exception.
func TestUnreadableParentKeepsTheCreationRecord(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so EACCES cannot be produced")
	}
	mnt, root, remote := cacheMount(t)
	outer := filepath.Join(root, "outer")
	inner := filepath.Join(outer, "inner")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	p := filepath.Join(inner, "made.txt")
	view := inView(mnt, p)

	// This session creates the name, so every query must reach the daemon. The
	// directory is resolved too, which is what the daemon later compares.
	if err := os.WriteFile(view, []byte("first"), 0o644); err != nil {
		t.Fatalf("create through the view: %v", err)
	}
	if _, err := os.Stat(inView(mnt, inner)); err != nil {
		t.Fatalf("stat the containing directory: %v", err)
	}

	// A command takes search permission off the grandparent, so the daemon's
	// comparison cannot reach the directory the view resolved: Lstat on it
	// fails with EACCES, and nothing was removed.
	remote.command(func() {
		if err := os.Chmod(outer, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
	})
	if err := os.Chmod(outer, 0o755); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(outer, 0o755) })

	// The name was never removed or recreated. Every query still has to ask.
	for i := 0; i < 2; i++ {
		remote.reset()
		if _, err := os.Stat(view); err != nil {
			t.Fatalf("stat %d after the permission was restored: %v", i, err)
		}
		if n := remote.countPath(p, proto.FxStat); n == 0 {
			t.Fatalf("query %d of a name this session created was answered from the view", i)
		}
	}
}

// A reply produced while one of the session's commands runs describes a tree
// that command may still change, so it is never retained: the next query has to
// reach the daemon even though the command has since finished.
func TestReplyDuringASessionCommandIsNotRetained(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	p := filepath.Join(root, "during.txt")
	view := inView(mnt, p)

	remote.beginCommand()
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(view); err != nil {
		t.Fatalf("stat while the command ran: %v", err)
	}
	remote.endCommand()

	remote.reset()
	if _, err := os.Stat(view); err != nil {
		t.Fatalf("stat after the command: %v", err)
	}
	if n := remote.countPath(p, proto.FxStat); n == 0 {
		t.Fatal("a reply produced while a session command ran was retained")
	}
}

// Closing a read-only handle has no durability to wait for: no implicit sync
// may be sent, while the daemon handle is still closed so locks are released.
func TestReadOnlyCloseSkipsImplicitSyncButStillCloses(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	p := hostFile(t, root, "readable.txt", []byte("bytes\n"), 0o644)
	view := inView(mnt, p)

	f, err := os.Open(view)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := f.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	remote.reset()
	if err := f.Close(); err != nil {
		t.Fatalf("close read-only: %v", err)
	}

	if n := remote.count(proto.FxFsync); n != 0 {
		t.Fatalf("closing a read-only handle sent %d sync requests, want 0", n)
	}
	waitFor(t, "the read-only handle to be released", func() bool { return remote.count(proto.FxClose) == 1 })
	if n := remote.count(proto.FxFsync); n != 0 {
		t.Fatalf("closing a read-only handle sent %d sync requests, want 0", n)
	}
}

// A handle opened for writing still syncs on close: the bytes it wrote must be
// durable before the program is told the close succeeded.
func TestWritableCloseStillSyncs(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	p := hostFile(t, root, "writable.txt", []byte("old\n"), 0o644)

	f, err := os.OpenFile(inView(mnt, p), os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("open for write: %v", err)
	}
	if _, err := f.Write([]byte("new\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	remote.reset()
	if err := f.Close(); err != nil {
		t.Fatalf("close writable: %v", err)
	}
	if n := remote.count(proto.FxFsync); n != 1 {
		t.Fatalf("closing a writable handle sent %d sync requests, want 1", n)
	}
}

// A program's own fsync is a durability request and must still reach the
// daemon even though the close-time sync is skipped for the same handle.
func TestExplicitFsyncStillReachesDaemon(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	p := hostFile(t, root, "explicit.txt", []byte("bytes\n"), 0o644)

	f, err := os.OpenFile(inView(mnt, p), os.O_RDONLY, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	remote.reset()
	if err := f.Sync(); err != nil {
		t.Fatalf("explicit fsync: %v", err)
	}
	if n := remote.count(proto.FxFsync); n != 1 {
		t.Fatalf("explicit fsync sent %d sync requests, want 1", n)
	}
}

// A write whose sync fails must still be reported. Skipping the implicit sync
// applies to read-only handles only; a writer that could not be made durable
// must not be told the close succeeded.
func TestWriteThenSyncFailureStillFails(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	p := hostFile(t, root, "durability.txt", []byte("old\n"), 0o644)

	f, err := os.OpenFile(inView(mnt, p), os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := f.Write([]byte("new\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	remote.fail(proto.FxFsync)
	if err := f.Close(); err == nil {
		t.Fatal("close succeeded although the write could not be synced")
	}
}

// The shapes a program uses to build state must work inside the window: making
// a directory, writing into it and reading the bytes straight back.
func TestMkdirWriteReadBackWithinWindow(t *testing.T) {
	mnt, root, _ := cacheMount(t)
	dir := inView(mnt, filepath.Join(root, "made", "deeper"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir -p: %v", err)
	}
	p := filepath.Join(dir, "object")
	if err := os.WriteFile(p, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("read back %q, want %q", got, "payload")
	}
}

// Another writer replacing the file is visible at the end of the window, and an
// already-open handle keeps the bytes it opened with.
func TestReplacementVisibleAfterWindowAndOldHandleKeepsBytes(t *testing.T) {
	mnt, root, _ := cacheMount(t)
	p := hostFile(t, root, "shared.txt", []byte("first-version"), 0o644)
	view := inView(mnt, p)

	held, err := os.Open(view)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer held.Close()
	if _, err := os.Stat(view); err != nil {
		t.Fatalf("stat before replace: %v", err)
	}

	// Another client replaces the file behind this view.
	tmp := filepath.Join(root, ".shared.tmp")
	if err := os.WriteFile(tmp, []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatal(err)
	}

	time.Sleep(entryWindow + 150*time.Millisecond)
	got, err := os.ReadFile(view)
	if err != nil {
		t.Fatalf("read after window: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("after the window the view serves %q, want the replacement %q", got, "second")
	}

	buf := make([]byte, 32)
	n, _ := held.ReadAt(buf, 0)
	if string(buf[:n]) != "first-version" {
		t.Fatalf("the open handle serves %q, want the bytes it opened with", buf[:n])
	}
}

// A descriptor duplicated across two owners must keep working after one of them
// closes it, and every client close still reaches the daemon so locks are
// released on the real descriptor rather than only in the client.
func TestDupThenCloseKeepsDescriptorAndReleasesLocks(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	p := hostFile(t, root, "locked.txt", []byte("bytes\n"), 0o644)
	view := inView(mnt, p)

	f, err := os.Open(view)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	dupFD, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	dup := os.NewFile(uintptr(dupFD), p)

	// Take a lock through the duplicated descriptor and release it again, so the
	// lock path is exercised through a handle opened read-only.
	lk := syscall.Flock_t{Type: syscall.F_RDLCK, Whence: 0, Start: 0, Len: 0}
	if err := syscall.FcntlFlock(dup.Fd(), syscall.F_SETLK, &lk); err != nil {
		t.Fatalf("set read lock: %v", err)
	}
	unlock := syscall.Flock_t{Type: syscall.F_UNLCK, Whence: 0, Start: 0, Len: 0}
	if err := syscall.FcntlFlock(dup.Fd(), syscall.F_SETLK, &unlock); err != nil {
		t.Fatalf("release read lock: %v", err)
	}

	remote.reset()
	if err := f.Close(); err != nil {
		t.Fatalf("close original: %v", err)
	}
	// The duplicate still owns the descriptor, so the daemon handle is not closed
	// yet; reading through it must keep working.
	buf := make([]byte, 16)
	if n, err := dup.ReadAt(buf, 0); err != nil && n == 0 {
		t.Fatalf("read through the duplicate after the original closed: %v", err)
	}
	if err := dup.Close(); err != nil {
		t.Fatalf("close duplicate: %v", err)
	}
	waitFor(t, "the last close to reach the daemon", func() bool { return remote.count(proto.FxClose) == 1 })
}

// A read whose daemon request fails must fail the program's read. go-fuse takes
// the reply bytes from the ReadResult and overwrites the errno with OK, so an
// error returned alongside a non-nil result is silently dropped and a dead
// connection looks like a clean end of file. The contract says an incomplete
// read ends in an explicit failure, so this must not be presented as success.
func TestFailedReadIsNotPresentedAsEndOfFile(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	p := hostFile(t, root, "remote.bin", []byte("payload"), 0o644)
	view := inView(mnt, p)

	f, err := os.Open(view)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	remote.fail(proto.FxPread)

	buf := make([]byte, 4)
	n, err := f.Read(buf)
	if err == nil {
		t.Fatalf("read against a failing daemon returned %d bytes and no error, want an explicit failure", n)
	}
	if n != 0 {
		t.Fatalf("a failed read reported %d bytes, want none", n)
	}
	// End of file is not a failure. It is how a dropped connection used to
	// surface: the read looked complete, so the caller had no reason to retry.
	if errors.Is(err, io.EOF) {
		t.Fatalf("a failed read looked like a clean end of file: %v", err)
	}
}
