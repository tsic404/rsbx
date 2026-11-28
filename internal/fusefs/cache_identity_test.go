package fusefs

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"

	"rsbx/internal/proto"
)

// A reply sent before the connection was lost must not be stored after it. The
// request it answers may belong to a daemon that is already gone, and the
// disconnect has just dropped everything that came from that connection.
func TestReplySentBeforeADisconnectIsNotRetained(t *testing.T) {
	state := newMountState(&Layout{})
	src := backing{kind: sourceRemote, attr: proto.Attr{Mode: proto.SIFREG, Ino: 7}}
	id := dirID{dev: 1, ino: 2}
	ents := []proto.DirEntry{{Name: "a", Attr: proto.Attr{Mode: proto.SIFREG, Ino: 9}}}

	stale := state.beginRequest()
	state.invalidate()
	state.retainResolve("/x", src, false, false, stale)
	state.retainListing(id, "/d", ents, false, stale)
	if _, ok := state.retainedResolve("/x"); ok {
		t.Fatal("a resolution whose request predates the disconnect was retained")
	}
	if _, ok := state.retainedListing(id); ok {
		t.Fatal("a listing whose request predates the disconnect was retained")
	}
	if _, ok := state.retainedResolve("/d/a"); ok {
		t.Fatal("a listing whose request predates the disconnect filled the child cache")
	}

	fresh := state.beginRequest()
	state.retainResolve("/y", src, false, false, fresh)
	state.retainListing(id, "/d", ents, false, fresh)
	if _, ok := state.retainedResolve("/y"); !ok {
		t.Fatal("a resolution sent in the current generation was dropped")
	}
	if _, ok := state.retainedListing(id); !ok {
		t.Fatal("a listing sent in the current generation was dropped")
	}
}

// A descriptor listing reads each child from the directory it opened. A bare
// name resolved against the daemon's working directory would report a
// same-named object from there instead of the child that was listed.
func TestListedChildAttributesComeFromTheListedDirectory(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	dir := filepath.Join(root, "enum")
	child := hostFile(t, dir, "target", []byte("payload"), 0o644)

	// A directory of the same name in the daemon's working directory, with a
	// different type and size than the listed child.
	decoy := t.TempDir()
	if err := os.MkdirAll(filepath.Join(decoy, "target"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(decoy)

	if _, err := os.ReadDir(inView(mnt, dir)); err != nil {
		t.Fatalf("enumeration: %v", err)
	}
	remote.reset()
	st, err := os.Stat(inView(mnt, child))
	if err != nil {
		t.Fatalf("stat of a listed child: %v", err)
	}
	if st.IsDir() {
		t.Fatal("a listed child took the attributes of a same-named directory in the daemon's working directory")
	}
	if st.Size() != int64(len("payload")) {
		t.Fatalf("listed child size = %d, want %d", st.Size(), len("payload"))
	}
	if n := remote.countPath(child, proto.FxStat); n != 0 {
		t.Fatalf("a listed child sent %d stat requests, want 0 (it travels with the listing)", n)
	}
}

// A directory handle answers for the inode it opened, and a directory replaced
// at its old path is a different directory with its own children. A listing
// filed under the name would hand one directory's children to the other.
func TestDirectoryListingFollowsTheInodeAcrossAPathSwap(t *testing.T) {
	mnt, root, remote := cacheMount(t)
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	hostFile(t, a, "one.txt", []byte("one"), 0o644)
	hostFile(t, b, "two.txt", []byte("two"), 0o644)
	viewA := inView(mnt, a)

	f, err := os.Open(viewA)
	if err != nil {
		t.Fatalf("open a: %v", err)
	}
	defer f.Close()

	remote.command(func() {
		held := filepath.Join(root, "held")
		if err := os.Rename(a, held); err != nil {
			t.Fatalf("move a aside: %v", err)
		}
		if err := os.Rename(b, a); err != nil {
			t.Fatalf("move b to a: %v", err)
		}
		if err := os.Rename(held, b); err != nil {
			t.Fatalf("move the old a to b: %v", err)
		}
	})

	// The open handle still lists the directory it opened.
	heldEnts, err := f.ReadDir(-1)
	if err != nil {
		t.Fatalf("list the open handle: %v", err)
	}
	if got := entryNames(heldEnts); len(got) != 1 || got[0] != "one.txt" {
		t.Fatalf("an open handle listed %v, want [one.txt]", got)
	}

	// The handle's listing describes a directory that now lives at b, so its
	// children are not answers for the name a, and are answers for b.
	remote.reset()
	if _, err := os.Stat(filepath.Join(viewA, "one.txt")); !os.IsNotExist(err) {
		t.Fatalf("a child of the moved directory was answered at its old path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(inView(mnt, b), "one.txt")); err != nil {
		t.Fatalf("the moved directory's child is missing at its current path: %v", err)
	}
	if n := remote.countPath(filepath.Join(b, "one.txt"), proto.FxStat); n != 0 {
		t.Fatalf("a child of the listed inode sent %d stat requests, want 0 (it travels with the listing)", n)
	}
}

// A listing belongs to the inode it was read from, and it names its children
// only when the daemon confirmed the name that inode currently has. Keyed by
// path instead, one directory's entries would answer for another directory
// placed at that path.
func TestListingsAreKeyedByInodeAndNamedByConfirmation(t *testing.T) {
	state := newMountState(&Layout{})
	first, second := dirID{dev: 1, ino: 10}, dirID{dev: 1, ino: 11}
	one := []proto.DirEntry{{Name: "one", Attr: proto.Attr{Mode: proto.SIFREG, Ino: 20}}}
	two := []proto.DirEntry{{Name: "two", Attr: proto.Attr{Mode: proto.SIFREG, Ino: 21}}}

	sent := state.beginRequest()
	state.retainListing(first, "/a", one, false, sent)
	if _, ok := state.retainedListing(second); ok {
		t.Fatal("a directory placed at the same path was answered from the other inode's listing")
	}

	// The daemon could not confirm a name for this listing, so it is kept for
	// the handle that read it and files no child under any path.
	sent = state.beginRequest()
	state.retainListing(second, "", two, false, sent)
	if held, ok := state.retainedListing(second); !ok || len(held) != 1 || held[0].Name != "two" {
		t.Fatalf("a handle's own listing was not kept: %v, %v", held, ok)
	}
	if _, ok := state.retainedResolve("/a/two"); ok {
		t.Fatal("a listing without a confirmed name filed a child under a path")
	}
}

// statRemote answers every stat with one fixed attribute set.
type statRemote struct{ attr proto.Attr }

func (r *statRemote) Do(req *proto.FxReq) (*proto.FxResp, error) {
	return &proto.FxResp{ID: req.ID, Kind: proto.KStat, Attr: r.attr}, nil
}

func (r *statRemote) ReadFile(string) ([]byte, proto.Attr, error) { return nil, proto.Attr{}, nil }
func (r *statRemote) WriteFile(string, []byte) error              { return nil }

// The attributes a query obtains are the ones that may be reused. Retaining the
// node's original attributes stores the value the query just replaced, so the
// next query inside the window reads back the old one.
func TestRefreshedAttributesAreTheOnesRetained(t *testing.T) {
	old := proto.Attr{Mode: proto.SIFREG | 0o644, Ino: 11, Dev: 1, Size: 3}
	fresh := proto.Attr{Mode: proto.SIFREG | 0o644, Ino: 11, Dev: 1, Size: 12}
	lay := &Layout{Remote: &statRemote{attr: fresh}}
	state := newMountState(lay)
	n := &Node{lay: lay, state: state, path: "/grow.txt", src: backing{kind: sourceRemote, attr: old}}

	var out fuse.AttrOut
	if errno := n.Getattr(context.Background(), nil, &out); errno != 0 {
		t.Fatalf("getattr: %v", errno)
	}
	if out.Attr.Size != fresh.Size {
		t.Fatalf("getattr returned size %d, want %d", out.Attr.Size, fresh.Size)
	}
	held, ok := state.retainedResolve("/grow.txt")
	if !ok {
		t.Fatal("the answer of a positive attribute query was not retained")
	}
	if held.attr.Size != fresh.Size {
		t.Fatalf("the retained attributes have size %d, want the returned %d", held.attr.Size, fresh.Size)
	}
}

func entryNames(ents []os.DirEntry) []string {
	names := make([]string, len(ents))
	for i, entry := range ents {
		names[i] = entry.Name()
	}
	sort.Strings(names)
	return names
}

// A reply from the connection that is already gone must not evict what the
// current connection has obtained in the meantime.
func TestStaleReplyDoesNotEvictCurrentResults(t *testing.T) {
	state := newMountState(&Layout{})
	src := backing{kind: sourceRemote, attr: proto.Attr{Mode: proto.SIFREG, Ino: 7}}
	id := dirID{dev: 1, ino: 2}
	ents := []proto.DirEntry{{Name: "a", Attr: proto.Attr{Mode: proto.SIFREG, Ino: 9}}}

	state.invalidate()
	current := state.beginRequest()
	state.retainResolve("/x", src, false, false, current)
	state.retainListing(id, "/d", ents, false, current)

	stale := freshness{epoch: current.epoch - 1}
	state.retainResolve("/x", src, false, false, stale)
	state.retainListing(id, "/d", ents, false, stale)
	// A created or volatile reply from the old connection is equally unable to
	// remove what the current one holds.
	state.retainResolve("/x", src, true, true, stale)

	if _, ok := state.retainedResolve("/x"); !ok {
		t.Fatal("a stale reply evicted a resolution the current connection obtained")
	}
	if _, ok := state.retainedListing(id); !ok {
		t.Fatal("a stale reply evicted a listing the current connection obtained")
	}
	if _, ok := state.retainedResolve("/d/a"); !ok {
		t.Fatal("a stale reply evicted a child the current connection obtained")
	}
}

// A listing of the daemon's tree must not fill a path the view serves from a
// declared local tree, and a retained remote answer must not be used there.
func TestRemoteListingDoesNotFillADeclaredLocalTree(t *testing.T) {
	const prefix = "/local/tree"
	root := NewRoot(&Layout{Remote: &statRemote{}, Local: readOnlyTree{prefix: prefix}})
	if err := root.Err(); err != nil {
		t.Fatalf("layout: %v", err)
	}
	defer root.Close()

	state := root.state
	state.retainListing(dirID{dev: 1, ino: 2}, prefix, []proto.DirEntry{{
		Name: "f", Attr: proto.Attr{Mode: proto.SIFREG, Ino: 9, Size: 7},
	}}, false, state.beginRequest())
	if _, ok := state.retainedResolve(prefix + "/f"); ok {
		t.Fatal("a remote listing filed a child under a declared local tree")
	}

	// Even a remote answer already in the cache must not be used for that path.
	state.retainResolve(prefix+"/f", backing{kind: sourceRemote, attr: proto.Attr{Mode: proto.SIFREG, Ino: 9, Size: 7}}, false, false, state.beginRequest())
	if held, errno := root.lookupBacking(prefix + "/f"); errno == 0 && held.kind == sourceRemote {
		t.Fatal("the view answered a declared local path from a retained remote result")
	}
}

// A child that travelled with a listing answers for the directory the listing
// was read from. Once that path names another inode, the child is not an answer
// for it any more.
func TestPrefilledChildIsBoundToItsListingDirectory(t *testing.T) {
	state := newMountState(&Layout{})
	listed := dirID{dev: 1, ino: 2}
	state.retainListing(listed, "/d", []proto.DirEntry{{
		Name: "a", Attr: proto.Attr{Mode: proto.SIFREG, Ino: 9},
	}}, false, state.beginRequest())
	if _, ok := state.retainedResolve("/d/a"); !ok {
		t.Fatal("a listed child is not answerable right after the listing")
	}

	// The path now names a different directory; the old child must not be used
	// under it.
	state.retainResolve("/d", backing{kind: sourceRemote, attr: proto.Attr{Mode: proto.SIFDIR | 0o755, Dev: 1, Ino: 3}}, false, false, state.beginRequest())
	if _, ok := state.retainedResolve("/d/a"); ok {
		t.Fatal("a listed child was answered under a directory that replaced its parent")
	}
}

// A listing delivered late must not put back the directory it was read from.
// The path may already have been resolved to a replacement, and the older
// inode's children must not answer under the newer one.
func TestLateListingDoesNotUndoANewerParentResolution(t *testing.T) {
	state := newMountState(&Layout{})
	enumeration := state.beginRequest()
	newer := state.beginRequest()
	state.retainResolve("/d", backing{kind: sourceRemote, attr: proto.Attr{Mode: proto.SIFDIR | 0o755, Dev: 1, Ino: 3}}, false, false, newer)
	state.retainListing(dirID{dev: 1, ino: 2}, "/d", []proto.DirEntry{{
		Name: "a", Attr: proto.Attr{Mode: proto.SIFREG, Ino: 9},
	}}, false, enumeration)

	if fact, ok := state.dirIDs["/d"]; !ok || fact.id.ino != 3 {
		t.Fatalf("the path identity was reverted to the old listing: %+v", fact)
	}
	if _, ok := state.retainedResolve("/d/a"); ok {
		t.Fatal("a late listing answered for the directory that replaced its parent")
	}

	newest := state.beginRequest()
	state.retainListing(dirID{dev: 1, ino: 3}, "/d", []proto.DirEntry{{
		Name: "b", Attr: proto.Attr{Mode: proto.SIFREG, Ino: 10},
	}}, false, newest)
	if _, ok := state.retainedResolve("/d/b"); !ok {
		t.Fatal("a child of the directory the path names now was not answerable")
	}
}
