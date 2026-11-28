package fusefs

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"rsbx/internal/paths"

	"rsbx/internal/fsremote"
	"rsbx/internal/proto"
)

// mappedRemote redirects daemon paths into a test tree without replacing the
// production handle and lock implementation.
type mappedRemote struct {
	server *fsremote.Server
	root   string
	calls  []proto.FxReq
}

func (r *mappedRemote) host(p string) string {
	return filepath.Join(r.root, strings.TrimPrefix(p, "/"))
}

func (r *mappedRemote) Do(req *proto.FxReq) (*proto.FxResp, error) {
	r.calls = append(r.calls, *req)
	request := *req
	if request.Path != "" {
		request.Path = r.host(request.Path)
	}
	if request.Op == proto.FxRename || request.Op == proto.FxLink {
		request.Arg = r.host(request.Arg)
	}
	return r.server.Handle(&request), nil
}

func (r *mappedRemote) ReadFile(p string) ([]byte, proto.Attr, error) {
	return fsRemote{s: r.server}.ReadFile(r.host(p))
}

func (r *mappedRemote) WriteFile(p string, data []byte) error {
	return fsRemote{s: r.server}.WriteFile(r.host(p), data)
}

func sourceRoot(t *testing.T, lay *Layout) (*Node, *mappedRemote) {
	t.Helper()
	r := &mappedRemote{server: fsremote.NewServer(), root: t.TempDir()}
	lay.Remote = r
	root := NewRoot(lay)
	if err := root.Err(); err != nil {
		root.Close()
		r.server.Close()
		t.Fatal(err)
	}
	fs.NewNodeFS(root, &fs.Options{})
	t.Cleanup(func() { root.Close(); r.server.Close() })
	return root, r
}

func lookupNode(t *testing.T, root *Node, p string) (*Node, fuse.EntryOut) {
	t.Helper()
	node := root
	var out fuse.EntryOut
	for _, name := range strings.Split(strings.TrimPrefix(filepath.Clean(p), string(filepath.Separator)), "/") {
		if name == "" {
			continue
		}
		out = fuse.EntryOut{}
		in, errno := node.Lookup(context.Background(), name, &out)
		if errno != 0 {
			t.Fatalf("lookup %s/%s: %v", node.currentPath(), name, errno)
		}
		node.AddChild(name, in, true)
		node = in.Operations().(*Node)
	}
	return node, out
}

func daemonFile(t *testing.T, remote *mappedRemote, p string, data []byte, mode os.FileMode) {
	t.Helper()
	host := remote.host(p)
	if err := os.MkdirAll(filepath.Dir(host), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(host, data, mode); err != nil {
		t.Fatal(err)
	}
}

func readHandle(t *testing.T, node *Node, h fs.FileHandle) []byte {
	t.Helper()
	var attr fuse.AttrOut
	if errno := node.Getattr(context.Background(), h, &attr); errno != 0 {
		t.Fatalf("handle stat: %v", errno)
	}
	buf := make([]byte, int(attr.Size)+16)
	result, errno := node.Read(context.Background(), h, buf, 0)
	if errno != 0 {
		t.Fatalf("read: %v", errno)
	}
	defer result.Done()
	data, status := result.Bytes(buf)
	if status != fuse.OK {
		t.Fatalf("read result: %v", status)
	}
	return data
}

func readNode(t *testing.T, node *Node) []byte {
	t.Helper()
	h, _, errno := node.Open(context.Background(), uint32(os.O_RDONLY))
	if errno != 0 {
		t.Fatalf("open %s: %v", node.currentPath(), errno)
	}
	defer h.(*handle).Release(context.Background())
	return readHandle(t, node, h)
}

func TestRemoteExecutableAndSharedObjectPreserveBytes(t *testing.T) {
	root, remote := sourceRoot(t, &Layout{})
	for _, filename := range []string{"/proj/tool", "/proj/libfoo.so", "/proj/ld-linux-project.so.2"} {
		body := []byte("original daemon bytes for " + filename)
		daemonFile(t, remote, filename, body, 0o755)
		node, entry := lookupNode(t, root, filename)
		if node.src.kind != sourceRemote || entry.Size != uint64(len(body)) {
			t.Fatalf("%s acquired a non-daemon source or size: %+v", filename, entry.Attr)
		}
		if got := string(readNode(t, node)); got != string(body) {
			t.Fatalf("%s read %q, want original bytes %q", filename, got, body)
		}
	}
}

func TestRemoteExecutableWritesUseDaemonDescriptor(t *testing.T) {
	root, remote := sourceRoot(t, &Layout{})
	daemonFile(t, remote, "/proj/tool", []byte("original"), 0o755)
	node, _ := lookupNode(t, root, "/proj/tool")
	h, _, errno := node.Open(context.Background(), uint32(os.O_RDWR))
	if errno != 0 {
		t.Fatal(errno)
	}
	defer h.(*handle).Release(context.Background())
	if _, errno := node.Write(context.Background(), h, []byte("changed!"), 0); errno != 0 {
		t.Fatal(errno)
	}
	got, err := os.ReadFile(remote.host("/proj/tool"))
	if err != nil || string(got) != "changed!" {
		t.Fatalf("daemon bytes = %q, %v", got, err)
	}
}

// Setattr sends metadata mutations in the fields the daemon reads. chmod
// carries the permission bits in Mode and truncate carries the length in
// Offset; encoding them anywhere else left the daemon applying chmod(0), which
// turned a 0755 install into a 0000 inode that the exec gate then refused.
// This asserts the daemon-side mode directly, so it holds without /dev/fuse.
func TestRemoteSetattrSendsModeInModeField(t *testing.T) {
	root, remote := sourceRoot(t, &Layout{})
	daemonFile(t, remote, "/proj/install", []byte("\x7fELF"), 0o600)
	node, _ := lookupNode(t, root, "/proj/install")
	h, _, errno := node.Open(context.Background(), uint32(os.O_RDWR))
	if errno != 0 {
		t.Fatal(errno)
	}
	defer h.(*handle).Release(context.Background())

	in := &fuse.SetAttrIn{}
	in.Valid, in.Mode = fuse.FATTR_MODE, 0o755
	var out fuse.AttrOut
	if errno := node.Setattr(context.Background(), h, in, &out); errno != 0 {
		t.Fatalf("setattr chmod: %v", errno)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(remote.host("/proj/install"), &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		t.Fatalf("daemon mode %#o lost its regular-file type", st.Mode)
	}
	if got := st.Mode & 0o7777; got != 0o755 {
		t.Fatalf("daemon mode after setattr chmod = %#o, want 0755", got)
	}
	if out.Mode != proto.SIFREG|0o755 {
		t.Fatalf("reply mode = %#o, want S_IFREG|0755", out.Mode)
	}

	// Truncation goes to the daemon's descriptor at the requested length.
	in = &fuse.SetAttrIn{}
	in.Valid, in.Size = fuse.FATTR_SIZE, 3
	if errno := node.Setattr(context.Background(), h, in, &out); errno != 0 {
		t.Fatalf("setattr truncate: %v", errno)
	}
	if err := syscall.Stat(remote.host("/proj/install"), &st); err != nil {
		t.Fatal(err)
	}
	if st.Size != 3 {
		t.Fatalf("daemon size after truncate = %d, want 3", st.Size)
	}
}

func TestRemoteHandleKeepsInodeAfterRenameAndUnlink(t *testing.T) {
	root, remote := sourceRoot(t, &Layout{})
	daemonFile(t, remote, "/proj/held", []byte("original"), 0o600)
	node, entry := lookupNode(t, root, "/proj/held")
	h, _, errno := node.Open(context.Background(), uint32(os.O_RDWR))
	if errno != 0 {
		t.Fatal(errno)
	}
	defer h.(*handle).Release(context.Background())
	if err := os.Rename(remote.host("/proj/held"), remote.host("/proj/moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(remote.host("/proj/moved")); err != nil {
		t.Fatal(err)
	}
	daemonFile(t, remote, "/proj/held", []byte("replacement"), 0o600)
	if got := string(readHandle(t, node, h)); got != "original" {
		t.Fatalf("held descriptor switched to %q", got)
	}
	var held fuse.AttrOut
	if errno := node.Getattr(context.Background(), h, &held); errno != 0 || held.Ino != entry.Ino {
		t.Fatalf("descriptor lost inode identity: %+v, %v", held.Attr, errno)
	}
	if _, errno := node.Write(context.Background(), h, []byte("changed!"), 0); errno != 0 {
		t.Fatal(errno)
	}
	got, err := os.ReadFile(remote.host("/proj/held"))
	if err != nil || string(got) != "replacement" {
		t.Fatalf("replacement was corrupted: %q, %v", got, err)
	}
}

func TestLookupSourceNeverSwitchesAfterReplacement(t *testing.T) {
	root, remote := sourceRoot(t, &Layout{})
	daemonFile(t, remote, "/proj/held", []byte("original"), 0o600)
	node, _ := lookupNode(t, root, "/proj/held")
	daemonFile(t, remote, "/proj/new", []byte("replacement"), 0o600)
	if err := os.Rename(remote.host("/proj/new"), remote.host("/proj/held")); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := node.Open(context.Background(), uint32(os.O_WRONLY|os.O_TRUNC)); errno != syscall.ESTALE {
		t.Fatalf("replaced inode open = %v, want ESTALE", errno)
	}
	got, err := os.ReadFile(remote.host("/proj/held"))
	if err != nil || string(got) != "replacement" {
		t.Fatalf("identity check ran after truncating replacement: %q, %v", got, err)
	}
	// Inside the retention window the view still describes the inode it
	// resolved, which is the old one: that is a retained answer, not a switch
	// to the replacement. Once the window has passed the identity check runs
	// and reports the replacement as ESTALE.
	var attr fuse.AttrOut
	if errno := node.Getattr(context.Background(), nil, &attr); errno != 0 {
		t.Fatalf("old inode stat inside the window = %v", errno)
	}
	if want := node.StableAttr().Ino; attr.Ino != want {
		t.Fatalf("the old node reported inode %d inside the window, want the one it resolved (%d)", attr.Ino, want)
	}
	time.Sleep(EntryRetention + 150*time.Millisecond)
	if errno := node.Getattr(context.Background(), nil, &attr); errno != syscall.ESTALE {
		t.Fatalf("old inode stat after the window = %v, want ESTALE", errno)
	}
}

func TestRemoteDirectoryHandleListsItsOpenedInode(t *testing.T) {
	root, remote := sourceRoot(t, &Layout{})
	daemonFile(t, remote, "/proj/dir/original", []byte("x"), 0o600)
	node, _ := lookupNode(t, root, "/proj/dir")
	f, _, errno := node.OpendirHandle(context.Background(), 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	h := f.(*handle)
	defer h.Release(context.Background())
	if err := os.Rename(remote.host("/proj/dir"), remote.host("/proj/moved")); err != nil {
		t.Fatal(err)
	}
	daemonFile(t, remote, "/proj/dir/replacement", []byte("x"), 0o600)
	entry, errno := h.Readdirent(context.Background())
	if errno != 0 || entry == nil || entry.Name != "original" {
		t.Fatalf("directory descriptor listed replacement: %+v, %v", entry, errno)
	}
}

func TestRemoteReadIsLiveWithoutAPageCache(t *testing.T) {
	root, remote := sourceRoot(t, &Layout{})
	daemonFile(t, remote, "/proj/live", []byte("first-generation"), 0o600)
	node, _ := lookupNode(t, root, "/proj/live")
	h, fuseFlags, errno := node.Open(context.Background(), uint32(os.O_RDONLY))
	if errno != 0 {
		t.Fatal(errno)
	}
	if fuseFlags&fuse.FOPEN_DIRECT_IO == 0 {
		t.Fatal("remote file was offered a persistent page cache")
	}
	if err := remote.WriteFile("/proj/live", []byte("second-generation")); err != nil {
		t.Fatal(err)
	}
	if got := string(readHandle(t, node, h)); got != "second-generation" {
		t.Fatalf("live descriptor read %q", got)
	}
	h.(*handle).Release(context.Background())
}

func TestRemoteDirectoryUnionListsOnlyConcreteAssets(t *testing.T) {
	program := filepath.Join(t.TempDir(), "program")
	if err := os.WriteFile(program, []byte("program"), 0o755); err != nil {
		t.Fatal(err)
	}
	root, remote := sourceRoot(t, &Layout{ExecPaths: []string{program}, LocalExec: func(p string) bool { return p == program }})
	other := filepath.Join(filepath.Dir(program), "unlisted-neighbor")
	if err := os.WriteFile(other, []byte("host-neighbor"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(program), "host-only"), []byte("ungranted"), 0o644); err != nil {
		t.Fatal(err)
	}
	daemonFile(t, remote, other, []byte("daemon-neighbor"), 0o644)
	daemonFile(t, remote, filepath.Join(filepath.Dir(program), "daemon-only"), []byte("daemon"), 0o644)
	parent, _ := lookupNode(t, root, filepath.Dir(program))
	stream, errno := parent.Readdir(context.Background())
	if errno != 0 {
		t.Fatal(errno)
	}
	defer stream.Close()
	names := map[string]bool{}
	for stream.HasNext() {
		entry, errno := stream.Next()
		if errno != 0 {
			t.Fatal(errno)
		}
		names[entry.Name] = true
	}
	if names["host-only"] || !names["unlisted-neighbor"] || !names["program"] || !names["daemon-only"] {
		t.Fatalf("union listing = %v", names)
	}
	neighbor, _ := lookupNode(t, root, other)
	if got := string(readNode(t, neighbor)); got != "daemon-neighbor" {
		t.Fatalf("uncompiled neighbor read %q", got)
	}
}

func TestConfigurationTreesNeverMergeDaemonContent(t *testing.T) {
	dir := t.TempDir()
	configuration := filepath.Join(dir, "configuration")
	if err := os.Mkdir(configuration, 0o700); err != nil {
		t.Fatal(err)
	}
	localFile := filepath.Join(configuration, "settings")
	if err := os.WriteFile(localFile, []byte("private-host-settings"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, remote := sourceRoot(t, &Layout{Local: fixedLocal(configuration)})
	daemonFile(t, remote, localFile, []byte("daemon-settings"), 0o600)
	daemonFile(t, remote, filepath.Join(configuration, "daemon-only"), []byte("daemon"), 0o600)
	remote.calls = nil
	node, _ := lookupNode(t, root, localFile)
	if got := string(readNode(t, node)); got != "private-host-settings" {
		t.Fatalf("configuration came from the wrong side: %q", got)
	}
	parent, _ := lookupNode(t, root, configuration)
	stream, errno := parent.Readdir(context.Background())
	if errno != 0 {
		t.Fatal(errno)
	}
	defer stream.Close()
	for stream.HasNext() {
		entry, errno := stream.Next()
		if errno != 0 {
			t.Fatal(errno)
		}
		if entry.Name == "daemon-only" {
			t.Fatal("a private configuration directory merged daemon content")
		}
	}
	for _, request := range remote.calls {
		if request.Path == configuration || strings.HasPrefix(request.Path, configuration+"/") {
			t.Fatalf("local configuration reached daemon IO: %+v", request)
		}
	}
}

func TestConfigurationSymlinkCannotEscapeItsHostRoot(t *testing.T) {
	dir := t.TempDir()
	configuration, outside := filepath.Join(dir, "configuration"), filepath.Join(dir, "outside")
	for _, directory := range []string{configuration, outside} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("ungranted-host-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(configuration, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	root, remote := sourceRoot(t, &Layout{Local: fixedLocal(configuration)})
	daemonFile(t, remote, secret, []byte("daemon-secret"), 0o600)
	if _, errno := root.lookupBacking(filepath.Join(link, "secret")); errno == 0 {
		t.Fatal("a host operation followed an interior configuration symlink")
	}
	node, entry := lookupNode(t, root, link)
	text, errno := node.Readlink(context.Background())
	if errno != 0 || string(text) != outside || entry.Size != uint64(len(outside)) {
		t.Fatalf("link metadata disagrees: %q, %+v, %v", text, entry.Attr, errno)
	}
	outsideNode, _ := lookupNode(t, root, secret)
	if got := string(readNode(t, outsideNode)); got != "daemon-secret" {
		t.Fatalf("unconfigured path exposed host data: %q", got)
	}
}

func TestConfigurationRootDescriptorSurvivesHostPathReplacement(t *testing.T) {
	dir := t.TempDir()
	configuration, moved, outside := filepath.Join(dir, "configuration"), filepath.Join(dir, "moved"), filepath.Join(dir, "outside")
	for _, directory := range []string{configuration, outside} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(configuration, "settings"), []byte("chosen-root"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "settings"), []byte("outside-root"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, _ := sourceRoot(t, &Layout{Local: fixedLocal(configuration)})
	if err := os.Rename(configuration, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, configuration); err != nil {
		t.Fatal(err)
	}
	node, _ := lookupNode(t, root, filepath.Join(configuration, "settings"))
	if got := string(readNode(t, node)); got != "chosen-root" {
		t.Fatalf("configuration root followed a replacement path: %q", got)
	}
}

func TestConfigurationHardLinkCannotModifyRuntimeAsset(t *testing.T) {
	dir := t.TempDir()
	configuration := filepath.Join(dir, "configuration")
	if err := os.Mkdir(configuration, 0o700); err != nil {
		t.Fatal(err)
	}
	library, alias := filepath.Join(dir, "library"), filepath.Join(configuration, "alias")
	if err := os.WriteFile(library, []byte("immutable-runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(library, alias); err != nil {
		t.Fatal(err)
	}
	root, _ := sourceRoot(t, &Layout{Local: fixedLocal(configuration), RuntimePaths: []string{library}})
	node, _ := lookupNode(t, root, alias)
	if _, _, errno := node.Open(context.Background(), uint32(os.O_WRONLY|os.O_TRUNC)); errno != syscall.EROFS {
		t.Fatalf("runtime hard-link write = %v, want EROFS", errno)
	}
	parent, _ := lookupNode(t, root, configuration)
	var entry fuse.EntryOut
	if _, _, _, errno := parent.Create(context.Background(), "alias", uint32(os.O_WRONLY|os.O_TRUNC), 0o600, &entry); errno != syscall.EROFS {
		t.Fatalf("runtime hard-link create = %v, want EROFS", errno)
	}
	if got, err := os.ReadFile(library); err != nil || string(got) != "immutable-runtime" {
		t.Fatalf("runtime was changed through a writable alias: %q, %v", got, err)
	}
}

func TestLocalHandlesKeepAppendFsyncLockAndIdentity(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "log")
	if err := os.WriteFile(filename, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, _ := sourceRoot(t, &Layout{Local: fixedLocal(dir)})
	node, entry := lookupNode(t, root, filename)
	h, _, errno := node.Open(context.Background(), uint32(os.O_RDWR|os.O_APPEND))
	if errno != 0 {
		t.Fatal(errno)
	}
	defer h.(*handle).Release(context.Background())
	if _, errno := node.Write(context.Background(), h, []byte("two"), 0); errno != 0 {
		t.Fatal(errno)
	}
	if errno := node.Fsync(context.Background(), h, 0); errno != 0 {
		t.Fatal(errno)
	}
	var lock, found fuse.FileLock
	lock.Typ = syscall.F_WRLCK
	if errno := node.Setlk(context.Background(), h, 7, &lock, 0); errno != 0 {
		t.Fatal(errno)
	}
	if errno := node.Getlk(context.Background(), h, 7, &lock, 0, &found); errno != 0 {
		t.Fatal(errno)
	}
	if found.Typ != syscall.F_UNLCK {
		t.Fatalf("descriptor lock conflicted with itself: %+v", found)
	}
	if got, err := os.ReadFile(filename); err != nil || string(got) != "onetwo" {
		t.Fatalf("append bytes = %q, %v", got, err)
	}
	var after fuse.AttrOut
	if errno := node.Getattr(context.Background(), h, &after); errno != 0 || after.Ino != entry.Ino || after.Size != 6 {
		t.Fatalf("handle identity/size changed: %+v, %v", after.Attr, errno)
	}
}

func TestLocalNodeKeepsChosenSourceAfterReplacement(t *testing.T) {
	dir := t.TempDir()
	filename, replacement := filepath.Join(dir, "settings"), filepath.Join(dir, "replacement")
	if err := os.WriteFile(filename, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, _ := sourceRoot(t, &Layout{Local: fixedLocal(dir)})
	node, _ := lookupNode(t, root, filename)
	if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, filename); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := node.Open(context.Background(), uint32(os.O_WRONLY|os.O_TRUNC)); errno != syscall.ESTALE {
		t.Fatalf("replaced local node open = %v, want ESTALE", errno)
	}
	if got, err := os.ReadFile(filename); err != nil || string(got) != "replacement" {
		t.Fatalf("replacement was truncated: %q, %v", got, err)
	}
}

func TestUnionRenameIsRejectedAcrossDaemonBoundary(t *testing.T) {
	configuration := filepath.Join(t.TempDir(), "configuration")
	if err := os.Mkdir(configuration, 0o700); err != nil {
		t.Fatal(err)
	}
	root, remote := sourceRoot(t, &Layout{Local: fixedLocal(configuration)})
	ancestor := filepath.Dir(configuration)
	daemonFile(t, remote, filepath.Join(ancestor, "project-file"), []byte("remote"), 0o600)
	daemonFile(t, remote, "/destination/file", []byte("remote"), 0o600)
	parent, _ := lookupNode(t, root, filepath.Dir(ancestor))
	child, _ := lookupNode(t, root, filepath.Join(ancestor, "project-file"))
	target, _ := lookupNode(t, root, "/destination")
	if errno := parent.Rename(context.Background(), filepath.Base(ancestor), target, "moved", 0); errno != syscall.EXDEV {
		t.Fatalf("union rename = %v, want EXDEV", errno)
	}
	if got := string(readNode(t, child)); got != "remote" {
		t.Fatalf("remote source changed by rejected rename: %q", got)
	}
}

func TestHardLinkAndStructuralInodesShareIdentity(t *testing.T) {
	root, remote := sourceRoot(t, &Layout{})
	daemonFile(t, remote, "/proj/one", []byte("shared"), 0o600)
	if err := os.Link(remote.host("/proj/one"), remote.host("/proj/two")); err != nil {
		t.Fatal(err)
	}
	one, first := lookupNode(t, root, "/proj/one")
	two, second := lookupNode(t, root, "/proj/two")
	if first.Ino != second.Ino || first.Nlink != 2 || second.Nlink != 2 {
		t.Fatalf("hard-link identity = %+v / %+v", first.Attr, second.Attr)
	}
	if one.src.attr.Dev != two.src.attr.Dev || one.src.attr.Ino != two.src.attr.Ino {
		t.Fatal("hard links chose different daemon identities")
	}
}

func TestSyntheticFilesAndDirectoriesStaySandboxOwned(t *testing.T) {
	root, _ := sourceRoot(t, &Layout{Synthetic: []string{"/proc"}, SyntheticFiles: []string{"/.rsbx-helpers/helper"}})
	proc, _ := lookupNode(t, root, "/proc")
	if _, _, errno := proc.Open(context.Background(), uint32(os.O_RDONLY)); errno != syscall.EISDIR {
		t.Fatalf("synthetic directory open = %v, want EISDIR", errno)
	}
	helper, _ := lookupNode(t, root, "/.rsbx-helpers/helper")
	if got := string(readNode(t, helper)); got != "" {
		t.Fatalf("mount placeholder had bytes %q", got)
	}
	if _, _, errno := helper.Open(context.Background(), uint32(os.O_WRONLY)); errno != syscall.EROFS {
		t.Fatalf("helper write = %v, want EROFS", errno)
	}
	if _, errno := proc.Readlink(context.Background()); errno != syscall.EINVAL {
		t.Fatalf("synthetic directory readlink = %v, want EINVAL", errno)
	}
}

func TestReadOnlyAndRuntimeAssetsRejectEveryWriteEntryPoint(t *testing.T) {
	dir := t.TempDir()
	readOnly, program, library := filepath.Join(dir, "read-only"), filepath.Join(dir, "program"), filepath.Join(dir, "library")
	if err := os.Mkdir(readOnly, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{program, library} {
		if err := os.WriteFile(filename, []byte("immutable"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	local, err := paths.New([]string{dir, readOnly}, false)
	if err != nil {
		t.Fatal(err)
	}
	local = local.WithReadOnly(map[string]bool{readOnly: true})
	root, _ := sourceRoot(t, &Layout{Local: local, ExecPaths: []string{program}, RuntimePaths: []string{library}, LocalExec: func(p string) bool { return p == program }})
	parent, _ := lookupNode(t, root, dir)
	for _, filename := range []string{program, library} {
		node, _ := lookupNode(t, root, filename)
		if _, _, errno := node.Open(context.Background(), uint32(os.O_WRONLY|os.O_TRUNC)); errno != syscall.EROFS {
			t.Errorf("write open %s = %v, want EROFS", filename, errno)
		}
		var entry fuse.EntryOut
		if _, _, _, errno := parent.Create(context.Background(), filepath.Base(filename), uint32(os.O_WRONLY|os.O_TRUNC), 0o600, &entry); errno != syscall.EROFS {
			t.Errorf("create over %s = %v, want EROFS", filename, errno)
		}
		in := &fuse.SetAttrIn{}
		in.Valid, in.Mode = fuse.FATTR_MODE, 0o777
		var attr fuse.AttrOut
		if errno := node.Setattr(context.Background(), nil, in, &attr); errno != syscall.EROFS {
			t.Errorf("chmod %s = %v, want EROFS", filename, errno)
		}
		if errno := parent.Unlink(context.Background(), filepath.Base(filename)); errno != syscall.EROFS {
			t.Errorf("unlink %s = %v, want EROFS", filename, errno)
		}
	}
	readOnlyParent, _ := lookupNode(t, root, readOnly)
	if _, _, _, errno := readOnlyParent.Create(context.Background(), "blocked", uint32(os.O_WRONLY|os.O_CREATE), 0o600, &fuse.EntryOut{}); errno != syscall.EROFS {
		t.Fatalf("read-only tree create = %v, want EROFS", errno)
	}
}

func TestExactAllowedAssetIsCompiledOnce(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "tool")
	if err := os.WriteFile(local, []byte("host-program"), 0o755); err != nil {
		t.Fatal(err)
	}
	calls := 0
	lay := &Layout{ExecPaths: []string{local}, LocalExec: func(p string) bool { calls++; return p == local }}
	root, remote := sourceRoot(t, lay)
	compiledCalls := calls
	daemonFile(t, remote, local, []byte("daemon-program-of-another-size"), 0o755)
	node, entry := lookupNode(t, root, local)
	lay.LocalExec = func(string) bool { t.Fatal("policy was rerun after construction"); return false }
	var attr fuse.AttrOut
	if errno := node.Getattr(context.Background(), nil, &attr); errno != 0 {
		t.Fatal(errno)
	}
	if entry.Ino != attr.Ino || entry.Size != attr.Size || entry.Mode != attr.Mode {
		t.Fatalf("lookup and stat disagree: %+v / %+v", entry.Attr, attr.Attr)
	}
	if got := string(readNode(t, node)); got != "host-program" {
		t.Fatalf("allowed name read %q", got)
	}
	if calls != compiledCalls {
		t.Fatalf("execution policy was rerun %d times", calls-compiledCalls)
	}
}

func TestPinnedExecutableKeepsItsChosenHostInode(t *testing.T) {
	dir := t.TempDir()
	program, replacement := filepath.Join(dir, "tool"), filepath.Join(dir, "replacement")
	if err := os.WriteFile(program, []byte("original"), 0o755); err != nil {
		t.Fatal(err)
	}
	root, _ := sourceRoot(t, &Layout{ExecPaths: []string{program}, LocalExec: func(p string) bool { return p == program }})
	node, before := lookupNode(t, root, program)
	if err := os.WriteFile(replacement, []byte("replacement"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, program); err != nil {
		t.Fatal(err)
	}
	if got := string(readNode(t, node)); got != "original" {
		t.Fatalf("pinned program switched inode: %q", got)
	}
	var after fuse.AttrOut
	if errno := node.Getattr(context.Background(), nil, &after); errno != 0 || after.Ino != before.Ino || after.Size != before.Size {
		t.Fatalf("pinned stat changed: %+v, %v", after.Attr, errno)
	}
}

func TestAssetAliasCannotWidenTheCompiledSnapshot(t *testing.T) {
	dir := t.TempDir()
	real, alias := filepath.Join(dir, "real"), filepath.Join(dir, "alias")
	if err := os.WriteFile(real, []byte("library"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	root := NewRoot(&Layout{RuntimePaths: []string{alias}})
	defer root.Close()
	if root.Err() == nil {
		t.Fatal("an uncompiled alias target silently widened host visibility")
	}
}

// A whole-file lock is asked for as "to the end of the file", which the kernel
// forwards as End == LLONG_MAX. The node must accept that range and must not
// report its own descriptor as a conflict.
func TestLockRangeCoversWholeFileOnTheWire(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "session.lock")
	if err := os.WriteFile(filename, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, _ := sourceRoot(t, &Layout{Local: fixedLocal(dir)})
	node, _ := lookupNode(t, root, filename)
	h, _, errno := node.Open(context.Background(), uint32(os.O_RDWR))
	if errno != 0 {
		t.Fatal(errno)
	}
	defer h.(*handle).Release(context.Background())

	// The kernel spells "to the end of the file" as End == LLONG_MAX on the
	// wire, not as the FUSE maximum, so the range that has to work is this one.
	whole := func(typ uint32) fuse.FileLock {
		return fuse.FileLock{Typ: typ, Start: 0, End: math.MaxInt64}
	}
	for _, typ := range []uint32{syscall.F_WRLCK, syscall.F_UNLCK} {
		lk := whole(typ)
		if errno := node.Setlk(context.Background(), h, 11, &lk, 0); errno != 0 {
			t.Fatalf("whole-file Setlk(type=%d) = %v, want success", typ, errno)
		}
	}
	// POSIX locks are per-process, so the holder this descriptor sees is
	// itself: the answer must be F_UNLCK rather than a self-conflict.
	question := whole(syscall.F_WRLCK)
	var found fuse.FileLock
	if errno := node.Getlk(context.Background(), h, 11, &question, 0, &found); errno != 0 {
		t.Fatalf("whole-file Getlk = %v, want success", errno)
	}
	if found.Typ != syscall.F_UNLCK {
		t.Fatalf("own descriptor reported a conflicting holder: %+v", found)
	}
}

// A rejected lock must name the kernel's real reason. A negative length makes
// fcntl answer EINVAL, and reporting that as EIO hides a malformed request
// behind "input/output error".
func TestLockRangeRejectsInvalidRangeAsEINVAL(t *testing.T) {
	if _, errno := lockRange(&fuse.FileLock{Typ: syscall.F_WRLCK, Start: 10, End: 5}); errno != syscall.EINVAL {
		t.Fatalf("end before start = %v, want EINVAL", errno)
	}
	beyond := &fuse.FileLock{Typ: syscall.F_WRLCK, Start: math.MaxUint64, End: math.MaxUint64}
	if _, errno := lockRange(beyond); errno != syscall.EINVAL {
		t.Fatalf("start beyond int64 = %v, want EINVAL", errno)
	}
	whole, errno := lockRange(&fuse.FileLock{Typ: syscall.F_WRLCK, Start: 0, End: ^uint64(0)})
	if errno != 0 || whole.Len != 0 {
		t.Fatalf("whole-file range = len %d errno %v, want len 0", whole.Len, errno)
	}
	atMax, errno := lockRange(&fuse.FileLock{Typ: syscall.F_WRLCK, Start: 0, End: math.MaxInt64})
	if errno != 0 || atMax.Len != 0 {
		t.Fatalf("End=LLONG_MAX range = len %d errno %v, want len 0", atMax.Len, errno)
	}
	partial, errno := lockRange(&fuse.FileLock{Typ: syscall.F_WRLCK, Start: 0, End: 99})
	if errno != 0 || partial.Len != 100 {
		t.Fatalf("partial range = len %d errno %v, want 100", partial.Len, errno)
	}
	if got := lockRangeEnd(&syscall.Flock_t{Start: 0, Len: 0}); got != ^uint64(0) {
		t.Fatalf("reverse of a whole-file lock = %d, want the end-of-file maximum", got)
	}
	if got := lockRangeEnd(&syscall.Flock_t{Start: 0, Len: 100}); got != 99 {
		t.Fatalf("reverse of [0,100) = %d, want 99", got)
	}
}
