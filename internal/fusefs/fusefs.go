// Package fusefs is the sandbox root filesystem.
//
// The tree is a union of two layers:
//
//	remote  — answered by the daemon; reads and writes go over the wire
//	host    — host directories kept read-only so whitelisted binaries work
//
// Executable directories are special: a name whose host path is *not* on the
// local allowlist is replaced by the trampoline binary. The host executable is
// then not reachable under that name at all, which is what makes redirection
// hold for statically linked programs too.
package fusefs

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"rsbx/internal/proto"
)

// LocalPaths is the path policy the filesystem consults. It is an interface so
// the filesystem can be tested without the policy package.
type LocalPaths interface {
	IsLocal(p string) bool
	Writable(p string) bool
	Roots() []string
}

// Remote answers filesystem requests against the daemon tree.
type Remote interface {
	Do(req *proto.FxReq) (*proto.FxResp, error)
	ReadFile(p string) ([]byte, proto.Attr, error)
	WriteFile(p string, data []byte) error
}

// Layout describes which sandbox paths come from where.
type Layout struct {
	Remote Remote
	// Local is the set of trees served from this machine. A path that matches
	// is opened, read and written directly: the daemon is never consulted.
	Local LocalPaths
	// ExecDirs lists sandbox directories whose names resolve through the
	// allowlist; a non-local name yields the trampoline.
	ExecDirs []string
	// Trampoline is the local ELF served for trapped names.
	Trampoline string
	// LocalExec reports whether an executable may run on this machine.
	LocalExec func(hostPath string) bool
	// Cache holds copies of remote files that were read, so repeated opens
	// are served locally. It is disposable.
	Cache string
	// TTL caches negative and positive lookups for this long.
	TTL time.Duration
	// Synthetic lists paths that exist only as mount points (bwrap needs to
	// create them), e.g. "/proc", "/dev", "/tmp".
	Synthetic []string
	// SyntheticFiles are mount points that are files, e.g. the guard binary.
	SyntheticFiles []string
	// HostDirs is the closure of the local trees over parent directories, so a
	// tree such as /usr/bin still implies a visible /usr.
	HostDirs map[string]bool
	// SystemLinks are sandbox paths that must appear as symlinks, e.g.
	// /lib -> usr/lib on a merged-usr host.
	SystemLinks map[string]string
}

type Node struct {
	fs.Inode
	lay  *Layout
	path string
	// phantom nodes stand in for bind-mount targets inside synthetic dirs
	phantom bool
}

var _ = (fs.NodeLookuper)((*Node)(nil))
var _ = (fs.NodeReaddirer)((*Node)(nil))
var _ = (fs.NodeGetattrer)((*Node)(nil))
var _ = (fs.NodeOpener)((*Node)(nil))
var _ = (fs.NodeReader)((*Node)(nil))
var _ = (fs.NodeWriter)((*Node)(nil))
var _ = (fs.NodeReadlinker)((*Node)(nil))
var _ = (fs.NodeCreater)((*Node)(nil))
var _ = (fs.NodeMkdirer)((*Node)(nil))
var _ = (fs.NodeUnlinker)((*Node)(nil))
var _ = (fs.NodeRenamer)((*Node)(nil))
var _ = (fs.NodeLinker)((*Node)(nil))
var _ = (fs.NodeSymlinker)((*Node)(nil))
var _ = (fs.NodeRmdirer)((*Node)(nil))
var _ = (fs.NodeGetlker)((*Node)(nil))
var _ = (fs.NodeSetlker)((*Node)(nil))
var _ = (fs.NodeSetlkwer)((*Node)(nil))
var _ = (fs.NodeSetattrer)((*Node)(nil))
var _ = (fs.FileFlusher)((*handle)(nil))
var _ = (fs.FileFsyncer)((*handle)(nil))
var _ = (fs.NodeFsyncer)((*Node)(nil))

// NewRoot builds the root node.
func NewRoot(l *Layout) *Node {
	if l.TTL <= 0 {
		l.TTL = 2 * time.Second
	}
	return &Node{lay: l, path: "/"}
}

// hostDir reports whether p is an ancestor of a host root and therefore must
// appear as a directory with the host roots beneath it as children.
func (n *Node) hostDir(p string) bool {
	if n.lay.Local != nil && n.lay.Local.IsLocal(p) {
		return false
	}
	return n.lay.HostDirs[p]
}

// hostChildren lists the immediate child names of a host directory.
func (n *Node) hostChildren(p string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(root string) {
		var child string
		switch {
		case p == "/":
			child = "/" + strings.SplitN(strings.TrimPrefix(root, "/"), "/", 2)[0]
		case strings.HasPrefix(root, p+"/"):
			rest := strings.TrimPrefix(root, p+"/")
			child = path.Join(p, strings.SplitN(rest, "/", 2)[0])
		default:
			return
		}
		if !seen[child] {
			seen[child] = true
			out = append(out, child)
		}
	}
	for _, root := range n.lay.Local.Roots() {
		add(root)
	}
	// Exec-policy directories may live deeper than any local tree (for
	// example /usr/bin under /usr); they still have to appear.
	for _, d := range n.lay.ExecDirs {
		add(d)
	}
	return out
}

// hostRoot returns the host path backing a sandbox path, when the path policy
// says it is local content.
//
// The two namespaces are the same string by design: a tree listed as local is
// served from the identical host path, so nothing has to be rewritten and a
// path printed by either side means the same file.
func (n *Node) hostRoot(p string) (string, bool) {
	if n.lay.Local == nil || !n.lay.Local.IsLocal(p) {
		return "", false
	}
	return p, true
}

// isLoader reports whether p is a dynamic loader or a shared object. Loaders
// are always local: they are what makes a dynamically linked program runnable.
func isLoader(p string) bool {
	base := path.Base(p)
	if strings.Contains(base, "ld-linux") || strings.Contains(base, "ld-musl") {
		return true
	}
	return strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.")
}

// execTarget returns the single file that backs an exec-policy member: either
// the local binary or the trampoline. Every filesystem operation goes through
// this decision so sizes and contents cannot disagree.
// execTarget resolves an allowlisted name to the file that backs it here.
//
// A name with no local file is served by the trampoline, so the file to stat is
// the trampoline itself. Only when the policy declines both — the name is local
// and allowed — does this stat the real path.
func (n *Node) execTarget(p string) (string, os.FileInfo, error) {
	if trap, ok := n.trapFor(p); ok {
		fi, err := os.Stat(trap)
		return trap, fi, err
	}
	fi, err := os.Stat(p)
	return p, fi, err
}

// writable reports whether modifications under p are permitted.
func (n *Node) writable(p string) bool {
	if n.lay.Local == nil {
		return false
	}
	return n.lay.Local.Writable(p)
}

// isSyntheticFile reports whether p is a file the sandbox reserves as a bind
// target. It must appear to exist without being created on the daemon.
func (n *Node) isSyntheticFile(p string) bool {
	for _, f := range n.lay.SyntheticFiles {
		if p == f {
			return true
		}
	}
	return false
}

// isSyntheticDir reports whether p is exactly a sandbox-provided mount point.
// Children of a synthetic directory are not automatic: only Create() may make
// them, and only as placeholders for a bind mount.
func (n *Node) isSyntheticDir(p string) bool {
	for _, d := range n.lay.Synthetic {
		if p == d {
			return true
		}
	}
	return false
}

// inSynthetic reports whether p lives below a synthetic directory, in which
// case the remote daemon is never consulted.
func (n *Node) inSynthetic(p string) bool {
	for _, d := range n.lay.Synthetic {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

func (n *Node) isExecDir(p string) bool {
	for _, d := range n.lay.ExecDirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// trapFor returns the trampoline when p is an executable the policy reroutes.
func (n *Node) trapFor(p string) (string, bool) {
	if n.lay.Trampoline == "" || n.lay.LocalExec == nil {
		return "", false
	}
	// The dynamic loader is executed by the kernel for every ELF that has an
	// interpreter. Trapping it would mean no local program could start at all.
	if isLoader(p) {
		return "", false
	}
	// Redirection applies only where the policy decides between names: an
	// exec-policy directory. A data file that merely happens to be executable
	// (a chmod 777 text file, a script inside a project tree) is not a program
	// the policy spoke about, and must pass through untouched. Without this an
	// agent reading a +x file from its own tree would silently receive the
	// trampoline binary.
	if !n.isExecDir(p) {
		return "", false
	}
	if trap, ok := n.trapForExact(p); ok {
		return trap, true
	}
	// A name inside an exec-policy directory that does not exist on this
	// machine can still be a program on the daemon. The policy says which
	// directory decides where programs run, not that every name in it is local;
	// an ssh-style session has to be able to run a tool that was only ever
	// installed on the other side. Without this the name resolves to ENOENT and
	// the session cannot use the daemon's programs at all.
	if !n.existsHere(p) {
		if kind, ok := n.remoteKind(p); ok && kind != proto.SIFDIR {
			return n.lay.Trampoline, true
		}
	}
	return "", false
}

// trapForExact is the original decision: the name is a local file that the
// policy declined to run here.
func (n *Node) trapForExact(p string) (string, bool) {
	host := p
	fi, err := os.Lstat(host)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
		return "", false
	}
	if n.lay.LocalExec(host) {
		return "", false
	}
	return n.lay.Trampoline, true
}

// existsHere reports whether the host has this path at all.
func (n *Node) existsHere(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// remoteKind asks the daemon what this path is there. It is only consulted for
// names the host does not have, so the common case costs no round trip. A
// directory must stay a directory: turning one into a trampoline would make
// every child of it unreachable.
func (n *Node) remoteKind(p string) (uint32, bool) {
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p})
	if err != nil || resp.Kind != proto.KStat {
		return 0, false
	}
	return resp.Attr.Mode &^ 0o7777, true
}

// kind extracts the file type bits. Comparing whole words matters: a regular
// file mode still has bits in common with every other type constant.
func kind(mode uint32) uint32 { return mode & 0o170000 }

// attrOf builds a complete attribute set. Every field the kernel may infer
// from another must be consistent: a directory reports no size, a symlink
// reports its target length, and blocks are only meaningful for regular files.
// attrOfFI builds an attribute from a real host file, timestamps included.
//
// Every tool that decides whether to rebuild, restage or refetch compares
// mtimes. Leaving them at zero makes every file look infinitely old, so caches
// never invalidate, `make` rebuilds unconditionally and `git status` reports
// the whole tree as modified.
func attrOfFI(mode uint32, fi os.FileInfo, ino uint64) fuse.Attr {
	a := attrOf(mode, uint64(fi.Size()), ino)
	if fi != nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Nlink > 0 {
			a.Nlink = uint32(st.Nlink)
		}
		mt := fi.ModTime()
		a.Mtime = uint64(mt.Unix())
		a.Mtimensec = uint32(mt.Nanosecond())
		a.Ctime = a.Mtime
		a.Ctimensec = a.Mtimensec
		a.Atime = a.Mtime
		a.Atimensec = a.Mtimensec
	}
	return a
}

// attrOfRemote builds an attribute from the daemon's description. The daemon
// sends whole seconds, so the sub-second field stays empty rather than invented.
func attrOfRemote(a proto.Attr, ino uint64) fuse.Attr {
	out := attrOf(a.Mode, a.Size, ino)
	if a.Mtime > 0 {
		out.Mtime = uint64(a.Mtime)
		out.Ctime = out.Mtime
		out.Atime = out.Mtime
	}
	if a.UID != 0 || a.GID != 0 {
		out.Uid, out.Gid = a.UID, a.GID
	}
	// A hard link is only useful if the caller can see that it has one: tools
	// that unlink a temporary name and expect the data to survive check this.
	if a.Nlink > 0 {
		out.Nlink = a.Nlink
	}
	return out
}

func attrOf(mode uint32, size uint64, ino uint64) fuse.Attr {
	a := fuse.Attr{Mode: mode, Ino: ino, Nlink: 1, Blksize: 4096}
	switch kind(mode) {
	case proto.SIFDIR:
		a.Size = 0
		a.Nlink = 2
	case proto.SIFLNK:
		a.Size = size
		a.Nlink = 1
	default:
		a.Size = size
		a.Nlink = 1
		a.Blocks = (size + 511) / 512
	}
	return a
}

func (n *Node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (in *fs.Inode, errno syscall.Errno) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("rsbx: PANIC in Lookup(%s/%s): %v", n.path, name, r)
			in, errno = nil, syscall.EIO
		}
	}()
	p := path.Join(n.path, name)
	// 1. trampolined executable
	if _, ok := n.trapFor(p); ok {
		fi, err := os.Stat(n.lay.Trampoline)
		if err != nil {
			return nil, syscall.EIO
		}
		s := &Node{lay: n.lay, path: p}
		out.Attr = attrOf(proto.SIFREG|0o555, uint64(fi.Size()), ino(p))
		return n.NewPersistentInode(ctx, s, fs.StableAttr{Mode: syscall.S_IFREG, Ino: ino(p)}), 0
	}
	// 2. a merged-usr symlink such as /lib -> usr/lib
	if target, ok := n.lay.SystemLinks[p]; ok {
		out.Attr = attrOf(proto.SIFLNK|0o777, uint64(len(target)), ino(p))
		child := &Node{lay: n.lay, path: p}
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFLNK, Ino: ino(p)}), 0
	}
	// 3. host passthrough
	if host, ok := n.hostRoot(p); ok {
		fi, err := os.Lstat(host)
		if err != nil {
			return nil, syscall.ENOENT
		}
		mode := uint32(proto.SIFREG) | uint32(fi.Mode().Perm())
		fmode := uint32(syscall.S_IFREG)
		switch {
		case fi.IsDir():
			mode, fmode = proto.SIFDIR|uint32(fi.Mode().Perm()), syscall.S_IFDIR
		case fi.Mode()&os.ModeSymlink != 0:
			mode, fmode = proto.SIFLNK|0o777, syscall.S_IFLNK
		}
		out.Attr = attrOfFI(mode, fi, ino(p))
		child := &Node{lay: n.lay, path: p}
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: fmode, Ino: ino(p)}), 0
	}
	// 3. a reserved file mount point (the guard and trampoline binaries)
	if n.isSyntheticFile(p) {
		out.Attr = attrOf(proto.SIFREG|0o600, 0, ino(p))
		child := &Node{lay: n.lay, path: p}
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG, Ino: ino(p)}), 0
	}
	// 4. exact mount point provided by the sandbox
	if n.isSyntheticDir(p) {
		out.Attr = attrOf(proto.SIFDIR|0o755, 0, ino(p))
		child := &Node{lay: n.lay, path: p}
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR, Ino: ino(p)}), 0
	}
	// 4. inside an exec-policy directory: every name resolves to either a
	//    local binary or a trampoline, both served from the host filesystem.
	//    This is the branch that makes an allowlisted program reachable at all.
	if n.isExecDir(p) {
		_, fi, err := n.execTarget(p)
		if err != nil {
			// No local file of that name. The daemon may still have it: a
			// directory of programs that exists only on the other side is an
			// ordinary thing for an ssh-style session to reach for.
			if mode, ok := n.remoteKind(p); ok {
				out.Attr = attrOf(mode, 0, ino(p))
				if resp, rerr := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p}); rerr == nil && resp.Kind == proto.KStat {
					out.Attr = attrOfRemote(resp.Attr, remoteIno(resp.Attr, p))
				}
				child := &Node{lay: n.lay, path: p}
				fm := uint32(syscall.S_IFREG)
				if mode == proto.SIFDIR {
					fm = syscall.S_IFDIR
				}
				return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: fm, Ino: out.Attr.Ino}), 0
			}
			return nil, syscall.ENOENT
		}
		mode := uint32(proto.SIFREG) | uint32(fi.Mode().Perm())
		fmode := uint32(syscall.S_IFREG)
		switch {
		case fi.IsDir():
			mode, fmode = proto.SIFDIR|uint32(fi.Mode().Perm()), syscall.S_IFDIR
		case fi.Mode()&os.ModeSymlink != 0:
			mode, fmode = proto.SIFLNK|0o777, syscall.S_IFLNK
		}
		out.Attr = attrOf(mode, uint64(fi.Size()), ino(p))
		child := &Node{lay: n.lay, path: p}
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: fmode, Ino: ino(p)}), 0
	}
	// 5. ancestor of a local tree: a directory that exists only to hold it.
	//    It must be listed as such, not as an entry with no children.
	if n.hostDir(p) {
		out.Attr = attrOf(proto.SIFDIR|0o555, 0, ino(p))
		child := &Node{lay: n.lay, path: p}
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR, Ino: ino(p)}), 0
	}
	// 5. nothing else lives inside a synthetic tree until bwrap mounts it
	if n.inSynthetic(p) {
		return nil, syscall.ENOENT
	}
	// 6. remote
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p})
	if err != nil {
		return nil, syscall.EIO
	}
	switch resp.Kind {
	case proto.KNone:
		return nil, syscall.ENOENT
	case proto.KErr:
		return nil, errnoOf(resp.Err)
	case proto.KStat:
		mode := uint32(syscall.S_IFREG)
		switch kind(resp.Attr.Mode) {
		case proto.SIFDIR:
			mode = syscall.S_IFDIR
		case proto.SIFLNK:
			mode = syscall.S_IFLNK
		}
		out.Attr = attrOfRemote(resp.Attr, remoteIno(resp.Attr, p))
		child := &Node{lay: n.lay, path: p}
		// A hard link means several names resolve to one inode. Whichever name
		// the kernel looks up last has to become the path that inode uses, or a
		// read through the other name asks the daemon for a file that was just
		// renamed or removed.
		if existing := n.GetChild(name); existing != nil {
			if node, ok := existing.Operations().(*Node); ok && node.path != p {
				node.path = p
			}
		}
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: mode, Ino: out.Attr.Ino}), 0
	}
	return nil, syscall.EIO
}

func (n *Node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	seen := map[string]bool{}
	var ents []fuse.DirEntry
	push := func(name string, mode uint32) {
		if seen[name] {
			return
		}
		seen[name] = true
		fm := uint32(syscall.S_IFREG)
		switch kind(mode) {
		case proto.SIFDIR:
			fm = syscall.S_IFDIR
		case proto.SIFLNK:
			fm = syscall.S_IFLNK
		}
		ents = append(ents, fuse.DirEntry{Name: name, Mode: fm, Ino: ino(path.Join(n.path, name))})
	}
	// A local tree is read from its host directory. An exec-policy directory
	// is also read from the host, but each entry is then resolved through the
	// policy, so the same listing yields local binaries and trampolines.
	host, fromHost := n.hostRoot(n.path)
	if !fromHost && n.isExecDir(n.path) {
		host, fromHost = n.path, true
	}
	if fromHost {
		des, err := os.ReadDir(host)
		if err != nil {
			return nil, syscall.ENOENT
		}
		execDir := n.isExecDir(n.path)
		for _, de := range des {
			name := de.Name()
			if execDir {
				if _, ok := n.trapFor(path.Join(n.path, name)); ok {
					push(name, proto.SIFREG|0o555)
					continue
				}
			}
			info, err := de.Info()
			if err != nil {
				continue
			}
			mode := uint32(proto.SIFREG) | uint32(info.Mode().Perm())
			switch {
			case info.IsDir():
				mode = proto.SIFDIR | uint32(info.Mode().Perm())
			case info.Mode()&os.ModeSymlink != 0:
				mode = proto.SIFLNK | 0o777
			}
			push(name, mode)
		}
	}
	if resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxList, Path: n.path}); err == nil && resp.Kind == proto.KDir {
		for _, e := range resp.Ents {
			push(e.Name, e.Mode)
		}
	}
	for _, child := range n.hostChildren(n.path) {
		push(path.Base(child), proto.SIFDIR|0o555)
	}
	for _, d := range n.lay.Synthetic {
		if path.Dir(d) == n.path {
			push(path.Base(d), proto.SIFDIR|0o755)
		}
	}
	for _, f := range n.lay.SyntheticFiles {
		if path.Dir(f) == n.path {
			push(path.Base(f), proto.SIFREG|0o600)
		}
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name < ents[j].Name })
	return fs.NewListDirStream(ents), 0
}

func (n *Node) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if h, ok := f.(*handle); ok && h.temp != "" {
		fi, err := os.Stat(h.temp)
		if err != nil {
			return syscall.EIO
		}
		// The local copy has its own mtime, which says when it was fetched, not
		// when the file changed. Report the daemon's metadata: tar compares the
		// stat it took before reading with the one after, and a zero timestamp
		// on either side reads as "the file changed while I was reading it".
		if h.base.Mode != 0 || h.base.Mtime != 0 {
			out.Attr = attrOfRemote(h.base, remoteIno(h.base, n.path))
			out.Attr.Size = uint64(fi.Size())
			return 0
		}
		out.Attr = attrOfFI(proto.SIFREG|0o644, fi, ino(n.path))
		return 0
	}
	// An exec-policy member is served from one file, chosen once by trapFor.
	// Getattr, Lookup and Open must all agree on which, or the kernel caches
	// one size and reads another.
	if n.isExecDir(n.path) {
		target, fi, err := n.execTarget(n.path)
		if err != nil {
			return syscall.ENOENT
		}
		mode := uint32(proto.SIFREG) | uint32(fi.Mode().Perm())
		switch {
		case fi.IsDir():
			mode = proto.SIFDIR | uint32(fi.Mode().Perm())
		case fi.Mode()&os.ModeSymlink != 0:
			mode = proto.SIFLNK | 0o777
		}
		_ = target
		out.Attr = attrOfFI(mode, fi, ino(n.path))
		return 0
	}
	if trap, ok := n.trapFor(n.path); ok {
		fi, err := os.Stat(trap)
		if err != nil {
			return syscall.EIO
		}
		out.Attr = attrOf(proto.SIFREG|0o555, uint64(fi.Size()), ino(n.path))
		return 0
	}
	if host, ok := n.hostRoot(n.path); ok {
		fi, err := os.Lstat(host)
		if err != nil {
			return syscall.ENOENT
		}
		mode := uint32(proto.SIFREG) | uint32(fi.Mode().Perm())
		switch {
		case fi.IsDir():
			mode = proto.SIFDIR | uint32(fi.Mode().Perm())
		case fi.Mode()&os.ModeSymlink != 0:
			mode = proto.SIFLNK | 0o777
		}
		out.Attr = attrOfFI(mode, fi, ino(n.path))
		return 0
	}
	if target, ok := n.lay.SystemLinks[n.path]; ok {
		out.Attr = attrOf(proto.SIFLNK|0o777, uint64(len(target)), ino(n.path))
		return 0
	}
	if n.isSyntheticFile(n.path) {
		out.Attr = attrOf(proto.SIFREG|0o600, 0, ino(n.path))
		return 0
	}
	if n.phantom {
		out.Attr = attrOf(proto.SIFREG|0o600, 0, ino(n.path))
		return 0
	}
	if n.hostDir(n.path) {
		out.Attr = attrOf(proto.SIFDIR|0o555, 0, ino(n.path))
		return 0
	}
	if n.isSyntheticDir(n.path) {
		out.Attr = attrOf(proto.SIFDIR|0o755, 0, ino(n.path))
		return 0
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: n.path})
	if err != nil {
		return syscall.EIO
	}
	switch resp.Kind {
	case proto.KNone:
		return syscall.ENOENT
	case proto.KErr:
		return errnoOf(resp.Err)
	}
	out.Attr = attrOfRemote(resp.Attr, remoteIno(resp.Attr, n.path))
	return 0
}

func (n *Node) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	if target, ok := n.lay.SystemLinks[n.path]; ok {
		return []byte(target), 0
	}
	if host, ok := n.hostRoot(n.path); ok {
		if target, err := os.Readlink(host); err == nil {
			return []byte(target), 0
		}
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxReadlink, Path: n.path})
	if err != nil || resp.Kind != proto.KLink {
		return nil, syscall.EINVAL
	}
	return resp.Data, 0
}

// heads are file handles: immutable files are served from the host, remote
// files are materialised once so writes behave like a normal filesystem.
type handle struct {
	f     *os.File
	temp  string
	dirty bool
	path  string
	lay   *Layout
	// base is the state the file had when it was opened. A remote write that
	// changed it since then is a real conflict: two writers, one file.
	base proto.Attr
	// private marks a temp file that belongs to this handle alone, so it is
	// removed on release. A write buffer uses the shared cache key instead.
	private bool
	// appendOnly marks handles opened for append, where the bytes are appended
	// on the daemon instead of being replayed from a local copy.
	appendOnly bool
	// remote marks a handle whose writes go to the daemon rather than a local
	// copy.
	remote string
}

// Flush is what a closed fd actually waits for. Programs that append with >> in
// a loop rely on it: they write, flush, write, flush. Without it the bytes sit
// in the handle until the file is finally released, and an append that reopens
// the path in between sees nothing.
func (h *handle) Flush(ctx context.Context) syscall.Errno {
	if h.f != nil {
		h.f.Sync()
	}
	return 0
}

// Fsync is the node-level form, which go-fuse dispatches when a handler
// implements NodeFsyncer. Both forms exist because the kernel does not
// distinguish them and go-fuse prefers the file handle.
func (n *Node) Fsync(ctx context.Context, f fs.FileHandle, flags uint32) syscall.Errno {
	if h, ok := f.(*handle); ok {
		return h.Fsync(ctx, flags)
	}
	return 0
}

// Fsync answers the durability request programs actually make. SQLite and
// every editor that writes a file then fsyncs rely on it; without an
// implementation the kernel answers ENOTSUP, which agents report as
// "EIO: i/o error, write" and retry forever.
func (h *handle) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	if h.f == nil {
		return 0
	}
	if h.remote != "" {
		// A remote write is already applied on the daemon side, one operation
		// per write; there is no local buffer left to flush.
		return 0
	}
	if err := h.f.Sync(); err != nil {
		switch {
		case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOTSUP):
			return 0
		}
		return errnoOf(err.Error())
	}
	return 0
}

// Release flushes a modified remote file back to the daemon.
//
// Two processes can hold the same path at once: a local one going through this
// filesystem, and a redirected one whose writes go straight to the daemon's
// disk. Replacement is therefore last-writer-wins, which is what a normal
// shared filesystem does too — but appends are merged, because an append is the
// one case where neither side can reconstruct the other's data.
func (h *handle) Release(ctx context.Context) syscall.Errno {
	if h.f != nil {
		h.f.Close()
	}
	if h.remote != "" {
		return 0
	}
	// A read handle owns a private copy of the bytes it was opened on, and
	// nothing else refers to it once the descriptor is gone.
	if h.temp != "" && !h.dirty && h.private {
		os.Remove(h.temp)
	}
	if !h.dirty || h.temp == "" {
		return 0
	}
	defer os.Remove(h.temp)
	data, err := os.ReadFile(h.temp)
	if err != nil {
		return syscall.EIO
	}
	if err := h.lay.Remote.WriteFile(h.path, data); err != nil {
		return syscall.EIO
	}
	return 0
}

func (n *Node) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	writes := flags&(uint32(os.O_WRONLY)|uint32(os.O_RDWR)|uint32(os.O_TRUNC)|uint32(os.O_APPEND)) != 0
	if trap, ok := n.trapFor(n.path); ok {
		if writes {
			return nil, 0, syscall.EROFS
		}
		f, err := os.Open(trap)
		if err != nil {
			return nil, 0, syscall.EIO
		}
		return &handle{f: f, path: n.path, lay: n.lay}, fuse.FOPEN_KEEP_CACHE, 0
	}
	if host, ok := n.hostRoot(n.path); ok {
		if writes && !n.writable(n.path) {
			return nil, 0, syscall.EROFS
		}
		openFlags := flags
		if !writes {
			openFlags = uint32(os.O_RDONLY)
		}
		f, err := os.OpenFile(host, int(openFlags), 0)
		if err != nil {
			return nil, 0, errnoOf(err.Error())
		}
		return &handle{
			f: f, path: n.path, lay: n.lay,
			appendOnly: flags&uint32(os.O_APPEND) != 0,
		}, 0, 0
	}
	// A member of an exec-policy directory is served from the host, and the
	// policy decides which file that is: the local binary, or the trampoline.
	//
	// Only a redirected name is read-only. Data files in the same directory
	// keep working normally: an agent's state directory often holds one .node
	// or .so, and making the whole tree unwritable because of it broke session
	// persistence with EROFS.
	if n.isExecDir(n.path) {
		_, trapped := n.trapFor(n.path)
		if trapped {
			// The trampoline is immutable: writing to it would replace the
			// program, not the data.
			if writes {
				return nil, 0, syscall.EROFS
			}
			f, err := os.Open(n.lay.Trampoline)
			if err != nil {
				return nil, 0, errnoOf(err.Error())
			}
			return &handle{f: f, path: n.path, lay: n.lay}, fuse.FOPEN_KEEP_CACHE, 0
		}
		// Any other name is ordinary host data, writable like any local file.
		// An exec directory is defined by holding programs, not by being
		// read-only: an agent's state tree commonly carries one .node or .so.
		openFlags := flags
		if !writes {
			openFlags = uint32(os.O_RDONLY)
		}
		f, err := os.OpenFile(n.path, int(openFlags), 0)
		if err != nil {
			return nil, 0, errnoOf(err.Error())
		}
		return &handle{
			f: f, path: n.path, lay: n.lay,
			appendOnly: flags&uint32(os.O_APPEND) != 0,
		}, 0, 0
	}
	// Every O_APPEND open, create or not, streams appends to the daemon: the
	// kernel may reuse an inode and skip CREATE entirely for the second
	// ">> file", so OPEN has to make the same choice.
	if writes {
		// A writable remote file stays on the daemon: the local copy could not
		// see what a redirected program writes, and would overwrite it.
		return &handle{
			remote: n.path, path: n.path, lay: n.lay,
			appendOnly: flags&uint32(os.O_APPEND) != 0,
		}, 0, 0
	}
	// remote file: materialise into scratch so ordinary read/write works.
	// The materialised copy is reused, which keeps repeated execs of the
	// same remote binary to one round trip.
	if !writes {
		if cached, _, err := n.lay.cached(n.path); err == nil {
			f, err := os.Open(cached)
			if err == nil {
				return &handle{f: f, path: n.path, lay: n.lay}, fuse.FOPEN_KEEP_CACHE, 0
			}
		}
	}
	data, attr, err := n.lay.Remote.ReadFile(n.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, syscall.ENOENT
		}
		return nil, 0, errnoOf(err.Error())
	}
	temp := filepath.Join(n.lay.Cache, hash(n.path))
	if err := os.MkdirAll(n.lay.Cache, 0o700); err != nil {
		return nil, 0, syscall.EIO
	}
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return nil, 0, syscall.EIO
	}
	// The stamp is what makes the copy usable later: it records the daemon's
	// metadata at fetch time, so a later open can tell whether it is stale.
	if err := os.WriteFile(temp+".meta", []byte(stampOf(attr)), 0o600); err != nil {
		return nil, 0, syscall.EIO
	}
	// This handle gets its own copy, not the shared cache entry.
	//
	// An open descriptor must keep reading the bytes it was opened on, even if
	// the name is later rewritten or removed. Sharing the cache file breaks
	// that: the next write rewrites the same path, and the holder starts reading
	// somebody else's content — or, once the entry is dropped, nothing at all.
	// The cache entry stays as the fast path for the next open; this private
	// copy is what the descriptor reads.
	priv, err := os.CreateTemp(filepath.Dir(temp), "open-*")
	if err != nil {
		return nil, 0, syscall.EIO
	}
	if _, err := priv.Write(data); err != nil {
		priv.Close()
		os.Remove(priv.Name())
		return nil, 0, syscall.EIO
	}
	f, err := os.Open(priv.Name())
	priv.Close()
	if err != nil {
		os.Remove(priv.Name())
		return nil, 0, syscall.EIO
	}
	temp = priv.Name()
	privateCopy := true
	// Keep the metadata the copy was fetched at. A handle-scoped getattr has to
	// answer with the file's own times, not the local copy's: tar stats a file,
	// reads it, then stats again, and reports "file changed as we read it" when
	// the second answer differs.
	return &handle{f: f, temp: temp, private: privateCopy, path: n.path, lay: n.lay, base: attr}, fuse.FOPEN_KEEP_CACHE, 0
}

// writeTemp is the scratch file that buffers a remote write before it is
// flushed back, created through Create().
func (n *Node) writeTemp(p string) (*handle, syscall.Errno) {
	// Write buffers get their own key: reusing the read-cache key would let a
	// small write truncate a large cached body that nothing asked to discard.
	temp := filepath.Join(n.lay.Cache, hash(p)+".w")
	if err := os.MkdirAll(n.lay.Cache, 0o700); err != nil {
		return nil, syscall.EIO
	}
	f, err := os.OpenFile(temp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, syscall.EIO
	}
	return &handle{f: f, temp: temp, path: p, lay: n.lay, dirty: true}, 0
}

func (n *Node) Read(ctx context.Context, f fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h, ok := f.(*handle)
	if !ok {
		return fuse.ReadResultData(nil), syscall.EBADF
	}
	if h.f == nil {
		// A remote write handle has no local file. Returning an empty success
		// here is silent data corruption: a database that writes and then reads
		// back the same page sees zeros and concludes it is damaged. Read the
		// bytes from the daemon instead, which is where they are.
		if h.remote == "" {
			return fuse.ReadResultData(nil), syscall.EBADF
		}
		data, _, err := h.lay.Remote.ReadFile(h.remote)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fuse.ReadResultData(nil), syscall.ENOENT
			}
			return fuse.ReadResultData(nil), syscall.EIO
		}
		if off >= int64(len(data)) {
			return fuse.ReadResultData(nil), 0
		}
		n := copy(dest, data[off:])
		return fuse.ReadResultData(dest[:n]), 0
	}
	cnt, err := h.f.ReadAt(dest, off)
	if cnt == 0 && err != nil {
		return fuse.ReadResultData(nil), 0
	}
	return fuse.ReadResultData(dest[:cnt]), 0
}

func (n *Node) Write(ctx context.Context, f fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	h, ok := f.(*handle)
	if !ok {
		return 0, syscall.EBADF
	}
	if h.f == nil && h.remote == "" {
		return 0, syscall.EIO
	}
	// Remote files are never written locally. Two writers can hold the same
	// path, and a local copy would replay stale bytes over the daemon's disk.
	if h.remote != "" {
		req := &proto.FxReq{Op: proto.FxAppend, Path: h.path, Data: data}
		if !h.appendOnly {
			req.Op = proto.FxWriteAt
			req.Arg = itoa(uint64(off))
		}
		if _, err := h.lay.Remote.Do(req); err != nil {
			return 0, syscall.EIO
		}
		h.lay.invalidate(h.remote)
		return uint32(len(data)), 0
	}
	// A file opened with O_APPEND rejects WriteAt outright; its writes must go
	// through Write, which the kernel positions at the end. Agents open their
	// own logs and transcripts that way, so this is the common case, not an
	// edge one.
	var cnt int
	var err error
	if h.appendOnly {
		cnt, err = h.f.Write(data)
	} else {
		cnt, err = h.f.WriteAt(data, off)
	}
	if err != nil {
		return 0, errnoOf(err.Error())
	}
	h.dirty = true
	return uint32(cnt), 0
}

// Setattr handles truncate and chmod on remote files.
// Byte-range locks.
//
// SQLite takes one before it touches a database file and treats a failure as
// "disk I/O error". go-fuse answers ENOSYS when no handler is installed, so a
// database on a remote tree was unopenable: the first write always failed.
//
// Arbitration is per mount, in this process. That is exactly the set of writers
// this kernel can route through here; a program running on the daemon reaches
// its own copy of the file by a different path and is covered by the daemon's
// own locking, not by pretending two lock tables are one.

type region struct {
	typ        uint32 // FUSE_GETLK_RDLCK / WRLCK / UNLCK
	start, end uint64
	pid        uint32
}

var (
	lockMu sync.Mutex
	locks  = map[string][]region{}
)

// overlap reports whether a conflicts with b, treating end == ^uint64(0) as
// "to infinity". Two ranges overlap when each starts before the other ends.
func overlap(a, b region) bool {
	return a.start <= b.end && b.start <= a.end
}

// conflicting returns the first held lock that blocks want, ignoring locks
// owned by the same owner. A shared lock conflicts only with an exclusive one.
func conflicting(path string, want region) (region, bool) {
	lockMu.Lock()
	defer lockMu.Unlock()
	for _, held := range locks[path] {
		if held.typ == syscall.F_UNLCK || held.pid == want.pid {
			continue
		}
		if !overlap(held, want) {
			continue
		}
		if want.typ == syscall.F_RDLCK && held.typ == syscall.F_RDLCK {
			continue
		}
		return held, true
	}
	return region{}, false
}

func (n *Node) Getlk(ctx context.Context, f fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	want := region{typ: lk.Typ, start: lk.Start, end: lk.End, pid: lk.Pid}
	if held, ok := conflicting(n.path, want); ok {
		out.Typ, out.Start, out.End, out.Pid = held.typ, held.start, held.end, held.pid
		return 0
	}
	out.Typ = syscall.F_UNLCK
	return 0
}

func (n *Node) Setlk(ctx context.Context, f fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	return n.setlk(f, lk, flags, false)
}

func (n *Node) Setlkw(ctx context.Context, f fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	return n.setlk(f, lk, flags, true)
}

func (n *Node) setlk(f fs.FileHandle, lk *fuse.FileLock, flags uint32, wait bool) syscall.Errno {
	r := region{typ: lk.Typ, start: lk.Start, end: lk.End, pid: lk.Pid}
	if r.typ == syscall.F_UNLCK {
		lockMu.Lock()
		defer lockMu.Unlock()
		kept := locks[n.path][:0]
		for _, held := range locks[n.path] {
			if held.pid == r.pid && overlap(held, r) {
				continue
			}
			kept = append(kept, held)
		}
		locks[n.path] = kept
		return 0
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		lockMu.Lock()
		var clash bool
		for _, held := range locks[n.path] {
			if held.typ == syscall.F_UNLCK || held.pid == r.pid {
				continue
			}
			if !overlap(held, r) {
				continue
			}
			if r.typ == syscall.F_RDLCK && held.typ == syscall.F_RDLCK {
				continue
			}
			clash = true
			break
		}
		if !clash {
			locks[n.path] = append(locks[n.path], r)
			lockMu.Unlock()
			return 0
		}
		lockMu.Unlock()
		// EAGAIN is what fcntl(F_SETLK) reports for a held lock, and what
		// SQLite expects before it backs off and retries.
		if !wait || time.Now().After(deadline) {
			return syscall.EAGAIN
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (n *Node) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if h, ok := f.(*handle); ok && h.temp != "" {
		if size, ok := in.GetSize(); ok {
			if err := h.f.Truncate(int64(size)); err != nil {
				return errnoOf(err.Error())
			}
			h.dirty = true
		}
		fi, err := h.f.Stat()
		if err != nil {
			return syscall.EIO
		}
		out.Attr = attrOf(proto.SIFREG|0o644, uint64(fi.Size()), ino(n.path))
		return 0
	}
	// A local tree is this machine's own file: rename, chmod and utimes go
	// straight to the host call. The kernel routes all of them through Setattr,
	// so leaving any of them unhandled makes the operation report success while
	// changing nothing.
	if host, ok := n.hostRoot(n.path); ok {
		if !n.writable(n.path) {
			return syscall.EROFS
		}
		if mode, ok := in.GetMode(); ok {
			if err := os.Chmod(host, os.FileMode(mode&0o7777)); err != nil {
				return errnoOf(err.Error())
			}
		}
		if size, ok := in.GetSize(); ok {
			if err := os.Truncate(host, int64(size)); err != nil {
				return errnoOf(err.Error())
			}
		}
		if wantTimes(in) {
			if err := applyTimes(host, in); err != nil {
				return errnoOf(err.Error())
			}
		}
		return n.Getattr(ctx, f, out)
	}
	if size, ok := in.GetSize(); ok {
		n.lay.Remote.Do(&proto.FxReq{Op: proto.FxTruncate, Path: n.path,
			Arg: itoa(uint64(size))})
		n.lay.invalidate(n.path)
	}
	if mode, ok := in.GetMode(); ok {
		n.lay.Remote.Do(&proto.FxReq{Op: proto.FxChmod, Path: n.path,
			Arg: strconv.FormatUint(uint64(mode&0o7777), 8)})
	}
	if wantTimes(in) {
		n.lay.Remote.Do(&proto.FxReq{Op: proto.FxUtimes, Path: n.path,
			Arg: timesArg(in)})
	}
	return n.Getattr(ctx, f, out)
}

// wantTimes reports whether the caller asked to set either timestamp. A
// truncate or chmod arrives through the same call, so the check has to be on the
// time fields alone.
func wantTimes(in *fuse.SetAttrIn) bool {
	_, a := in.GetATime()
	_, m := in.GetMTime()
	return a || m
}

// timesArg encodes the requested times for the daemon. A side that was not
// mentioned keeps its value, which utimensat spells as UTIME_OMIT: -1 here.
func timesArg(in *fuse.SetAttrIn) string {
	a, m := int64(-1), int64(-1)
	if v, ok := in.GetATime(); ok {
		a = v.UnixNano()
	}
	if v, ok := in.GetMTime(); ok {
		m = v.UnixNano()
	}
	return strconv.FormatInt(a, 10) + "," + strconv.FormatInt(m, 10)
}

// applyTimes sets timestamps on a host file, leaving an unmentioned side alone.
func applyTimes(host string, in *fuse.SetAttrIn) error {
	fi, err := os.Stat(host)
	if err != nil {
		return err
	}
	atime, mtime := fi.ModTime(), fi.ModTime()
	if v, ok := in.GetATime(); ok {
		atime = v
	}
	if v, ok := in.GetMTime(); ok {
		mtime = v
	}
	return os.Chtimes(host, atime, mtime)
}

func (n *Node) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	p := path.Join(n.path, name)
	if host, ok := n.hostRoot(p); ok {
		if !n.writable(p) {
			return nil, nil, 0, syscall.EROFS
		}
		return n.createLocal(ctx, host, name, flags, mode, out)
	}
	// A reserved file mount point is created as a placeholder: bwrap replaces
	// it with the real bind, and nothing may reach the daemon's tree.
	if n.isSyntheticFile(p) {
		out.Attr = attrOf(proto.SIFREG|0o600, 0, ino(p))
		child := &Node{lay: n.lay, path: p, phantom: true}
		inode := n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG, Ino: ino(p)})
		return inode, &handle{path: p, lay: n.lay}, 0, 0
	}
	// Mount points inside synthetic dirs are placeholders: bwrap replaces
	// them with the real bind mount, so they must exist but hold no data.
	if n.isSyntheticDir(n.path) {
		out.Attr = attrOf(proto.SIFREG|0o600, 0, ino(p))
		child := &Node{lay: n.lay, path: p, phantom: true}
		inode := n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG, Ino: ino(p)})
		return inode, &handle{path: p, lay: n.lay}, 0, 0
	}
	// O_APPEND creates without truncating: an existing file keeps its bytes,
	// and the appends themselves are streamed by Open/Write.
	if flags&uint32(os.O_APPEND) != 0 {
		// create + append: touch the daemon side, never truncating
		if _, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxAppend, Path: p}); err != nil {
			return nil, nil, 0, syscall.EIO
		}
		out.Attr = attrOf(proto.SIFREG|mode, 0, ino(p))
		child := &Node{lay: n.lay, path: p}
		inode := n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG, Ino: ino(p)})
		return inode, &handle{remote: p, path: p, lay: n.lay, appendOnly: true}, 0, 0
	}
	if flags&uint32(os.O_EXCL) != 0 {
		if resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p}); err == nil && resp.Kind == proto.KStat {
			return nil, nil, 0, syscall.EEXIST
		}
	}
	// A writable remote file stays on the daemon, exactly as it does when Open
	// takes the same decision. Buffering it locally first would make the file
	// briefly empty on the daemon — and a database that creates its journal,
	// writes the page, then re-reads the file through a second descriptor
	// would find nothing there. O_TRUNC is the only request that clears the
	// existing bytes; O_CREAT on an existing file must leave them alone.
	exists := false
	if resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p}); err == nil {
		exists = resp.Kind == proto.KStat
	}
	if !exists || flags&uint32(os.O_TRUNC) != 0 {
		if err := n.lay.Remote.WriteFile(p, nil); err != nil {
			return nil, nil, 0, syscall.EIO
		}
		n.lay.invalidate(p)
	}
	// Use the identity the daemon just assigned. A path-derived number here
	// would differ from the one Lookup reports for the same file, and a later
	// hard link to it would appear to live on a different inode.
	stats := proto.Attr{Mode: proto.SIFREG | mode}
	if resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p}); err == nil && resp.Kind == proto.KStat {
		stats = resp.Attr
	}
	out.Attr = attrOfRemote(stats, remoteIno(stats, p))
	child := &Node{lay: n.lay, path: p}
	inode := n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG, Ino: out.Attr.Ino})
	return inode, &handle{
		remote: p, path: p, lay: n.lay,
		appendOnly: flags&uint32(os.O_APPEND) != 0,
	}, 0, 0
}

func (n *Node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	p := path.Join(n.path, name)
	if _, ok := n.hostRoot(p); ok {
		if !n.writable(p) {
			return nil, syscall.EROFS
		}
		if err := os.Mkdir(p, os.FileMode(mode)); err != nil {
			return nil, errnoOf(err.Error())
		}
		out.Attr = attrOf(proto.SIFDIR|mode, 0, ino(p))
		child := &Node{lay: n.lay, path: p}
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR, Ino: ino(p)}), 0
	}
	// inside a sandbox mount point, mkdir only needs to succeed so bwrap can
	// prepare its bind targets; the directory holds nothing of its own
	if n.inSynthetic(p) {
		out.Attr = attrOf(proto.SIFDIR|mode, 0, ino(p))
		child := &Node{lay: n.lay, path: p}
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR, Ino: ino(p)}), 0
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxMkdir, Path: p, Arg: itoa(uint64(mode))})
	if err != nil || resp.Kind == proto.KErr {
		return nil, syscall.EIO
	}
	out.Attr = attrOf(proto.SIFDIR|mode, 0, ino(p))
	child := &Node{lay: n.lay, path: p}
	return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR, Ino: ino(p)}), 0
}

// createLocal creates a file in a writable local tree. The handle is a plain
// host file descriptor: local trees have no remote counterpart to synchronise.
func (n *Node) createLocal(ctx context.Context, host, name string, flags, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	f, err := os.OpenFile(host, int(flags), os.FileMode(mode))
	if err != nil {
		return nil, nil, 0, errnoOf(err.Error())
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, 0, syscall.EIO
	}
	m := proto.SIFREG | uint32(fi.Mode().Perm())
	out.Attr = attrOf(m, uint64(fi.Size()), ino(host))
	p := path.Join(n.path, name)
	child := &Node{lay: n.lay, path: p}
	inode := n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG, Ino: ino(p)})
	return inode, &handle{
		f: f, path: p, lay: n.lay,
		// An O_APPEND file rejects WriteAt; remember how it was opened so Write
		// picks the right call. Agents create-then-append their logs this way.
		appendOnly: flags&uint32(os.O_APPEND) != 0,
	}, 0, 0
}

func (n *Node) Unlink(ctx context.Context, name string) syscall.Errno {
	p := path.Join(n.path, name)
	if _, ok := n.hostRoot(p); ok {
		if !n.writable(p) {
			return syscall.EROFS
		}
		if err := os.Remove(p); err != nil {
			return errnoOf(err.Error())
		}
		n.rehomeAfterUnlink(name, p)
		return 0
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxUnlink, Path: p})
	if err != nil {
		return syscall.EIO
	}
	if e := respErrno(resp); e != 0 {
		return e
	}
	n.rehomeAfterUnlink(name, p)
	return 0
}

// rehomeAfterUnlink keeps a surviving hard link usable.
//
// Removing one name of a file that has others must not break the rest: the
// kernel hands every name of a hard-linked file the same inode, and that inode
// carries a single path. If the path it carries is the name just removed, a read
// through any surviving name asks for a file that no longer exists — the name
// still lists, and every open of it fails with ENOENT.
//
// The successor is whichever sibling still resolves to a file, checked through
// the same backend the entry came from, so this works for a local tree and a
// remote one alike.
func (n *Node) rehomeAfterUnlink(name, removed string) {
	child := n.GetChild(name)
	if child == nil {
		return
	}
	node, ok := child.Operations().(*Node)
	if !ok || node.path != removed {
		return
	}
	for _, sibling := range n.Children() {
		other, ok := sibling.Operations().(*Node)
		if !ok || sibling == child || other.path == "" || other.path == removed {
			continue
		}
		if n.serves(other.path) {
			node.path = other.path
			return
		}
	}
}

// respErrno maps a daemon reply to an errno, keeping the difference between
// "no such file" and a real failure.
func respErrno(resp *proto.FxResp) syscall.Errno {
	if resp == nil {
		return syscall.EIO
	}
	switch resp.Kind {
	case proto.KOk, proto.KStat:
		return 0
	case proto.KNone:
		return syscall.ENOENT
	case proto.KErr:
		return errnoOf(resp.Err)
	}
	return syscall.EIO
}

// serves reports whether a path still names something this mount can read.
func (n *Node) serves(p string) bool {
	if _, ok := n.hostRoot(p); ok {
		_, err := os.Lstat(p)
		return err == nil
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p})
	return err == nil && resp.Kind == proto.KStat
}

// Rmdir removes an empty directory. Unlink must not do this job: "delete this
// directory" and "delete this file" are different questions, and one recursive
// answer to both destroys data.
func (n *Node) Rmdir(ctx context.Context, name string) syscall.Errno {
	p := path.Join(n.path, name)
	if _, ok := n.hostRoot(p); ok {
		if !n.writable(p) {
			return syscall.EROFS
		}
		// os.Remove refuses a non-empty directory, which is the contract rmdir
		// has to keep.
		if err := os.Remove(p); err != nil {
			return errnoOf(err.Error())
		}
		return 0
	}
	if n.inSynthetic(p) {
		// a bind target bwrap made itself; removing it would only be undone
		return 0
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxRmdir, Path: p})
	if err != nil {
		return syscall.EIO
	}
	return respErrno(resp)
}

// Symlink stores the link text as given. Only the link's own directory is
// resolved, so a target outside the root is a dangling link, not an escape.
func (n *Node) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	p := path.Join(n.path, name)
	if _, ok := n.hostRoot(p); ok {
		if !n.writable(p) {
			return nil, syscall.EROFS
		}
		if err := os.Symlink(target, p); err != nil {
			return nil, errnoOf(err.Error())
		}
		out.Attr = attrOf(proto.SIFLNK|0o777, uint64(len(target)), ino(p))
		child := &Node{lay: n.lay, path: p}
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFLNK, Ino: ino(p)}), 0
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxSymlink, Path: p, Arg: target})
	if err != nil {
		return nil, syscall.EIO
	}
	if e := respErrno(resp); e != 0 {
		return nil, e
	}
	out.Attr = attrOf(proto.SIFLNK|0o777, uint64(len(target)), ino(p))
	child := &Node{lay: n.lay, path: p}
	return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFLNK, Ino: ino(p)}), 0
}

// Link creates a hard link: a second name for bytes that already exist.
//
// Both names must live in the same tree. A hard link cannot cross a filesystem
// boundary, so a local name and a remote name have no inode to share — that is
// EPERM rather than EXDEV, because the kernel answers EXDEV by copying, which
// would silently turn a link into duplicated data.
func (n *Node) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	p := path.Join(n.path, name)
	src := path.Join("/", target.EmbeddedInode().Path(nil))
	if tn, ok := target.EmbeddedInode().Operations().(*Node); ok && tn.path != "" {
		src = tn.path
	}
	_, srcLocal := n.hostRoot(src)
	_, dstLocal := n.hostRoot(p)
	if srcLocal != dstLocal {
		return nil, syscall.EPERM
	}
	n.lay.invalidate(p)
	n.lay.invalidate(src)
	if dstLocal {
		if !n.writable(p) {
			return nil, syscall.EROFS
		}
		if err := os.Link(src, p); err != nil {
			return nil, errnoOf(err.Error())
		}
	} else {
		resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxLink, Path: p, Arg: src})
		if err != nil {
			return nil, syscall.EIO
		}
		if e := respErrno(resp); e != 0 {
			return nil, e
		}
		n.lay.invalidate(p)
	}
	// Answer with the file's real identity: the daemon's inode number, link
	// count and times. Both names of a hard link must present the same inode, or
	// the kernel sees two unrelated files and reports nlink 1 on each.
	stats := proto.Attr{}
	if dstLocal {
		if fi, err := os.Lstat(p); err == nil {
			out.Attr = attrOfFI(proto.SIFREG|uint32(fi.Mode().Perm()), fi, ino(p))
			child := &Node{lay: n.lay, path: p}
			return n.NewInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG, Ino: out.Attr.Ino}), 0
		}
	} else if resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p}); err == nil && resp.Kind == proto.KStat {
		stats = resp.Attr
	}
	if stats.Mode == 0 {
		stats.Mode = proto.SIFREG | 0o644
	}
	out.Attr = attrOfRemote(stats, remoteIno(stats, p))
	child := &Node{lay: n.lay, path: p}
	// NewInode, not NewPersistentInode: the number is deliberately a duplicate of
	// the target's. The persistent variant remembers inode numbers and would
	// hand back the first name's inode, leaving the new name out of the tree.
	return n.NewInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG, Ino: out.Attr.Ino}), 0
}

func (n *Node) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	from := path.Join(n.path, name)
	// Inode.Path returns a path relative to the root, so it has to be anchored
	// before it can be compared against the policy or the host filesystem.
	to := path.Join("/", newParent.EmbeddedInode().Path(nil), newName)
	if _, ok := n.hostRoot(from); ok {
		// a local file may only move within its own writable tree
		if !n.writable(from) || !n.writable(to) {
			return syscall.EROFS
		}
		if err := os.Rename(from, to); err != nil {
			return errnoOf(err.Error())
		}
		n.lay.invalidate(from)
		n.lay.invalidate(to)
		n.repoint(moved(name, from, to))
		return 0
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxRename, Path: from, Arg: to})
	if err != nil {
		return syscall.EIO
	}
	if e := respErrno(resp); e != 0 {
		return e
	}
	// Both paths in a rename describe the same bytes: the destination now has
	// them and the source no longer does. A cached copy of either would be
	// served to the next open, and git reads its object back immediately after
	// renaming it into place.
	n.lay.invalidate(from)
	n.lay.invalidate(to)
	n.repoint(moved(name, from, to))
	return 0
}

// moved carries the inode lookup a Rename needs in order to re-anchor the
// renamed node. Both sides of a rename have to be revisited: the kernel keeps
// serving the destination dentry from the source inode, and that inode still
// believes it lives at the old path.
type moveTarget struct {
	name string
	from string
	to   string
}

func moved(name, from, to string) moveTarget { return moveTarget{name, from, to} }

// repoint moves the renamed inode's notion of its own path to the destination.
//
// Without this, an atomic write (create temp, rename over the target, reopen)
// succeeds at the rename and then fails every later open with ENOENT: the
// kernel resolves the destination dentry to an inode that still answers to the
// temp name, and the daemon has no file by that name any more.
func (n *Node) repoint(m moveTarget) {
	if child := n.GetChild(m.name); child != nil {
		reanchor(child, m.from, m.to)
	}
}

// reanchor rewrites an inode's path, and the path of every inode already cached
// beneath it.
//
// Renaming a directory moves the whole dentry subtree in the kernel, so a later
// open of the destination resolves to inodes created under the old name and
// Lookup never runs again for them. Rewriting only the directory itself leaves
// every child pointing at a path the daemon no longer has, which turns
// "mv a b && cat b/f" into a silent ENOENT.
func reanchor(in *fs.Inode, from, to string) {
	if node, ok := in.Operations().(*Node); ok {
		switch {
		case node.path == from:
			node.path = to
		case strings.HasPrefix(node.path, from+"/"):
			node.path = to + strings.TrimPrefix(node.path, from)
		}
	}
	for _, child := range in.Children() {
		reanchor(child, from, to)
	}
}

func errnoOf(msg string) syscall.Errno {
	switch {
	case strings.Contains(msg, "no such file"):
		return syscall.ENOENT
	case strings.Contains(msg, "permission denied"):
		return syscall.EACCES
	case strings.Contains(msg, "is a directory"):
		return syscall.EISDIR
	case strings.Contains(msg, "not a directory"):
		return syscall.ENOTDIR
	case strings.Contains(msg, "not empty"):
		return syscall.ENOTEMPTY
	case strings.Contains(msg, "file exists"):
		return syscall.EEXIST
	}
	return syscall.EIO
}

func hash(p string) string {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(p); i++ {
		h ^= uint64(p[i])
		h *= 1099511628211
	}
	return strings.TrimPrefix(itoa(h), "-")
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

var _ = sync.Mutex{}

// cached returns the copy of a remote path that is still current.
//
// Current means the daemon's metadata for that path still matches the metadata
// recorded when the copy was made. Comparing the copy's own age would only tell
// us how long ago we fetched it, which says nothing about whether the daemon
// changed the file since.
func (l *Layout) cached(p string) (string, proto.Attr, error) {
	full := filepath.Join(l.Cache, hash(p))
	fi, err := os.Stat(full)
	if err != nil {
		return "", proto.Attr{}, err
	}
	stamp, err := os.ReadFile(full + ".meta")
	if err != nil {
		return "", proto.Attr{}, os.ErrNotExist
	}
	remote, err := l.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p})
	if err != nil {
		return "", proto.Attr{}, err
	}
	if remote.Kind != proto.KStat || string(stamp) != stampOf(remote.Attr) {
		return "", proto.Attr{}, os.ErrNotExist
	}
	attr := remote.Attr
	attr.Size = uint64(fi.Size())
	return full, attr, nil
}

// stampOf renders the metadata that decides whether a cached copy is current.
// invalidate drops the cached copy of a remote path.
//
// The cache is keyed by path and stamped with the daemon's metadata at fetch
// time, so a stale entry is normally detected on the next open. A write through
// this mount is the one case where the mount knows better: it changed the file
// itself, and the stamp it holds was taken before that. Leaving the entry means
// the next open serves the pre-write content, which a database then reports as
// "no such table" — a silent revert, not an error.
func (l *Layout) invalidate(p string) {
	if l == nil || l.Cache == "" {
		return
	}
	full := filepath.Join(l.Cache, hash(p))
	os.Remove(full)
	os.Remove(full + ".meta")
}

func stampOf(a proto.Attr) string {
	return fmt.Sprintf("%d:%d:%d", a.Size, a.Mtime, a.Ino)
}

// ino is a synthetic inode number; the kernel only needs uniqueness within a
// directory, so a hash of the sandbox path is enough and survives restarts.
// ino derives a stable inode number from a path, for entries that have no
// daemon-side identity of their own (synthetic mount points, trampolines).
//
// It is a fallback only. A real file's inode number must come from the side
// that owns it: two names for one file have to share an inode number, or the
// kernel treats a hard link as two unrelated files and `ln` reports nlink 1.
func ino(p string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(p); i++ {
		h ^= uint64(p[i])
		h *= 1099511628211
	}
	if h == 0 {
		return 1
	}
	return h
}

// remoteIno is the inode number to use for a remote entry. The daemon's number
// is unique per file, so both names of a hard link land on the same value.
func remoteIno(a proto.Attr, p string) uint64 {
	if a.Ino != 0 {
		return a.Ino
	}
	return ino(p)
}
