// Package fusefs is the sandbox root filesystem.
//
// The tree is a union of two layers:
//
//	remote  — answered by the daemon; every open file is a real daemon
//	          descriptor, so reads, writes, stat, fsync and locks all act on
//	          the same object the daemon's programs see
//	host    — host directories kept read-only so allowlisted binaries work
//
// Executable directories are special. A name that is a program on the daemon
// and is not allowed to run here is replaced by the trampoline binary. A path
// inside an explicitly local tree is always that tree's own content: local
// content takes precedence over execution policy, so a script in a local tree
// is never replaced by trampoline bytes.
package fusefs

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
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

// Remote answers filesystem requests against the daemon tree. Handle-based
// production opens always carry a real daemon descriptor; ReadFile and
// WriteFile are whole-file conveniences built on those handles.
type Remote interface {
	Do(req *proto.FxReq) (*proto.FxResp, error)
	ReadFile(p string) ([]byte, proto.Attr, error)
	WriteFile(p string, data []byte) error
}

// Layout describes which sandbox paths come from where.
type Layout struct {
	Remote Remote
	// Local is the set of trees served from this machine. A path that matches
	// is that tree's own content first: it is opened, read and written
	// directly, whatever the execution policy says. Content priority wins
	// over exec redirection.
	Local LocalPaths
	// ExecDirs lists sandbox directories whose names resolve through the
	// allowlist; a remote program that may not run here yields the
	// trampoline. Names inside explicit local trees are never redirected.
	ExecDirs []string
	// Trampoline is the local ELF served for trapped names.
	Trampoline string
	// LocalExec reports whether an executable may run on this machine.
	LocalExec func(hostPath string) bool
	// Cache is disposable scratch space owned by the sandbox. The filesystem
	// no longer keeps copies of remote content here: every remote open is a
	// real daemon handle, so there is no snapshot to be stale.
	Cache string
	// TTL caches negative and positive lookups for this long.
	TTL time.Duration
	// Synthetic lists paths that exist only as mount points (the launcher
	// creates them), e.g. "/proc", "/dev", "/tmp".
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

// allowedExec returns the file info for an allowlisted program: the one path
// outside an explicit local tree that may expose its own host bytes. Every
// other name in an exec-policy directory is ordinary session content and is
// served remote, even when the same name happens to exist on this host. Only
// the allowed executable's own bytes (and the ancestors that hold it) are host
// content; membership in a program directory never exposes a host listing.
func (n *Node) allowedExec(p string) (os.FileInfo, bool) {
	if n.lay.LocalExec == nil || isLoader(p) {
		return nil, false
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
		return nil, false
	}
	if !n.lay.LocalExec(p) {
		return nil, false
	}
	return fi, true
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
		// The name has to be a program on the daemon, not merely present.
		// Anything else — a data file, a directory, a placeholder — is content
		// that belongs to the session, and answering it with the trampoline
		// replaces the user's file with a copy of this binary. Creating a file
		// in an exec directory is an ordinary thing to do, and every new file
		// is absent locally by definition.
		if n.remoteIsProgram(p) {
			return n.lay.Trampoline, true
		}
	}
	return "", false
}

// remoteIsProgram reports whether the daemon holds an executable regular file at
// this path.
func (n *Node) remoteIsProgram(p string) bool {
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p})
	if err != nil || resp.Kind != proto.KStat {
		return false
	}
	return kind(resp.Attr.Mode) == proto.SIFREG && resp.Attr.Mode&0o111 != 0
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
	// All three timestamps come from the daemon's stat, at nanosecond
	// precision. Substituting mtime for atime reports a timestamp the file
	// does not have, which breaks futimens/UTIME_OMIT and any tool that
	// compares them.
	if a.Mtime > 0 {
		out.Mtime = uint64(a.Mtime)
		out.Mtimensec = a.MtimeNsec
	}
	if a.Ctime > 0 {
		out.Ctime = uint64(a.Ctime)
		out.Ctimensec = a.CtimeNsec
	}
	if a.Atime > 0 {
		out.Atime = uint64(a.Atime)
		out.Atimensec = a.AtimeNsec
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
	// 4. inside an exec-policy directory. Only the allowlisted executable's
	//    own bytes are host content; every other name is an ordinary session
	//    file and is served remote, even when the same name exists here. A
	//    directory that holds programs does not expose a host listing.
	if n.isExecDir(p) {
		if fi, ok := n.allowedExec(p); ok {
			out.Attr = attrOfFI(proto.SIFREG|uint32(fi.Mode().Perm()), fi, ino(p))
			child := &Node{lay: n.lay, path: p}
			return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG, Ino: ino(p)}), 0
		}
		if _, ok := n.trapFor(p); ok {
			fi, err := os.Stat(n.lay.Trampoline)
			if err != nil {
				return nil, syscall.EIO
			}
			out.Attr = attrOf(proto.SIFREG|0o555, uint64(fi.Size()), ino(p))
			child := &Node{lay: n.lay, path: p}
			return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG, Ino: ino(p)}), 0
		}
		// Any other name is ordinary session content; resolve it exactly as
		// any remote path would be, so an exec directory never leaks a host
		// listing.
		return n.remoteLookup(ctx, p, out)
	}
	// 5. ancestor of a local tree: a directory that exists only to hold it.
	//    It must be listed as such, not as an entry with no children.
	if n.hostDir(p) {
		out.Attr = attrOf(proto.SIFDIR|0o555, 0, ino(p))
		child := &Node{lay: n.lay, path: p}
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR, Ino: ino(p)}), 0
	}
	// 5. nothing else lives inside a synthetic tree; the launcher owns it
	if n.inSynthetic(p) {
		return nil, syscall.ENOENT
	}
	// 6. remote
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p})
	if err != nil {
		return nil, errnoFromErr(err)
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
	// An explicit local tree is read from its host directory: local content
	// has priority over everything else. An exec-policy directory is NOT read
	// from the host at all: the daemon's listing is authoritative, and only
	// allowlisted executables (served from host bytes) and trampolined remote
	// programs are reconciled against it. Membership in a program directory
	// never exposes a host listing of ordinary files.
	host, fromHost := n.hostRoot(n.path)
	execDir := n.isExecDir(n.path) && !fromHost
	if fromHost {
		des, err := os.ReadDir(host)
		if err != nil {
			return nil, syscall.ENOENT
		}
		for _, de := range des {
			name := de.Name()
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
	// Names of an exec-policy directory that only exist here are injected:
	// the allowlisted executable itself, and the local executables the policy
	// declines to run here (each of those is the trampoline).
	//
	// The per-name decision is made from what this machine has, not by asking
	// the daemon about every entry: a PATH directory holds hundreds of names,
	// and one listing must not become hundreds of round trips. A name that is
	// absent here but is a program on the daemon still resolves correctly when
	// the kernel looks it up, which is the request that actually needs the
	// answer.
	if execDir {
		if des, err := os.ReadDir(n.path); err == nil {
			for _, de := range des {
				child := path.Join(n.path, de.Name())
				if fi, err := os.Lstat(child); err != nil || fi.Mode()&0o111 == 0 {
					continue
				}
				if _, ok := n.allowedExec(child); ok {
					push(de.Name(), proto.SIFREG|0o555)
				} else if n.lay.LocalExec == nil || !n.lay.LocalExec(child) {
					push(de.Name(), proto.SIFREG|0o555)
				}
			}
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
	if h, ok := f.(*handle); ok {
		if h.fd != nil || h.rhandle != 0 {
			return n.handleGetattr(h, out)
		}
	}
	// An exec-policy member is served from one file, chosen once by the policy.
	// Getattr, Lookup and Open must all agree on which, or the kernel caches
	// one size and reads another.
	if n.isExecDir(n.path) {
		if fi, ok := n.allowedExec(n.path); ok {
			out.Attr = attrOfFI(proto.SIFREG|uint32(fi.Mode().Perm()), fi, ino(n.path))
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
		return n.remoteGetattr(n.path, out)
	}
	if trap, ok := n.trapFor(n.path); ok {
		fi, err := os.Stat(trap)
		if err != nil {
			return syscall.EIO
		}
		out.Attr = attrOf(proto.SIFREG|0o555, uint64(fi.Size()), ino(n.path))
		return 0
	}
	// A reserved bind target is the sandbox's own file. The launcher replaces
	// it with a real mount, so the daemon must never be asked about it.
	if n.isSyntheticFile(n.path) {
		out.Attr = attrOf(proto.SIFREG|0o600, 0, ino(n.path))
		return 0
	}
	if n.isSyntheticDir(n.path) {
		out.Attr = attrOf(proto.SIFDIR|0o755, 0, ino(n.path))
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
	return n.remoteGetattr(n.path, out)
}

// remoteGetattr answers a path stat from the daemon, propagating its numeric
// errno rather than flattening every failure to EIO.
func (n *Node) remoteGetattr(p string, out *fuse.AttrOut) syscall.Errno {
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p})
	if err != nil {
		return errnoFromErr(err)
	}
	switch resp.Kind {
	case proto.KNone:
		return syscall.ENOENT
	case proto.KErr:
		return errnoOf(resp.Err)
	case proto.KStat:
		out.Attr = attrOfRemote(resp.Attr, remoteIno(resp.Attr, p))
		return 0
	}
	return syscall.EIO
}

// remoteLookup resolves a path on the daemon, as the Lookup tail does; exec
// directories fall back here for names that are not allowlisted programs.
func (n *Node) remoteLookup(ctx context.Context, p string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p})
	if err != nil {
		return nil, errnoFromErr(err)
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
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: mode, Ino: out.Attr.Ino}), 0
	}
	return nil, syscall.EIO
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

// A handle is one open descriptor. A local file holds a real host fd; a
// remote file holds a live daemon handle and every read, write, fsync and
// stat asks the file where it actually lives. Nothing is ever copied off the
// daemon into a scratch snapshot: an in-place write by another client has to
// be seen by the next read of an existing descriptor.
type handle struct {
	// fd is set for local files (and the trampoline): all kernel operations
	// go through it.
	fd *os.File
	// rhandle is the daemon-side handle for a remote file, 0 when unset.
	rhandle uint64
	// dir marks a directory handle opened by OpendirHandle; Release closes
	// it as a directory descriptor and Fsyncdir syncs it.
	dir bool
	// diroff walks a remote listing one entry per Readdirent call.
	diroff int
	ents   []proto.DirEntry
	path   string
	lay    *Layout
	// base is the state the file had when it was opened; for a remote handle
	// it is refreshed by every FxFstat, so Getattr on a descriptor always
	// answers the inode that descriptor holds.
	base proto.Attr
	// appendOnly marks handles opened for append: the daemon fd carries
	// O_APPEND and a positioned write is sent with Offset -1.
	appendOnly bool
	// phantom marks a handle for a sandbox-reserved bind target: the launcher
	// mounts a real file there, so the daemon is never consulted.
	phantom bool
}

// OpendirHandle opens a directory descriptor. The remote branch asks the
// daemon for a real directory fd, so Fsyncdir can sync the same handle the
// entries were listed from — an fsync(dirfd) proof needs the descriptor, not
// a path. Local trees open their own host directory fd.
func (n *Node) OpendirHandle(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if _, ok := n.hostRoot(n.path); ok {
		d, err := os.Open(n.path)
		if err != nil {
			return nil, 0, errnoOf(err.Error())
		}
		return &handle{fd: d, dir: true, path: n.path, lay: n.lay}, 0, 0
	}
	if n.inSynthetic(n.path) {
		// A bind target the launcher made itself has no daemon counterpart;
		// the node's own child list is the whole directory.
		return &handle{dir: true, path: n.path, lay: n.lay}, 0, 0
	}
	h, _, errno := n.openRemote(n.path, uint32(os.O_RDONLY|syscall.O_DIRECTORY), 0)
	if errno != 0 {
		return nil, 0, errno
	}
	h.dir = true
	return h, 0, 0
}

// Readdirent serves one directory entry from the descriptor OpendirHandle
// opened. A remote handle lists from the daemon; a local fd reads names
// through the open directory fd; a synthetic placeholder has no entries.
func (h *handle) Readdirent(ctx context.Context) (*fuse.DirEntry, syscall.Errno) {
	if h.fd != nil {
		names, err := h.fd.Readdirnames(1)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, errnoOf(err.Error())
		}
		if len(names) == 0 {
			return nil, 0
		}
		name := names[0]
		mode := uint32(proto.SIFREG)
		if fi, err := os.Lstat(path.Join(h.path, name)); err == nil {
			switch {
			case fi.IsDir():
				mode = proto.SIFDIR
			case fi.Mode()&os.ModeSymlink != 0:
				mode = proto.SIFLNK
			}
		}
		return &fuse.DirEntry{Name: name, Mode: mode}, 0
	}
	if h.rhandle != 0 {
		if h.ents == nil {
			resp, err := h.lay.Remote.Do(&proto.FxReq{Op: proto.FxList, Path: h.path})
			if err != nil {
				return nil, errnoFromErr(err)
			}
			if resp.Errno != 0 {
				return nil, syscall.Errno(resp.Errno)
			}
			h.ents = resp.Ents
		}
		if h.diroff >= len(h.ents) {
			return nil, 0
		}
		e := h.ents[h.diroff]
		h.diroff++
		return &fuse.DirEntry{Name: e.Name, Mode: e.Mode, Ino: ino(path.Join(h.path, e.Name))}, 0
	}
	// Synthetic placeholder directory: its entries are the launcher's mount
	// targets and never real content.
	return nil, 0
}

// Fsyncdir syncs a directory descriptor, as an fsync(dirfd) proof requires.
// go-fuse routes FSYNC with a directory handle here when the handle
// implements FileFsyncdirer; the descriptor is the one OpendirHandle opened.
func (h *handle) Fsyncdir(ctx context.Context, flags uint32) syscall.Errno {
	if h.fd != nil {
		err := h.fd.Sync()
		if err != nil {
			switch {
			case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOTSUP):
				return 0
			}
			return errnoOf(err.Error())
		}
		return 0
	}
	if h.rhandle != 0 {
		resp, err := h.lay.Remote.Do(&proto.FxReq{Op: proto.FxFsync, Handle: h.rhandle, Flags: flags})
		if err != nil {
			return errnoFromErr(err)
		}
		if resp.Errno != 0 {
			return syscall.Errno(resp.Errno)
		}
		return 0
	}
	// A synthetic placeholder has nothing to sync: the launcher owns the bind
	// target, and this filesystem never wrote to it.
	return 0
}

// statOf records a handle's underlying file as a proto.Attr, for Getattr to
// report the bytes the descriptor actually serves.
func statOf(f *os.File) proto.Attr {
	fi, err := f.Stat()
	if err != nil {
		return proto.Attr{Mode: proto.SIFREG}
	}
	a := proto.Attr{
		Mode:  proto.SIFREG | uint32(fi.Mode().Perm()),
		Size:  uint64(fi.Size()),
		Mtime: fi.ModTime().Unix(),
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		a.Ino = st.Ino
		a.Dev = uint64(st.Dev)
		a.Nlink = uint32(st.Nlink)
	}
	return a
}

// Flush is what a closed fd actually waits for. Programs that append with >> in
// a loop rely on it: they write, flush, write, flush. Without it the bytes sit
// in the handle until the file is finally released, and an append that reopens
// the path in between sees nothing.
func (h *handle) Flush(ctx context.Context) syscall.Errno {
	return h.Fsync(ctx, 0)
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
	if h.fd != nil {
		if err := h.fd.Sync(); err != nil {
			switch {
			case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOTSUP):
				return 0
			}
			return errnoOf(err.Error())
		}
		return 0
	}
	if h.rhandle != 0 {
		resp, err := h.lay.Remote.Do(&proto.FxReq{Op: proto.FxFsync, Handle: h.rhandle, Flags: flags})
		if err != nil {
			return errnoFromErr(err)
		}
		if resp.Errno != 0 {
			return syscall.Errno(resp.Errno)
		}
		return 0
	}
	// A remote handle with no daemon descriptor and no local fd has nothing
	// real to sync; claiming success would be a lie about durability.
	return syscall.EBADF
}

// Release closes the descriptor. A remote handle's bytes are already on the
// daemon, so there is nothing left to write back — dirty temp files and
// whole-file snapshots no longer exist.
func (h *handle) Release(ctx context.Context) syscall.Errno {
	if h.fd != nil {
		h.fd.Close()
		h.fd = nil
	}
	if h.rhandle != 0 {
		_, err := h.lay.Remote.Do(&proto.FxReq{Op: proto.FxClose, Handle: h.rhandle})
		if err != nil {
			return errnoFromErr(err)
		}
		h.rhandle = 0
	}
	return 0
}

func (n *Node) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	writes := flags&(uint32(os.O_WRONLY)|uint32(os.O_RDWR)|uint32(os.O_TRUNC)|uint32(os.O_APPEND)) != 0
	appendMode := flags&uint32(os.O_APPEND) != 0
	// A reserved bind target exists only so the launcher has somewhere to
	// mount the real helper. It holds no bytes of its own.
	if n.isSyntheticFile(n.path) || n.isSyntheticDir(n.path) {
		f, err := os.OpenFile(os.DevNull, int(flags&uint32(syscall.O_ACCMODE)), 0)
		if err != nil {
			return nil, 0, errnoFromErr(err)
		}
		return &handle{fd: f, path: n.path, lay: n.lay, phantom: true}, 0, 0
	}
	if trap, ok := n.trapFor(n.path); ok {
		if writes {
			return nil, 0, syscall.EROFS
		}
		f, err := os.Open(trap)
		if err != nil {
			return nil, 0, syscall.EIO
		}
		// The handle carries the attributes of the program the name stands
		// for, not those of the file it was opened from. Getattr on this
		// descriptor reports the trampoline's size, and if the mode it copies
		// lacks the execute bit the kernel refuses the second exec of the same
		// name while the first one succeeded.
		base := statOf(f)
		base.Mode = proto.SIFREG | 0o555
		return &handle{
			fd: f, path: n.path, lay: n.lay, base: base,
		}, fuse.FOPEN_KEEP_CACHE, 0
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
			fd: f, path: n.path, lay: n.lay,
			appendOnly: appendMode,
			// A local file is the host's own: an open descriptor keeps the
			// inode it opened, even if the name is later replaced. Getattr on
			// that descriptor has to report the same size Read serves, so base
			// is the inode's own metadata.
			base: statOf(f),
		}, 0, 0
	}
	// A member of an exec-policy directory is served from the host only for
	// the allowlisted executable or the trampoline; the directory does not
	// expose any other host file, so everything else falls through to the
	// remote branches below.
	if n.isExecDir(n.path) {
		if _, ok := n.allowedExec(n.path); ok {
			openFlags := flags
			if !writes {
				openFlags = uint32(os.O_RDONLY)
			}
			f, err := os.OpenFile(n.path, int(openFlags), 0)
			if err != nil {
				return nil, 0, errnoOf(err.Error())
			}
			return &handle{
				fd: f, path: n.path, lay: n.lay,
				appendOnly: appendMode,
				base:       statOf(f),
			}, 0, 0
		}
		if _, trapped := n.trapFor(n.path); trapped {
			// The trampoline is immutable: writing to it would replace the
			// program, not the data.
			if writes {
				return nil, 0, syscall.EROFS
			}
			f, err := os.Open(n.lay.Trampoline)
			if err != nil {
				return nil, 0, errnoOf(err.Error())
			}
			return &handle{fd: f, path: n.path, lay: n.lay}, fuse.FOPEN_KEEP_CACHE, 0
		}
	}
	// A remote open is a daemon-side descriptor. The daemon fd carries
	// O_APPEND (so the append position is decided where the file lives) and
	// keeps the inode it opened across rename and unlink.
	h, _, errno := n.openRemote(n.path, flags, 0)
	if errno != 0 {
		return nil, 0, errno
	}
	// Direct I/O is what makes a remote descriptor trustworthy: with
	// FOPEN_KEEP_CACHE the kernel would keep serving page-cache content read
	// before a redirected program wrote the file in place, and never ask this
	// daemon again. There is no mmap for a FUSE direct-I/O file; a program that
	// mmaps a remote file gets SIGBUS rather than knowingly stale bytes.
	return h, fuse.FOPEN_DIRECT_IO, 0
}

func (n *Node) Read(ctx context.Context, f fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h, ok := f.(*handle)
	if !ok {
		return fuse.ReadResultData(nil), syscall.EBADF
	}
	if h.fd != nil {
		cnt, err := h.fd.ReadAt(dest, off)
		if cnt == 0 && err != nil {
			return fuse.ReadResultData(nil), 0
		}
		return fuse.ReadResultData(dest[:cnt]), 0
	}
	if h.rhandle == 0 {
		return fuse.ReadResultData(nil), syscall.EBADF
	}
	// A remote descriptor reads where the file lives, chunked under the frame
	// limit. There is no snapshot: an in-place write by another client shows
	// up in the next read, exactly as on a local filesystem.
	var got []byte
	remaining := int64(len(dest))
	pos := off
	for remaining > 0 {
		chunk := int64(proto.MaxIO)
		if remaining < chunk {
			chunk = remaining
		}
		resp, err := h.lay.Remote.Do(&proto.FxReq{
			Op: proto.FxPread, Handle: h.rhandle, Offset: pos, Size: uint32(chunk),
		})
		if err != nil {
			return fuse.ReadResultData(nil), errnoFromErr(err)
		}
		if resp.Errno != 0 {
			return fuse.ReadResultData(nil), syscall.Errno(resp.Errno)
		}
		if len(resp.Data) == 0 {
			break
		}
		got = append(got, resp.Data...)
		pos += int64(len(resp.Data))
		remaining -= int64(len(resp.Data))
		if len(resp.Data) < int(chunk) {
			break
		}
	}
	return fuse.ReadResultData(got), 0
}

func (n *Node) Write(ctx context.Context, f fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	h, ok := f.(*handle)
	if !ok {
		return 0, syscall.EBADF
	}
	if h.fd != nil {
		// A file opened with O_APPEND rejects WriteAt outright; its writes must
		// go through Write, which the kernel positions at the end. Agents open
		// their own logs and transcripts that way.
		var cnt int
		var err error
		if h.appendOnly {
			cnt, err = h.fd.Write(data)
		} else {
			cnt, err = h.fd.WriteAt(data, off)
		}
		if err != nil {
			return 0, errnoOf(err.Error())
		}
		return uint32(cnt), 0
	}
	if h.rhandle == 0 {
		return 0, syscall.EIO
	}
	// The daemon-side fd enforces O_APPEND itself; a positioned write is a
	// pwrite on the same live descriptor. Chunks stay under the frame limit.
	sent := uint32(0)
	for sent < uint32(len(data)) {
		end := sent + proto.MaxIO
		if end > uint32(len(data)) {
			end = uint32(len(data))
		}
		req := &proto.FxReq{
			Op: proto.FxPwrite, Handle: h.rhandle,
			Data: data[sent:end], Offset: off + int64(sent),
		}
		if h.appendOnly {
			req.Offset = -1
		}
		resp, err := h.lay.Remote.Do(req)
		if err != nil {
			return sent, errnoFromErr(err)
		}
		if resp.Errno != 0 {
			return sent, syscall.Errno(resp.Errno)
		}
		if resp.Count == 0 {
			return sent, syscall.EIO
		}
		sent += resp.Count
	}
	return sent, 0
}

// Setattr handles metadata changes on remote files.
//
// Byte-range locks.
//
// SQLite takes one before it touches a database file and treats a failure as
// "disk I/O error". Locks have to be arbitrated where the bytes live: a
// program running on the daemon, or another client, reaches the same file
// through its own path. A per-mount table here would believe it held a lock
// that the daemon granted to somebody else, so every lock question goes to the
// daemon's own descriptor for this open file. Local trees keep the kernel
// lock on their real fd.

func (n *Node) Getlk(ctx context.Context, f fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	h, _ := f.(*handle)
	if h != nil && h.rhandle != 0 {
		resp, err := h.lay.Remote.Do(&proto.FxReq{
			Op: proto.FxGetlk, Handle: h.rhandle, Owner: owner,
			Lock: &proto.LockInfo{Typ: lk.Typ, Start: lk.Start, End: lk.End, Pid: lk.Pid},
		})
		if err != nil {
			return errnoFromErr(err)
		}
		if resp.Errno != 0 {
			return syscall.Errno(resp.Errno)
		}
		if resp.Lock != nil {
			out.Typ, out.Start, out.End, out.Pid = resp.Lock.Typ, resp.Lock.Start, resp.Lock.End, resp.Lock.Pid
		} else {
			out.Typ = syscall.F_UNLCK
		}
		return 0
	}
	if h != nil && h.fd != nil {
		fl := syscall.Flock_t{Type: int16(lk.Typ), Start: int64(lk.Start), Len: int64(lk.End - lk.Start + 1)}
		if err := syscall.FcntlFlock(h.fd.Fd(), syscall.F_GETLK, &fl); err != nil {
			return errnoOf(err.Error())
		}
		out.Typ, out.Start, out.End = uint32(fl.Type), uint64(fl.Start), uint64(fl.Start+fl.Len-1)
		if fl.Type == syscall.F_UNLCK {
			out.Typ = syscall.F_UNLCK
		}
		return 0
	}
	return syscall.EBADF
}

func (n *Node) Setlk(ctx context.Context, f fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	return n.setlk(f, owner, lk, false)
}

func (n *Node) Setlkw(ctx context.Context, f fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	return n.setlk(f, owner, lk, true)
}

func (n *Node) setlk(f fs.FileHandle, owner uint64, lk *fuse.FileLock, wait bool) syscall.Errno {
	h, _ := f.(*handle)
	op := byte(proto.FxSetlk)
	if wait {
		op = proto.FxSetlkw
	}
	if h != nil && h.rhandle != 0 {
		resp, err := h.lay.Remote.Do(&proto.FxReq{
			Op: op, Handle: h.rhandle, Owner: owner,
			Lock: &proto.LockInfo{Typ: lk.Typ, Start: lk.Start, End: lk.End, Pid: lk.Pid},
		})
		if err != nil {
			return errnoFromErr(err)
		}
		return respErrno(resp)
	}
	if h != nil && h.fd != nil {
		cmd := syscall.F_SETLK
		if wait {
			cmd = syscall.F_SETLKW
		}
		fl := syscall.Flock_t{Type: int16(lk.Typ), Start: int64(lk.Start), Len: int64(lk.End - lk.Start + 1)}
		if err := syscall.FcntlFlock(h.fd.Fd(), cmd, &fl); err != nil {
			return errnoOf(err.Error())
		}
		return 0
	}
	return syscall.EBADF
}

func (n *Node) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	h, _ := f.(*handle)
	// A local tree is this machine's own file: rename, chmod and utimes go
	// straight to the host call. The kernel routes all of them through Setattr,
	// so leaving any of them unhandled makes the operation report success while
	// changing nothing.
	if h != nil && h.fd != nil {
		if size, ok := in.GetSize(); ok {
			if err := h.fd.Truncate(int64(size)); err != nil {
				return errnoOf(err.Error())
			}
		}
		if mode, ok := in.GetMode(); ok {
			if err := h.fd.Chmod(os.FileMode(mode & 0o7777)); err != nil {
				return errnoOf(err.Error())
			}
		}
		if wantTimes(in) {
			if err := applyTimes(h.fd.Name(), in); err != nil {
				return errnoOf(err.Error())
			}
		}
		return n.handleGetattr(h, out)
	}
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
	// Metadata on an opened remote descriptor acts on that descriptor's own
	truncOp, chmodOp, utimesOp := byte(proto.FxTruncate), byte(proto.FxChmod), byte(proto.FxUtimes)
	req := &proto.FxReq{Path: n.path}
	if h != nil && h.rhandle != 0 {
		truncOp, chmodOp, utimesOp = proto.FxFtruncate, proto.FxFchmod, proto.FxFutimes
		req.Handle = h.rhandle
		req.Path = ""
	}
	if size, ok := in.GetSize(); ok {
		req.Op, req.Arg = truncOp, itoa(size)
		if e := n.metaErr(req); e != 0 {
			return e
		}
	}
	if mode, ok := in.GetMode(); ok {
		req.Op, req.Arg = chmodOp, strconv.FormatUint(uint64(mode&0o7777), 8)
		if e := n.metaErr(req); e != 0 {
			return e
		}
	}
	if wantTimes(in) {
		req.Op, req.Arg = utimesOp, timesArg(in)
		if e := n.metaErr(req); e != 0 {
			return e
		}
	}
	return n.Getattr(ctx, f, out)
}

// metaErr performs one metadata mutation on the daemon and maps its numeric
// errno. A mutation is never reported as success when the daemon failed.
func (n *Node) metaErr(req *proto.FxReq) syscall.Errno {
	resp, err := n.lay.Remote.Do(req)
	if err != nil {
		return errnoFromErr(err)
	}
	return respErrno(resp)
}

// handleGetattr answers a stat from the open descriptor itself.
func (n *Node) handleGetattr(h *handle, out *fuse.AttrOut) syscall.Errno {
	if h.fd != nil {
		fi, err := h.fd.Stat()
		if err != nil {
			return errnoOf(err.Error())
		}
		out.Attr = attrOfFI(h.base.Mode, fi, h.base.Ino)
		return 0
	}
	if h.rhandle != 0 {
		resp, err := h.lay.Remote.Do(&proto.FxReq{Op: proto.FxFstat, Handle: h.rhandle})
		if err != nil {
			return errnoFromErr(err)
		}
		if resp.Errno != 0 {
			return syscall.Errno(resp.Errno)
		}
		if resp.Kind != proto.KStat && resp.Kind != proto.KHandle {
			return syscall.EIO
		}
		h.base = resp.Attr
		out.Attr = attrOfRemote(resp.Attr, remoteIno(resp.Attr, h.path))
		return 0
	}
	return syscall.EBADF
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
// timesArg encodes the timestamps a SETATTR actually asked for. A field with
// no FATTR_*_NOW and no FATTR_* flag must travel as UTIME_OMIT: GetATime and
// GetMTime turn *_NOW into time.Now(), which would silently substitute a
// current timestamp for "leave it alone".
func timesArg(in *fuse.SetAttrIn) string {
	a, m := int64(-1), int64(-1)
	if in.Valid&fuse.FATTR_ATIME != 0 && in.Valid&fuse.FATTR_ATIME_NOW == 0 {
		a = time.Unix(int64(in.Atime), int64(in.Atimensec)).UnixNano()
	}
	if in.Valid&fuse.FATTR_MTIME != 0 && in.Valid&fuse.FATTR_MTIME_NOW == 0 {
		m = time.Unix(int64(in.Mtime), int64(in.Mtimensec)).UnixNano()
	}
	return strconv.FormatInt(a, 10) + "," + strconv.FormatInt(m, 10)
}

// applyTimes sets timestamps on a host file, leaving an unmentioned side alone.
// A side the caller did not mention keeps its value, which utimensat spells as
// UTIME_OMIT; reading the old value back and rewriting it loses sub-nanosecond
// precision and races a concurrent writer.
func applyTimes(host string, in *fuse.SetAttrIn) error {
	return setFileTimes(host, in)
}

func (n *Node) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	p := path.Join(n.path, name)
	if host, ok := n.hostRoot(p); ok {
		if !n.writable(p) {
			return nil, nil, 0, syscall.EROFS
		}
		return n.createLocal(ctx, host, name, flags, mode, out)
	}
	// A reserved file mount point is created as a placeholder: the launcher
	// replaces it with the real bind, and nothing may reach the daemon's tree.
	// The handle carries the phantom mark too, so Open and Getattr on it stay
	// in the sandbox and never ask the daemon about a file that is not there.
	if n.isSyntheticFile(p) || n.isSyntheticDir(n.path) {
		out.Attr = attrOf(proto.SIFREG|0o600, 0, ino(p))
		child := &Node{lay: n.lay, path: p, phantom: true}
		inode := n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG, Ino: ino(p)})
		return inode, &handle{path: p, lay: n.lay, phantom: true}, 0, 0
	}
	// The daemon opens the file with O_CREAT and the caller's exact mode, so
	// 0600 stays 0600 regardless of the client's umask. O_CREAT on an existing
	// name keeps its bytes; only O_TRUNC clears them. O_APPEND is carried on
	// the daemon fd, so the append position is decided where the file lives.
	of := flags | uint32(syscall.O_CREAT)
	h, inoN, errno := n.openRemote(p, of, mode)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	out.Attr = attrOfRemote(h.base, inoN)
	child := &Node{lay: n.lay, path: p}
	inode := n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG, Ino: out.Attr.Ino})
	return inode, h, 0, 0
}

// openRemote opens a daemon-side descriptor. It returns the handle, the inode
// number to present for the entry, and a numeric errno.
func (n *Node) openRemote(p string, flags uint32, mode uint32) (*handle, uint64, syscall.Errno) {
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxOpen, Path: p, Flags: flags, Mode: mode})
	if err != nil {
		return nil, 0, errnoFromErr(err)
	}
	if resp.Errno != 0 {
		return nil, 0, syscall.Errno(resp.Errno)
	}
	if resp.Kind != proto.KHandle || resp.Handle == 0 {
		return nil, 0, syscall.EIO
	}
	h := &handle{
		rhandle:    resp.Handle,
		path:       p,
		lay:        n.lay,
		appendOnly: flags&uint32(syscall.O_APPEND) != 0,
		base:       resp.Attr,
	}
	return h, remoteIno(resp.Attr, p), 0
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
	// inside a reserved mount point, mkdir only needs to succeed so the
	// launcher has a target to mount over
	// prepare its bind targets; the directory holds nothing of its own
	if n.inSynthetic(p) {
		out.Attr = attrOf(proto.SIFDIR|mode, 0, ino(p))
		child := &Node{lay: n.lay, path: p}
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR, Ino: ino(p)}), 0
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxMkdir, Path: p, Arg: strconv.FormatUint(uint64(mode), 10)})
	if err != nil {
		return nil, errnoFromErr(err)
	}
	if e := respErrno(resp); e != 0 {
		return nil, e
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
		fd: f, path: p, lay: n.lay,
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
		return errnoFromErr(err)
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
	if resp.Errno != 0 {
		return syscall.Errno(resp.Errno)
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
		// a bind target the launcher owns; removing it would only be undone
		return 0
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxRmdir, Path: p})
	if err != nil {
		return errnoFromErr(err)
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
		return nil, errnoFromErr(err)
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
			return nil, errnoFromErr(err)
		}
		if e := respErrno(resp); e != 0 {
			return nil, e
		}
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
		n.repoint(moved(name, from, to))
		return 0
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxRename, Path: from, Arg: to})
	if err != nil {
		return errnoFromErr(err)
	}
	if e := respErrno(resp); e != 0 {
		return e
	}
	// An open descriptor follows its inode across a rename on the daemon, so
	// nothing cached has to be dropped here.
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

// errnoFromErr preserves a typed syscall.Errno carried by a transport error.
// A remote Do returns the daemon's errno directly, so this never guesses from
// message text when the error already names an errno.
func errnoFromErr(err error) syscall.Errno {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	if errors.Is(err, os.ErrNotExist) {
		return syscall.ENOENT
	}
	if errors.Is(err, os.ErrPermission) {
		return syscall.EACCES
	}
	if errors.Is(err, os.ErrExist) {
		return syscall.EEXIST
	}
	return errnoOf(err.Error())
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

// There is deliberately no whole-file cache here. Every remote read, write,
// stat and fsync is answered by the daemon's own descriptor for the file, so
// there is no local copy that a rename, unlink or external writer could leave
// stale; correctness no longer depends on invalidating a snapshot.

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
