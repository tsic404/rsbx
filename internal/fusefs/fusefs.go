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
func (n *Node) execTarget(p string) (string, os.FileInfo, error) {
	target := p
	if trap, ok := n.trapFor(p); ok {
		target = trap
	}
	fi, err := os.Stat(target)
	return target, fi, err
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

// kind extracts the file type bits. Comparing whole words matters: a regular
// file mode still has bits in common with every other type constant.
func kind(mode uint32) uint32 { return mode & 0o170000 }

// attrOf builds a complete attribute set. Every field the kernel may infer
// from another must be consistent: a directory reports no size, a symlink
// reports its target length, and blocks are only meaningful for regular files.
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
		out.Attr = attrOf(mode, uint64(fi.Size()), ino(p))
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
		out.Attr = attrOf(resp.Attr.Mode, resp.Attr.Size, ino(p))
		child := &Node{lay: n.lay, path: p}
		return n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: mode, Ino: ino(p)}), 0
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
		out.Attr = attrOf(proto.SIFREG|0o644, uint64(fi.Size()), ino(n.path))
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
		out.Attr = attrOf(mode, uint64(fi.Size()), ino(n.path))
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
		out.Attr = attrOf(mode, uint64(fi.Size()), ino(n.path))
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
	out.Attr = attrOf(resp.Attr.Mode, resp.Attr.Size, ino(n.path))
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
	// A read-only open of a remote file has nothing to flush, so the handle
	// must not look dirty: that is what previously left copies behind.
	f, err := os.Open(temp)
	if err != nil {
		return nil, 0, syscall.EIO
	}
	return &handle{f: f, temp: temp, path: n.path, lay: n.lay}, fuse.FOPEN_KEEP_CACHE, 0
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
		return fuse.ReadResultData(nil), 0
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
	if size, ok := in.GetSize(); ok {
		n.lay.Remote.Do(&proto.FxReq{Op: proto.FxTruncate, Path: n.path,
			Arg: itoa(uint64(size))})
	}
	return n.Getattr(ctx, f, out)
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
	h, errno := n.writeTemp(p)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	n.lay.Remote.WriteFile(p, nil)
	out.Attr = attrOf(proto.SIFREG|mode, 0, ino(p))
	child := &Node{lay: n.lay, path: p}
	inode := n.NewPersistentInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG, Ino: ino(p)})
	return inode, h, 0, 0
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
		return 0
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxUnlink, Path: p})
	if err != nil || resp.Kind == proto.KErr {
		return syscall.EIO
	}
	return 0
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
		// The inode for the moved file keeps the old path, and an open that
		// still references it would resolve against a name that no longer
		// exists. Repoint it at the destination: an atomic write (create temp,
		// rename, reopen) otherwise fails on the reopen with ENOENT.
		if child := n.GetChild(name); child != nil {
			if moved, ok := child.Operations().(*Node); ok {
				moved.path = to
			}
		}
		return 0
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxRename, Path: from, Arg: to})
	if err != nil || resp.Kind == proto.KErr {
		return syscall.EIO
	}
	return 0
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
func stampOf(a proto.Attr) string {
	return fmt.Sprintf("%d:%d:%d", a.Size, a.Mtime, a.Ino)
}

// ino is a synthetic inode number; the kernel only needs uniqueness within a
// directory, so a hash of the sandbox path is enough and survives restarts.
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
