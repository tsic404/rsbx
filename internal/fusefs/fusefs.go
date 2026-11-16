// Package fusefs is the sandbox root filesystem.
//
// Daemon files remain daemon bytes, including executable projects and shared
// objects. The only host exceptions are exact allowed programs, their compiled
// runtime assets, and explicitly configured local trees. Execution routing is
// independent of this filesystem; reading a program never substitutes a helper.
package fusefs

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"

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
	// Local contains explicit writable or read-only host configuration trees.
	Local LocalPaths
	// ExecPaths enumerates exact host executable assets, including aliases.
	ExecPaths []string
	// RuntimePaths enumerates concrete read-only loader/interpreter/library files.
	RuntimePaths []string
	// LocalExec confirms exact executable assets while the layout is compiled.
	LocalExec func(hostPath string) bool
	// Synthetic lists paths that exist only as mount points (the launcher
	// creates them), e.g. "/proc", "/dev", "/tmp".
	Synthetic []string
	// SyntheticFiles are mount points that are files, e.g. the guard binary.
	SyntheticFiles []string
	// HostDirs supplies structural union directories, never host listings.
	HostDirs map[string]bool
	// SystemLinks supplies explicit structural sandbox links when needed.
	SystemLinks map[string]string
}

type Node struct {
	fs.Inode
	lay   *Layout
	state *mountState
	mu    sync.RWMutex
	path  string
	src   backing
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

// NewRoot compiles rooted host mappings for one mount. Call Err before mounting,
// and Close after unmounting to release every descriptor the layout owns.
func NewRoot(l *Layout) *Node {
	layout := *l
	return &Node{lay: &layout, state: newMountState(&layout), path: "/", src: backing{kind: sourceUnion, attr: proto.Attr{Mode: proto.SIFDIR | 0o555}, readOnly: true}}
}

func (n *Node) Err() error { return n.state.err }

func (n *Node) Close() error { return n.state.close() }

func (n *Node) currentPath() string {
	n.mu.RLock()
	p := n.path
	n.mu.RUnlock()
	if p == "/" {
		return p
	}
	if _, parent := n.Parent(); parent != nil {
		return path.Join("/", n.Inode.Path(nil))
	}
	return p
}

// kind extracts the file type bits. Comparing whole words matters: a regular
// file mode still has bits in common with every other type constant.
func kind(mode uint32) uint32 { return mode & 0o170000 }

// attrOfRemote preserves the backend's complete attribute set, including inode
// identity, nanosecond timestamps and the zero link count of an unlinked fd.
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
	out.Uid, out.Gid = a.UID, a.GID
	if a.Ino != 0 || a.Nlink != 0 {
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

func (n *Node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	p := path.Join(n.currentPath(), name)
	src, errno := n.lookupBacking(p)
	if errno != 0 {
		return nil, errno
	}
	return n.newEntry(ctx, p, src, out), 0
}

func (n *Node) lookupBacking(p string) (backing, syscall.Errno) {
	r := n.state.route(p)
	src := backing{kind: r.kind, attr: r.attr, readOnly: r.readOnly, link: r.link, tree: r.tree}
	switch r.kind {
	case sourceHost:
		host, owned, err := n.state.resolveHost(p, r)
		if err != nil {
			return backing{}, errnoFromErr(err)
		}
		if owned {
			defer host.close()
		}
		attr, err := host.stat()
		if err != nil {
			return backing{}, errnoFromErr(err)
		}
		src.attr, src.link = attr, host.link
		if r.asset != nil {
			src.host = host
		} else {
			src.readOnly = src.readOnly || n.state.protected[[2]uint64{attr.Dev, attr.Ino}]
		}
	case sourceRemote:
		attr, errno := n.remoteStat(p)
		if errno != 0 {
			return backing{}, errno
		}
		src.attr = attr
	case sourceUnion:
		attr, errno := n.remoteStat(p)
		if errno == 0 && kind(attr.Mode) == proto.SIFDIR {
			src.attr = attr
		} else if errno != 0 && errno != syscall.ENOENT && errno != syscall.ENOTDIR {
			return backing{}, errno
		}
	case sourceSynthetic:
		if src.attr.Mode == 0 {
			if child := n.GetChild(path.Base(p)); child != nil {
				if node, ok := child.Operations().(*Node); ok && node.src.kind == sourceSynthetic {
					return node.src, 0
				}
			}
			return backing{}, syscall.ENOENT
		}
	}
	return src, 0
}

func (n *Node) newEntry(ctx context.Context, p string, src backing, out *fuse.EntryOut) *fs.Inode {
	inoN := ino(p)
	switch src.kind {
	case sourceHost:
		inoN = identityIno("host", src.attr, p)
	case sourceRemote:
		inoN = remoteIno(src.attr, p)
	case sourceUnion:
		if src.attr.Ino != 0 {
			inoN = remoteIno(src.attr, p)
		}
	}
	out.Attr = attrOfRemote(src.attr, inoN)
	gen := uint64(src.kind)*2 + 1
	if src.readOnly {
		gen++
	}
	if src.tree != nil {
		gen ^= ino(src.tree.prefix)
	}
	stable := fs.StableAttr{Mode: kind(src.attr.Mode), Ino: inoN, Gen: gen}
	if existing := n.GetChild(path.Base(p)); existing != nil && existing.StableAttr() == stable {
		return existing
	}
	child := &Node{lay: n.lay, state: n.state, path: p, src: src}
	if src.kind == sourceSynthetic {
		return n.NewPersistentInode(ctx, child, stable)
	}
	return n.NewInode(ctx, child, stable)
}

func (n *Node) remoteStat(p string) (proto.Attr, syscall.Errno) {
	if n.lay.Remote == nil {
		return proto.Attr{}, syscall.EIO
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxStat, Path: p})
	if err != nil {
		return proto.Attr{}, errnoFromErr(err)
	}
	if resp == nil {
		return proto.Attr{}, syscall.EIO
	}
	if errno := respErrno(resp); errno != 0 {
		return proto.Attr{}, errno
	}
	if resp.Kind != proto.KStat {
		return proto.Attr{}, syscall.EIO
	}
	return resp.Attr, 0
}

// hostMetadata uses the mapping selected at Lookup. It never asks the policy
// again or follows a sandbox symlink inside a host configuration tree.
func (n *Node) hostMetadata() (*hostObject, bool, syscall.Errno) {
	if n.src.host != nil {
		return n.src.host, false, 0
	}
	p := n.currentPath()
	if p == "" {
		return nil, false, syscall.ENOENT
	}
	host, err := n.src.tree.lookup(p)
	if err != nil {
		return nil, false, errnoFromErr(err)
	}
	if !sameIdentity(n.src.attr, host.attr) {
		host.close()
		return nil, false, syscall.ESTALE
	}
	return host, true, 0
}

func (n *Node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	f, _, errno := n.OpendirHandle(ctx, uint32(os.O_RDONLY))
	if errno != 0 {
		return nil, errno
	}
	h := f.(*handle)
	defer h.Release(ctx)
	if errno := h.loadEntries(); errno != 0 {
		return nil, errno
	}
	entries := make([]fuse.DirEntry, len(h.ents))
	for i, entry := range h.ents {
		entries[i] = fuse.DirEntry{Name: entry.Name, Mode: kind(entry.Mode)}
	}
	return fs.NewListDirStream(entries), 0
}

func (n *Node) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if h, ok := f.(*handle); ok {
		return n.handleGetattr(h, out)
	}
	p := n.currentPath()
	switch n.src.kind {
	case sourceHost:
		host, owned, errno := n.hostMetadata()
		if errno != 0 {
			return errno
		}
		if owned {
			defer host.close()
		}
		attr, err := host.stat()
		if err != nil {
			return errnoFromErr(err)
		}
		out.Attr = attrOfRemote(attr, identityIno("host", attr, p))
	case sourceRemote, sourceUnion:
		if n.src.kind == sourceUnion && n.src.attr.Ino == 0 {
			out.Attr = attrOfRemote(n.src.attr, ino(p))
			return 0
		}
		attr, errno := n.remoteStat(p)
		if errno != 0 {
			return errno
		}
		if !sameIdentity(n.src.attr, attr) {
			return syscall.ESTALE
		}
		out.Attr = attrOfRemote(attr, remoteIno(attr, p))
	default:
		out.Attr = attrOfRemote(n.src.attr, ino(p))
	}
	return 0
}

func (n *Node) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	if n.src.kind == sourceHost || n.src.kind == sourceLink {
		if kind(n.src.attr.Mode) != proto.SIFLNK {
			return nil, syscall.EINVAL
		}
		return []byte(n.src.link), 0
	}
	if n.src.kind != sourceRemote {
		return nil, syscall.EINVAL
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxReadlink, Path: n.currentPath()})
	if err != nil {
		return nil, errnoFromErr(err)
	}
	if resp == nil {
		return nil, syscall.EIO
	}
	if resp.Errno != 0 {
		return nil, syscall.Errno(resp.Errno)
	}
	if resp.Kind != proto.KLink {
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
	// fd is a live local descriptor; every IO/metadata operation uses it.
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
	// base records the opened inode for creation replies. Descriptor stats are
	// always fresh fstat requests and never depend on this snapshot.
	base proto.Attr
	// appendOnly marks handles opened for append: the daemon fd carries
	// O_APPEND and a positioned write is sent with Offset -1.
	appendOnly bool
	readOnly   bool
	overlay    []proto.DirEntry
	listed     bool
	// phantom marks a handle for a sandbox-reserved bind target: the launcher
	// mounts a real file there, so the daemon is never consulted.
	phantom bool
}

func (b *backing) hostWritable() bool {
	return b.kind == sourceHost && !b.readOnly && kind(b.attr.Mode) != proto.SIFLNK
}

// OpendirHandle keeps the real directory inode for listing and fsync. Union
// directories merge only concrete local names into the daemon listing.
func (n *Node) OpendirHandle(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if kind(n.src.attr.Mode) != proto.SIFDIR && n.src.attr.Mode != 0 {
		return nil, 0, syscall.ENOTDIR
	}
	p := n.currentPath()
	var h *handle
	switch n.src.kind {
	case sourceHost:
		host, owned, errno := n.hostMetadata()
		if errno != 0 {
			return nil, 0, errno
		}
		if owned {
			defer host.close()
		}
		fd, err := host.open(uint32(os.O_RDONLY | syscall.O_DIRECTORY))
		if err != nil {
			return nil, 0, errnoFromErr(err)
		}
		h = &handle{fd: fd, base: n.src.attr, readOnly: n.src.readOnly}
	case sourceSynthetic:
		h = &handle{phantom: true, base: n.src.attr, readOnly: true}
	default:
		var errno syscall.Errno
		h, _, errno = n.openRemote(p, uint32(os.O_RDONLY|syscall.O_DIRECTORY), 0)
		if errno != 0 {
			if n.src.kind != sourceUnion || errno != syscall.ENOENT && errno != syscall.ENOTDIR {
				return nil, 0, errno
			}
			h = &handle{phantom: true, base: n.src.attr, readOnly: true}
		} else if (n.src.kind == sourceRemote || n.src.attr.Ino != 0) && !sameIdentity(n.src.attr, h.base) {
			h.Release(ctx)
			return nil, 0, syscall.ESTALE
		}
	}
	h.dir, h.path, h.lay = true, p, n.lay
	h.overlay = n.state.children[p]
	return h, 0, 0
}

func (h *handle) loadEntries() syscall.Errno {
	if h.listed {
		return 0
	}
	var entries []proto.DirEntry
	if h.fd != nil {
		local, err := h.fd.ReadDir(-1)
		if err != nil {
			return errnoFromErr(err)
		}
		entries = make([]proto.DirEntry, len(local))
		for i, entry := range local {
			mode := uint32(proto.SIFREG)
			switch {
			case entry.IsDir():
				mode = proto.SIFDIR
			case entry.Type()&os.ModeSymlink != 0:
				mode = proto.SIFLNK
			}
			entries[i] = proto.DirEntry{Name: entry.Name(), Mode: mode}
		}
	} else if h.rhandle != 0 {
		resp, err := h.lay.Remote.Do(&proto.FxReq{Op: proto.FxList, Handle: h.rhandle})
		if err != nil {
			return errnoFromErr(err)
		}
		if resp == nil {
			return syscall.EIO
		}
		if resp.Errno != 0 {
			return syscall.Errno(resp.Errno)
		}
		if resp.Kind != proto.KDir {
			return syscall.EIO
		}
		entries = resp.Ents
	}
	if len(h.overlay) != 0 {
		positions := make(map[string]int, len(entries)+len(h.overlay))
		for i, entry := range entries {
			positions[entry.Name] = i
		}
		for _, entry := range h.overlay {
			if i, exists := positions[entry.Name]; exists {
				entries[i] = entry
			} else {
				positions[entry.Name] = len(entries)
				entries = append(entries, entry)
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	h.ents, h.listed = entries, true
	return 0
}

func (h *handle) Readdirent(ctx context.Context) (*fuse.DirEntry, syscall.Errno) {
	if errno := h.loadEntries(); errno != 0 {
		return nil, errno
	}
	if h.diroff >= len(h.ents) {
		return nil, 0
	}
	entry := h.ents[h.diroff]
	h.diroff++
	return &fuse.DirEntry{Name: entry.Name, Mode: kind(entry.Mode)}, 0
}

func (h *handle) Seekdir(ctx context.Context, off uint64) syscall.Errno {
	if errno := h.loadEntries(); errno != 0 {
		return errno
	}
	if off > uint64(len(h.ents)) {
		return syscall.EINVAL
	}
	h.diroff = int(off)
	return 0
}

func (h *handle) Releasedir(ctx context.Context, flags uint32) { h.Release(ctx) }

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
	if h.phantom {
		return 0
	}
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
	writes := flags&uint32(os.O_WRONLY|os.O_RDWR|os.O_TRUNC|os.O_APPEND|os.O_CREATE) != 0
	p := n.currentPath()
	switch n.src.kind {
	case sourceHost:
		if writes && n.src.readOnly {
			return nil, 0, syscall.EROFS
		}
		host, owned, errno := n.hostMetadata()
		if errno != 0 {
			return nil, 0, errno
		}
		if owned {
			defer host.close()
		}
		fd, err := host.open(flags)
		if err != nil {
			return nil, 0, errnoFromErr(err)
		}
		return &handle{fd: fd, path: p, lay: n.lay, base: n.src.attr, readOnly: n.src.readOnly, appendOnly: flags&uint32(os.O_APPEND) != 0}, 0, 0
	case sourceSynthetic:
		if writes {
			return nil, 0, syscall.EROFS
		}
		if kind(n.src.attr.Mode) == proto.SIFDIR {
			return nil, 0, syscall.EISDIR
		}
		return &handle{path: p, lay: n.lay, base: n.src.attr, phantom: true, readOnly: true}, 0, 0
	case sourceUnion:
		return nil, 0, syscall.EISDIR
	case sourceLink:
		return nil, 0, syscall.ELOOP
	}
	// Defer truncation until the opened descriptor's identity agrees with the
	// inode Lookup returned. A racing pathname replacement is never corrupted.
	h, _, errno := n.openRemote(p, flags&^uint32(os.O_TRUNC)|uint32(syscall.O_NOFOLLOW), 0)
	if errno != 0 {
		return nil, 0, errno
	}
	if !sameIdentity(n.src.attr, h.base) {
		h.Release(ctx)
		return nil, 0, syscall.ESTALE
	}
	if flags&uint32(os.O_TRUNC) != 0 {
		// The length travels in Offset, the field the daemon truncates to.
		if errno := n.metaErr(&proto.FxReq{Op: proto.FxFtruncate, Handle: h.rhandle, Offset: 0}); errno != 0 {
			h.Release(ctx)
			return nil, 0, errno
		}
	}
	// Reads always reach the live daemon descriptor. Mmap capability, when the
	// kernel supports direct-IO mmap, is negotiated by the mount controller.
	return h, fuse.FOPEN_DIRECT_IO, 0
}

func (n *Node) Read(ctx context.Context, f fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h, ok := f.(*handle)
	if !ok {
		return fuse.ReadResultData(nil), syscall.EBADF
	}
	if h.phantom {
		return fuse.ReadResultData(nil), 0
	}
	if h.fd != nil {
		count, err := h.fd.ReadAt(dest, off)
		if err != nil && !errors.Is(err, io.EOF) {
			return fuse.ReadResultData(dest[:count]), errnoFromErr(err)
		}
		return fuse.ReadResultData(dest[:count]), 0
	}
	if h.rhandle == 0 {
		return fuse.ReadResultData(nil), syscall.EBADF
	}
	read := 0
	for read < len(dest) {
		chunk := min(len(dest)-read, int(proto.MaxIO))
		resp, err := h.lay.Remote.Do(&proto.FxReq{Op: proto.FxPread, Handle: h.rhandle, Offset: off + int64(read), Size: uint32(chunk)})
		if err != nil {
			return fuse.ReadResultData(dest[:read]), errnoFromErr(err)
		}
		if resp == nil || len(resp.Data) > chunk {
			return fuse.ReadResultData(dest[:read]), syscall.EIO
		}
		if resp.Errno != 0 {
			return fuse.ReadResultData(dest[:read]), syscall.Errno(resp.Errno)
		}
		read += copy(dest[read:], resp.Data)
		if len(resp.Data) < chunk {
			break
		}
	}
	return fuse.ReadResultData(dest[:read]), 0
}

func (n *Node) Write(ctx context.Context, f fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	h, ok := f.(*handle)
	if !ok {
		return 0, syscall.EBADF
	}
	if h.readOnly || h.phantom {
		return 0, syscall.EROFS
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
		if resp == nil {
			return sent, syscall.EIO
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
		if resp == nil {
			return syscall.EIO
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
	if h != nil && h.phantom {
		return syscall.EROFS
	}
	if h != nil && h.fd != nil {
		if h.readOnly {
			return syscall.EROFS
		}
		if size, ok := in.GetSize(); ok {
			if err := h.fd.Truncate(int64(size)); err != nil {
				return errnoFromErr(err)
			}
		}
		if mode, ok := in.GetMode(); ok {
			if err := h.fd.Chmod(os.FileMode(mode & 0o7777)); err != nil {
				return errnoFromErr(err)
			}
		}
		uid, hasUID := in.GetUID()
		gid, hasGID := in.GetGID()
		if hasUID || hasGID {
			if !hasUID {
				uid = ^uint32(0)
			}
			if !hasGID {
				gid = ^uint32(0)
			}
			if err := h.fd.Chown(int(uid), int(gid)); err != nil {
				return errnoFromErr(err)
			}
		}
		if wantTimes(in) {
			if err := setFileTimes(h.fd, in); err != nil {
				return errnoFromErr(err)
			}
		}
		return n.Getattr(ctx, f, out)
	}
	if n.src.kind == sourceHost {
		host, owned, errno := n.hostMetadata()
		if errno != 0 {
			return errno
		}
		if owned {
			defer host.close()
		}
		if !n.src.hostWritable() {
			return syscall.EROFS
		}
		if size, ok := in.GetSize(); ok {
			fd, err := host.open(uint32(os.O_WRONLY))
			if err != nil {
				return errnoFromErr(err)
			}
			err = fd.Truncate(int64(size))
			fd.Close()
			if err != nil {
				return errnoFromErr(err)
			}
		}
		if mode, ok := in.GetMode(); ok {
			if err := chmodHost(host, mode&0o7777); err != nil {
				return errnoFromErr(err)
			}
		}
		uid, hasUID := in.GetUID()
		gid, hasGID := in.GetGID()
		if hasUID || hasGID {
			if !hasUID {
				uid = ^uint32(0)
			}
			if !hasGID {
				gid = ^uint32(0)
			}
			if err := chownHost(host, int(uid), int(gid)); err != nil {
				return errnoFromErr(err)
			}
		}
		if wantTimes(in) {
			times := host.file
			if times == nil {
				return syscall.EROFS
			}
			if err := setFileTimes(times, in); err != nil {
				return errnoFromErr(err)
			}
		}
		attr, err := host.stat()
		if err != nil {
			return errnoFromErr(err)
		}
		out.Attr = attrOfRemote(attr, identityIno("host", attr, n.currentPath()))
		return 0
	}
	if n.src.kind != sourceRemote && n.src.kind != sourceUnion && (h == nil || h.rhandle == 0) {
		return syscall.EROFS
	}
	if h == nil || h.rhandle == 0 {
		flags := uint32(os.O_RDONLY | syscall.O_NOFOLLOW)
		if _, truncate := in.GetSize(); truncate {
			flags = uint32(os.O_WRONLY | syscall.O_NOFOLLOW)
		}
		var errno syscall.Errno
		h, _, errno = n.openRemote(n.currentPath(), flags, 0)
		if errno != 0 {
			return errno
		}
		defer h.Release(ctx)
		if !sameIdentity(n.src.attr, h.base) {
			return syscall.ESTALE
		}
	}
	truncOp, chmodOp, utimesOp := byte(proto.FxFtruncate), byte(proto.FxFchmod), byte(proto.FxFutimes)
	req := &proto.FxReq{Handle: h.rhandle}
	if size, ok := in.GetSize(); ok {
		// FxFtruncate carries the new length in Offset, which is the field the
		// daemon truncates to. A decimal Arg left Offset at zero, so any
		// requested length became truncate(fd, 0).
		req.Op, req.Offset = truncOp, int64(size)
		if e := n.metaErr(req); e != 0 {
			return e
		}
	}
	if mode, ok := in.GetMode(); ok {
		// FxFchmod carries the permission bits in the typed Mode field and the
		// daemon chmods to exactly that. Encoding them in Arg instead left
		// Mode zero, so every chmod through a descriptor applied chmod(0): a
		// file created 0755 came back 0000 and could not be executed.
		req.Op, req.Mode = chmodOp, mode&0o7777
		if e := n.metaErr(req); e != 0 {
			return e
		}
	}
	_, hasUID := in.GetUID()
	_, hasGID := in.GetGID()
	if hasUID || hasGID {
		return syscall.ENOTSUP
	}
	if wantTimes(in) {
		req.Op, req.Arg = utimesOp, timesArg(in)
		if e := n.metaErr(req); e != 0 {
			return e
		}
	}
	return n.Getattr(ctx, h, out)
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
	return h.Getattr(context.Background(), out)
}

func (h *handle) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	if h.phantom {
		out.Attr = attrOfRemote(h.base, ino(h.path))
		return 0
	}
	if h.fd != nil {
		fi, err := h.fd.Stat()
		if err != nil {
			return errnoFromErr(err)
		}
		attr := hostAttr(fi)
		out.Attr = attrOfRemote(attr, identityIno("host", attr, h.path))
		return 0
	}
	if h.rhandle != 0 {
		resp, err := h.lay.Remote.Do(&proto.FxReq{Op: proto.FxFstat, Handle: h.rhandle})
		if err != nil {
			return errnoFromErr(err)
		}
		if resp == nil {
			return syscall.EIO
		}
		if resp.Errno != 0 {
			return syscall.Errno(resp.Errno)
		}
		if resp.Kind != proto.KStat && resp.Kind != proto.KHandle {
			return syscall.EIO
		}
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

// timesArg encodes exactly the requested times. Unmentioned sides use -1
// (UTIME_OMIT); explicit *_NOW fields share one captured current timestamp.
func timesArg(in *fuse.SetAttrIn) string {
	a, m := int64(-1), int64(-1)
	now := int64(0)
	if in.Valid&(fuse.FATTR_ATIME_NOW|fuse.FATTR_MTIME_NOW) != 0 {
		now = time.Now().UnixNano()
	}
	if in.Valid&fuse.FATTR_ATIME_NOW != 0 {
		a = now
	} else if in.Valid&fuse.FATTR_ATIME != 0 {
		a = time.Unix(int64(in.Atime), int64(in.Atimensec)).UnixNano()
	}
	if in.Valid&fuse.FATTR_MTIME_NOW != 0 {
		m = now
	} else if in.Valid&fuse.FATTR_MTIME != 0 {
		m = time.Unix(int64(in.Mtime), int64(in.Mtimensec)).UnixNano()
	}
	return strconv.FormatInt(a, 10) + "," + strconv.FormatInt(m, 10)
}

// openRemote opens a daemon-side descriptor. It returns the handle, the inode
// number to present for the entry, and a numeric errno.
func (n *Node) openRemote(p string, flags uint32, mode uint32) (*handle, uint64, syscall.Errno) {
	if n.lay.Remote == nil {
		return nil, 0, syscall.EIO
	}
	resp, err := n.lay.Remote.Do(&proto.FxReq{Op: proto.FxOpen, Path: p, Flags: flags, Mode: mode})
	if err != nil {
		return nil, 0, errnoFromErr(err)
	}
	if resp == nil {
		return nil, 0, syscall.EIO
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

func (n *Node) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	p := path.Join(n.currentPath(), name)
	r := n.state.route(p)
	if r.kind == sourceSynthetic {
		if kind(r.attr.Mode) == proto.SIFREG {
			return nil, nil, 0, syscall.EEXIST
		}
		out.Attr = attrOf(proto.SIFREG|mode, 0, ino(p))
		src := backing{kind: sourceSynthetic, attr: proto.Attr{Mode: proto.SIFREG | mode}, readOnly: true}
		return n.newEntry(ctx, p, src, out), &handle{path: p, lay: n.lay, base: src.attr, phantom: true, readOnly: true}, 0, 0
	}
	if r.kind != sourceRemote && r.kind != sourceHost {
		return nil, nil, 0, syscall.EROFS
	}
	if r.kind == sourceHost {
		if r.readOnly {
			return nil, nil, 0, syscall.EROFS
		}
		fd, attr, err := r.tree.create(r.relative, flags, mode, n.state.protected)
		if err != nil {
			return nil, nil, 0, errnoFromErr(err)
		}
		h := &handle{fd: fd, path: p, lay: n.lay, base: attr, appendOnly: flags&uint32(os.O_APPEND) != 0}
		return n.newEntry(ctx, p, backing{kind: sourceHost, attr: attr, tree: r.tree, readOnly: n.state.protected[[2]uint64{attr.Dev, attr.Ino}]}, out), h, 0, 0
	}
	h, _, errno := n.openRemote(p, flags|uint32(syscall.O_CREAT|syscall.O_NOFOLLOW), mode)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	return n.newEntry(ctx, p, backing{kind: sourceRemote, attr: h.base}, out), h, fuse.FOPEN_DIRECT_IO, 0
}

func (n *Node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	p := path.Join(n.currentPath(), name)
	r := n.state.route(p)
	switch r.kind {
	case sourceSynthetic:
		if kind(r.attr.Mode) == 0 {
			out.Attr = attrOf(proto.SIFDIR|mode, 0, ino(p))
			return n.newEntry(ctx, p, backing{kind: sourceSynthetic, attr: proto.Attr{Mode: proto.SIFDIR | mode}, readOnly: true}, out), 0
		}
		return nil, syscall.EEXIST
	case sourceHost:
		if r.readOnly {
			return nil, syscall.EROFS
		}
		parent, child, err := r.tree.parent(r.relative)
		if err != nil {
			return nil, errnoFromErr(err)
		}
		defer parent.Close()
		if err := unix.Mkdirat(int(parent.Fd()), child, mode); err != nil {
			return nil, errnoFromErr(err)
		}
		host, err := r.tree.lookup(p)
		if err != nil {
			return nil, errnoFromErr(err)
		}
		defer host.close()
		return n.newEntry(ctx, p, backing{kind: sourceHost, attr: host.attr, tree: r.tree}, out), 0
	case sourceUnion, sourceLink:
		return nil, syscall.EROFS
	}
	if errno := n.metaErr(&proto.FxReq{Op: proto.FxMkdir, Path: p, Mode: mode, Arg: strconv.FormatUint(uint64(mode), 10)}); errno != 0 {
		return nil, errno
	}
	attr, errno := n.remoteStat(p)
	if errno != 0 {
		return nil, errno
	}
	return n.newEntry(ctx, p, backing{kind: sourceRemote, attr: attr}, out), 0
}

func (n *Node) Unlink(ctx context.Context, name string) syscall.Errno {
	p := path.Join(n.currentPath(), name)
	r := n.state.route(p)
	switch r.kind {
	case sourceHost:
		if r.readOnly {
			return syscall.EROFS
		}
		parent, child, err := r.tree.parent(r.relative)
		if err != nil {
			return errnoFromErr(err)
		}
		defer parent.Close()
		if err := unix.Unlinkat(int(parent.Fd()), child, 0); err != nil {
			return errnoFromErr(err)
		}
	case sourceRemote:
		if errno := n.metaErr(&proto.FxReq{Op: proto.FxUnlink, Path: p}); errno != 0 {
			return errno
		}
	default:
		return syscall.EROFS
	}
	if child := n.GetChild(name); child != nil {
		if node, ok := child.Operations().(*Node); ok {
			node.mu.Lock()
			node.path = ""
			node.mu.Unlock()
		}
	}
	return 0
}

func (n *Node) Rmdir(ctx context.Context, name string) syscall.Errno {
	p := path.Join(n.currentPath(), name)
	r := n.state.route(p)
	switch r.kind {
	case sourceHost:
		if r.readOnly {
			return syscall.EROFS
		}
		parent, child, err := r.tree.parent(r.relative)
		if err != nil {
			return errnoFromErr(err)
		}
		defer parent.Close()
		if err := unix.Unlinkat(int(parent.Fd()), child, unix.AT_REMOVEDIR); err != nil {
			return errnoFromErr(err)
		}
	case sourceRemote:
		if errno := n.metaErr(&proto.FxReq{Op: proto.FxRmdir, Path: p}); errno != 0 {
			return errno
		}
	case sourceSynthetic:
		return 0
	default:
		return syscall.EROFS
	}
	if child := n.GetChild(name); child != nil {
		if node, ok := child.Operations().(*Node); ok {
			node.mu.Lock()
			node.path = ""
			node.mu.Unlock()
		}
	}
	return 0
}

func (n *Node) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	p := path.Join(n.currentPath(), name)
	r := n.state.route(p)
	attr := proto.Attr{Mode: proto.SIFLNK | 0o777, Size: uint64(len(target))}
	src := backing{kind: sourceRemote, attr: attr, link: target}
	switch r.kind {
	case sourceHost:
		if r.readOnly {
			return nil, syscall.EROFS
		}
		parent, child, err := r.tree.parent(r.relative)
		if err != nil {
			return nil, errnoFromErr(err)
		}
		defer parent.Close()
		if err := unix.Symlinkat(target, int(parent.Fd()), child); err != nil {
			return nil, errnoFromErr(err)
		}
		host, err := r.tree.lookup(p)
		if err != nil {
			return nil, errnoFromErr(err)
		}
		defer host.close()
		src = backing{kind: sourceHost, attr: host.attr, link: host.link, tree: r.tree, readOnly: n.state.protected[[2]uint64{host.attr.Dev, host.attr.Ino}]}
	case sourceRemote:
		if errno := n.metaErr(&proto.FxReq{Op: proto.FxSymlink, Path: p, Arg: target}); errno != 0 {
			return nil, errno
		}
	default:
		return nil, syscall.EROFS
	}
	return n.newEntry(ctx, p, src, out), 0
}

func (n *Node) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	tn, ok := target.EmbeddedInode().Operations().(*Node)
	if !ok {
		return nil, syscall.EPERM
	}
	p := path.Join(n.currentPath(), name)
	r := n.state.route(p)
	switch tn.src.kind {
	case sourceHost:
		if r.kind != sourceHost || r.tree != tn.src.tree || r.readOnly || !tn.src.hostWritable() {
			return nil, syscall.EPERM
		}
		host, owned, errno := tn.hostMetadata()
		if errno != 0 {
			return nil, errno
		}
		if owned {
			defer host.close()
		}
		parent, child, err := r.tree.parent(r.relative)
		if err != nil {
			return nil, errnoFromErr(err)
		}
		defer parent.Close()
		if err := linkHost(host, parent, child); err != nil {
			return nil, errnoFromErr(err)
		}
		attr, errno := tn.pathAttr()
		if errno != 0 {
			return nil, errno
		}
		return n.newEntry(ctx, p, backing{kind: sourceHost, attr: attr, tree: r.tree, readOnly: r.readOnly}, out), 0
	case sourceRemote:
		if r.kind != sourceRemote {
			return nil, syscall.EPERM
		}
		if errno := n.metaErr(&proto.FxReq{Op: proto.FxLink, Path: p, Arg: tn.currentPath()}); errno != 0 {
			return nil, errno
		}
		attr, errno := tn.pathAttr()
		if errno != 0 {
			return nil, errno
		}
		return n.newEntry(ctx, p, backing{kind: sourceRemote, attr: attr}, out), 0
	default:
		return nil, syscall.EPERM
	}
}

func (n *Node) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	from := path.Join(n.currentPath(), name)
	target, ok := newParent.EmbeddedInode().Operations().(*Node)
	if !ok {
		return syscall.EPERM
	}
	to := path.Join(target.currentPath(), newName)
	oldRoute, newRoute := n.state.route(from), n.state.route(to)
	if oldRoute.kind != newRoute.kind || oldRoute.kind != sourceRemote && oldRoute.tree != newRoute.tree {
		return syscall.EXDEV
	}
	if flags != 0 {
		return syscall.EINVAL
	}
	switch oldRoute.kind {
	case sourceHost:
		if oldRoute.readOnly || newRoute.readOnly || n.state.directories[from] || n.state.directories[to] {
			return syscall.EROFS
		}
		oldParent, oldName, err := oldRoute.tree.parent(oldRoute.relative)
		if err != nil {
			return errnoFromErr(err)
		}
		defer oldParent.Close()
		newParentFile, newBase, err := newRoute.tree.parent(newRoute.relative)
		if err != nil {
			return errnoFromErr(err)
		}
		defer newParentFile.Close()
		if err := unix.Renameat(int(oldParent.Fd()), oldName, int(newParentFile.Fd()), newBase); err != nil {
			return errnoFromErr(err)
		}
	case sourceRemote:
		if errno := n.metaErr(&proto.FxReq{Op: proto.FxRename, Path: from, Arg: to}); errno != 0 {
			return errno
		}
	default:
		return syscall.EROFS
	}
	n.repoint(moved(name, from, to))
	return 0
}

func (n *Node) pathAttr() (proto.Attr, syscall.Errno) {
	if n.src.kind == sourceHost {
		host, owned, errno := n.hostMetadata()
		if errno != 0 {
			return proto.Attr{}, errno
		}
		if owned {
			defer host.close()
		}
		attr, err := host.stat()
		if err != nil {
			return proto.Attr{}, errnoFromErr(err)
		}
		return attr, 0
	}
	return n.remoteStat(n.currentPath())
}

func (n *Node) repoint(m moveTarget) {
	if child := n.GetChild(m.name); child != nil {
		reanchor(child, m.from, m.to)
	}
}

func reanchor(in *fs.Inode, from, to string) {
	if node, ok := in.Operations().(*Node); ok {
		node.mu.Lock()
		if node.path == from {
			node.path = to
		} else if strings.HasPrefix(node.path, from+"/") {
			node.path = to + strings.TrimPrefix(node.path, from)
		}
		node.mu.Unlock()
	}
	for _, child := range in.Children() {
		reanchor(child, from, to)
	}
}

type moveTarget struct{ name, from, to string }

func moved(name, from, to string) moveTarget { return moveTarget{name, from, to} }

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

// There is deliberately no whole-file cache here. Every remote read, write,
// stat and fsync is answered by the daemon's own descriptor for the file, so
// there is no local copy that a rename, unlink or external writer could leave
// stale; correctness no longer depends on invalidating a snapshot.

// ino gives a stable identity to structural directories and mount targets.
// Real files instead use their source, device and inode identity, so aliases
// share an inode without colliding with a file on another backend or device.
func ino(p string) uint64 {
	var h uint64 = 1469598103934665603
	for i := range p {
		h ^= uint64(p[i])
		h *= 1099511628211
	}
	if h == 0 {
		return 1
	}
	return h
}

// remoteIno namespaces the daemon device/inode identity independently of host
// and synthetic entries. All hard links to the same daemon inode agree.
func remoteIno(a proto.Attr, p string) uint64 {
	return identityIno("remote", a, p)
}
