package fusefs

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"rsbx/internal/proto"
)

type sourceKind uint8

const (
	sourceRemote sourceKind = iota
	sourceHost
	sourceUnion
	sourceSynthetic
	sourceLink
)

// backing is chosen by Lookup, never by Getattr or Open. Exact assets pin their
// inode; configuration nodes keep one descriptor root plus the looked-up
// device/inode identity. A pathname replacement is ESTALE, never a source switch.
type backing struct {
	kind     sourceKind
	host     *hostObject
	tree     *localTree
	attr     proto.Attr
	readOnly bool
	link     string
}

type localTree struct {
	prefix   string
	fd       *os.File
	relative string
	readOnly bool
	err      error
}

type asset struct {
	host *hostObject
	err  error
}

type route struct {
	kind     sourceKind
	tree     *localTree
	relative string
	asset    *asset
	readOnly bool
	attr     proto.Attr
	link     string
}

// mountState owns all root descriptors and the still-live host inode pins.
// Descriptor roots make sandbox path strings unambiguous and prevent a link
// inside a configuration tree from redirecting a host operation outside it.
type mountState struct {
	mu          sync.Mutex
	closed      bool
	objects     map[*hostObject]struct{}
	protected   map[[2]uint64]bool
	trees       []*localTree
	assets      map[string]*asset
	directories map[string]bool
	synthetic   map[string]uint32
	links       map[string]string
	children    map[string][]proto.DirEntry
	err         error
}

func newMountState(l *Layout) *mountState {
	s := &mountState{
		objects: map[*hostObject]struct{}{}, assets: map[string]*asset{},
		directories: map[string]bool{"/": true}, synthetic: map[string]uint32{},
		protected: map[[2]uint64]bool{},
		links:     map[string]string{}, children: map[string][]proto.DirEntry{},
	}
	if l.Local != nil {
		for _, prefix := range l.Local.Roots() {
			if !path.IsAbs(prefix) {
				s.setError(fmt.Errorf("local tree %q is not absolute", prefix))
				continue
			}
			prefix = path.Clean(prefix)
			tree := openLocalTree(prefix, !l.Local.Writable(prefix))
			s.trees = append(s.trees, tree)
			s.setError(tree.err)
			s.addAncestors(prefix)
		}
		sort.Slice(s.trees, func(i, j int) bool { return len(s.trees[i].prefix) > len(s.trees[j].prefix) })
	}
	for group, filenames := range [][]string{l.ExecPaths, l.RuntimePaths} {
		for _, filename := range filenames {
			if !path.IsAbs(filename) {
				s.setError(fmt.Errorf("host asset %q is not absolute", filename))
				continue
			}
			filename = path.Clean(filename)
			if group == 0 && l.LocalExec != nil && !l.LocalExec(filename) {
				s.setError(fmt.Errorf("executable asset %q is not allowed by the policy", filename))
				continue
			}
			if _, exists := s.assets[filename]; exists {
				continue
			}
			host, err := openHostAsset(filename)
			if host != nil {
				s.track(host)
				s.protected[[2]uint64{host.attr.Dev, host.attr.Ino}] = true
			}
			s.assets[filename] = &asset{host: host, err: err}
			s.setError(err)
			s.addAncestors(filename)
		}
	}
	for directory := range l.HostDirs {
		if path.IsAbs(directory) {
			s.directories[path.Clean(directory)] = true
		}
	}
	for _, directory := range l.Synthetic {
		if path.IsAbs(directory) {
			directory = path.Clean(directory)
			s.synthetic[directory] = proto.SIFDIR | 0o755
			s.addAncestors(directory)
		}
	}
	for _, filename := range l.SyntheticFiles {
		if path.IsAbs(filename) {
			filename = path.Clean(filename)
			s.synthetic[filename] = proto.SIFREG | 0o600
			s.addAncestors(filename)
		}
	}
	for filename, target := range l.SystemLinks {
		if path.IsAbs(filename) {
			s.links[path.Clean(filename)] = target
			s.addAncestors(filename)
		}
	}
	for filename, asset := range s.assets {
		if asset.err == nil && kind(asset.host.attr.Mode) == proto.SIFLNK {
			if _, exists := s.assets[asset.host.link]; !exists {
				asset.err = fmt.Errorf("asset alias %q points outside the compiled snapshot to %q", filename, asset.host.link)
				s.setError(asset.err)
			}
		}
	}
	s.compileChildren()
	return s
}

func (s *mountState) setError(err error) {
	if err != nil && s.err == nil {
		s.err = err
	}
}

func (s *mountState) addAncestors(filename string) {
	for directory := path.Dir(filename); ; directory = path.Dir(directory) {
		s.directories[directory] = true
		if directory == "/" {
			return
		}
	}
}

func (s *mountState) compileChildren() {
	entries := map[string]map[string]uint32{}
	add := func(filename string, mode uint32) {
		if filename == "/" {
			return
		}
		parent := path.Dir(filename)
		if entries[parent] == nil {
			entries[parent] = map[string]uint32{}
		}
		entries[parent][path.Base(filename)] = mode
	}
	for directory := range s.directories {
		add(directory, proto.SIFDIR|0o555)
	}
	for filename := range s.links {
		add(filename, proto.SIFLNK|0o777)
	}
	for _, tree := range s.trees {
		mode := uint32(proto.SIFDIR | 0o755)
		if tree.fd != nil {
			if host, err := tree.lookup(tree.prefix); err == nil {
				mode = host.attr.Mode
				host.close()
			}
		}
		add(tree.prefix, mode)
	}
	for filename, asset := range s.assets {
		if asset.host != nil {
			add(filename, asset.host.attr.Mode)
		}
	}
	for filename, mode := range s.synthetic {
		add(filename, mode)
	}
	for parent, names := range entries {
		children := make([]proto.DirEntry, 0, len(names))
		for name, mode := range names {
			children = append(children, proto.DirEntry{Name: name, Mode: mode})
		}
		sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })
		s.children[parent] = children
	}
}

func (s *mountState) route(filename string) route {
	if asset, exists := s.assets[filename]; exists {
		return route{kind: sourceHost, asset: asset, readOnly: true}
	}
	if mode, exists := s.synthetic[filename]; exists {
		return route{kind: sourceSynthetic, attr: proto.Attr{Mode: mode}, readOnly: true}
	}
	for _, tree := range s.trees {
		if filename == tree.prefix || strings.HasPrefix(filename, tree.prefix+"/") || tree.prefix == "/" {
			relative := strings.TrimPrefix(strings.TrimPrefix(filename, tree.prefix), "/")
			return route{kind: sourceHost, tree: tree, relative: path.Join(tree.relative, relative), readOnly: tree.readOnly}
		}
	}
	if target, exists := s.links[filename]; exists {
		return route{kind: sourceLink, link: target, attr: proto.Attr{Mode: proto.SIFLNK | 0o777, Size: uint64(len(target))}, readOnly: true}
	}
	if s.directories[filename] {
		return route{kind: sourceUnion, attr: proto.Attr{Mode: proto.SIFDIR | 0o555}, readOnly: true}
	}
	for directory, mode := range s.synthetic {
		if kind(mode) == proto.SIFDIR && strings.HasPrefix(filename, directory+"/") {
			return route{kind: sourceSynthetic, readOnly: true}
		}
	}
	return route{kind: sourceRemote}
}

func (s *mountState) resolveHost(filename string, r route) (*hostObject, bool, error) {
	if r.asset != nil {
		return r.asset.host, false, r.asset.err
	}
	if r.tree.err != nil {
		return nil, false, r.tree.err
	}
	parent, name, err := r.tree.parent(r.relative)
	if err != nil {
		return nil, false, err
	}
	defer parent.Close()
	host, err := pinHostAt(parent, name)
	return host, true, err
}

func (s *mountState) track(host *hostObject) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		host.close()
		return false
	}
	s.objects[host] = struct{}{}
	return true
}

func (s *mountState) close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	objects := s.objects
	s.objects = nil
	s.mu.Unlock()
	var result error
	for host := range objects {
		result = errors.Join(result, host.close())
	}
	for _, tree := range s.trees {
		if tree.fd != nil {
			result = errors.Join(result, tree.fd.Close())
		}
	}
	return result
}

// openLocalTree follows only the explicitly configured root at construction.
// Every later component is resolved relative to the pinned descriptor with
// O_NOFOLLOW. A missing root keeps a pinned nearest-existing parent so it can
// be created, without falling back to the daemon or following a later symlink.
func openLocalTree(prefix string, readOnly bool) *localTree {
	tree := &localTree{prefix: prefix, readOnly: readOnly}
	candidate := prefix
	for {
		fi, err := os.Stat(candidate)
		if err == nil && fi.IsDir() {
			tree.fd, tree.err = openHostDirectory(candidate)
			return tree
		}
		if err == nil && candidate == prefix {
			real, err := filepath.EvalSymlinks(prefix)
			if err != nil {
				tree.err = err
				return tree
			}
			tree.fd, tree.err = openHostDirectory(filepath.Dir(real))
			tree.relative = filepath.Base(real)
			return tree
		}
		if err != nil && !os.IsNotExist(err) {
			tree.err = err
			return tree
		}
		if candidate == "/" {
			tree.err = syscall.ENOTDIR
			return tree
		}
		tree.relative = path.Join(path.Base(candidate), tree.relative)
		candidate = path.Dir(candidate)
	}
}

func (t *localTree) parent(relative string) (*os.File, string, error) {
	if t.err != nil {
		return nil, "", t.err
	}
	if relative == "" || relative == "." {
		fd, err := unix.FcntlInt(t.fd.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return nil, "", err
		}
		return os.NewFile(uintptr(fd), t.prefix), ".", nil
	}
	if path.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, "../") {
		return nil, "", syscall.EPERM
	}
	fd, err := unix.FcntlInt(t.fd.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, "", err
	}
	parent := os.NewFile(uintptr(fd), t.prefix)
	parts := strings.Split(relative, "/")
	for _, component := range parts[:len(parts)-1] {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			parent.Close()
			return nil, "", syscall.EPERM
		}
		next, err := openHostDirectoryAt(parent, component)
		parent.Close()
		if err != nil {
			return nil, "", err
		}
		parent = next
	}
	return parent, parts[len(parts)-1], nil
}

func (t *localTree) lookup(filename string) (*hostObject, error) {
	relative := strings.TrimPrefix(strings.TrimPrefix(filename, t.prefix), "/")
	relative = path.Join(t.relative, relative)
	parent, name, err := t.parent(relative)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return pinHostAt(parent, name)
}

func openHostAsset(filename string) (*hostObject, error) {
	parentPath, err := filepath.EvalSymlinks(filepath.Dir(filename))
	if err != nil {
		return nil, err
	}
	parent, err := openHostDirectory(parentPath)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	host, err := pinHostAt(parent, filepath.Base(filename))
	if err != nil {
		return nil, err
	}
	if kind(host.attr.Mode) == proto.SIFLNK {
		// Exact asset aliases point at another compiled exact asset, not at an
		// ungranted host directory symlink or a daemon-specific alias target.
		host.link, err = filepath.EvalSymlinks(filename)
		if err != nil {
			host.close()
			return nil, err
		}
		host.attr.Size = uint64(len(host.link))
	} else if kind(host.attr.Mode) != proto.SIFREG {
		host.close()
		return nil, fmt.Errorf("host runtime/executable asset %q is not a regular file", filename)
	}
	return host, nil
}

func identityIno(domain string, a proto.Attr, filename string) uint64 {
	h := uint64(1469598103934665603)
	for i := range domain {
		h = (h ^ uint64(domain[i])) * 1099511628211
	}
	if a.Ino == 0 {
		for i := range filename {
			h = (h ^ uint64(filename[i])) * 1099511628211
		}
	} else {
		for _, value := range [2]uint64{a.Dev, a.Ino} {
			for range 8 {
				h = (h ^ (value & 0xff)) * 1099511628211
				value >>= 8
			}
		}
	}
	if h == 0 || h == ^uint64(0) {
		return 1
	}
	return h
}

func sameIdentity(a, b proto.Attr) bool {
	return a.Ino == 0 || b.Ino == 0 || a.Ino == b.Ino && a.Dev == b.Dev && kind(a.Mode) == kind(b.Mode)
}

// create pins the parent before opening the leaf and delays truncation until
// the opened inode is known not to be an immutable executable/runtime alias.
func (t *localTree) create(relative string, flags, mode uint32, protected map[[2]uint64]bool) (*os.File, proto.Attr, error) {
	if t.readOnly {
		return nil, proto.Attr{}, syscall.EROFS
	}
	parent, name, err := t.parent(relative)
	if err != nil {
		return nil, proto.Attr{}, err
	}
	defer parent.Close()
	openFlags := int(flags)&^syscall.O_TRUNC | unix.O_CREAT | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Openat(int(parent.Fd()), name, openFlags, mode&0o7777)
	if err != nil {
		return nil, proto.Attr{}, err
	}
	f := os.NewFile(uintptr(fd), name)
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, proto.Attr{}, err
	}
	attr := hostAttr(fi)
	if flags&uint32(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_TRUNC) != 0 && protected[[2]uint64{attr.Dev, attr.Ino}] {
		f.Close()
		return nil, proto.Attr{}, syscall.EROFS
	}
	if flags&uint32(os.O_TRUNC) != 0 {
		if err := f.Truncate(0); err != nil {
			f.Close()
			return nil, proto.Attr{}, err
		}
		fi, err = f.Stat()
		if err != nil {
			f.Close()
			return nil, proto.Attr{}, err
		}
		attr = hostAttr(fi)
	}
	return f, attr, nil
}
