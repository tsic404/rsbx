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
	"time"

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

	// retained holds results the view may answer without the daemon: one entry
	// per sandbox path, and one listing per enumerated directory. Both are read
	// only while connected, so a lost connection turns the next query into an
	// explicit failure instead of a retained answer.
	cacheMu  sync.Mutex
	resolved map[string]retainedResult
	listings map[dirID]retainedListing
	// dirIDs is the inode each directory path was last confirmed to name, and
	// the request that confirmed it. A child that travelled with a listing is
	// answerable only while its parent path still names the directory the
	// listing was read from, and an answer sent before that confirmation must
	// not put the older identity back.
	dirIDs map[string]dirFact
	// epoch moves forward every time the retained results stop being
	// answerable. A result is published only under the epoch its request was
	// sent in, so a reply delivered just before a disconnect cannot refill what
	// that disconnect dropped.
	epoch uint64
	// seq numbers the requests this view has sent. Replies may arrive out of
	// order, so a fact learned by a later request is not overwritten by a reply
	// to an earlier one.
	seq uint64
}

// dirFact is an inode identity and the request that confirmed it.
type dirFact struct {
	id  dirID
	seq uint64
}

type retainedResult struct {
	src   backing
	until time.Time
	seq   uint64
	// parent and prefilled mark a child that came with a directory listing:
	// it answers for that directory, not for whichever directory the path
	// names later.
	parent    dirID
	prefilled bool
}

// dirID is a directory's inode identity. Listings are keyed by it rather than
// by path: a handle answers for the inode it opened, which may have been
// replaced at that path by another directory with its own children.
type dirID struct {
	dev, ino uint64
}

type retainedListing struct {
	ents  []proto.DirEntry
	until time.Time
	seq   uint64
	// at is the name the directory had when the listing was taken, so a change
	// to that name can drop the listing.
	at string
}

func newMountState(l *Layout) *mountState {
	s := &mountState{
		objects: map[*hostObject]struct{}{}, assets: map[string]*asset{},
		directories: map[string]bool{"/": true}, synthetic: map[string]uint32{},
		protected: map[[2]uint64]bool{},
		links:     map[string]string{}, children: map[string][]proto.DirEntry{},
		resolved: map[string]retainedResult{},
		listings: map[dirID]retainedListing{},
		dirIDs:   map[string]dirFact{},
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

// freshness is the generation a daemon request was sent in. A result may be
// retained only when no invalidation happened in between: the reply may have
// been produced before that invalidation and delivered after it.
type freshness struct {
	epoch uint64
	// seq orders requests, so a reply to an earlier one cannot replace a fact
	// that a later one already established.
	seq uint64
}

// beginRequest records the generation the caller's request is about to be sent
// in. Pass the value to the corresponding retain call.
func (s *mountState) beginRequest() freshness {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.seq++
	return freshness{epoch: s.epoch, seq: s.seq}
}

// retainedResolve answers a path from a result the view already holds. Only a
// result obtained from the daemon is ever stored here; the window starts when
// that result arrived and a hit never extends it.
func (s *mountState) retainedResolve(p string) (backing, bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	held, ok := s.resolved[p]
	if !ok {
		return backing{}, false
	}
	if !time.Now().Before(held.until) {
		delete(s.resolved, p)
		return backing{}, false
	}
	if held.prefilled {
		if cur, known := s.dirIDs[path.Dir(p)]; !known || cur.id != held.parent {
			delete(s.resolved, p)
			return backing{}, false
		}
	}
	return held.src, true
}

// retainResolve stores a resolution result. Two replies are never stored: one
// that says this session established the name, and one produced while a command
// of this session was running. In both cases the session may delete or rename
// the name next, so the next query has to reach the daemon.
//
// A reply sent before a disconnect belongs to a connection that is gone: it is
// neither stored nor allowed to change what the current connection has since
// obtained. Below the lock, a stale generation returns before any write or
// deletion, so a late reply cannot evict a result that arrived after it.
func (s *mountState) retainResolve(p string, src backing, created, volatile bool, sent freshness) {
	if src.kind != sourceRemote && src.kind != sourceUnion {
		return
	}
	now := time.Now()
	s.cacheMu.Lock()
	if sent.epoch != s.epoch {
		s.cacheMu.Unlock()
		return
	}
	if created || volatile {
		delete(s.resolved, p)
		s.cacheMu.Unlock()
		return
	}
	if cur, ok := s.resolved[p]; ok && cur.seq > sent.seq {
		// A reply to an earlier request must not replace what a later one has
		// already established.
		s.cacheMu.Unlock()
		return
	}
	s.resolved[p] = retainedResult{src: src, until: now.Add(EntryRetention), seq: sent.seq}
	if kind(src.attr.Mode) == proto.SIFDIR && src.attr.Ino != 0 {
		s.confirmDirLocked(p, dirID{dev: src.attr.Dev, ino: src.attr.Ino}, sent.seq)
	}
	s.pruneLocked(now)
	s.cacheMu.Unlock()
}

func (s *mountState) forgetResolve(p string) {
	s.cacheMu.Lock()
	delete(s.resolved, p)
	s.cacheMu.Unlock()
}

// forgetPath drops the retained result for one name and the retained listing of
// its parent: the session just changed that entry through the view, so the next
// query must show the change rather than a result obtained before it.
func (s *mountState) forgetPath(p string) {
	s.cacheMu.Lock()
	delete(s.resolved, p)
	s.forgetListingLocked(path.Dir(p))
	s.cacheMu.Unlock()
}

// forgetTree drops retained results at or below p, for a renamed or removed
// directory whose children are addressed through the old prefix.
func (s *mountState) forgetTree(p string) {
	s.cacheMu.Lock()
	for name := range s.resolved {
		if name == p || strings.HasPrefix(name, p+"/") {
			delete(s.resolved, name)
		}
	}
	for id, held := range s.listings {
		if held.at == p || strings.HasPrefix(held.at, p+"/") {
			delete(s.listings, id)
		}
	}
	s.cacheMu.Unlock()
}

// retainedListing answers a directory enumeration for the inode the handle
// opened. A listing is a single result: reusing it does not restart its window.
func (s *mountState) retainedListing(id dirID) ([]proto.DirEntry, bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	held, ok := s.listings[id]
	if !ok {
		return nil, false
	}
	if !time.Now().Before(held.until) {
		delete(s.listings, id)
		return nil, false
	}
	return held.ents, true
}

// retainListing stores one enumeration for the inode it was read from, together
// with the child attributes that travelled with it. Every stored child shares
// the listing's expiry, so a later lookup of a listed child neither asks the
// daemon nor starts a new window.
//
// Path-keyed child results are stored only when the daemon confirmed that the
// path the caller named still holds the listed inode: a listing taken through a
// handle describes the inode that handle opened, which another directory may
// have replaced at that path. Names whose creation the daemon attributed to
// this session are skipped, as is any name the local overlay covers: only a
// positive answer that still belongs to the daemon may be reused. A listing
// produced while a session command ran is not stored at all: that command may
// change any of the children next.
func (s *mountState) retainListing(id dirID, at string, ents []proto.DirEntry, volatile bool, sent freshness) {
	until := time.Now().Add(EntryRetention)
	kept := append([]proto.DirEntry(nil), ents...)
	s.cacheMu.Lock()
	if sent.epoch != s.epoch {
		// A reply from a connection that is gone neither stores its listing nor
		// removes what the current connection has already obtained.
		s.cacheMu.Unlock()
		return
	}
	if volatile {
		delete(s.listings, id)
		if at != "" {
			s.forgetListingLocked(at)
		}
		s.cacheMu.Unlock()
		return
	}
	if at != "" {
		covered := make(map[string]bool, len(s.children[at]))
		for _, entry := range s.children[at] {
			covered[entry.Name] = true
		}
		for _, entry := range kept {
			if entry.Created || covered[entry.Name] || entry.Attr.Ino == 0 {
				continue
			}
			child := path.Join(at, entry.Name)
			// The listing describes the daemon's tree, but not every name below
			// that path belongs to it in this view: a declared local tree, an
			// asset or a mount point keeps its own source. Filing the daemon's
			// answer for such a name would answer the next lookup with remote
			// attributes before the route is consulted.
			switch s.route(child).kind {
			case sourceRemote, sourceUnion:
			default:
				continue
			}
			if cur, exists := s.resolved[child]; exists && cur.seq > sent.seq {
				continue
			}
			s.resolved[child] = retainedResult{
				src:       backing{kind: sourceRemote, attr: entry.Attr},
				until:     until,
				seq:       sent.seq,
				parent:    id,
				prefilled: true,
			}
		}
	}
	if cur, ok := s.listings[id]; !ok || cur.seq <= sent.seq {
		s.listings[id] = retainedListing{ents: kept, until: until, seq: sent.seq, at: at}
	}
	if at != "" {
		s.confirmDirLocked(at, id, sent.seq)
	}
	s.pruneLocked(time.Now())
	s.cacheMu.Unlock()
}

// pruneLocked drops expired entries once a session has touched enough paths
// that the maps would otherwise keep growing with results nobody reads again.
func (s *mountState) pruneLocked(now time.Time) {
	if len(s.resolved) > 4096 {
		for p, held := range s.resolved {
			if !now.Before(held.until) {
				delete(s.resolved, p)
			}
		}
	}
	if len(s.listings) > 512 {
		for p, held := range s.listings {
			if !now.Before(held.until) {
				delete(s.listings, p)
			}
		}
	}
}

// forgetListing drops every enumeration taken at dir, for a change the view
// made to its children. Listings are keyed by inode, so the name is matched
// against the name each listing was taken under.
func (s *mountState) forgetListing(dir string) {
	s.cacheMu.Lock()
	s.forgetListingLocked(dir)
	s.cacheMu.Unlock()
}

func (s *mountState) forgetListingLocked(dir string) {
	// A listing read from a handle whose name the daemon could not confirm has
	// no path, so no path change can make it stale.
	if dir == "" {
		return
	}
	for id, held := range s.listings {
		if held.at == dir {
			delete(s.listings, id)
		}
	}
}

// invalidate drops every retained result and moves the generation forward. It
// runs when the daemon connection is lost: a retained answer must not outlive
// the connection it came from, or a disconnected session would keep reporting
// that remote paths still exist. Moving the generation under the same lock is
// what keeps a reply delivered just before the loss from being stored after it.
func (s *mountState) invalidate() {
	s.cacheMu.Lock()
	s.epoch++
	s.resolved = map[string]retainedResult{}
	s.listings = map[dirID]retainedListing{}
	s.dirIDs = map[string]dirFact{}
	s.cacheMu.Unlock()
}

// confirmDirLocked records that this path names id, unless a later request has
// already established a newer fact. A listing delivered late must not put the
// directory it was read from back over a replacement the view has since
// resolved.
func (s *mountState) confirmDirLocked(p string, id dirID, seq uint64) {
	if cur, ok := s.dirIDs[p]; ok && cur.seq > seq {
		return
	}
	s.dirIDs[p] = dirFact{id: id, seq: seq}
}

// forgetNames drops the answers for the names a command of this session
// changed. Only those names leave the cache: the command reported them, so no
// other name is affected.
func (s *mountState) forgetNames(names []string) {
	s.cacheMu.Lock()
	for _, p := range names {
		delete(s.resolved, p)
		delete(s.dirIDs, p)
		s.forgetListingLocked(p)
		s.forgetListingLocked(path.Dir(p))
		for held := range s.resolved {
			if strings.HasPrefix(held, p+"/") {
				delete(s.resolved, held)
			}
		}
	}
	s.cacheMu.Unlock()
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
