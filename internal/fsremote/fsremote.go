// Package fsremote serves filesystem operations for the daemon side.
//
// The daemon's filesystem IS the remote filesystem: every path is a native
// absolute path, used verbatim. There is no root, no prefix translation and no
// sandbox materialisation. A Server belongs to one connection and owns that
// connection's real descriptor table: once a file is opened, reads and writes
// go through the kernel descriptor, so a rename or unlink of the name cannot
// change what the handle refers to.
//
// Byte-range locks are real kernel open-file-description (OFD) locks. The lock
// owner is the triple (connection, Owner value, inode): every handle of that
// triple shares one independent open file description kept open for the
// connection, so the owner's locks through different handles are one lock;
// any other Owner value, any other connection and any native process see a
// conflicting lock. Locks are taken against the inode the handle opened (via
// its /proc/self/fd name), never against a re-opened pathname. Closing the
// locked file, closing the connection, or the owner unlocking drops them.
package fsremote

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"rsbx/internal/proto"
)

// openFile is one open descriptor. append records O_APPEND at open time so a
// positioned write becomes an append on the real descriptor instead of a
// rejected WriteAt.
type openFile struct {
	f      *os.File
	append bool
}

// lockKey names a lock owner: one connection, one Owner value, one inode. dev
// and ino come from the opened descriptor, so a rename or unlink cannot move
// a lock to a different file.
type lockKey struct {
	dev   uint64
	ino   uint64
	owner uint64
}

// lockEntry is the independent open file description that owns the locks of
// one (connection, Owner, inode) triple. Every handle of that owner uses it,
// so the owner's locks through different handles are one lock; another owner,
// another connection or a native process sees a conflicting lock.
type lockEntry struct {
	mu       sync.Mutex
	f        *os.File
	writable bool
	handles  map[uint64]struct{}
	done     chan struct{}
}

// SessionState is the per-session state one connection can share with the
// others of the same session. The daemon runs the session's commands itself,
// so only it can tell whether a command may be changing names, and which names
// the session established.
type SessionState interface {
	// Created reports whether this session established the name at path.
	Created(path string) bool
	// MarkDir records a directory this session's view resolved, with its
	// children. Comparing it after a command is how the daemon learns which
	// names that command added or removed: it never infers provenance from an
	// inode's timestamps.
	MarkDir(path string, dev, ino uint64, names []string)
	// MarkCreated and MarkRemoved update that ledger with a name this
	// connection established or removed.
	MarkCreated(path string)
	MarkRemoved(path string)
	// LedgerSeq reports the current generation. Read it before observing the
	// tree so ForgetCreated can retire only the record that observation saw.
	LedgerSeq() uint64
	// ForgetCreated retires the record for a name an observation found gone. A
	// name that merely appeared is not recorded and must not be inferred.
	ForgetCreated(path string, seq uint64)
	// State reports the session's mutation epoch and whether one of its
	// commands is running right now.
	State() (epoch uint64, running bool)
}

// Server answers file operations for one connection.
type Server struct {
	mu      sync.Mutex
	nextID  uint64
	handles map[uint64]*openFile
	locks   map[lockKey]*lockEntry
	// waiters carries the cancellation channel of every waiting FxSetlkw for a
	// handle, so closing that handle wakes its waiters.
	waiters map[uint64]map[chan struct{}]struct{}
	// created records the names this connection established. The view asks
	// before it retains a resolution: a name the session created must be
	// re-resolved every time, so a later delete or rename is visible at once.
	// A name stays recorded for the connection's lifetime; only removing it
	// through this connection forgets it, and forgetting would be the unsafe
	// direction.
	created map[string]struct{}
	closed  bool
	// closedCh is closed when Close runs; it wakes lock requests waiting for a
	// conflicting lock instead of leaving them stuck on the descriptor table.
	closedCh chan struct{}
	// sess is shared by every connection of one session. With a session bound,
	// the session's ledger answers creation provenance and its state stamps
	// every reply; without one the connection answers for itself.
	sessMu sync.RWMutex
	sess   SessionState
}

// NewServer creates a per-connection file server.
func NewServer() *Server {
	return &Server{
		handles:  make(map[uint64]*openFile),
		locks:    make(map[lockKey]*lockEntry),
		waiters:  make(map[uint64]map[chan struct{}]struct{}),
		created:  make(map[string]struct{}),
		closedCh: make(chan struct{}),
	}
}

func (s *Server) markCreated(p string) {
	s.sessMu.RLock()
	sess := s.sess
	s.sessMu.RUnlock()
	if sess != nil {
		sess.MarkCreated(p)
		return
	}
	s.mu.Lock()
	s.created[p] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) markRemoved(p string) {
	s.sessMu.RLock()
	sess := s.sess
	s.sessMu.RUnlock()
	if sess != nil {
		sess.MarkRemoved(p)
		return
	}
	s.mu.Lock()
	delete(s.created, p)
	s.mu.Unlock()
}

func (s *Server) isCreated(p string) bool {
	s.sessMu.RLock()
	sess := s.sess
	s.sessMu.RUnlock()
	if sess != nil {
		return sess.Created(p)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.created[p]
	return ok
}

// ledgerSeq reports the session's current ledger generation, or zero for a
// connection that answers for itself.
func (s *Server) ledgerSeq() uint64 {
	s.sessMu.RLock()
	sess := s.sess
	s.sessMu.RUnlock()
	if sess == nil {
		return 0
	}
	return sess.LedgerSeq()
}

// forgetAbsent retires the ledger record for a name an observation found gone.
// seq is the generation read before the observation, so only the record that
// observation could have seen is dropped and one that landed after it began is
// kept.
func (s *Server) forgetAbsent(p string, seq uint64) {
	s.sessMu.RLock()
	sess := s.sess
	s.sessMu.RUnlock()
	if sess != nil {
		sess.ForgetCreated(p, seq)
		return
	}
	s.mu.Lock()
	delete(s.created, p)
	s.mu.Unlock()
}

// markDir records a directory a view just resolved. A reply produced while a
// command runs describes the tree mid-change and is never a baseline, so only
// answers given with no command running are recorded.
func (s *Server) markDir(p string, st *syscall.Stat_t, names []string) {
	s.sessMu.RLock()
	sess := s.sess
	s.sessMu.RUnlock()
	if sess == nil {
		return
	}
	if _, running := sess.State(); running {
		return
	}
	if names == nil {
		des, err := os.ReadDir(p)
		if err != nil {
			return
		}
		names = make([]string, 0, len(des))
		for _, de := range des {
			names = append(names, de.Name())
		}
	}
	sess.MarkDir(p, uint64(st.Dev), uint64(st.Ino), names)
}

// UseSession binds this connection to the session it belongs to. It must be
// called before the first request: the binding decides both creation
// provenance and the epoch stamped on every reply.
func (s *Server) UseSession(sess SessionState) {
	s.sessMu.Lock()
	s.sess = sess
	s.sessMu.Unlock()
}

// Close cancels waiting operations and releases every descriptor the
// connection still holds. Locks die with the descriptions that own them.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closedCh)
	handles := s.handles
	locks := s.locks
	waiters := s.waiters
	s.handles = make(map[uint64]*openFile)
	s.locks = make(map[lockKey]*lockEntry)
	s.waiters = make(map[uint64]map[chan struct{}]struct{})
	s.mu.Unlock()

	for _, set := range waiters {
		for ch := range set {
			close(ch)
		}
	}
	for _, e := range locks {
		e.close()
	}
	var firstErr error
	for _, h := range handles {
		if err := h.f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// put registers a descriptor and returns its handle. A closed server takes no
// new descriptor: the caller closes the file rather than leaking it.
func (s *Server) put(f *os.File, appendMode bool) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, false
	}
	s.nextID++
	s.handles[s.nextID] = &openFile{f: f, append: appendMode}
	return s.nextID, true
}

// get fetches a descriptor without removing it.
func (s *Server) get(h uint64) (*openFile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.handles[h]
	return f, ok
}

// take removes a descriptor from the table. Only the caller that receives it
// closes it, so a concurrent FxClose cannot close a file an in-flight request
// is still using.
func (s *Server) take(h uint64) (*openFile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.handles[h]
	if ok {
		delete(s.handles, h)
	}
	return f, ok
}

// attrOf converts a native stat into the wire attribute set. Mode keeps the
// Linux type bits verbatim, all three timestamps carry nanosecond precision,
// and Dev rides along with Ino because the daemon's / spans mounted
// filesystems where st_ino alone is not an identity.
func attrOf(st *syscall.Stat_t) proto.Attr {
	a, m, c := statTimes(st)
	return proto.Attr{
		Mode:      statMode(st),
		Size:      uint64(st.Size),
		Mtime:     m.Sec,
		MtimeNsec: uint32(m.Nsec),
		Ctime:     c.Sec,
		CtimeNsec: uint32(c.Nsec),
		Atime:     a.Sec,
		AtimeNsec: uint32(a.Nsec),
		Ino:       uint64(st.Ino),
		Dev:       statDev(st),
		UID:       st.Uid,
		GID:       st.Gid,
		Nlink:     statNlink(st),
	}
}

// errResp builds a failure reply carrying the numeric errno. Err keeps a
// detail string for logs; the errno is the value callers branch on. A wrapped
// syscall.Errno is unwrapped, so *os.PathError and fmt-wrapped errors still
// report the value the kernel chose.
func errResp(id uint32, err error) *proto.FxResp {
	errno := uint32(syscall.EIO)
	var en syscall.Errno
	switch {
	case errors.As(err, &en):
		errno = uint32(en)
	case errors.Is(err, os.ErrNotExist):
		errno = uint32(syscall.ENOENT)
	case errors.Is(err, os.ErrPermission):
		errno = uint32(syscall.EACCES)
	case errors.Is(err, os.ErrExist):
		errno = uint32(syscall.EEXIST)
	}
	resp := &proto.FxResp{ID: id, Kind: proto.KErr, Errno: errno}
	if err != nil {
		resp.Err = err.Error()
	}
	return resp
}

func okOrErr(id uint32, err error) *proto.FxResp {
	if err != nil {
		return errResp(id, err)
	}
	return &proto.FxResp{ID: id, Kind: proto.KOk}
}

// Handle answers one request and stamps the reply with the session state the
// operation started under. The epoch is read before the operation runs: a
// command that starts during it then holds an epoch the reply does not have, so
// the view cannot retain a result produced before that command's changes.
func (s *Server) Handle(req *proto.FxReq) *proto.FxResp {
	s.sessMu.RLock()
	sess := s.sess
	s.sessMu.RUnlock()
	var epoch uint64
	var running bool
	if sess != nil {
		epoch, running = sess.State()
	}
	resp := s.handle(req)
	if resp != nil {
		resp.Epoch, resp.Volatile = epoch, running
	}
	return resp
}

// handle answers one request. It never blocks longer than the operation
// itself: a waiting lock runs on its own goroutine, so the connection's
// reader stays live.
func (s *Server) handle(req *proto.FxReq) *proto.FxResp {
	switch req.Op {
	case proto.FxOpen:
		return s.fxOpen(req)
	case proto.FxClose:
		return s.fxClose(req)
	case proto.FxFstat:
		return s.fxFstat(req)
	case proto.FxPread:
		return s.fxPread(req)
	case proto.FxPwrite:
		return s.fxPwrite(req)
	case proto.FxFsync:
		return s.fxFsync(req)
	case proto.FxFtruncate:
		return s.fxFtruncate(req)
	case proto.FxFchmod:
		return s.fxFchmod(req)
	case proto.FxFutimes:
		return s.fxFutimes(req)
	case proto.FxGetlk:
		return s.fxGetlk(req)
	case proto.FxSetlk:
		return s.fxSetlk(req, false)
	case proto.FxSetlkw:
		return s.fxSetlk(req, true)
	case proto.FxStat:
		return s.fxStat(req)
	case proto.FxList:
		return s.fxList(req)
	case proto.FxReadlink:
		return s.fxReadlink(req)
	case proto.FxMkdir:
		return s.fxMkdir(req)
	case proto.FxUnlink:
		return s.fxUnlink(req)
	case proto.FxRmdir:
		if err := syscall.Rmdir(req.Path); err != nil {
			return errResp(req.ID, err)
		}
		s.markRemoved(req.Path)
		return okOrErr(req.ID, nil)
	case proto.FxSymlink:
		// Arg is the link text, Path is the name to create.
		if err := os.Symlink(req.Arg, req.Path); err != nil {
			return errResp(req.ID, err)
		}
		s.markCreated(req.Path)
		return okOrErr(req.ID, nil)
	case proto.FxLink:
		// Path is the new name, Arg is the existing file.
		if err := os.Link(req.Arg, req.Path); err != nil {
			return errResp(req.ID, err)
		}
		s.markCreated(req.Path)
		return okOrErr(req.ID, nil)
	case proto.FxRename:
		if err := os.Rename(req.Path, req.Arg); err != nil {
			return errResp(req.ID, err)
		}
		s.markRemoved(req.Path)
		s.markCreated(req.Arg)
		return okOrErr(req.ID, nil)
	case proto.FxAccess:
		return s.fxAccess(req)
	case proto.FxChmod:
		return s.fxChmod(req)
	case proto.FxUtimes:
		return s.fxUtimes(req)
	case proto.FxTruncate:
		return s.fxTruncate(req)
	}
	return errResp(req.ID, fmt.Errorf("unknown op %d: %w", req.Op, syscall.ENOSYS))
}

// ---- metadata operations ----

func (s *Server) fxStat(req *proto.FxReq) *proto.FxResp {
	var st syscall.Stat_t
	// The generation is read before the lookup: an establishment made after this
	// point carries a higher one, so the forgetting below leaves it alone.
	seq := s.ledgerSeq()
	if err := syscall.Lstat(req.Path, &st); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			// The name this session established is gone. Retire the record so a
			// later name at the same path is not answered as this session's own.
			s.forgetAbsent(req.Path, seq)
			// Only a metadata lookup that found nothing answers KNone; every
			// mutation and open reports KErr with its errno.
			return &proto.FxResp{ID: req.ID, Kind: proto.KNone, Errno: uint32(syscall.ENOENT), Err: err.Error()}
		}
		return errResp(req.ID, err)
	}
	if statMode(&st)&proto.SIFDIR == proto.SIFDIR {
		s.markDir(req.Path, &st, nil)
	}
	return &proto.FxResp{ID: req.ID, Kind: proto.KStat, Attr: attrOf(&st), Created: s.isCreated(req.Path)}
}

func (s *Server) fxList(req *proto.FxReq) *proto.FxResp {
	var des []os.DirEntry
	var err error
	dir := req.Path
	var df *os.File
	var id syscall.Stat_t
	haveID := false
	if req.Handle != 0 {
		f, ok := s.get(req.Handle)
		if !ok {
			return errResp(req.ID, syscall.EBADF)
		}
		// List the opened inode, not the current name: a directory renamed
		// after it was opened still lists its own entries.
		des, err = readDirHandle(f.f)
		df = f.f
		id, haveID = statFile(f.f)
		// Children are named relative to the directory's current path, which is
		// also what the creation ledger records. The name is reported only when
		// it still leads to the listed inode: a directory replaced at that path
		// is another directory, and its children must not be filed under it.
		if current, ok := handleDirPath(f.f); ok {
			dir = current
			var st syscall.Stat_t
			if serr := syscall.Lstat(current, &st); serr != nil || !sameInode(&st, &id, haveID) {
				dir = ""
			}
		} else {
			dir = ""
		}
	} else {
		des, err = os.ReadDir(req.Path)
		var st syscall.Stat_t
		if serr := syscall.Lstat(req.Path, &st); serr == nil {
			id, haveID = st, true
		}
	}
	if err != nil {
		return errResp(req.ID, err)
	}
	ents := make([]proto.DirEntry, 0, len(des))
	for _, de := range des {
		entry := proto.DirEntry{Name: de.Name()}
		if df != nil {
			// A descriptor listing has no path to resolve children against:
			// de.Info() would stat the bare name in the daemon's working
			// directory. Read each child from the open directory instead, and
			// leave its attributes off when that is not possible.
			if st, ok := statAt(df, de.Name()); ok {
				entry.Mode = statMode(&st)
				entry.Attr = attrOf(&st)
				if dir != "" {
					entry.Created = s.isCreated(dir + "/" + de.Name())
				}
			} else {
				entry.Mode = direntTypeMode(de)
			}
			ents = append(ents, entry)
			continue
		}
		// Attach the child's attributes to the entry when the listing can read
		// them. Children then share the listing's single expiry instead of
		// each starting a window of its own.
		if info, err := de.Info(); err == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				entry.Mode = statMode(st)
				entry.Attr = attrOf(st)
				entry.Created = s.isCreated(dir + "/" + de.Name())
			} else {
				entry.Mode = entryMode(info)
			}
		} else {
			entry.Mode = dirEntryMode(de)
		}
		ents = append(ents, entry)
	}
	resp := &proto.FxResp{ID: req.ID, Kind: proto.KDir, Ents: ents, DirPath: dir}
	if haveID {
		resp.DirDev, resp.DirIno = statDev(&id), uint64(id.Ino)
	}
	if dir != "" && haveID {
		names := make([]string, len(ents))
		for i, entry := range ents {
			names[i] = entry.Name
		}
		s.markDir(dir, &id, names)
	}
	return resp
}

// entryMode maps a FileInfo onto the wire mode when the native stat is not
// available (non-Linux builds).
func entryMode(info os.FileInfo) uint32 {
	mode := uint32(info.Mode().Perm())
	switch {
	case info.IsDir():
		mode |= proto.SIFDIR
	case info.Mode()&os.ModeSymlink != 0:
		mode |= proto.SIFLNK
	default:
		mode |= proto.SIFREG
	}
	return mode
}

// direntTypeMode reports the Linux type bits a directory entry carries itself,
// without resolving the name against any directory.
func direntTypeMode(de os.DirEntry) uint32 {
	switch {
	case de.IsDir():
		return proto.SIFDIR
	case de.Type()&os.ModeSymlink != 0:
		return proto.SIFLNK
	default:
		return proto.SIFREG
	}
}

// statFile reports the inode an open descriptor refers to.
func statFile(f *os.File) (syscall.Stat_t, bool) {
	info, err := f.Stat()
	if err != nil {
		return syscall.Stat_t{}, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return syscall.Stat_t{}, false
	}
	return *st, true
}

// sameInode reports whether st names the inode id holds. An unknown identity
// confirms nothing, so the caller must not claim a name for it.
func sameInode(st, id *syscall.Stat_t, known bool) bool {
	return known && uint64(st.Dev) == uint64(id.Dev) && st.Ino == id.Ino
}

// dirEntryMode reports the Linux type and permission bits of a directory
// entry, from lstat when available and from the dirent type otherwise.
func dirEntryMode(de os.DirEntry) uint32 {
	if info, err := de.Info(); err == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			return statMode(st)
		}
		return entryMode(info)
	}
	switch {
	case de.IsDir():
		return proto.SIFDIR
	case de.Type()&os.ModeSymlink != 0:
		return proto.SIFLNK
	default:
		return proto.SIFREG
	}
}

func (s *Server) fxReadlink(req *proto.FxReq) *proto.FxResp {
	t, err := os.Readlink(req.Path)
	if err != nil {
		return errResp(req.ID, err)
	}
	return &proto.FxResp{ID: req.ID, Kind: proto.KLink, Data: []byte(t)}
}

func (s *Server) fxMkdir(req *proto.FxReq) *proto.FxResp {
	mode, err := typedMode(req.Mode, req.Arg)
	if err != nil {
		return errResp(req.ID, err)
	}
	if err := os.Mkdir(req.Path, mode); err != nil {
		return errResp(req.ID, err)
	}
	s.markCreated(req.Path)
	return okOrErr(req.ID, nil)
}

// typedMode takes a permission mode from the typed Mode field when it is set,
// otherwise from the decimal Arg the client encodes it in. There is no
// substitute default: a request without a mode is EINVAL.
func typedMode(mode uint32, arg string) (os.FileMode, error) {
	if mode != 0 {
		return os.FileMode(mode & 0o7777), nil
	}
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return 0, syscall.EINVAL
	}
	v, err := strconv.ParseUint(arg, 10, 32)
	if err != nil {
		return 0, syscall.EINVAL
	}
	return os.FileMode(v & 0o7777), nil
}

// fxUnlink removes exactly one name. It refuses a directory: rmdir is the
// operation that answers "is this empty and gone", unlink is "this name goes".
func (s *Server) fxUnlink(req *proto.FxReq) *proto.FxResp {
	var st syscall.Stat_t
	if err := syscall.Lstat(req.Path, &st); err == nil {
		if statMode(&st)&syscall.S_IFMT == syscall.S_IFDIR {
			return errResp(req.ID, syscall.EISDIR)
		}
	}
	if err := os.Remove(req.Path); err != nil {
		return errResp(req.ID, err)
	}
	s.markRemoved(req.Path)
	return okOrErr(req.ID, nil)
}

func (s *Server) fxAccess(req *proto.FxReq) *proto.FxResp {
	mode := uint32(req.Flags)
	if mode == 0 {
		mode = req.Mode & 0o7
	}
	return okOrErr(req.ID, syscall.Access(req.Path, mode&0o7))
}

func (s *Server) fxChmod(req *proto.FxReq) *proto.FxResp {
	mode, err := strconv.ParseUint(req.Arg, 8, 32)
	if err != nil {
		return errResp(req.ID, err)
	}
	return okOrErr(req.ID, os.Chmod(req.Path, os.FileMode(mode)))
}

// fxUtimes stamps a path. An empty field means UTIME_OMIT: the value that is
// already on the file survives instead of this server substituting a fresh
// timestamp.
func (s *Server) fxUtimes(req *proto.FxReq) *proto.FxResp {
	ts, err := parseTimespec(req.Arg)
	if err != nil {
		return errResp(req.ID, err)
	}
	return okOrErr(req.ID, utimensatAt(-1, req.Path, ts))
}

func (s *Server) fxTruncate(req *proto.FxReq) *proto.FxResp {
	size, err := strconv.ParseInt(req.Arg, 10, 64)
	if err != nil {
		return errResp(req.ID, err)
	}
	return okOrErr(req.ID, syscall.Truncate(req.Path, size))
}

// ---- handle operations ----

// fxOpen opens the native path. Flags are Linux O_* values used as given:
// O_CREAT pairs with the requested Mode, and O_APPEND stays on the descriptor
// so every write lands at the end decided by the file itself.
func (s *Server) fxOpen(req *proto.FxReq) *proto.FxResp {
	f, created, err := s.openPath(req.Path, int(req.Flags), os.FileMode(req.Mode&0o7777))
	if err != nil {
		return errResp(req.ID, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		return errResp(req.ID, err)
	}
	h, ok := s.put(f, req.Flags&uint32(syscall.O_APPEND) != 0)
	if !ok {
		f.Close()
		return errResp(req.ID, syscall.EBADF)
	}
	if created {
		s.markCreated(req.Path)
	}
	if statMode(&st)&proto.SIFDIR == proto.SIFDIR {
		s.markDir(req.Path, &st, nil)
	}
	return &proto.FxResp{ID: req.ID, Kind: proto.KHandle, Handle: h, Attr: attrOf(&st), Created: created || s.isCreated(req.Path)}
}

// openPath opens p and reports whether this call established the name. A
// create is attempted exclusively first so the answer is a fact rather than an
// inference: an O_CREAT that meets an existing name is an open, not a
// creation, and must not be recorded as one.
func (s *Server) openPath(p string, flags int, mode os.FileMode) (*os.File, bool, error) {
	if flags&syscall.O_CREAT == 0 {
		f, err := os.OpenFile(p, flags, mode)
		return f, false, err
	}
	f, err := os.OpenFile(p, flags|syscall.O_EXCL, mode)
	if err == nil {
		return f, true, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, false, err
	}
	f, err = os.OpenFile(p, flags, mode)
	return f, false, err
}

func (s *Server) fxClose(req *proto.FxReq) *proto.FxResp {
	f, ok := s.take(req.Handle)
	if !ok {
		return errResp(req.ID, syscall.EBADF)
	}
	s.cancelWaiters(req.Handle)
	s.releaseHandleLocks(req.Handle)
	return okOrErr(req.ID, f.f.Close())
}

func (s *Server) fxFstat(req *proto.FxReq) *proto.FxResp {
	f, ok := s.get(req.Handle)
	if !ok {
		return errResp(req.ID, syscall.EBADF)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.f.Fd()), &st); err != nil {
		return errResp(req.ID, err)
	}
	return &proto.FxResp{ID: req.ID, Kind: proto.KStat, Attr: attrOf(&st), Handle: req.Handle}
}

func (s *Server) fxPread(req *proto.FxReq) *proto.FxResp {
	f, ok := s.get(req.Handle)
	if !ok {
		return errResp(req.ID, syscall.EBADF)
	}
	if req.Size > proto.MaxIO {
		return errResp(req.ID, syscall.EINVAL)
	}
	buf := make([]byte, int(req.Size))
	n, err := f.f.ReadAt(buf, req.Offset)
	if n > 0 || err == nil || errors.Is(err, io.EOF) {
		// EOF is a successful, empty read; a short read keeps the bytes the
		// kernel returned.
		return &proto.FxResp{ID: req.ID, Kind: proto.KData, Data: buf[:n], Count: uint32(n), Handle: req.Handle}
	}
	return errResp(req.ID, err)
}

func (s *Server) fxPwrite(req *proto.FxReq) *proto.FxResp {
	f, ok := s.get(req.Handle)
	if !ok {
		return errResp(req.ID, syscall.EBADF)
	}
	var n int
	var err error
	if f.append {
		// O_APPEND decides the position in the kernel. Write is the call that
		// carries that flag; WriteAt would be refused with ESPIPE.
		n, err = f.f.Write(req.Data)
	} else {
		n, err = f.f.WriteAt(req.Data, req.Offset)
	}
	if err != nil && n == 0 {
		return errResp(req.ID, err)
	}
	// Count is what the descriptor accepted, which may be short.
	return &proto.FxResp{ID: req.ID, Kind: proto.KOk, Count: uint32(n), Handle: req.Handle}
}

func (s *Server) fxFsync(req *proto.FxReq) *proto.FxResp {
	f, ok := s.get(req.Handle)
	if !ok {
		return errResp(req.ID, syscall.EBADF)
	}
	// A directory fsync and a file fsync are the same call for the kernel.
	return okOrErr(req.ID, f.f.Sync())
}

func (s *Server) fxFtruncate(req *proto.FxReq) *proto.FxResp {
	f, ok := s.get(req.Handle)
	if !ok {
		return errResp(req.ID, syscall.EBADF)
	}
	return okOrErr(req.ID, f.f.Truncate(req.Offset))
}

func (s *Server) fxFchmod(req *proto.FxReq) *proto.FxResp {
	f, ok := s.get(req.Handle)
	if !ok {
		return errResp(req.ID, syscall.EBADF)
	}
	return okOrErr(req.ID, f.f.Chmod(os.FileMode(req.Mode&0o7777)))
}

// fxFutimes sets timestamps through the descriptor with AT_EMPTY_PATH: the
// metadata belongs to the opened inode, not to whatever the name points at
// now.
func (s *Server) fxFutimes(req *proto.FxReq) *proto.FxResp {
	f, ok := s.get(req.Handle)
	if !ok {
		return errResp(req.ID, syscall.EBADF)
	}
	ts, err := parseTimespec(req.Arg)
	if err != nil {
		return errResp(req.ID, err)
	}
	return okOrErr(req.ID, utimensatAt(int(f.f.Fd()), "", ts))
}

// ---- locks ----

// lockKeyOf names the inode and owner a lock request speaks for. The identity
// comes from the open descriptor, never from its path.
func lockKeyOf(f *openFile, owner uint64) (lockKey, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.f.Fd()), &st); err != nil {
		return lockKey{}, err
	}
	return lockKey{dev: statDev(&st), ino: uint64(st.Ino), owner: owner}, nil
}

// entryFor returns the lock description of this owner, creating it when the
// owner has none yet. Every handle of the owner shares one description, so
// its locks are one lock; another owner uses another description and the
// kernel makes them conflict.
func (s *Server) entryFor(f *openFile, h uint64, key lockKey) (*lockEntry, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, syscall.EBADF
	}
	if e, ok := s.locks[key]; ok {
		e.handles[h] = struct{}{}
		s.mu.Unlock()
		return e, nil
	}
	s.mu.Unlock()

	fd, writable, err := openLockFd(f.f)
	if err != nil {
		return nil, err
	}
	e := &lockEntry{
		f:        os.NewFile(uintptr(fd), "lock"),
		writable: writable,
		handles:  map[uint64]struct{}{h: {}},
		done:     make(chan struct{}),
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		e.close()
		return nil, syscall.EBADF
	}
	if other, ok := s.locks[key]; ok {
		other.handles[h] = struct{}{}
		s.mu.Unlock()
		e.close()
		return other, nil
	}
	s.locks[key] = e
	s.mu.Unlock()
	return e, nil
}

// close releases the description; the kernel drops every lock held or pending
// on it.
func (e *lockEntry) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.f == nil {
		return
	}
	e.f.Close()
	e.f = nil
	close(e.done)
}

func (e *lockEntry) set(lk *syscall.Flock_t) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.f == nil {
		return syscall.EBADF
	}
	return ofdSetlk(int(e.f.Fd()), lk)
}

func (e *lockEntry) get(lk *syscall.Flock_t) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.f == nil {
		return syscall.EBADF
	}
	return ofdGetlk(int(e.f.Fd()), lk)
}

// releaseHandleLocks drops the lock descriptions a closing handle had used.
// Closing a file releases its locks, natively and here, so every lock of that
// owner on that inode goes with the closed description even while the owner
// still has another handle open; the kernel drops all of them when the
// description closes. A waiting FxSetlkw sees the description's done channel
// and returns instead of retrying.
func (s *Server) releaseHandleLocks(h uint64) {
	s.mu.Lock()
	var drop []*lockEntry
	for key, e := range s.locks {
		if _, ok := e.handles[h]; !ok {
			continue
		}
		delete(s.locks, key)
		drop = append(drop, e)
	}
	s.mu.Unlock()
	for _, e := range drop {
		e.close()
	}
}

// registerWaiter returns a channel closed when this handle or the whole
// connection closes. Nothing is parked in the kernel: the caller retries a
// nonblocking lock, so Close cannot leak a blocked fcntl goroutine.
func (s *Server) registerWaiter(h uint64) chan struct{} {
	ch := make(chan struct{})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		close(ch)
		return ch
	}
	set := s.waiters[h]
	if set == nil {
		set = make(map[chan struct{}]struct{})
		s.waiters[h] = set
	}
	set[ch] = struct{}{}
	return ch
}

// waiterCount reports how many lock requests are currently parked. Tests use
// it to synchronise with a blocked FxSetlkw instead of sleeping.
func (s *Server) waiterCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, set := range s.waiters {
		n += len(set)
	}
	return n
}

func (s *Server) unregisterWaiter(h uint64, ch chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if set := s.waiters[h]; set != nil {
		delete(set, ch)
		if len(set) == 0 {
			delete(s.waiters, h)
		}
	}
}

// cancelWaiters wakes the waiting lock requests parked for one handle.
func (s *Server) cancelWaiters(h uint64) {
	s.mu.Lock()
	set := s.waiters[h]
	delete(s.waiters, h)
	s.mu.Unlock()
	for ch := range set {
		close(ch)
	}
}

// kernelLock converts a FUSE lock into the kernel's flock. The range is
// inclusive on the wire; length zero means "to the end of the file". l_pid
// stays 0: an OFD lock has no process owner, its description is the owner.
func kernelLock(info *proto.LockInfo) (*syscall.Flock_t, error) {
	var typ int16
	switch info.Typ {
	case 0:
		typ = syscall.F_RDLCK
	case 1:
		typ = syscall.F_WRLCK
	case 2:
		typ = syscall.F_UNLCK
	default:
		return nil, syscall.EINVAL
	}
	if info.Start > math.MaxInt64 {
		return nil, syscall.EINVAL
	}
	lk := &syscall.Flock_t{Type: typ, Whence: 0, Start: int64(info.Start)}
	switch {
	case info.End == ^uint64(0) || info.End >= math.MaxInt64:
		lk.Len = 0 // infinite
	case info.End < info.Start:
		return nil, syscall.EINVAL
	default:
		lk.Len = int64(info.End-info.Start) + 1
	}
	return lk, nil
}

// fuseLockType maps the kernel's lock type back into FUSE's numbering.
func fuseLockType(t int16) uint32 {
	switch t {
	case syscall.F_RDLCK:
		return 0
	case syscall.F_WRLCK:
		return 1
	default:
		return 2
	}
}

// lockEnd turns start and length back into FUSE's inclusive end. A zero
// length is "to the end of the file", spelled as the maximum value.
func lockEnd(start int64, length int64) uint64 {
	if length <= 0 {
		return ^uint64(0)
	}
	return uint64(start) + uint64(length) - 1
}

// fxGetlk asks the kernel which lock conflicts with the caller's question,
// through the owner's own description so the owner's locks are not reported
// against itself.
func (s *Server) fxGetlk(req *proto.FxReq) *proto.FxResp {
	f, ok := s.get(req.Handle)
	if !ok {
		return errResp(req.ID, syscall.EBADF)
	}
	if req.Lock == nil {
		return errResp(req.ID, syscall.EINVAL)
	}
	lk, err := kernelLock(req.Lock)
	if err != nil {
		return errResp(req.ID, err)
	}
	key, err := lockKeyOf(f, req.Owner)
	if err != nil {
		return errResp(req.ID, err)
	}
	s.mu.Lock()
	e := s.locks[key]
	s.mu.Unlock()
	switch {
	case e != nil:
		err = e.get(lk)
	default:
		// No lock identity exists for this owner: a throwaway description of
		// the same inode sees every other description's locks and owns none.
		var fd int
		fd, _, err = openLockFd(f.f)
		if err != nil {
			// The descriptor itself is still a useful view when a fresh
			// description cannot be opened; it owns no locks.
			err = ofdGetlk(int(f.f.Fd()), lk)
			break
		}
		err = ofdGetlk(fd, lk)
		syscall.Close(fd)
	}
	if err != nil {
		return errResp(req.ID, err)
	}
	if lk.Type == syscall.F_UNLCK {
		return &proto.FxResp{ID: req.ID, Kind: proto.KOk, Handle: req.Handle}
	}
	return &proto.FxResp{ID: req.ID, Kind: proto.KOk, Handle: req.Handle, Lock: &proto.LockInfo{
		Typ:   fuseLockType(lk.Type),
		Start: uint64(lk.Start),
		End:   lockEnd(lk.Start, lk.Len),
		Pid:   0,
	}}
}

// fxSetlk takes or drops a lock. With wait it retries a nonblocking OFD lock
// until it is granted, the handle closes, or the connection closes. No
// goroutine is ever left parked in F_OFD_SETLKW.
func (s *Server) fxSetlk(req *proto.FxReq, wait bool) *proto.FxResp {
	f, ok := s.get(req.Handle)
	if !ok {
		return errResp(req.ID, syscall.EBADF)
	}
	if req.Lock == nil {
		return errResp(req.ID, syscall.EINVAL)
	}
	if req.LkFlags&1 != 0 { // FUSE_LK_FLOCK: flock(2), not POSIX fcntl
		return s.fxFlock(req, f, wait)
	}
	lk, err := kernelLock(req.Lock)
	if err != nil {
		return errResp(req.ID, err)
	}
	key, err := lockKeyOf(f, req.Owner)
	if err != nil {
		return errResp(req.ID, err)
	}
	if lk.Type == syscall.F_UNLCK {
		s.mu.Lock()
		e := s.locks[key]
		s.mu.Unlock()
		if e == nil {
			// Nothing of this owner is held: unlock is not an error.
			return &proto.FxResp{ID: req.ID, Kind: proto.KOk}
		}
		if err := e.set(lk); err != nil {
			return errResp(req.ID, err)
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KOk}
	}
	e, err := s.entryFor(f, req.Handle, key)
	if err != nil {
		return errResp(req.ID, err)
	}
	if lk.Type == syscall.F_WRLCK && !e.writable {
		return errResp(req.ID, syscall.EBADF)
	}
	if !wait {
		if err := e.set(lk); err != nil {
			return errResp(req.ID, err)
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KOk}
	}
	cancel := s.registerWaiter(req.Handle)
	defer s.unregisterWaiter(req.Handle, cancel)
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for {
		err := e.set(lk)
		if err == nil {
			return &proto.FxResp{ID: req.ID, Kind: proto.KOk}
		}
		if !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EINTR) {
			return errResp(req.ID, err)
		}
		select {
		case <-s.closedCh:
			return errResp(req.ID, syscall.EINTR)
		case <-cancel:
			return errResp(req.ID, syscall.EINTR)
		case <-e.done:
			return errResp(req.ID, syscall.EBADF)
		case <-tick.C:
		}
	}
}

// fxFlock applies a whole-file flock(2) request on the daemon's own open
// descriptor. flock and POSIX byte-range locks are independent namespaces on
// Linux; routing a FUSE flock request through OFD fcntl would silently place
// it in the wrong one. The FUSE lock type maps to LOCK_SH/LOCK_EX/LOCK_UN;
// LOCK_MAND has no meaning over FUSE and is refused.
func (s *Server) fxFlock(req *proto.FxReq, f *openFile, wait bool) *proto.FxResp {
	var op int
	switch req.Lock.Typ {
	case 0:
		op = syscall.LOCK_SH
	case 1:
		op = syscall.LOCK_EX
	case 2:
		op = syscall.LOCK_UN
	default:
		return errResp(req.ID, syscall.EINVAL)
	}
	fd := int(f.f.Fd())
	if !wait {
		if err := syscall.Flock(fd, op|syscall.LOCK_NB); err != nil {
			return errResp(req.ID, err)
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KOk}
	}
	cancel := s.registerWaiter(req.Handle)
	defer s.unregisterWaiter(req.Handle, cancel)
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for {
		err := syscall.Flock(fd, op|syscall.LOCK_NB)
		if err == nil {
			return &proto.FxResp{ID: req.ID, Kind: proto.KOk}
		}
		if !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			return errResp(req.ID, err)
		}
		select {
		case <-s.closedCh:
			return errResp(req.ID, syscall.EINTR)
		case <-cancel:
			return errResp(req.ID, syscall.EINTR)
		case <-tick.C:
		}
	}
}

// parseTimespec decodes "<atime>,<mtime>" in decimal nanoseconds. An empty or
// negative field becomes UTIME_OMIT: the kernel keeps the value that is
// already on the file instead of this server substituting a timestamp of its
// own.
func parseTimespec(arg string) ([2]syscall.Timespec, error) {
	var ts [2]syscall.Timespec
	parts := strings.SplitN(arg, ",", 2)
	if len(parts) != 2 {
		return ts, syscall.EINVAL
	}
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			ts[i] = syscall.Timespec{Nsec: utimeOmit}
			continue
		}
		v, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			return ts, syscall.EINVAL
		}
		if v < 0 {
			ts[i] = syscall.Timespec{Nsec: utimeOmit}
			continue
		}
		ts[i] = syscall.Timespec{Sec: v / 1_000_000_000, Nsec: v % 1_000_000_000}
	}
	return ts, nil
}
