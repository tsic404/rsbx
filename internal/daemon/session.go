package daemon

import (
	"errors"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
)

// sessionTable ties the connections of one rsbx session together.
//
// The daemon executes both the session's filesystem requests and the commands
// it runs on the session's behalf. A command changes the remote tree directly,
// without passing through the filesystem callbacks the view can see, so the
// daemon is the only side that can tell the view that a name it retained may
// have changed. Connections of one session carry the same opaque token; a
// connection without one is a session of its own, as before.
type sessionTable struct {
	mu   sync.Mutex
	byID map[string]*session
}

// acquire returns the shared state for token, creating it on first use. An
// empty token yields no session: the connection then answers for itself and
// nothing is announced across connections.
func (t *sessionTable) acquire(token string) *session {
	if token == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.byID == nil {
		t.byID = map[string]*session{}
	}
	s := t.byID[token]
	if s == nil {
		s = &session{created: map[string]uint64{}, dirs: map[string]dirSnapshot{}, subs: map[*sessionSub]struct{}{}}
		t.byID[token] = s
	}
	s.refs++
	return s
}

// release drops one connection's claim on the session. The state goes away
// with the last connection, so a finished session leaves nothing behind.
func (t *sessionTable) release(token string, s *session) {
	if s == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s.refs--
	if s.refs <= 0 && t.byID[token] == s {
		delete(t.byID, token)
	}
}

// session is the state every connection of one session shares: the names this
// session established, the mutation epoch, whether one of its commands is
// running, and the filesystem connections to announce changes to.
type session struct {
	mu      sync.Mutex
	refs    int // guarded by sessionTable.mu
	epoch   uint64
	running int
	// created records the names this session established, each with the ledger
	// generation that made the record. The generation lets a confirmed absence
	// retire only the record it could have seen, so an establishment that landed
	// concurrently is not discarded with it.
	created map[string]uint64
	// ledger counts establishments and only ever grows.
	ledger uint64
	// dirs is every directory this session's views resolved while no command
	// was running, with the children it had then. Comparing it with the tree
	// after a command tells which names disappeared while it ran, without
	// trusting any inode timestamp. A name that appeared is not attributed to
	// the command: a directory comparison cannot tell which side created it.
	dirs map[string]dirSnapshot
	subs map[*sessionSub]struct{}
}

// dirSnapshot is one directory as a view last saw it.
type dirSnapshot struct {
	dev, ino uint64
	names    map[string]struct{}
}

// dirSnapshotLimit bounds how many directories one session keeps. A session
// that resolved more directories than this is command-heavy enough that the
// oldest snapshots are dropped rather than growing without bound.
const dirSnapshotLimit = 256

// MarkDir records a directory this session's view resolved while no command was
// running, together with the names it held then.
func (s *session) MarkDir(p string, dev, ino uint64, names []string) {
	if s == nil {
		return
	}
	kids := make(map[string]struct{}, len(names))
	for _, name := range names {
		kids[name] = struct{}{}
	}
	s.mu.Lock()
	if _, ok := s.dirs[p]; ok || len(s.dirs) < dirSnapshotLimit {
		s.dirs[p] = dirSnapshot{dev: dev, ino: ino, names: kids}
	}
	s.mu.Unlock()
}

// sessionSub is one filesystem connection that wants the session's mutation
// announcements. write must be safe to call from any goroutine and reports
// whether the frame reached the client.
type sessionSub struct {
	write func(epoch uint64, names []string) bool
}

// Created reports whether this session established the name.
func (s *session) Created(path string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.created[path]
	return ok
}

// MarkCreated records a name this session established.
func (s *session) MarkCreated(path string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.ledger++
	s.created[path] = s.ledger
	s.mu.Unlock()
}

// LedgerSeq reports the current generation. Read it before observing the tree:
// a name established after that point carries a higher generation, so
// ForgetCreated bounded by this value leaves it alone.
func (s *session) LedgerSeq() uint64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ledger
}

// ForgetCreated retires the record for a name an observation found gone,
// together with the records below it: a vanished directory takes its descendants
// out of reach too. A record newer than seq is kept, so one established after the
// observation began survives it.
func (s *session) ForgetCreated(path string, seq uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.forgetCreatedLocked(path, seq)
	s.mu.Unlock()
}

func (s *session) forgetCreatedLocked(path string, seq uint64) {
	if cur, ok := s.created[path]; ok && cur <= seq {
		delete(s.created, path)
	}
	for name, cur := range s.created {
		if cur <= seq && strings.HasPrefix(name, path+"/") {
			delete(s.created, name)
		}
	}
}

// MarkRemoved forgets a name this session removed. Only the session's own
// connections reach this, so a name another session removed stays recorded
// here, which is the safe direction: it is simply asked for again.
func (s *session) MarkRemoved(path string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.created, path)
	s.mu.Unlock()
}

// State reports the epoch the next reply belongs to and whether one of the
// session's commands is running. A reply produced while a command runs may
// describe the tree at any point during it, so it is never retained.
func (s *session) State() (epoch uint64, volatile bool) {
	if s == nil {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch, s.running > 0
}

// commandStarted records that one of the session's commands is about to run
// and announces the new epoch before the child exists. Announcement precedes
// the change, so a reply produced before it is stamped with an older epoch and
// cannot be retained once the view has adopted the new one.
func (s *session) commandStarted() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.running++
	s.epoch++
	epoch := s.epoch
	subs := make([]*sessionSub, 0, len(s.subs))
	for sub := range s.subs {
		subs = append(subs, sub)
	}
	s.mu.Unlock()
	for _, sub := range subs {
		if !sub.write(epoch, nil) {
			s.unsubscribe(sub)
		}
	}
}

// commandFinished ends the window in which replies are not retainable and
// reconciles what the session's commands changed. The daemon runs those
// commands itself but cannot see which names they touched, so it compares the
// directories its views last saw with the tree as it is now and announces the
// names that disappeared. Only removals are announced: which side created a
// name that appeared is not observable from a directory comparison, so no name
// is ever recorded as this session's own from one. A command that changed
// nothing announces nothing, so it costs the views no retained result.
//
// A directory the comparison could not read is announced so the views drop what
// they held, but it retires no creation record: a lookup that failed for lack of
// permission says nothing about whether a name is still there.
func (s *session) commandFinished() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.running--
	if s.running > 0 {
		s.mu.Unlock()
		return
	}
	before := make(map[string]dirSnapshot, len(s.dirs))
	for p, d := range s.dirs {
		before[p] = d
	}
	// The generation is read with the snapshots, so a name established after
	// this point carries a higher one and the forgetting below leaves it alone.
	seq := s.ledger
	subs := make([]*sessionSub, 0, len(s.subs))
	for sub := range s.subs {
		subs = append(subs, sub)
	}
	s.mu.Unlock()

	gone, changed, after := reconcileDirs(before)

	s.mu.Lock()
	s.dirs = after
	epoch := s.epoch
	// A name a command removed is gone. Keep the fact that this session
	// established it only while the name is there. Once it is confirmed gone,
	// whatever later appears at that path is a different name: the daemon did not
	// create it, so it keeps the ordinary positive-entry window.
	//
	// Only a confirmed absence retires a record. A directory the comparison
	// could not read is not evidence that anything disappeared: a non-root
	// daemon loses search permission on a parent and gets EACCES for a child
	// that is still there. Retiring the records below such a directory would
	// silently drop the retention C-19 promises for names the daemon itself
	// created. Those views still drop what they retained — it may be stale —
	// but they ask the daemon again instead of answering as if the name were
	// still this session's own.
	for _, p := range gone {
		s.forgetCreatedLocked(p, seq)
	}
	s.mu.Unlock()
	if len(changed) == 0 {
		return
	}
	for _, sub := range subs {
		if !sub.write(epoch, changed) {
			s.unsubscribe(sub)
		}
	}
}

// reconcileDirs reports what changed since the views last saw these
// directories, and the snapshots to keep for the next command.
//
// gone lists paths that are confirmed absent: the directory itself no longer
// exists, was replaced by another inode, or lost a child the view had seen.
// Only these may retire a creation record.
//
// changed lists every path a view should drop retained results for. It is gone
// plus the directories the comparison could not read for a reason other than
// absence — a parent whose search permission the command took away, for
// instance. Those are not evidence of a change, so they keep their snapshot and
// retire no record; the view still drops them because what it retained may be
// stale.
//
// Names that appeared are not reported at all: a directory comparison cannot
// tell who created them, and treating another party's creation as this
// session's own would cost the view the retention the contract promises for
// those names.
func reconcileDirs(before map[string]dirSnapshot) (gone, changed []string, after map[string]dirSnapshot) {
	after = make(map[string]dirSnapshot, len(before))
	for p, had := range before {
		var st syscall.Stat_t
		err := syscall.Lstat(p, &st)
		switch {
		case err == nil && (uint64(st.Dev) != had.dev || st.Ino != had.ino):
			// Another inode now holds this path: the directory the view saw is
			// gone, whatever stands in its place.
			gone = append(gone, p)
			continue
		case err != nil && !isAbsent(err):
			// The lookup failed for a reason that is not absence. Retire
			// nothing and keep the old snapshot: the next comparison must still
			// start from what the view saw.
			changed = append(changed, p)
			after[p] = had
			continue
		case err != nil:
			gone = append(gone, p)
			continue
		}
		des, err := os.ReadDir(p)
		if err != nil {
			if isAbsent(err) {
				gone = append(gone, p)
			} else {
				changed = append(changed, p)
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
				gone = append(gone, path.Join(p, name))
			}
		}
		after[p] = dirSnapshot{dev: had.dev, ino: had.ino, names: now}
	}
	changed = append(changed, gone...)
	return gone, changed, after
}

// isAbsent reports whether err says the name is not there, as opposed to a
// lookup that could not be answered. Only absence is evidence that a name this
// session created is gone; a permission error means the daemon could not look.
func isAbsent(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR)
}

func (s *session) subscribe(fn func(uint64, []string) bool) *sessionSub {
	sub := &sessionSub{write: fn}
	s.mu.Lock()
	s.subs[sub] = struct{}{}
	s.mu.Unlock()
	return sub
}

// currentEpoch reports the epoch a newly attached connection must adopt before
// its first reply, so a view that reconnects resumes with the session's state
// instead of a baseline of zero.
func (s *session) currentEpoch() uint64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch
}

func (s *session) unsubscribe(sub *sessionSub) {
	if s == nil || sub == nil {
		return
	}
	s.mu.Lock()
	delete(s.subs, sub)
	s.mu.Unlock()
}
