package daemon

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"rsbx/internal/proto"
)

// A session's state is shared by every connection that carries its token, and a
// command start is announced to all of them with a new epoch while replies stay
// non-retainable until it finishes.
func TestSessionAnnouncesCommandStartAndIsVolatileWhileRunning(t *testing.T) {
	var table sessionTable
	s := table.acquire("token")
	if s == nil {
		t.Fatal("a token did not acquire a session")
	}
	defer table.release("token", s)

	var announced []uint64
	sub := s.subscribe(func(epoch uint64, _ []string) bool {
		announced = append(announced, epoch)
		return true
	})
	defer s.unsubscribe(sub)

	if epoch, running := s.State(); epoch != 0 || running {
		t.Fatalf("fresh session state = (%d, %v), want (0, false)", epoch, running)
	}
	s.commandStarted()
	if epoch, running := s.State(); epoch != 1 || !running {
		t.Fatalf("state during the first command = (%d, %v), want (1, true)", epoch, running)
	}
	s.commandFinished()
	if epoch, running := s.State(); epoch != 1 || running {
		t.Fatalf("state after the first command = (%d, %v), want (1, false)", epoch, running)
	}
	s.commandStarted()
	s.commandFinished()
	if epoch, _ := s.State(); epoch != 2 {
		t.Fatalf("epoch after two commands = %d, want 2", epoch)
	}
	if len(announced) != 2 || announced[0] != 1 || announced[1] != 2 {
		t.Fatalf("announced epochs = %v, want [1 2]", announced)
	}
}

// A connection that drops while an announcement is written is forgotten, so a
// dead view cannot block or slow the commands of a live one.
func TestSessionDropsSubscriberThatCannotBeWritten(t *testing.T) {
	var table sessionTable
	s := table.acquire("token")
	defer table.release("token", s)

	var live []uint64
	dead := s.subscribe(func(uint64, []string) bool { return false })
	alive := s.subscribe(func(epoch uint64, _ []string) bool {
		live = append(live, epoch)
		return true
	})
	defer s.unsubscribe(alive)

	s.commandStarted()
	if len(live) != 1 {
		t.Fatalf("live subscriber saw %d announcements, want 1", len(live))
	}
	s.mu.Lock()
	_, stillThere := s.subs[dead]
	s.mu.Unlock()
	if stillThere {
		t.Fatal("a subscriber whose write failed was kept")
	}
	s.commandFinished()
}

// Names this session established are recorded on the session, not on one
// connection, so every connection of the session answers provenance the same.
func TestSessionCreationLedgerIsSharedAcrossConnections(t *testing.T) {
	var table sessionTable
	first := table.acquire("token")
	defer table.release("token", first)
	second := table.acquire("token")
	defer table.release("token", second)
	if first != second {
		t.Fatal("the same token produced two session states")
	}

	first.MarkCreated("/proj/made.txt")
	if !second.Created("/proj/made.txt") {
		t.Fatal("a name created on one connection is unknown to the other")
	}
	second.MarkRemoved("/proj/made.txt")
	if first.Created("/proj/made.txt") {
		t.Fatal("a removed name is still recorded")
	}
}

// A filesystem connection that named its session is told when one of that
// session's commands starts, before the command can change the tree.
func TestSessionConnectionIsInvalidatedWhenItsCommandStarts(t *testing.T) {
	srv := &Server{Logf: func(string, ...any) {}}
	dir := t.TempDir()

	view, viewDaemon := net.Pipe()
	defer view.Close()
	go srv.ServeConn(viewDaemon)
	if err := view.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	if err := proto.WriteFrame(view, proto.TSession, proto.SessionPayload("token")); err != nil {
		t.Fatal(err)
	}
	// The connection adopts the session's current epoch before serving.
	f, err := proto.ReadFrame(view)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != proto.TInvalidate {
		t.Fatalf("first frame on a session connection = %#x, want TInvalidate", f.Type)
	}
	if epoch, _, derr := proto.DecodeInvalidate(f.Payload); derr != nil || epoch != 0 {
		t.Fatalf("baseline epoch = %d (%v), want 0", epoch, derr)
	}

	if err := proto.WriteFrame(view, proto.TFxReq, (&proto.FxReq{ID: 1, Op: proto.FxStat, Path: dir}).Encode()); err != nil {
		t.Fatal(err)
	}
	f, err = proto.ReadFrame(view)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != proto.TFxResp {
		t.Fatalf("reply frame = %#x, want TFxResp", f.Type)
	}

	execConn, execDaemon := net.Pipe()
	defer execConn.Close()
	go srv.ServeConn(execDaemon)
	go func() {
		req := &proto.ExecReq{
			Target:  "/bin/sh",
			Argv:    []string{"/bin/sh", "-c", "true"},
			Dir:     dir,
			Session: "token",
		}
		_ = proto.WriteFrame(execConn, proto.TExec, req.Encode())
	}()

	for {
		f, err = proto.ReadFrame(view)
		if err != nil {
			t.Fatalf("the view was not told about its session's command: %v", err)
		}
		if f.Type != proto.TInvalidate {
			continue
		}
		epoch, _, derr := proto.DecodeInvalidate(f.Payload)
		if derr != nil {
			t.Fatalf("decode invalidation: %v", derr)
		}
		if epoch != 1 {
			t.Fatalf("announced epoch = %d, want 1", epoch)
		}
		return
	}
}

// A command announces the names it actually changed: a removed name is reported
// for dropping, an added name becomes the session's own, and a command that
// changed nothing reports nothing.
func TestCommandFinishedReconcilesChangedDirectories(t *testing.T) {
	var table sessionTable
	s := table.acquire("token")
	defer table.release("token", s)

	var announced [][]string
	sub := s.subscribe(func(_ uint64, names []string) bool {
		if len(names) > 0 {
			announced = append(announced, names)
		}
		return true
	})
	defer s.unsubscribe(sub)

	dir := t.TempDir()
	keep, gone := filepath.Join(dir, "keep"), filepath.Join(dir, "gone")
	for _, p := range []string{keep, gone} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(dir, &st); err != nil {
		t.Fatal(err)
	}
	s.MarkDir(dir, uint64(st.Dev), st.Ino, []string{"keep", "gone"})
	s.commandStarted()
	s.commandFinished()
	if len(announced) != 0 {
		t.Fatalf("a command that changed nothing announced %v", announced)
	}

	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "made"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.commandStarted()
	s.commandFinished()
	if len(announced) != 1 {
		t.Fatalf("announcements = %v, want one list", announced)
	}
	if len(announced[0]) != 1 || announced[0][0] != gone {
		t.Fatalf("announced %v, want only the removed name", announced[0])
	}
	// A name that appeared is not recorded as this session's own: a directory
	// comparison cannot tell which side created it, and claiming it would cost
	// the retention another party's name is entitled to.
	if s.Created(filepath.Join(dir, "made")) {
		t.Fatal("a name that merely appeared was recorded as this session's own")
	}
	if s.Created(keep) {
		t.Fatal("an unchanged name was recorded as this session's own")
	}

	// A name this session established, which a command then removes, loses its
	// record in the same comparison. A later command that creates the same
	// spelling is another party's creation.
	swap := filepath.Join(dir, "swap")
	if err := os.WriteFile(swap, []byte("z"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.MarkCreated(swap)
	s.MarkDir(dir, uint64(st.Dev), st.Ino, []string{"keep", "swap"})
	if err := os.Remove(swap); err != nil {
		t.Fatal(err)
	}
	s.commandStarted()
	s.commandFinished()
	if s.Created(swap) {
		t.Fatal("a record survived the name's removal by a command")
	}

	// A command that changed nothing after that still announces nothing.
	settled := len(announced)
	s.commandStarted()
	s.commandFinished()
	if len(announced) != settled {
		t.Fatalf("a later no-op command announced %v", announced)
	}
}

// A record is retired only for the generation that preceded the observation.
// The competing establishment is at the same path, so this is the only thing
// that can keep the new record: matching on the path alone would drop it, and
// so would dropping the generation comparison. A name this session established
// after the observation is a different establishment and keeps its provenance:
// forgetting it would cost the retention C-19 promises for names the daemon
// itself created.
func TestForgetCreatedKeepsANameEstablishedAfterTheObservation(t *testing.T) {
	var table sessionTable
	s := table.acquire("token")
	defer table.release("token", s)

	const p = "/proj/file.txt"
	s.MarkCreated(p)
	before := s.LedgerSeq()

	// The same path is established again after the observation began. A later
	// query found the earlier name gone, but this record is newer than that
	// observation and must survive it.
	s.MarkCreated(p)

	s.ForgetCreated(p, before)
	if !s.Created(p) {
		t.Fatal("a record established after the observation was discarded with it")
	}

	// A second observation, taken after that establishment, does retire it: the
	// bound still works in the direction it is meant to.
	after := s.LedgerSeq()
	s.ForgetCreated(p, after)
	if s.Created(p) {
		t.Fatal("a record the observation could have seen kept its record")
	}
}

// A directory the comparison could not read is not a directory that disappeared.
// A non-root daemon loses search permission on a parent directory and gets
// EACCES for a child that is still there. The view drops what it retained, since
// it may be stale, but the names the daemon itself created keep their records:
// once the permission is restored they must still be asked for on every query.
func TestUnreadableDirectoryKeepsItsCreatedRecords(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so EACCES cannot be produced")
	}
	var table sessionTable
	s := table.acquire("token")
	defer table.release("token", s)

	base := t.TempDir()
	outer := filepath.Join(base, "outer")
	inner := filepath.Join(outer, "inner")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	made := filepath.Join(inner, "made.txt")
	if err := os.WriteFile(made, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	var st syscall.Stat_t
	if err := syscall.Lstat(inner, &st); err != nil {
		t.Fatal(err)
	}
	s.MarkDir(inner, uint64(st.Dev), st.Ino, []string{"made.txt"})
	s.MarkCreated(made)

	var announced [][]string
	sub := s.subscribe(func(_ uint64, names []string) bool {
		if len(names) > 0 {
			announced = append(announced, names)
		}
		return true
	})
	defer s.unsubscribe(sub)

	// The command takes search permission off the parent, then the daemon
	// compares the directory its view last saw. The lookup fails with EACCES.
	if err := os.Chmod(outer, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(outer, 0o755) })
	s.commandStarted()
	s.commandFinished()

	if !s.Created(made) {
		t.Fatal("a record was retired for a directory the comparison could not read")
	}
	// The view is still told to drop what it held: it cannot know the entries
	// are unchanged.
	if len(announced) != 1 {
		t.Fatalf("announcements = %v, want the unreadable directory reported", announced)
	}

	// Restoring the permission leaves the file in place and the record intact,
	// so every later query still asks the daemon.
	if err := os.Chmod(outer, 0o755); err != nil {
		t.Fatal(err)
	}
	s.commandStarted()
	s.commandFinished()
	if !s.Created(made) {
		t.Fatal("the record did not survive the permission being restored")
	}
}

// A record created for a directory covers the names below it: when the directory
// is confirmed gone, its descendants are out of reach with it.
func TestForgettingAVanishedDirectoryAlsoDropsItsDescendants(t *testing.T) {
	var table sessionTable
	s := table.acquire("token")
	defer table.release("token", s)

	s.MarkCreated("/proj/dir")
	s.MarkCreated("/proj/dir/child.txt")
	seq := s.LedgerSeq()
	s.ForgetCreated("/proj/dir", seq)

	if s.Created("/proj/dir") {
		t.Fatal("the vanished directory kept its record")
	}
	if s.Created("/proj/dir/child.txt") {
		t.Fatal("a name below the vanished directory kept its record")
	}
}
