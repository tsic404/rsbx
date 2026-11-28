//go:build linux && (amd64 || arm64)

package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"rsbx/internal/proto"
)

const traceOptions = unix.PTRACE_O_TRACESYSGOOD | unix.PTRACE_O_TRACESECCOMP |
	unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACEVFORK | unix.PTRACE_O_TRACECLONE |
	unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_TRACEVFORKDONE | unix.PTRACE_O_EXITKILL

var errTraceeExit = errors.New("tracee exited during exec interception")

type traceTask struct {
	pid            int
	stopped        bool
	queued         bool
	interrupt      bool
	synthetic      bool
	listening      bool
	vfork          bool
	group          int
	newborn        bool
	pendingSignals []unix.Signal
}

type traceStop struct {
	pid    int
	status unix.WaitStatus
}

type scriptPermit struct {
	image        execAsset
	prefix, tail []string
}

// execDecision is the immutable controller decision for one thread group.
// It is recorded before the approved exec is replayed so that the kernel's
// PTRACE_EVENT_EXEC can be validated wherever it is observed: during the
// injected wait, or later through the main loop when the execing thread was
// not the group leader and the wait report carries the remapped TID.
type execDecision struct {
	expected execAsset
	script   *scriptImagePlan
	argv     []string
	env      []string
	remote   *proto.ExecReq
}

// Ordinary I/O uses PTRACE_CONT, not a pair of syscall stops. The executing
// guard's inherited seccomp filter selects execve/execveat with RET_TRACE;
// it also denies filter replacement, untraced clones, cross-process memory
// APIs, and asynchronous writers. Read-only /proc prevents writable mem FDs.
// At an exec stop all descendants (including CLONE_VM peers) are suspended.
// The supervisor copies arguments into a fresh private mapping, opens and
// pins the real executable in the tracee, and executes either that approved
// immutable inode or the bound native gateway. No read-path/CONTINUE race is
// an execution boundary. PTRACE_EVENT_EXEC validates the new inode before
// its first instruction, and the remote request remains in PID 1's memory.
type tracer struct {
	policy  *execPolicy
	server  *gatewayServer
	tasks   map[int]*traceTask
	queue   []traceStop
	permits map[int]scriptPermit
	// decisions holds one approved exec per thread group between the replay
	// of the exec syscall and the kernel's PTRACE_EVENT_EXEC. It is the
	// immutable decision, keyed by thread group because exec de-threads the
	// caller and the event can arrive under a different TID.
	decisions   map[int]execDecision
	entry       int
	entryExited bool
	code        int
	signals     chan os.Signal
	tick        *time.Ticker
	deadline    time.Time
	killed      bool

	// reverseGroups are the guarded bootstraps the supervisor started for
	// stub-driven commands. They are not the entry: their exit is reported
	// back to the caller and never tears down the session.
	reverseGroups map[int]bool
	reverseStatus map[int]chan int
	reverseJobs   chan reverseJob
	reverseSpec   *launchSpec
	acceptReverse bool
	// session is the token every command routed to the daemon carries, so the
	// daemon can announce it to this session's filesystem view.
	session string
}

// localTarget reports whether a reverse caller asked for a program the
// session's policy pinned as local. Identity is the inode, never the name, so
// replacing the file after launch does not widen the grant.
func (p *execPolicy) localTarget(target string) bool {
	id, mode, err := pathIdentity(target)
	if err != nil || mode&unix.S_IFMT != unix.S_IFREG {
		return false
	}
	return p.local[id]
}

// spawnReverse starts one command under the same guard the entry receives.
// It is called from the supervisor's wait loop, never from a goroutine: the
// bootstrap freezes and seizes every thread, so the new process must not be
// born while another ptrace operation is in flight.
func (t *tracer) spawnReverse(spec *launchSpec, req *proto.ExecReq, reply chan<- reverseResult) error {
	target, err := reverseTarget(spec, req)
	if err != nil {
		return err
	}
	req.Target = target
	if !t.policy.localTarget(req.Target) {
		return fmt.Errorf("local execution refused: %s is not an allowlisted local executable", req.Target)
	}
	if req.Dir != "" {
		fi, err := os.Stat(req.Dir)
		if err != nil || !fi.IsDir() {
			return fmt.Errorf("local execution refused: chdir %s is not a directory", req.Dir)
		}
	}
	data, err := json.Marshal(GuardSpec{Target: req.Target, Argv: req.Argv, Env: req.Env, ExecPaths: spec.ExecPaths})
	if err != nil {
		return err
	}
	guardSpec, err := sealedPayload("rsbx-guard-reverse", data)
	if err != nil {
		return err
	}
	defer guardSpec.Close()
	gateR, gateW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer gateR.Close()
	defer gateW.Close()
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		stdinR.Close()
		stdinW.Close()
		return err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		stdinR.Close()
		stdinW.Close()
		outR.Close()
		outW.Close()
		return err
	}
	cmd := exec.Command(GuardPath, "-rsbx-guard-spec-fd", "3", "-rsbx-guard-gate-fd", "4")
	cmd.Dir = req.Dir
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stdin = stdinR
	cmd.Stdout, cmd.Stderr = outW, errW
	cmd.ExtraFiles = []*os.File{guardSpec, gateR}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		stdinR.Close()
		stdinW.Close()
		outR.Close()
		outW.Close()
		errR.Close()
		errW.Close()
		return fmt.Errorf("start reverse guard: %w", err)
	}
	pid := cmd.Process.Pid
	stdinR.Close()
	started := false
	defer func() {
		if !started {
			unix.Kill(-pid, unix.SIGKILL)
			stdinW.Close()
			outR.Close()
			errR.Close()
		}
	}()
	t.reverseGroups[pid] = true
	outW.Close()
	errW.Close()
	gateR.Close()
	defer cmd.Process.Release()
	if err := t.attachBootstrap(pid); err != nil {
		outR.Close()
		errR.Close()
		return err
	}
	if err := t.policy.imageMatches(pid, t.policy.guard); err != nil {
		outR.Close()
		errR.Close()
		return err
	}
	// A reverse bootstrap execs the guard without a preceding seccomp stop,
	// exactly like the entry, so the EXEC validator must accept it here too.
	if _, err := gateW.Write([]byte{'1'}); err != nil {
		outR.Close()
		errR.Close()
		return err
	}
	gateW.Close()
	status := make(chan int, 1)
	t.reverseStatus[pid] = status
	if err = t.releaseFrozen(0); err != nil {
		return err
	}
	started = true
	reply <- reverseResult{stdout: outR, stderr: errR, stdin: stdinW, pid: pid, status: status}
	return nil
}

func runTraced(spec *launchSpec, server *gatewayServer) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if os.Getpid() != 1 {
		return 126, fmt.Errorf("exec supervisor must be private PID 1")
	}
	policy, err := pinnedExecPolicy(spec)
	if err != nil {
		return 126, err
	}
	// The reverse executor is reached only on a control connection the
	// controller registered a session token on. Each accepted request spawns
	// its own guarded bootstrap, exactly like the entry, so the new command
	// inherits the session's exec policy instead of bypassing it.
	var jobs chan reverseJob
	if spec.ReverseToken != "" {
		file := os.NewFile(6, "rsbx-reverse-listener")
		listener, err := net.FileListener(file)
		file.Close()
		if err != nil {
			return 126, err
		}
		jobs = make(chan reverseJob, 32)
		reverse := newReverseListener(listener, spec.ReverseToken, jobs)
		defer reverse.Close()
	}
	t := &tracer{policy: policy, server: server, tasks: map[int]*traceTask{}, permits: map[int]scriptPermit{}, decisions: map[int]execDecision{}, signals: make(chan os.Signal, 32), tick: time.NewTicker(time.Millisecond), reverseGroups: map[int]bool{}, reverseStatus: map[int]chan int{}, reverseJobs: jobs, session: spec.Session}
	t.reverseSpec = spec
	defer t.tick.Stop()
	signal.Notify(t.signals, forwardedSignals...)
	defer signal.Stop(t.signals)
	data, err := json.Marshal(GuardSpec{Target: spec.Target, Argv: spec.Argv, Env: spec.Env, ExecPaths: spec.ExecPaths})
	if err != nil {
		return 127, err
	}
	guardSpec, err := sealedPayload("rsbx-guard", data)
	if err != nil {
		return 127, err
	}
	defer guardSpec.Close()
	gateR, gateW, err := os.Pipe()
	if err != nil {
		return 127, err
	}
	defer gateR.Close()
	defer gateW.Close()
	cmd := exec.Command(GuardPath, "-rsbx-guard-spec-fd", "3", "-rsbx-guard-gate-fd", "4")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.ExtraFiles = []*os.File{guardSpec, gateR}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return 127, fmt.Errorf("start native execution guard: %w", err)
	}
	t.entry = cmd.Process.Pid
	defer cmd.Process.Release()
	gateR.Close()
	// Go helpers may already have runtime threads. They execute only trusted
	// startup code and block at the sealed-spec gate; SEIZE every existing
	// thread, then INTERRUPT and enumerate again before releasing that gate.
	if err := t.attachBootstrap(t.entry); err != nil {
		t.killAndReap()
		return 126, err
	}
	if err := policy.imageMatches(t.entry, policy.guard); err != nil {
		t.killAndReap()
		return 126, err
	}
	if spec.ManageTTY {
		if spec.TerminalFD < 0 || spec.TerminalFD > 2 {
			t.killAndReap()
			return 126, fmt.Errorf("invalid inherited terminal descriptor")
		}
		if err := setTerminalGroup(spec.TerminalFD, t.entry); err != nil {
			t.killAndReap()
			return 126, fmt.Errorf("assign terminal to entry process group: %w", err)
		}
	}
	if _, err := gateW.Write([]byte{'1'}); err != nil {
		t.killAndReap()
		return 126, err
	}
	gateW.Close()
	if err := t.releaseFrozen(0); err != nil {
		t.killAndReap()
		return 126, err
	}
	for {
		// Reverse requests are only serviced between wait reports: the
		// bootstrap freezes every descendant, so it must never overlap an
		// in-flight exec interception. A refusal is a result, not a panic.
		select {
		case job := <-t.reverseJobs:
			accepting := t.acceptReverse
			t.acceptReverse = false
			if err := t.spawnReverse(spec, job.request, job.reply); err != nil {
				job.reply <- reverseResult{err: err}
				if releaseErr := t.releaseFrozen(0); releaseErr != nil {
					t.killAndReap()
					return 126, releaseErr
				}
			}
			t.acceptReverse = accepting
		default:
		}
		var s traceStop
		if len(t.queue) != 0 {
			s = t.queue[0]
			t.queue = t.queue[1:]
			if task := t.tasks[s.pid]; task != nil {
				task.queued = false
			} else {
				continue
			}
		} else {
			t.acceptReverse = true
			s, err = t.receive()
			t.acceptReverse = false
			if s.pid == -1 {
				continue
			}
			if err == unix.ECHILD {
				return t.code, nil
			}
			if err != nil {
				t.killAndReap()
				return 126, err
			}
			if err := t.note(s); err != nil {
				t.killAndReap()
				return 126, err
			}
		}
		if s.status.Exited() || s.status.Signaled() {
			continue
		}
		if err := t.dispatch(s); err != nil {
			if errors.Is(err, errTraceeExit) {
				if releaseErr := t.releaseFrozen(0); releaseErr != nil {
					t.killAndReap()
					return 126, releaseErr
				}
				continue
			}
			t.killAndReap()
			return 126, err
		}
	}
}

func seizeThread(pid int) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_SEIZE, uintptr(pid), 0, traceOptions, 0, 0)
	if errno != 0 {
		return fmt.Errorf("seize thread %d: %w", pid, errno)
	}
	return nil
}

func (t *tracer) attachBootstrap(pid int) error {
	for {
		entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
		if err != nil {
			return err
		}
		added := false
		for _, e := range entries {
			tid, err := strconv.Atoi(e.Name())
			if err != nil {
				return err
			}
			if t.tasks[tid] != nil {
				continue
			}
			if err := seizeThread(tid); err != nil {
				return err
			}
			t.tasks[tid] = &traceTask{pid: tid, group: pid}
			added = true
		}
		if err := t.freezeAll(0); err != nil {
			return err
		}
		if !added {
			return nil
		}
	}
}

func (t *tracer) handleSignal(sig os.Signal) {
	s, ok := sig.(syscall.Signal)
	if !ok {
		return
	}
	// kill(-1) is namespace-scoped and excludes PID 1. A descendant that
	// called setsid/setpgid is still signalled and killed with the session.
	_ = unix.Kill(-1, s)
	if terminatingSignal(sig) && t.deadline.IsZero() {
		t.deadline = time.Now().Add(sessionGrace)
	}
}

func (t *tracer) serviceSignals() {
	for {
		select {
		case sig := <-t.signals:
			t.handleSignal(sig)
		default:
			goto drained
		}
	}
drained:
	if !t.deadline.IsZero() && !t.killed && !time.Now().Before(t.deadline) {
		t.killed = true
		_ = unix.Kill(-1, unix.SIGKILL)
	}
}

func (t *tracer) receive() (traceStop, error) {
	for {
		t.serviceSignals()
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, unix.WALL|unix.WNOHANG, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return traceStop{}, err
		}
		if pid != 0 {
			return traceStop{pid, ws}, nil
		}
		select {
		case sig := <-t.signals:
			t.handleSignal(sig)
		case <-t.tick.C:
			if t.acceptReverse && len(t.reverseJobs) > 0 {
				return traceStop{pid: -1}, nil
			}
		}
	}
}

func (t *tracer) note(s traceStop) error {
	if s.status.Exited() || s.status.Signaled() {
		group := 0
		if task := t.tasks[s.pid]; task != nil {
			group = task.group
		}
		delete(t.tasks, s.pid)
		delete(t.permits, s.pid)
		// A recorded decision binds the thread group, not one thread of it: an
		// exec destroys the caller's sibling threads while the approved exec is
		// still in flight, so a sibling exit must not retract it. The record is
		// dropped only when no task in that group remains.
		if group > 0 && !t.groupAlive(group, s.pid) {
			delete(t.decisions, group)
		}

		t.server.Forget(s.pid)
		if t.reverseGroups[s.pid] {
			// A reverse command's exit is a result, not a session end. The
			// caller is draining both pipes and then reads this status.
			delete(t.reverseGroups, s.pid)
			if status := t.reverseStatus[s.pid]; status != nil {
				status <- exitCode(s.status)
			}
			delete(t.reverseStatus, s.pid)
		}
		if s.pid == t.entry && !t.entryExited {
			t.entryExited, t.code = true, exitCode(s.status)
			_ = unix.Kill(-1, unix.SIGTERM)
			if t.deadline.IsZero() {
				t.deadline = time.Now().Add(sessionGrace)
			}
		}
		return nil
	}
	if !s.status.Stopped() {
		return fmt.Errorf("unexpected wait status %#x", uint32(s.status))
	}
	task := t.tasks[s.pid]
	if task == nil {
		task = &traceTask{pid: s.pid}
		t.tasks[s.pid] = task
	}
	task.stopped = true
	if task.group == 0 {
		group, err := threadGroupID(s.pid)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		task.group = group
	}
	cause := s.status.TrapCause()
	if cause == unix.PTRACE_EVENT_FORK || cause == unix.PTRACE_EVENT_VFORK || cause == unix.PTRACE_EVENT_CLONE {
		child, err := unix.PtraceGetEventMsg(s.pid)
		if err != nil {
			return err
		}
		if t.tasks[int(child)] == nil {
			t.tasks[int(child)] = &traceTask{pid: int(child), newborn: true}
		}
	}
	if cause == unix.PTRACE_EVENT_VFORK_DONE {
		task.vfork = false
	}
	return nil
}

func (t *tracer) enqueue(s traceStop) {
	if task := t.tasks[s.pid]; task != nil && !task.queued {
		task.queued = true
		t.queue = append(t.queue, s)
	}
}

func (t *tracer) freezeAll(active int) error {
	for {
		ready := true
		for pid, task := range t.tasks {
			if task.stopped || task.vfork {
				continue
			}
			ready = false
			if task.interrupt {
				continue
			}
			if err := unix.PtraceInterrupt(pid); err != nil {
				if err == unix.ESRCH {
					// The thread vanished between the task scan and the
					// interrupt; drop it so the loop cannot wait for a
					// stop that will never arrive.
					delete(t.tasks, pid)
					continue
				}
				return fmt.Errorf("interrupt descendant %d: %w", pid, err)
			}
			task.interrupt = true
		}
		if ready {
			return nil
		}
		s, err := t.receive()
		if err != nil {
			return err
		}
		if err := t.note(s); err != nil {
			return err
		}
		if s.pid == active && (s.status.Exited() || s.status.Signaled()) {
			return errTraceeExit
		}
		if !s.status.Stopped() {
			continue
		}
		task := t.tasks[s.pid]
		if task.interrupt && s.status.TrapCause() == unix.PTRACE_EVENT_STOP && s.status.StopSignal() == unix.SIGTRAP {
			task.synthetic = true
		} else {
			t.enqueue(s)
		}
	}
}

func (t *tracer) resume(pid int, sig int) error {
	task := t.tasks[pid]
	if task == nil {
		return nil
	}
	if err := unix.PtraceCont(pid, sig); err != nil && err != unix.ESRCH {
		return err
	}
	task.stopped, task.interrupt, task.synthetic, task.listening = false, false, false, false
	for _, pending := range task.pendingSignals {
		_ = unix.Kill(pid, pending)
	}
	task.pendingSignals = nil
	return nil
}

func (t *tracer) listen(pid int) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_LISTEN, uintptr(pid), 0, 0, 0, 0)
	if errno != 0 && errno != unix.ESRCH {
		return errno
	}
	if task := t.tasks[pid]; task != nil {
		task.stopped, task.synthetic, task.interrupt, task.listening = false, false, false, true
	}
	return nil
}

func (t *tracer) releaseFrozen(except int) error {
	for pid, task := range t.tasks {
		if pid == except || !task.stopped || !task.synthetic || task.queued {
			continue
		}
		var err error
		if task.listening {
			err = t.listen(pid)
		} else {
			err = t.resume(pid, 0)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *tracer) dispatch(s traceStop) error {
	cause, sig := s.status.TrapCause(), s.status.StopSignal()
	switch cause {
	case unix.PTRACE_EVENT_SECCOMP:
		info, err := readSyscallInfo(s.pid)
		if err != nil {
			return err
		}
		if info.Op != unix.PTRACE_SYSCALL_INFO_SECCOMP || info.number() != unix.SYS_EXECVE && info.number() != unix.SYS_EXECVEAT {
			return fmt.Errorf("unexpected seccomp trace event")
		}
		return t.intercept(s.pid, info)
	case unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_CLONE:
		return t.resume(s.pid, 0)
	case unix.PTRACE_EVENT_VFORK:
		t.tasks[s.pid].vfork = true
		return t.resume(s.pid, 0)
	case unix.PTRACE_EVENT_VFORK_DONE:
		return t.resume(s.pid, 0)
	case unix.PTRACE_EVENT_EXEC:
		// The supervisor starts the guard itself, so a seize that lands while
		// that bootstrap exec is committing reports an EXEC with no seccomp
		// stop behind it. It is accepted only for the entry group and only as
		// the exact pinned guard image; the guard's own exec of the entry
		// program has a recorded decision and is validated normally.
		_, recorded := t.decisions[t.groupOf(s.pid)]
		if t.entryBootstrapExec(t.groupOf(s.pid)) || t.reverseGroups[t.groupOf(s.pid)] && !recorded {
			if err := t.policy.imageMatches(s.pid, t.policy.guard); err != nil {
				return err
			}
			return t.resume(s.pid, 0)
		}
		// The event reached the main loop instead of the injected wait: the
		// execing thread was not the one this loop expected, or its report was
		// queued while another descendant was being inspected. The decision is
		// recorded per thread group, so it can still be validated here — an
		// event with no recorded decision is the only real violation.
		return t.completeExec(s.pid, t.groupOf(s.pid))
	case unix.PTRACE_EVENT_STOP:
		if task := t.tasks[s.pid]; task != nil && task.newborn {
			task.newborn = false
			return t.resume(s.pid, 0)
		}
		if sig == unix.SIGTRAP {
			return t.resume(s.pid, 0)
		}
		return t.listen(s.pid)
	}
	if sig == unix.SIGTRAP|0x80 {
		return fmt.Errorf("unexpected ordinary syscall stop")
	}
	return t.resume(s.pid, int(sig))
}

// entryBootstrapExec reports whether an EXEC wait report is the supervisor's
// own bootstrap exec of the pinned guard. The supervisor performs that exec
// itself, outside the seccomp filter it later installs, so no controller
// decision can precede it. The event is recognized structurally: the report
// belongs to the entry thread group and no decision was recorded for it. Any
// later exec of that group — including the guard's exec of the entry program —
// has a recorded decision and is validated as one.
func (t *tracer) entryBootstrapExec(group int) bool {
	if group != t.entry {
		return false
	}
	_, recorded := t.decisions[group]
	return !recorded
}

// groupOf resolves the thread group a wait report belongs to. After an exec
// de-threads the caller the kernel reports the new TID as the group id, so the
// live /proc value is authoritative; the recorded per-TID group is the
// fallback when the thread has already vanished.
func (t *tracer) groupOf(pid int) int {
	if task := t.tasks[pid]; task != nil && task.group > 0 {
		if current, err := threadGroupID(pid); err == nil {
			return current
		}
		return task.group
	}
	if current, err := threadGroupID(pid); err == nil {
		return current
	}
	return pid
}

// groupAlive reports whether any traced task still belongs to group. A
// decision is retracted only when the whole thread group is gone; a sibling
// thread that the exec itself destroys leaves the pending decision intact.
// The exiting pid is already gone from the task map, and the de-threaded
// execing thread shares its TID with the group id, so both identity forms are
// covered by the same comparison.
func (t *tracer) groupAlive(group, exiting int) bool {
	for pid, task := range t.tasks {
		if pid == exiting {
			continue
		}
		if task.group == group || pid == group {
			return true
		}
	}
	return false
}

// During injection only the executing thread may advance, and only between
// kernel syscall stops. Other wait reports are queued without resuming a
// user instruction. Exec can de-thread and change a nonleader TID to its
// TGID; the ptrace event's old TID is the authoritative remap.
// At an exec event all siblings have died. Discard their queued stops before
// the old leader PID can be reused by the execing thread; a stale seccomp
// record must never be applied to the new executable image.
func (t *tracer) commitThreadGroup(oldPID, newPID int) error {
	active := t.tasks[oldPID]
	if active == nil {
		return fmt.Errorf("execing thread lost its tracing state")
	}
	group := active.group
	if group <= 0 {
		return fmt.Errorf("execing thread has no kernel thread group")
	}
	queue := t.queue[:0]
	for _, stop := range t.queue {
		if member := t.tasks[stop.pid]; member != nil && member.group == group {
			continue
		}
		queue = append(queue, stop)
	}
	t.queue = queue
	for pid, member := range t.tasks {
		if member.group == group {
			delete(t.tasks, pid)
		}
	}
	delete(t.permits, group)
	active.pid, active.group, active.stopped = newPID, newPID, true
	active.queued, active.synthetic, active.interrupt, active.listening, active.newborn = false, false, false, false, false
	t.tasks[newPID] = active
	return nil
}

func (t *tracer) injectedStop(pid int, want uint8, nr uint64, execEvent bool) (traceStop, traceSyscallInfo, error) {
	for {
		s, err := t.receive()
		if err != nil {
			return s, traceSyscallInfo{}, err
		}
		if s.status.Stopped() && s.status.TrapCause() == unix.PTRACE_EVENT_EXEC {
			old, err := unix.PtraceGetEventMsg(s.pid)
			if err != nil {
				return s, traceSyscallInfo{}, err
			}
			// Exec replaced this thread's image. Match it to the injection by
			// thread group, not by TID: a de-threaded caller is reported under
			// the former thread-group id, which may differ from the TID whose
			// syscall was injected.
			if int(old) == pid || s.pid == pid || t.groupOf(s.pid) == t.groupOf(pid) {
				if !execEvent {
					return s, traceSyscallInfo{}, fmt.Errorf("unexpected image while injecting syscall %d", nr)
				}
				if err := t.commitThreadGroup(pid, s.pid); err != nil {
					return s, traceSyscallInfo{}, err
				}
				if err := t.note(s); err != nil {
					return s, traceSyscallInfo{}, err
				}
				return s, traceSyscallInfo{}, nil
			}
		}
		if err := t.note(s); err != nil {
			return s, traceSyscallInfo{}, err
		}
		if s.pid != pid {
			if s.status.Stopped() {
				t.enqueue(s)
			}
			continue
		}
		if s.status.Exited() || s.status.Signaled() {
			return s, traceSyscallInfo{}, errTraceeExit
		}
		cause := s.status.TrapCause()
		if s.status.StopSignal() == unix.SIGTRAP|0x80 || cause == unix.PTRACE_EVENT_SECCOMP {
			info, err := readSyscallInfo(pid)
			if err != nil {
				return s, info, err
			}
			if info.Op == unix.PTRACE_SYSCALL_INFO_ENTRY || info.Op == unix.PTRACE_SYSCALL_INFO_SECCOMP {
				if info.number() != nr {
					return s, info, fmt.Errorf("injected syscall number changed to %d, expected %d", info.number(), nr)
				}
			}
			if info.Op == want {
				return s, info, nil
			}
			if err := unix.PtraceSyscall(pid, 0); err != nil {
				return s, info, err
			}
			t.tasks[pid].stopped = false
			continue
		}
		if strayInjectionEvent(cause) {
			return s, traceSyscallInfo{}, fmt.Errorf("unexpected ptrace event during injection")
		}
		sig := s.status.StopSignal()
		if sig == unix.SIGTRAP {
			// A group stop or synthetic stop: only PTRACE_SYSCALL resumes
			// the interrupted injected call without executing user code.
			sig = 0
		} else if !injectedDeliverable(sig) {
			// SIGKILL and the job-control defaults must fail the injection
			// rather than resume the tracee into user code.
			return s, traceSyscallInfo{}, fmt.Errorf("injected call interrupted by signal %d", sig)
		} else {
			// A delivered signal would run its handler in the middle of the
			// injected call. Queue it for the next resume, which restarts
			// the tracee with signal 0.
			t.tasks[pid].pendingSignals = append(t.tasks[pid].pendingSignals, sig)
			sig = 0
		}
		if err := unix.PtraceSyscall(pid, int(sig)); err != nil {
			return s, traceSyscallInfo{}, err
		}
		t.tasks[pid].stopped = false
	}
}

// strayInjectionEvent reports whether a stop observed while an injected call
// is in flight means the tracee left that call. TrapCause is negative when the
// stop signal is not SIGTRAP, which is an ordinary signal delivery rather than
// a ptrace event, and zero for a plain SIGTRAP stop. Both are handled by the
// restart path: a signal delivery is queued for the next resume, and a plain
// SIGTRAP stop resumes with no signal. Only a real ptrace event other than
// PTRACE_EVENT_STOP means a sibling event the injection cannot absorb.
func strayInjectionEvent(cause int) bool {
	return cause > 0 && cause != unix.PTRACE_EVENT_STOP
}

// injectedDeliverable reports whether a signal received during a restart
// chain may be handed to the tracee with PTRACE_SYSCALL. The process-
// stopping defaults never are: allowing them would end the syscall restart
// loop and execute user instructions with the injected register image.
func injectedDeliverable(sig unix.Signal) bool {
	switch sig {
	case unix.SIGKILL, unix.SIGSTOP, unix.SIGTSTP, unix.SIGTTIN, unix.SIGTTOU:
		return false
	}
	return true
}

func (t *tracer) injectedCall(pid int, original traceRegs, nr uint64, args [6]uint64, first bool) (int64, error) {
	var err error
	if first {
		err = replaceEntry(pid, original, nr, args)
	} else {
		err = replayCall(pid, original, nr, args)
	}
	if err != nil {
		return 0, err
	}
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		return 0, err
	}
	t.tasks[pid].stopped = false
	_, info, err := t.injectedStop(pid, unix.PTRACE_SYSCALL_INFO_EXIT, nr, false)
	if err != nil {
		return 0, err
	}
	return int64(info.Data[0]), nil
}

func syscallError(result int64) error {
	if result < 0 && result >= -4095 {
		return unix.Errno(-result)
	}
	return nil
}

func (t *tracer) returnExecError(pid int, original traceRegs, errno unix.Errno, first bool, memory *execMemory) error {
	if first {
		if _, err := t.injectedCall(pid, original, unix.SYS_GETPID, [6]uint64{}, true); err != nil {
			return err
		}
	}
	if memory != nil {
		result, err := t.injectedCall(pid, original, unix.SYS_MUNMAP, [6]uint64{memory.base, uint64(len(memory.bytes))}, false)
		if err != nil {
			return err
		}
		if err := syscallError(result); err != nil {
			return err
		}
	}
	if err := restoreResult(pid, original, -int64(errno)); err != nil {
		return err
	}
	if err := t.resume(pid, 0); err != nil {
		return err
	}
	return t.releaseFrozen(pid)
}

func (t *tracer) closeInjectedFD(pid int, original traceRegs, fd int) error {
	result, err := t.injectedCall(pid, original, unix.SYS_CLOSE, [6]uint64{uint64(fd)}, false)
	if err != nil {
		return err
	}
	return syscallError(result)
}

func fdTarget(pid, fd int) (string, executableID, uint32, error) {
	name := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	path, err := os.Readlink(name)
	if err != nil {
		return "", executableID{}, 0, unix.EBADF
	}
	id, mode, err := pathIdentity(name)
	if err != nil {
		return "", id, mode, err
	}
	return path, id, mode, nil
}

func namedDaemonTarget(path string) error {
	if !filepath.IsAbs(path) || strings.HasSuffix(path, " (deleted)") || strings.Contains(path, " (unreachable)") {
		return fmt.Errorf("executable descriptor has no stable daemon pathname: %s; anonymous/deleted executables are never uploaded or run locally", path)
	}
	return nil
}

const atFDCWDArgument = ^uint64(99)

func (t *tracer) intercept(pid int, info traceSyscallInfo) error {
	if err := t.freezeAll(pid); err != nil {
		return err
	}
	original, err := readTraceRegs(pid)
	if err != nil {
		return err
	}
	ip := original.ip()
	if ip < uint64(len(traceSyscallInstruction)) {
		return fmt.Errorf("invalid exec syscall site")
	}
	instruction := make([]byte, len(traceSyscallInstruction))
	if err := traceRead(pid, ip-uint64(len(instruction)), instruction); err != nil || !bytes.Equal(instruction, traceSyscallInstruction) {
		return fmt.Errorf("exec syscall site is not the native syscall instruction")
	}
	if t.entryExited || !t.deadline.IsZero() {
		return t.returnExecError(pid, original, unix.ECANCELED, true, nil)
	}
	in, err := captureInvocation(pid, info)
	if err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return t.returnExecError(pid, original, errno, true, nil)
		}
		return err
	}
	memory, err := newExecMemory(in.path, in.argv, in.env)
	if err != nil {
		return t.returnExecError(pid, original, unix.E2BIG, true, nil)
	}
	result, err := t.injectedCall(pid, original, unix.SYS_MMAP,
		[6]uint64{0, uint64(len(memory.bytes)), unix.PROT_READ | unix.PROT_WRITE, unix.MAP_PRIVATE | unix.MAP_ANONYMOUS, ^uint64(0), 0}, true)
	if err != nil {
		return err
	}
	if errno := syscallError(result); errno != nil {
		return t.returnExecError(pid, original, errno.(unix.Errno), false, nil)
	}
	memory.relocate(uint64(result), in.argv, in.env)
	if n, err := unix.PtracePokeData(pid, uintptr(memory.base), memory.bytes); err != nil || n != len(memory.bytes) {
		return fmt.Errorf("copy immutable exec arguments: %v", err)
	}
	fd, owned := in.dirfd, false
	if in.path != "" {
		flags := uint64(unix.O_PATH | unix.O_CLOEXEC)
		if in.execveat && in.flags&unix.AT_SYMLINK_NOFOLLOW != 0 {
			flags |= unix.O_NOFOLLOW
		}
		result, err = t.injectedCall(pid, original, unix.SYS_OPENAT, [6]uint64{uint64(int64(in.dirfd)), memory.pathAddr(), flags}, false)
		if err != nil {
			return err
		}
		if errno := syscallError(result); errno != nil {
			return t.returnExecError(pid, original, errno.(unix.Errno), false, memory)
		}
		fd, owned = int(result), true
	}
	target, id, mode, err := fdTarget(pid, fd)
	if err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return t.returnExecError(pid, original, errno, false, memory)
		}
		return err
	}
	if mode&unix.S_IFMT == unix.S_IFLNK && in.flags&unix.AT_SYMLINK_NOFOLLOW != 0 {
		if owned {
			if err := t.closeInjectedFD(pid, original, fd); err != nil {
				return err
			}
		}
		return t.returnExecError(pid, original, unix.ELOOP, false, memory)
	}
	// A non-regular target and a regular file without an execute bit both
	// surface as EACCES to the tracee, exactly as its own kernel exec would:
	// probing a directory or a non-executable file is a recoverable failure
	// the caller may fall back from, never a session-level error.
	if mode&unix.S_IFMT != unix.S_IFREG || mode&0o111 == 0 {
		if owned {
			if err := t.closeInjectedFD(pid, original, fd); err != nil {
				return err
			}
		}
		return t.returnExecError(pid, original, unix.EACCES, false, memory)
	}
	local := t.policy.local[id]
	group, err := threadGroupID(pid)
	if err != nil {
		return err
	}
	permit, permitted := t.permits[group]
	matchedPermit := permitted && id == assetID(permit.image) && permit.matches(in.argv)
	if matchedPermit {
		local = true
	}
	expected := t.policy.identities[id]
	var script *scriptImagePlan
	var remote *proto.ExecReq
	execNr := uint64(unix.SYS_EXECVEAT)
	execArgs := [6]uint64{uint64(fd), memory.emptyAddr(), memory.argvAddr(), memory.envAddr(), unix.AT_EMPTY_PATH}
	if local {
		if c, ok := t.policy.scripts[id]; ok {
			filename := c.Script
			if owned {
				if err := t.closeInjectedFD(pid, original, fd); err != nil {
					return err
				}
				owned = false
			}
			if in.execveat && (in.path == "" || !filepath.IsAbs(in.path) && in.dirfd != unix.AT_FDCWD) {
				// Preserve kernel FD-script naming and the original descriptor's
				// CLOEXEC behavior. The file identity and argument pages are pinned
				// while all processes that could share its fd table remain stopped.
				filename = fmt.Sprintf("/dev/fd/%d", in.dirfd)
				if in.path != "" {
					filename += "/" + in.path
				}
				execArgs = [6]uint64{uint64(int64(in.dirfd)), memory.pathAddr(), memory.argvAddr(), memory.envAddr(), uint64(in.flags)}
			} else {
				resolved := in.path
				if !filepath.IsAbs(resolved) {
					resolved = filepath.Join(in.cwd, in.path)
				}
				if asset, known := t.policy.paths[resolved]; known && assetID(asset) == id {
					filename = in.path
				}
				if err := memory.retarget(pid, filename); err != nil {
					return err
				}
				execNr = unix.SYS_EXECVE
				execArgs = [6]uint64{memory.pathAddr(), memory.argvAddr(), memory.envAddr()}
			}
			plan, err := t.policy.scriptPlan(id, filename, in.argv)
			if err != nil {
				return err
			}
			script, expected = &plan, plan.image
		} else if matchedPermit {
			expected = permit.image
		}
	} else {
		if err := namedDaemonTarget(target); err != nil {
			// An unstable name (anonymous or deleted descriptor) is a refusal
			// of this exec, not a reason to kill an allowed program: report it
			// as the tracee's own exec failure. Only the descriptor this
			// supervisor opened is closed; the caller's fd stays untouched.
			if owned {
				if err := t.closeInjectedFD(pid, original, fd); err != nil {
					return err
				}
			}
			return t.returnExecError(pid, original, unix.EPERM, false, memory)
		}
		remote = &proto.ExecReq{Target: target, Argv: in.argv, Env: in.env, Dir: in.cwd, Session: t.session}
		if owned {
			if err := t.closeInjectedFD(pid, original, fd); err != nil {
				return err
			}
		}
		if err := memory.retarget(pid, TrampolinePath); err != nil {
			return err
		}
		result, err = t.injectedCall(pid, original, unix.SYS_OPENAT, [6]uint64{atFDCWDArgument, memory.pathAddr(), unix.O_PATH | unix.O_CLOEXEC}, false)
		if err != nil {
			return err
		}
		if err := syscallError(result); err != nil {
			return fmt.Errorf("open native gateway: %w", err)
		}
		fd = int(result)
		_, gatewayID, _, err := fdTarget(pid, fd)
		if err != nil || gatewayID != assetID(t.policy.gateway) {
			return fmt.Errorf("native gateway descriptor identity changed")
		}
		expected = t.policy.gateway
		execArgs[0] = uint64(fd)
	}
	result, err = t.injectedCall(pid, original, unix.SYS_MPROTECT, [6]uint64{memory.base, uint64(len(memory.bytes)), unix.PROT_READ}, false)
	if err != nil {
		return err
	}
	if err := syscallError(result); err != nil {
		return fmt.Errorf("protect captured exec arguments: %w", err)
	}
	// The immutable decision is recorded before the approved syscall is
	// replayed. Exec de-threads the caller, so the eventual PTRACE_EVENT_EXEC
	// can be reported under a different TID; binding the decision to the
	// thread group, not to this stack frame, keeps it authoritative.
	t.decisions[group] = execDecision{expected: expected, script: script, argv: in.argv, env: in.env, remote: remote}
	if err := replayCall(pid, original, execNr, execArgs); err != nil {
		delete(t.decisions, group)
		return err
	}
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		delete(t.decisions, group)
		return err
	}
	t.tasks[pid].stopped = false
	s, exit, err := t.injectedStop(pid, unix.PTRACE_SYSCALL_INFO_EXIT, execNr, true)
	if err != nil {
		delete(t.decisions, group)
		return err
	}
	if s.status.TrapCause() != unix.PTRACE_EVENT_EXEC {
		delete(t.decisions, group)
		if remote != nil {
			return fmt.Errorf("native gateway exec failed: %v", syscallError(int64(exit.Data[0])))
		}
		if owned {
			if _, err := t.injectedCall(pid, original, unix.SYS_CLOSE, [6]uint64{uint64(fd)}, false); err != nil {
				return err
			}
		}
		if errno := syscallError(int64(exit.Data[0])); errno != nil {
			return t.returnExecError(pid, original, errno.(unix.Errno), false, memory)
		}
		return fmt.Errorf("exec returned without a committed image")
	}
	return t.completeExec(s.pid, group)
}

// completeExec validates the committed image against the recorded immutable
// decision for that thread group. It runs at the PTRACE_EVENT_EXEC stop, from
// either the injected wait or the main loop, before the tracee executes a user
// instruction of the new image.
func (t *tracer) completeExec(pid, group int) error {
	decision, ok := t.decisions[group]
	if !ok {
		return fmt.Errorf("exec committed for thread group %d without a recorded controller decision", group)
	}
	if err := t.policy.imageMatches(pid, decision.expected); err != nil {
		return err
	}
	argv, env, err := committedVectors(pid)
	if err != nil {
		return err
	}
	if decision.script != nil {
		if !decision.script.matches(argv) {
			return fmt.Errorf("kernel interpreter argv differs from the pinned script request")
		}
	} else if !slices.Equal(argv, decision.argv) {
		return fmt.Errorf("committed argv differs from the immutable request")
	}
	if !slices.Equal(env, decision.env) {
		return fmt.Errorf("committed environment differs from the immutable request")
	}
	if decision.script != nil && decision.script.permit != nil {
		t.permits[pid] = *decision.script.permit
	}
	delete(t.decisions, group)
	if decision.remote != nil {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err != nil || cwd != decision.remote.Dir {
			return fmt.Errorf("gateway cwd differs from the captured request")
		}
		// The original target/argv/environment/cwd are immutable controller
		// data. Only this committed gateway PID can consume them.
		if err := t.server.Publish(pid, decision.remote); err != nil {
			return err
		}
	}
	if err := t.resume(pid, 0); err != nil {
		return err
	}
	return t.releaseFrozen(pid)
}

func (t *tracer) killAndReap() {
	_ = unix.Kill(-1, unix.SIGKILL)
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, unix.WALL, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return
		}
		if ws.Stopped() {
			_ = unix.PtraceCont(pid, int(unix.SIGKILL))
		}
		if ws.Exited() || ws.Signaled() {
			t.server.Forget(pid)
		}
	}
}
