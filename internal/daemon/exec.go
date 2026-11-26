// Package daemon implements the remote side: it runs processes and owns the
// remote filesystem tree. The daemon's native view is the remote filesystem:
// there is no jail, no root override and no path translation.
package daemon

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"rsbx/internal/proto"
	"rsbx/internal/pty"
)

// Server serves exec sessions and filesystem requests.
type Server struct {
	// Logf is optional.
	Logf func(format string, args ...any)
	// sessions ties the connections of one rsbx session together. It is shared
	// by every connection this server accepts.
	sessions sessionTable
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// ServeConn handles one accepted connection.
func (s *Server) ServeConn(c net.Conn) {
	defer c.Close()
	f, err := proto.ReadFrame(c)
	if err != nil {
		return
	}
	switch f.Type {
	case proto.TExec:
		s.serveExec(c, f.Payload)
	case proto.THello:
		s.ReverseHandshake(c, f.Payload)
	case proto.TFxReq, proto.TSession:
		s.serveFS(c, f)
	default:
		s.logf("rsbxd: unexpected opening frame %#x", f.Type)
	}
}

func (s *Server) serveExec(c net.Conn, payload []byte) {
	req, err := proto.DecodeExecReq(payload)
	if err != nil {
		proto.WriteFrame(c, proto.TErr, []byte("rsbxd: bad exec request"))
		proto.WriteFrame(c, proto.TExit, proto.ExitPayload(127))
		return
	}
	// The command runs on this machine, so this is the only place that learns
	// it may change names the session's view retained. A request without a
	// session token answers for itself and announces nothing.
	var sess *session
	if req.Session != "" {
		sess = s.sessions.acquire(req.Session)
		defer s.sessions.release(req.Session, sess)
	}
	if req.TTY {
		s.execTTY(c, req, sess)
		return
	}
	s.execPipes(c, req, sess)
}

// resolveCwd validates the requested working directory. There is no fallback:
// the client said where to run, and silently running somewhere else changes
// what the command does. On failure it reports the error on the connection and
// returns false so the caller aborts.
func (s *Server) resolveCwd(c net.Conn, dir string) (string, bool) {
	if dir == "" {
		return "", true
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		proto.WriteFrame(c, proto.TErr, []byte(fmt.Sprintf("rsbxd: chdir %s: no such directory", dir)))
		proto.WriteFrame(c, proto.TExit, proto.ExitPayload(127))
		return "", false
	}
	return dir, true
}

// build constructs the child command from the request verbatim. Argv, cwd and
// env are used exactly as sent. An empty env is a genuinely empty environment,
// never an inheritance request: Env is always non-nil, because exec.Cmd treats
// nil as "inherit the daemon's environment". The child runs in its own process
// group so a signal reaches the whole tree and a disconnect can take every
// descendant with it.
func (s *Server) build(req *proto.ExecReq, dir string) *exec.Cmd {
	cmd := exec.Command(req.Target, req.Argv[1:]...)
	cmd.Args = append([]string(nil), req.Argv...)
	cmd.Dir = dir
	cmd.Env = req.Env
	if cmd.Env == nil {
		// exec.Cmd reads nil Env as "inherit the daemon's environment"; the
		// wire's zero-entry env is genuinely empty, so force a non-nil slice.
		cmd.Env = []string{}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func (s *Server) execPipes(c net.Conn, req *proto.ExecReq, sess *session) {
	dir, ok := s.resolveCwd(c, req.Dir)
	if !ok {
		return
	}
	cmd := s.build(req, dir)

	// Child stdin is an exec-managed pipe: Wait closes the write end on exit,
	// which is exactly the EOF the child should see/value for stdin.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		proto.WriteFrame(c, proto.TErr, []byte(err.Error()))
		return
	}
	// stdout/stderr are plain os.Pipes assigned to cmd.Stdout/cmd.Stderr, not
	// StdoutPipe/StderrPipe. Wait therefore does not own them: it would close
	// a pipe with unread buffered data and drop the tail of the output. We
	// close the parent's write ends right after Start and drain the read ends
	// ourselves to EOF, so nothing is lost.
	outR, outW, err := os.Pipe()
	if err != nil {
		stdin.Close()
		proto.WriteFrame(c, proto.TErr, []byte(err.Error()))
		return
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		stdin.Close()
		outR.Close()
		outW.Close()
		proto.WriteFrame(c, proto.TErr, []byte(err.Error()))
		return
	}
	cmd.Stdout = outW
	cmd.Stderr = errW
	sess.commandStarted()
	if err := cmd.Start(); err != nil {
		sess.commandFinished()
		stdin.Close()
		outR.Close()
		outW.Close()
		errR.Close()
		errW.Close()
		proto.WriteFrame(c, proto.TErr, []byte(fmt.Sprintf("rsbxd: exec %s: %v", req.Target, err)))
		proto.WriteFrame(c, proto.TExit, proto.ExitPayload(127))
		return
	}
	// The parent no longer needs the write ends; EOF on the read ends is the
	// signal that the child (and its descendants) closed them.
	outW.Close()
	errW.Close()

	var wmu sync.Mutex
	send := func(typ byte, p []byte) bool {
		wmu.Lock()
		defer wmu.Unlock()
		return proto.WriteFrame(c, typ, p) == nil
	}
	send(proto.TReady, nil)

	pgid := -cmd.Process.Pid
	var pumps sync.WaitGroup
	pumps.Add(2)
	pump := func(r *os.File, typ byte) {
		defer pumps.Done()
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Read(buf)
			if n > 0 && !send(typ, buf[:n]) {
				// The client is gone: that is a cancel, not a reason to keep
				// the child alive.
				syscall.Kill(pgid, syscall.SIGKILL)
				r.Close()
				return
			}
			if err != nil {
				r.Close()
				return
			}
		}
	}
	go pump(outR, proto.TStdout)
	go pump(errR, proto.TStderr)

	// The control reader and the stdin writer are separate goroutines. If they
	// shared one loop, a child that stops reading its stdin would block the
	// reader forever on a pipe write, and it could never forward TSig or
	// notice a disconnect. The reader hands frames to an unbounded queue, so
	// backpressure stays in the writer: it parks on a blocked pipe write (and
	// is unblocked on disconnect by stdin.Close()), while the reader keeps
	// handling signals. done cancels both helpers at teardown.
	done := make(chan struct{})
	queue := newStdinQueue(done)
	var stdinWg sync.WaitGroup
	stdinWg.Add(1)
	go func() { // stdin writer
		defer stdinWg.Done()
		for {
			data, open := queue.next()
			if !open {
				return
			}
			if data == nil { // EOF sentinel
				stdin.Close()
				return
			}
			if _, err := stdin.Write(data); err != nil {
				return
			}
		}
	}()
	go func() { // control reader
		for {
			f, err := proto.ReadFrame(c)
			if err != nil {
				// Disconnect: cancel the whole tree and unblock a stdin write
				// that is parked because the child stopped reading.
				syscall.Kill(pgid, syscall.SIGKILL)
				stdin.Close()
				return
			}
			switch f.Type {
			case proto.TSig:
				if len(f.Payload) >= 4 {
					syscall.Kill(pgid, decodeSignal(f.Payload))
				}
			case proto.TStdin:
				// nil is the EOF sentinel the writer recognises; a non-empty
				// payload is data.
				var data []byte
				if len(f.Payload) > 0 {
					data = f.Payload
				}
				queue.add(data)
			}
		}
	}()

	// Wait exactly once so the reported status is the real one. Wait does not
	// manage the stdout/stderr pipes, so it cannot drop their buffered output:
	// we drain both to EOF first, then report.
	_ = cmd.Wait()
	sess.commandFinished()
	pumps.Wait()
	send(proto.TExit, proto.ExitPayload(waitStatus(cmd)))
	close(done)
	stdinWg.Wait()
}

func (s *Server) execTTY(c net.Conn, req *proto.ExecReq, sess *session) {
	dir, ok := s.resolveCwd(c, req.Dir)
	if !ok {
		return
	}
	master, slave, err := pty.Open()
	if err != nil {
		proto.WriteFrame(c, proto.TErr, []byte("rsbxd: pty: "+err.Error()))
		proto.WriteFrame(c, proto.TExit, proto.ExitPayload(127))
		return
	}
	defer master.Close()
	_ = pty.SetWinsize(master, req.Rows, req.Cols)

	cmd := s.build(req, dir)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	// A pty session is its own session, with the pty slave as controlling
	// terminal. That makes it the session (and process group) leader, so
	// signalling -pid reaches the whole tree.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	sess.commandStarted()
	if err := cmd.Start(); err != nil {
		sess.commandFinished()
		slave.Close()
		proto.WriteFrame(c, proto.TErr, []byte(fmt.Sprintf("rsbxd: exec %s: %v", req.Target, err)))
		proto.WriteFrame(c, proto.TExit, proto.ExitPayload(127))
		return
	}
	slave.Close()

	var wmu sync.Mutex
	send := func(typ byte, p []byte) bool {
		wmu.Lock()
		defer wmu.Unlock()
		return proto.WriteFrame(c, typ, p) == nil
	}
	send(proto.TReady, nil)

	// Pump the pty output to the client. EIO marks the child's natural exit:
	// the controlling terminal hangs up when its session leader dies.
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		buf := make([]byte, 32<<10)
		for {
			n, err := master.Read(buf)
			if n > 0 && !send(proto.TTty, buf[:n]) {
				// A failed send is a cancel: take the whole tree down.
				syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				return
			}
			if err != nil {
				return
			}
		}
	}()

	// Handle input, resizes and signals until the connection goes away. A
	// disconnect kills the tree so nothing outlives the session.
	go func() {
		for {
			f, err := proto.ReadFrame(c)
			if err != nil {
				syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				return
			}
			switch f.Type {
			case proto.TTty, proto.TStdin:
				if _, err := master.Write(f.Payload); err != nil {
					syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					return
				}
			case proto.TWinch:
				if len(f.Payload) >= 4 {
					rows := uint16(f.Payload[0])<<8 | uint16(f.Payload[1])
					cols := uint16(f.Payload[2])<<8 | uint16(f.Payload[3])
					_ = pty.SetWinsize(master, rows, cols)
				}
			case proto.TSig:
				if len(f.Payload) >= 4 {
					syscall.Kill(-cmd.Process.Pid, decodeSignal(f.Payload))
				}
			}
		}
	}()

	// Wait for the child to exit naturally, then let the pump observe the
	// hangup and drain the last bytes before reporting the real status.
	_ = cmd.Wait()
	sess.commandFinished()
	<-pumpDone
	send(proto.TExit, proto.ExitPayload(waitStatus(cmd)))
}

// decodeSignal reads the 4-byte big-endian i32 signal id in a TSig frame.
func decodeSignal(p []byte) syscall.Signal {
	return syscall.Signal(int32(p[0])<<24 | int32(p[1])<<16 | int32(p[2])<<8 | int32(p[3]))
}

// stdinQueue is an unbounded FIFO of stdin frames between the control reader
// and the stdin writer. It is deliberately unbounded: the writer parks on a
// blocked pipe write, so queueing is where backpressure lives, and an
// unbounded queue keeps the reader free to serve TSig and detect a disconnect
// no matter how much data the child has stopped consuming. next reports
// open=false once done closes, which releases a parked writer.
type stdinQueue struct {
	cond   *sync.Cond
	q      [][]byte
	closed bool
}

func newStdinQueue(done <-chan struct{}) *stdinQueue {
	q := &stdinQueue{cond: sync.NewCond(&sync.Mutex{})}
	go func() {
		<-done
		q.cond.L.Lock()
		q.closed = true
		q.cond.L.Unlock()
		q.cond.Broadcast()
	}()
	return q
}

func (q *stdinQueue) add(data []byte) {
	q.cond.L.Lock()
	if !q.closed {
		q.q = append(q.q, data)
	}
	q.cond.L.Unlock()
	q.cond.Broadcast()
}

func (q *stdinQueue) next() (data []byte, open bool) {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()
	for len(q.q) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.q) == 0 {
		return nil, false
	}
	data = q.q[0]
	q.q = q.q[1:]
	return data, true
}

// waitStatus reports the exit code, or 128+signal when the child was killed.
func waitStatus(cmd *exec.Cmd) int {
	if cmd.ProcessState == nil {
		return 127
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return cmd.ProcessState.ExitCode()
}
