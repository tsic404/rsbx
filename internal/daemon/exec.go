// Package daemon implements the remote side: it runs processes and owns the
// remote filesystem tree.
package daemon

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"rsbx/internal/proto"
	"rsbx/internal/pty"
)

// Server serves exec sessions and filesystem requests for one remote root.
type Server struct {
	Root string
	// Logf is optional.
	Logf func(format string, args ...any)
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
	case proto.TFxReq:
		s.serveFS(c, f)
	default:
		s.logf("rsbxd: unexpected opening frame %#x", f.Type)
	}
}

// resolve maps an absolute sandbox path to the daemon root.
func (s *Server) resolve(p string) string {
	clean := filepath.Clean("/" + p)
	if clean == "/" {
		return s.Root
	}
	return filepath.Join(s.Root, clean)
}

func (s *Server) serveExec(c net.Conn, payload []byte) {
	req, err := proto.DecodeExecReq(payload)
	if err != nil || len(req.Argv) == 0 {
		proto.WriteFrame(c, proto.TErr, []byte("rsbxd: bad exec request"))
		return
	}
	dir := s.resolve(req.Dir)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		dir = s.Root
	}
	if req.TTY {
		s.execTTY(c, req, dir)
		return
	}
	s.execPipes(c, req, dir)
}

// build constructs the child command. The child sees s.Root as "/", so a path
// the client sends means the same thing on both sides. bwrap provides that
// view; without it the daemon would have to translate every argument.
func (s *Server) build(req *proto.ExecReq, dir string) *exec.Cmd {
	var cmd *exec.Cmd
	if jail, err := s.jail(req); err == nil {
		cmd = jail
	} else {
		cmd = exec.Command(req.Argv[0], req.Argv[1:]...)
		cmd.Dir = dir
	}
	env := req.Env
	if len(env) == 0 {
		env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/", "TERM=xterm-256color"}
	}
	cmd.Env = env
	return cmd
}

// jail wraps argv in a bwrap invocation that makes Root the child's /.
func (s *Server) jail(req *proto.ExecReq) (*exec.Cmd, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, err
	}
	args := []string{
		"--bind", s.Root, "/",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
	}
	// the toolchain the remote side needs to run anything at all
	for _, d := range []string{"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"} {
		args = append(args, "--ro-bind-try", d, d)
	}
	if req.Dir != "" {
		args = append(args, "--chdir", req.Dir)
	}
	args = append(args, "--die-with-parent")
	args = append(args, req.Argv...)
	return exec.Command(bwrap, args...), nil
}

func (s *Server) execPipes(c net.Conn, req *proto.ExecReq, dir string) {
	cmd := s.build(req, dir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		proto.WriteFrame(c, proto.TErr, []byte(err.Error()))
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		proto.WriteFrame(c, proto.TErr, []byte(err.Error()))
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		proto.WriteFrame(c, proto.TErr, []byte(err.Error()))
		return
	}
	if err := cmd.Start(); err != nil {
		proto.WriteFrame(c, proto.TErr, []byte(fmt.Sprintf("rsbxd: exec %s: %v", req.Argv[0], err)))
		proto.WriteFrame(c, proto.TExit, proto.ExitPayload(127))
		return
	}
	var wmu sync.Mutex
	send := func(typ byte, p []byte) {
		wmu.Lock()
		proto.WriteFrame(c, typ, p)
		wmu.Unlock()
	}
	send(proto.TReady, nil)

	var wg sync.WaitGroup
	wg.Add(2)
	pump := func(r io.Reader, typ byte) {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				send(typ, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}
	go pump(stdout, proto.TStdout)
	go pump(stderr, proto.TStderr)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			f, err := proto.ReadFrame(c)
			if err != nil {
				stdin.Close()
				return
			}
			switch f.Type {
			case proto.TStdin:
				if len(f.Payload) == 0 {
					stdin.Close()
					continue
				}
				if _, err := stdin.Write(f.Payload); err != nil {
					return
				}
			case proto.TSig:
				if len(f.Payload) >= 4 {
					_ = cmd.Process.Signal(syscall.Signal(int(int32(f.Payload[0]))))
				}
			}
		}
	}()
	wg.Wait()
	status := waitStatus(cmd)
	wmu.Lock()
	proto.WriteFrame(c, proto.TExit, proto.ExitPayload(status))
	wmu.Unlock()
	// give the reader goroutine a moment to notice the closed socket rather
	// than tearing the connection down from under a pending write
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
	}
}

func (s *Server) execTTY(c net.Conn, req *proto.ExecReq, dir string) {
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
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		slave.Close()
		proto.WriteFrame(c, proto.TErr, []byte(fmt.Sprintf("rsbxd: exec %s: %v", req.Argv[0], err)))
		proto.WriteFrame(c, proto.TExit, proto.ExitPayload(127))
		return
	}
	slave.Close()

	var wmu sync.Mutex
	send := func(typ byte, p []byte) {
		wmu.Lock()
		proto.WriteFrame(c, typ, p)
		wmu.Unlock()
	}
	send(proto.TReady, nil)

	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				send(proto.TTty, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	for {
		f, err := proto.ReadFrame(c)
		if err != nil {
			_ = cmd.Process.Signal(syscall.SIGKILL)
			break
		}
		switch f.Type {
		case proto.TTty, proto.TStdin:
			if _, err := master.Write(f.Payload); err != nil {
				_ = cmd.Process.Signal(syscall.SIGKILL)
			}
		case proto.TWinch:
			if len(f.Payload) >= 4 {
				rows := uint16(f.Payload[0])<<8 | uint16(f.Payload[1])
				cols := uint16(f.Payload[2])<<8 | uint16(f.Payload[3])
				_ = pty.SetWinsize(master, rows, cols)
			}
		case proto.TSig:
			if len(f.Payload) >= 4 {
				sig := syscall.Signal(int32(f.Payload[0])<<24>>24 | int32(f.Payload[1])<<16 | int32(f.Payload[2])<<8 | int32(f.Payload[3]))
				_ = cmd.Process.Signal(sig)
			}
		}
	}
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			s.logf("rsbxd: wait: %v", err)
		}
	}
	status := waitStatus(cmd)
	wmu.Lock()
	proto.WriteFrame(c, proto.TExit, proto.ExitPayload(status))
	wmu.Unlock()
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
