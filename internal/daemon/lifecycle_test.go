package daemon

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"rsbx/internal/proto"
)

// runClient drives one exec session over a pipe pair and returns the frames
// the daemon sends, in order. onReady runs once TReady arrives, so a test can
// act on a started child without competing for the read side.
func runClient(t *testing.T, req *proto.ExecReq, onReady func(d net.Conn)) ([]proto.Frame, error) {
	t.Helper()
	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()
	done := make(chan []proto.Frame, 1)
	go func() {
		var frames []proto.Frame
		for {
			f, err := proto.ReadFrame(d)
			if err != nil {
				done <- frames
				return
			}
			frames = append(frames, f)
			if f.Type == proto.TReady && onReady != nil {
				// Write from a separate goroutine: the pipe is synchronous, so
				// writing here would deadlock against this reader.
				go onReady(d)
			}
			if f.Type == proto.TExit {
				done <- frames
				return
			}
		}
	}()
	errc := make(chan error, 1)
	go func() {
		if err := proto.WriteFrame(d, proto.TExec, req.Encode()); err != nil {
			errc <- err
		}
	}()
	(&Server{}).ServeConn(c)
	frames := <-done
	select {
	case err := <-errc:
		return frames, err
	default:
		return frames, nil
	}
}

func exitStatus(frames []proto.Frame) (int, bool) {
	for _, f := range frames {
		if f.Type == proto.TExit {
			return proto.ParseExit(f.Payload), true
		}
	}
	return 0, false
}

func frameType(frames []proto.Frame, typ byte) bool {
	for _, f := range frames {
		if f.Type == typ {
			return true
		}
	}
	return false
}

func sigFrame(sig syscall.Signal) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(int32(sig)))
	return b[:]
}

// A non-TTY child must report its real exit status. The old daemon never
// waited on the child, so /bin/true returned 127.
func TestExecPipesReportsRealStatus(t *testing.T) {
	frames, err := runClient(t, &proto.ExecReq{
		Argv: []string{"/bin/sh", "-c", "exit 42"},
	}, nil)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	code, ok := exitStatus(frames)
	if !ok || code != 42 {
		t.Fatalf("exit status = %d (found=%v), want 42", code, ok)
	}
}

// A signal is decoded and delivered to the child's process group, so a TERM
// the shell traps surfaces as that shell's exit code.
func TestSignalForwardedToProcessGroup(t *testing.T) {
	// TReady only means the process started; the trap is installed slightly
	// later. The child writes a file once its handler is live, so the signal
	// below is never a race against shell startup.
	ready := filepath.Join(t.TempDir(), "ready")
	script := "trap 'exit 7' TERM; : > " + ready + "; while :; do :; done"
	frames, err := runClient(t, &proto.ExecReq{
		Argv: []string{"/bin/sh", "-c", script},
	}, func(d net.Conn) {
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Errorf("child never installed its TERM trap")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		proto.WriteFrame(d, proto.TSig, sigFrame(syscall.SIGTERM))
	})
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	code, ok := exitStatus(frames)
	if !ok || code != 7 {
		t.Fatalf("exit status = %d (found=%v), want 7 (trapped TERM)", code, ok)
	}
}

// Dropping the connection cancels the child: nothing outlives the session.
func TestDisconnectKillsChild(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	c, d := net.Pipe()
	go func() {
		defer c.Close()
		req := &proto.ExecReq{
			Argv: []string{"/bin/sh", "-c", "echo $$ > " + pidFile + "; sleep 60"},
		}
		proto.WriteFrame(d, proto.TExec, req.Encode())
		// Wait for TReady, then the child has written its pid soon after.
		for {
			f, err := proto.ReadFrame(d)
			if err != nil {
				return
			}
			if f.Type == proto.TReady {
				break
			}
		}
		for range 200 {
			if _, err := os.Stat(pidFile); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		c.Close() // client hangs up
	}()
	(&Server{}).ServeConn(c) // returns when the daemon notices the hangup

	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	var pid int
	for _, ch := range pidBytes {
		if ch < '0' || ch > '9' {
			break
		}
		pid = pid*10 + int(ch-'0')
	}
	if pid == 0 {
		t.Fatalf("child pid not captured from %s", pidFile)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("child %d survived the disconnect", pid)
}

// A missing requested cwd fails the session instead of silently falling back
// to a guessed directory.
func TestCwdValidationNoFallback(t *testing.T) {
	frames, err := runClient(t, &proto.ExecReq{
		Argv: []string{"/bin/true"},
		Dir:  filepath.Join(t.TempDir(), "does-not-exist"),
	}, nil)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	if !frameType(frames, proto.TErr) {
		t.Fatalf("expected TErr for a missing cwd, got %v", frames)
	}
	code, ok := exitStatus(frames)
	if !ok || code != 127 {
		t.Fatalf("exit = %d (found=%v), want 127", code, ok)
	}
}

// A TTY child that exits naturally reports its real status instead of hanging
// on the open pty.
func TestTTYNaturalExit(t *testing.T) {
	frames, err := runClient(t, &proto.ExecReq{
		Argv: []string{"/bin/sh", "-c", "exit 5"},
		TTY:  true,
		Rows: 24,
		Cols: 80,
	}, nil)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	code, ok := exitStatus(frames)
	if !ok || code != 5 {
		t.Fatalf("tty exit status = %d (found=%v), want 5", code, ok)
	}
}

// The tail of stdout and stderr must survive the child's exit. The daemon
// hands the child plain pipes and drains them to EOF before reporting the
// exit status, so buffered output is flushed rather than discarded with the
// pipe readers at Wait time.
func TestOutputTailNotLost(t *testing.T) {
	const n = 2000
	frames, err := runClient(t, &proto.ExecReq{
		Argv: []string{"/bin/sh", "-c",
			"i=0; while [ $i -lt " + strconv.Itoa(n) + " ]; do echo out$i; echo err$i >&2; i=$((i+1)); done"},
	}, nil)
	if err != nil {
		t.Fatalf("session error: %v", err)
	}
	var gotOut, gotErr []byte
	for _, f := range frames {
		switch f.Type {
		case proto.TStdout:
			gotOut = append(gotOut, f.Payload...)
		case proto.TStderr:
			gotErr = append(gotErr, f.Payload...)
		}
	}
	// The last lines of both streams are the ones the old StdoutPipe/Wait
	// order dropped: Wait closed the readers while data was still buffered.
	wantLastOut := "out" + strconv.Itoa(n-1)
	wantLastErr := "err" + strconv.Itoa(n-1)
	if !strings.Contains(string(gotOut), wantLastOut) {
		t.Fatalf("stdout tail lost: %q not in last 200 bytes %q", wantLastOut, tailOf(gotOut, 200))
	}
	if !strings.Contains(string(gotErr), wantLastErr) {
		t.Fatalf("stderr tail lost: %q not in last 200 bytes %q", wantLastErr, tailOf(gotErr, 200))
	}
	if gotLines := strings.Count(string(gotOut), "\n"); gotLines != n {
		t.Fatalf("stdout lines = %d, want %d", gotLines, n)
	}
	if gotLines := strings.Count(string(gotErr), "\n"); gotLines != n {
		t.Fatalf("stderr lines = %d, want %d", gotLines, n)
	}
}

func tailOf(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}
