//go:build linux && (amd64 || arm64)

package sandbox

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"rsbx/internal/proto"
)

func TestReverseTargetRequiresAbsoluteAllowedPath(t *testing.T) {
	spec := &launchSpec{ReverseAllow: []string{"/usr/bin/env", "/usr/bin/env2", "/home/tsic/rsbx-itest/agent-bin/multica"}}
	if _, err := reverseTarget(spec, &proto.ExecReq{Target: "env", Argv: []string{"env"}}); err == nil || !strings.Contains(err.Error(), "not in local.allow") {
		t.Fatalf("bare command was accepted: %v", err)
	}
	if target, err := reverseTarget(spec, &proto.ExecReq{Target: "/usr/bin/env", Argv: []string{"env"}}); err != nil || target != "/usr/bin/env" {
		t.Fatalf("allowed absolute command failed: target=%q err=%v", target, err)
	}
	if _, err := reverseTarget(spec, &proto.ExecReq{Target: "/usr/bin/../bin/env", Argv: []string{"env"}}); err != nil {
		t.Fatalf("normalized allowed command failed: %v", err)
	}
	if _, err := reverseTarget(spec, &proto.ExecReq{Target: "/usr/bin/missing", Argv: []string{"missing"}}); err == nil {
		t.Fatal("unlisted absolute command was accepted")
	}
}

func TestReverseTargetRejectsUnsafeInputs(t *testing.T) {
	spec := &launchSpec{ReverseAllow: []string{"/bin/sh"}}
	for _, test := range []proto.ExecReq{
		{Target: "/bin/sh", Argv: []string{"sh"}, TTY: true},
		{Target: "/bin/sh", Argv: []string{"sh"}, Env: []string{"LD_PRELOAD=/tmp/x.so"}},
		{Target: "/bin/sh", Argv: []string{"sh"}, Dir: "relative"},
		{Target: "/bin/sh", Argv: []string{"sh", "a\x00b"}},
	} {
		if _, err := reverseTarget(spec, &test); err == nil {
			t.Fatalf("unsafe request accepted: %+v", test)
		}
	}
}

func TestReverseListenerRejectsBadTokenAndDeniesUnknownCommand(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	jobs := make(chan reverseJob, 1)
	server := newReverseListener(listener, strings.Repeat("a", 64), jobs)
	defer server.Close()
	go func() {
		job := <-jobs
		_, targetErr := reverseTarget(&launchSpec{ReverseAllow: []string{"/bin/sh"}}, job.request)
		job.reply <- reverseResult{err: targetErr}
	}()
	client := &ReverseClient{Address: listener.Addr().String(), Token: strings.Repeat("a", 64)}
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	done := make(chan error, 1)
	go func() {
		done <- client.RunLocal(context.Background(), &proto.ExecReq{Target: "/bin/echo", Argv: []string{"echo"}}, local)
	}()
	frame, err := proto.ReadFrame(peer)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != proto.TErr || !strings.Contains(string(frame.Payload), "not in local.allow") {
		t.Fatalf("unexpected denial: %q", frame.Payload)
	}
	frame, err = proto.ReadFrame(peer)
	if err != nil || frame.Type != proto.TExit {
		t.Fatalf("denial was not followed by exit status: %v %#x", err, frame.Type)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	bad := &ReverseClient{Address: listener.Addr().String(), Token: strings.Repeat("b", 64)}
	local2, peer2 := net.Pipe()
	defer local2.Close()
	defer peer2.Close()
	go func() {
		bad.RunLocal(context.Background(), &proto.ExecReq{Target: "/bin/sh", Argv: []string{"sh"}}, local2)
	}()
	frame, err = proto.ReadFrame(peer2)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != proto.TErr || !strings.Contains(string(frame.Payload), "invalid session capability") {
		t.Fatalf("bad token accepted: %q", frame.Payload)
	}
	frame, err = proto.ReadFrame(peer2)
	if err != nil || frame.Type != proto.TExit {
		t.Fatalf("bad-token denial was not followed by exit status: %v %#x", err, frame.Type)
	}
}

func TestBridgeReverseKeepsOutputBeforeExitFrame(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdoutR.Close()
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stderrR.Close()
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdinR.Close()
	defer stdinW.Close()

	status := make(chan int, 1)
	status <- 0
	// The bridge kills the child's process group when it finishes, so the pid
	// has to name a disposable process rather than this test.
	child := exec.Command("/bin/sh", "-c", "sleep 30")
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	go bridgeReverse(serverConn, reverseResult{
		stdout: stdoutR,
		stderr: stderrR,
		stdin:  stdinW,
		status: status,
		pid:    child.Process.Pid,
	})

	stdoutW.WriteString("final-output\n")
	stdoutW.Close()
	stderrW.Close()

	sawOutput := false
	for {
		frame, err := proto.ReadFrame(clientConn)
		if err != nil {
			t.Fatalf("closed before exit frame after output: %v", err)
		}
		if frame.Type == proto.TStdout {
			sawOutput = true
			continue
		}
		if frame.Type != proto.TExit {
			continue
		}
		if !sawOutput {
			t.Fatal("exit frame arrived before final stdout")
		}
		return
	}
}
