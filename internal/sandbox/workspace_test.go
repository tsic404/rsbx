package sandbox

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"rsbx/internal/rpc"
)

// A declared workspace replaces the caller's own working directory: the
// session starts at the path in the daemon's tree, not wherever rsbx happened
// to be launched from.
func TestWorkspaceBecomesSessionStartDir(t *testing.T) {
	plan, dir := testPlan(t, []string{"/bin/sh"}, nil)
	ws := filepath.Join(dir, "daemon-tree", "tasks", "17")
	if err := plan.SetWorkspace(ws, ""); err != nil {
		t.Fatal(err)
	}
	got, err := plan.startDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != ws {
		t.Fatalf("start directory = %s, want %s", got, ws)
	}
}

// A workspace inside a tree this machine declares local is local content, so
// remote commands could not reach it; the declaration is refused.
func TestWorkspaceRejectsLocalTree(t *testing.T) {
	private := t.TempDir()
	plan, _ := testPlan(t, []string{"/bin/sh"}, []string{private})
	if err := plan.SetWorkspace(filepath.Join(private, "ws"), ""); err == nil {
		t.Fatal("workspace inside a local tree accepted")
	}
}

// A seed living in a local tree is private material; it must not travel
// through the initialization channel.
func TestWorkspaceRejectsPrivateSeed(t *testing.T) {
	private := t.TempDir()
	if err := os.WriteFile(filepath.Join(private, "private.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, _ := testPlan(t, []string{"/bin/sh"}, []string{private})
	if err := plan.SetWorkspace(filepath.Join(t.TempDir(), "ws"), private); err == nil {
		t.Fatal("private seed accepted")
	}
}

// Reserved paths are session facilities or kernel views, not daemon content:
// a workspace cannot be created there.
func TestWorkspaceRejectsReservedPaths(t *testing.T) {
	plan, _ := testPlan(t, []string{"/bin/sh"}, nil)
	for _, path := range []string{
		BrokerDir + "/ws",
		HelperDir + "/ws",
		"/proc/ws",
		"/dev/ws",
	} {
		if err := plan.SetWorkspace(path, ""); err == nil {
			t.Errorf("reserved path %s accepted as a workspace", path)
		}
	}
}

// A daemon that accepts the connection and then stops answering must not hold
// the start open: cancelling the session closes the transport, which releases
// the pending request, and the initialization returns.
func TestEnsureWorkspaceReturnsWhenSessionIsCancelled(t *testing.T) {
	dir := tempDirOutsideTmp(t)
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		close(accepted)
		go func() {
			defer c.Close()
			if _, err := c.Read(make([]byte, 1)); err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, c)
			close(closed)
		}()
	}()
	plan, _ := testPlan(t, []string{"/bin/sh"}, nil)
	plan.Remote = rpc.NewFS(rpc.Target{Socket: sock})
	t.Cleanup(func() { _ = plan.Remote.Close() })
	if err := plan.SetWorkspace(filepath.Join(dir, "daemon-tree", "tasks", "17"), ""); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- plan.EnsureWorkspace(ctx) }()
	select {
	case <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("initialization never reached the daemon")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("initialization returned %v, want cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("initialization did not return after cancellation")
	}
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("session transport was not closed")
	}
}
