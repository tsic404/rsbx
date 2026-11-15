package main

import (
	"path/filepath"
	"testing"
)

// The daemon has to be a single instance per socket. Two daemons sharing one
// socket path race for every connection, so a client stalls whenever its
// connection lands on the wrong one — which is nearly impossible to see from
// the outside and reads as a hang.
func TestLockInstanceAllowsOneHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.sock.lock")
	unlock, err := lockInstance(path)
	if err != nil {
		t.Fatalf("first holder refused: %v", err)
	}
	defer unlock()

	if _, err := lockInstance(path); err == nil {
		t.Fatal("a second holder acquired the same lock")
	}
}

// After the first holder releases, another daemon may start. The lock has to
// follow the process, not the path.
func TestLockInstanceReleasedOnUnlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.sock.lock")
	unlock, err := lockInstance(path)
	if err != nil {
		t.Fatalf("first holder refused: %v", err)
	}
	unlock()

	if _, err := lockInstance(path); err != nil {
		t.Fatalf("second holder refused after release: %v", err)
	}
}
