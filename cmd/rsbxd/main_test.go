package main

import (
	"path/filepath"
	"testing"
)

// The daemon must be a single instance per socket path. Without a lock a
// second daemon could unlink the path, bind again, and leave two listeners
// where only the last one is reachable — which reads as an intermittent
// "daemon hangs" and is nearly impossible to see from the outside.
func TestLockInstanceAllowsOneHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.sock.lock")
	unlock, err := lockInstance(path)
	if err != nil {
		t.Fatalf("first holder refused: %v", err)
	}
	defer unlock()

	if unlock2, err := lockInstance(path); err == nil {
		// Release immediately so the second acquisition is not leaked.
		unlock2()
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

	unlock2, err := lockInstance(path)
	if err != nil {
		t.Fatalf("second holder refused after release: %v", err)
	}
	unlock2()
}
