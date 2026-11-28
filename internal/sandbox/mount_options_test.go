package sandbox

import (
	"testing"
	"time"

	"rsbx/internal/fusefs"
)

// The cache boundaries a caller can observe are part of the contract, so they
// are pinned here rather than left to whatever a future edit happens to pass.
func TestMountOptionsKeepOneSecondWindow(t *testing.T) {
	opts := mountOptions()

	// The windows are decided per source by the filesystem: a local tree is kept
	// by the kernel for one second, and a daemon-derived result is retained by the
	// view so it can be dropped on a disconnect. A mount-wide value would be
	// substituted into every reply that leaves the field at zero, which would
	// cache daemon-derived answers in the kernel where a lost connection cannot
	// invalidate them, so both options must stay unset.
	if opts.EntryTimeout != nil {
		t.Fatalf("EntryTimeout = %v, want unset so a per-name zero survives", *opts.EntryTimeout)
	}
	if fusefs.EntryRetention != time.Second {
		t.Fatalf("EntryRetention = %v, want one second", fusefs.EntryRetention)
	}
	if opts.AttrTimeout != nil {
		t.Fatalf("AttrTimeout = %v, want unset so a daemon-derived attribute set is not kernel-cached", *opts.AttrTimeout)
	}
	// A nil negative timeout is go-fuse's "never remember a miss"; the explicit
	// zero records that the absence is a decision, not an oversight.
	if opts.NegativeTimeout == nil {
		t.Fatal("NegativeTimeout unset: a miss must be recorded as deliberately uncached")
	}
	if *opts.NegativeTimeout != 0 {
		t.Fatalf("NegativeTimeout = %v, want zero (a miss is never remembered)", *opts.NegativeTimeout)
	}
	if !opts.MountOptions.EnableLocks {
		t.Fatal("EnableLocks off: locks would be arbitrated in the client instead of the daemon")
	}
}
