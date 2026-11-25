package lockrange

import (
	"math"
	"syscall"
	"testing"
)

// A range that reaches the end of the file becomes a zero length, the
// kernel's own spelling; deriving a length from those ends overflows.
func TestToFlockWholeFileNeverOverflows(t *testing.T) {
	for _, end := range []uint64{math.MaxInt64, ^uint64(0)} {
		fl, err := ToFlock(syscall.F_WRLCK, 0, end)
		if err != nil {
			t.Fatalf("end=%d: %v", end, err)
		}
		if fl.Len != 0 {
			t.Fatalf("end=%d: len=%d, want 0 (to the end of the file)", end, fl.Len)
		}
		if fl.Start != 0 || fl.Type != syscall.F_WRLCK {
			t.Fatalf("end=%d: %+v", end, fl)
		}
	}
}

func TestToFlockPartialRangeIsInclusive(t *testing.T) {
	fl, err := ToFlock(syscall.F_RDLCK, 10, 109)
	if err != nil {
		t.Fatal(err)
	}
	if fl.Start != 10 || fl.Len != 100 {
		t.Fatalf("start=%d len=%d, want 10/100", fl.Start, fl.Len)
	}
	one, err := ToFlock(syscall.F_RDLCK, 7, 7)
	if err != nil || one.Len != 1 {
		t.Fatalf("single byte: len=%d err=%v, want 1", one.Len, err)
	}
}

func TestToFlockRejectsRangesTheKernelCannotExpress(t *testing.T) {
	if _, err := ToFlock(syscall.F_WRLCK, 10, 5); err != syscall.EINVAL {
		t.Fatalf("end before start: %v, want EINVAL", err)
	}
	if _, err := ToFlock(syscall.F_WRLCK, math.MaxInt64+1, math.MaxInt64+1); err != syscall.EINVAL {
		t.Fatalf("start beyond int64: %v, want EINVAL", err)
	}
}

func TestEndSpellsEndOfFileAsTheMaximum(t *testing.T) {
	if got := End(0, 0); got != ^uint64(0) {
		t.Fatalf("zero length = %d, want the maximum", got)
	}
	if got := End(0, 100); got != 99 {
		t.Fatalf("[0,100) = %d, want 99", got)
	}
	if got := End(5, 1); got != 5 {
		t.Fatalf("single byte at 5 = %d, want 5", got)
	}
}

// A reply must never spell end-of-file as the protocol's maximum: the kernel
// checks a conflicting lock's end against OFFSET_MAX and answers EIO beyond it.
func TestReplyEndStaysWithinTheKernelMaximum(t *testing.T) {
	for _, end := range []uint64{^uint64(0), math.MaxInt64, math.MaxInt64 + 1} {
		if got := ReplyEnd(end); got != math.MaxInt64 {
			t.Fatalf("reply end for %d = %d, want %d", end, got, uint64(math.MaxInt64))
		}
	}
	if got := ReplyEnd(99); got != 99 {
		t.Fatalf("reply end for a bounded range = %d, want 99", got)
	}
	if got := ReplyEnd(0); got != 0 {
		t.Fatalf("reply end for a single byte = %d, want 0", got)
	}
}
