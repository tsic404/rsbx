//go:build linux

package pty

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

// isTerminal asks the terminal driver the same question the kernel answers for
// an interactive session: TCGETS succeeds only on a tty.
func isTerminal(f *os.File) bool {
	var t syscall.Termios
	return ioctl(f.Fd(), syscall.TCGETS, unsafe.Pointer(&t)) == nil
}

// Open must hand back a usable terminal pair. A master that is not a tty, or a
// slave still locked by TIOCSPTLCK, would fail at the first session instead of
// here, where the cause is named.
func TestOpenReturnsUsableTerminalPair(t *testing.T) {
	master, slave, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()

	if !isTerminal(master) {
		t.Error("master side is not a terminal")
	}
	if !isTerminal(slave) {
		t.Error("slave side is not a terminal")
	}
	if master.Fd() == slave.Fd() {
		t.Error("master and slave share one descriptor")
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(slave.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	// The slave must be a character device; a regular file here would mean the
	// pts path resolved to something else entirely.
	if st.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		t.Errorf("slave is not a character device: mode %o", st.Mode)
	}
}

// The window size a session reports is the one the caller set. Resize
// forwarding depends on this round trip: a terminal that answered zeroes would
// silently leave the remote program with the wrong geometry.
func TestSetWinsizeRoundTrip(t *testing.T) {
	master, slave, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()

	if err := SetWinsize(master, 40, 100); err != nil {
		t.Fatalf("set winsize: %v", err)
	}
	rows, cols := GetWinsize(master)
	if rows != 40 || cols != 100 {
		t.Fatalf("winsize = %dx%d, want 40x100", rows, cols)
	}
	// Both ends describe one terminal, so the slave sees the same geometry.
	rows, cols = GetWinsize(slave)
	if rows != 40 || cols != 100 {
		t.Fatalf("slave winsize = %dx%d, want 40x100", rows, cols)
	}
}

// A zero dimension means "not known", so the call leaves the current size
// alone rather than resizing the terminal to nothing.
func TestSetWinsizeIgnoresZero(t *testing.T) {
	master, slave, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()

	if err := SetWinsize(master, 24, 80); err != nil {
		t.Fatal(err)
	}
	if err := SetWinsize(master, 0, 0); err != nil {
		t.Fatalf("zero winsize reported an error: %v", err)
	}
	rows, cols := GetWinsize(master)
	if rows != 24 || cols != 80 {
		t.Fatalf("zero resize changed the geometry: %dx%d", rows, cols)
	}
}

// GetWinsize is called on whatever the caller passed as stdin, which is often
// a pipe or a file. It must answer zeroes instead of failing or blocking.
func TestGetWinsizeOnNonTerminal(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "not-a-terminal"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if rows, cols := GetWinsize(f); rows != 0 || cols != 0 {
		t.Fatalf("regular file reported a terminal size: %dx%d", rows, cols)
	}
}
