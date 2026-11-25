package syserrno

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
)

// A call that already names its errno must report that value. Mapping EINVAL
// onto EIO is what made a malformed lock length look like a broken disk.
func TestOfKeepsTheErrnoTheErrorCarries(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want syscall.Errno
	}{
		{"bare errno", syscall.EINVAL, syscall.EINVAL},
		{"syscall error", os.NewSyscallError("fcntl", syscall.EINVAL), syscall.EINVAL},
		{"path error", &os.PathError{Op: "open", Path: "x", Err: syscall.EACCES}, syscall.EACCES},
		{"wrapped", fmt.Errorf("lock: %w", syscall.EINVAL), syscall.EINVAL},
		{"double wrapped", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", syscall.ENOSPC)), syscall.ENOSPC},
		{"fs not exist", os.ErrNotExist, syscall.ENOENT},
		// The text says one thing and the wrapped errno another: only reading
		// the errno itself gives the right answer here.
		{"text disagrees with the errno", fmt.Errorf("lock: permission denied: %w", syscall.EAGAIN), syscall.EAGAIN},
	}
	for _, c := range cases {
		if got := Of(c.err); got != c.want {
			t.Errorf("%s: Of(%v) = %v, want %v", c.name, c.err, got, c.want)
		}
	}
}

// Only an error that carries no errno falls back to the text.
func TestOfTextIsTheLastResort(t *testing.T) {
	if got := Of(errors.New("open x: invalid argument")); got != syscall.EINVAL {
		t.Fatalf("text-only EINVAL = %v, want EINVAL", got)
	}
	if got := Of(errors.New("something else entirely")); got != syscall.EIO {
		t.Fatalf("unknown text = %v, want EIO", got)
	}
}
