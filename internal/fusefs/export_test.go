package fusefs

import (
	"os"
	"syscall"
)

// setFdLock takes one POSIX (OFD) range lock on a host fd. Whole-file locks
// are Start 0, Len 0, Whence SEEK_SET.
func setFdLock(f *os.File, lk *syscall.Flock_t) error {
	return syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, lk)
}
