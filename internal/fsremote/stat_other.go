//go:build !linux

package fsremote

import (
	"os"
	"syscall"
)

// Non-Linux builds cannot exercise the real syscalls; these stubs exist so the
// package compiles for host-side tooling. The daemon itself runs on Linux, and
// operations needing them fail with ENOSYS at run time there rather than
// approximating the wire syscalls with something else.

const utimeOmit = (1 << 30) - 2 // UTIME_OMIT

func utimensatAt(fd int, path string, ts [2]syscall.Timespec) error { return syscall.ENOSYS }

func ofdGetlk(fd int, lk *syscall.Flock_t) error { return syscall.ENOSYS }

func ofdSetlk(fd int, lk *syscall.Flock_t) error { return syscall.ENOSYS }

func openLockFd(f *os.File) (int, bool, error) { return 0, false, syscall.ENOSYS }

// readDirHandle lists through the handle's own file. There is no /proc to
// obtain a fresh description from, so the handle's directory offset advances;
// listing is still complete on the first pass.
func readDirHandle(f *os.File) ([]os.DirEntry, error) {
	return f.ReadDir(-1)
}

func statTimes(st *syscall.Stat_t) (a, m, c syscall.Timespec) {
	return st.Atimespec, st.Mtimespec, st.Ctimespec
}

func statMode(st *syscall.Stat_t) uint32 { return uint32(st.Mode) }

func statDev(st *syscall.Stat_t) uint64 { return uint64(st.Dev) }

func statNlink(st *syscall.Stat_t) uint32 { return uint32(st.Nlink) }
