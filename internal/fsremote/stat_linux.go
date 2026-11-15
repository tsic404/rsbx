//go:build linux

package fsremote

import (
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// Linux-only syscalls: utimensat with a descriptor, and raw fcntl OFD lock
// commands. They live behind a build tag because the constants and argument
// forms are Linux specific.

const (
	// utimeOmit is UTIME_OMIT: "keep what is there". Sent through the real
	// syscall so the prior value, including its nanoseconds, survives.
	utimeOmit = (1 << 30) - 2

	atEmptyPath = 0x1000 // AT_EMPTY_PATH

	// oPath is O_PATH: a descriptor that names a file without opening it. The
	// syscall package does not export the flag, but the kernel value is stable.
	oPath = 0x200000
)

// utimensatAt sets times either on a path (fd < 0) or through a descriptor
// with AT_EMPTY_PATH. The metadata follows the file itself: through a
// descriptor it belongs to the opened inode, not to whatever the name points
// at now. A trailing symlink is followed on the path form, as native
// utimensat(2) does by default.
var emptyPath = [1]byte{0}

func utimensatAt(fd int, path string, ts [2]syscall.Timespec) error {
	var dirfd uintptr
	var p uintptr
	var flags uintptr
	if fd < 0 {
		dirfd = ^uintptr(0) // AT_FDCWD
		ptr, err := syscall.BytePtrFromString(path)
		if err != nil {
			return err
		}
		p = uintptr(unsafe.Pointer(ptr))
	} else {
		// AT_EMPTY_PATH requires a pointer to an empty string, not a NULL
		// pathname: the kernel rejects NULL with EINVAL even though the
		// descriptor alone names the file.
		dirfd = uintptr(fd)
		p = uintptr(unsafe.Pointer(&emptyPath[0]))
		flags = atEmptyPath
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_UTIMENSAT, dirfd,
		p, uintptr(unsafe.Pointer(&ts[0])), flags, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// ofdGetlk asks which open file description lock, if any, conflicts. The
// kernel fills lk with the holder when one exists and leaves F_UNLCK when not.
func ofdGetlk(fd int, lk *syscall.Flock_t) error {
	return ofdFcntl(fd, 0x24 /* F_OFD_GETLK */, lk)
}

// ofdSetlk takes or drops one OFD lock without waiting.
func ofdSetlk(fd int, lk *syscall.Flock_t) error {
	return ofdFcntl(fd, 0x25 /* F_OFD_SETLK */, lk)
}

// ofdFcntl performs one fcntl flock command on a raw descriptor.
func ofdFcntl(fd int, cmd uint32, lk *syscall.Flock_t) error {
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(cmd), uintptr(unsafe.Pointer(lk)))
	if errno != 0 {
		return errno
	}
	return nil
}

// openLockFd returns a fresh description of the same inode for locking. The
// fd-anchored /proc/self/fd path names the descriptor's own file even after
// its name was renamed or unlinked; the description is independent, so closing
// one handle does not release locks the owner still holds through another.
//
// The second return reports whether the description is writable, which a write
// lock requires. An O_PATH description is the last resort (a write-only file
// or one this process may open neither read-write nor read-only): it still
// carries the OFD lock identity, and the caller refuses write locks through
// it.
func openLockFd(f *os.File) (int, bool, error) {
	var st, st2 syscall.Stat_t
	fd := int(f.Fd())
	if err := syscall.Fstat(fd, &st); err != nil {
		return 0, false, err
	}
	// A write lock needs a writable description, and a read-only handle must
	// refuse one exactly as fcntl on that descriptor would.
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
	if errno != 0 {
		return 0, false, errno
	}
	writable := int(flags)&syscall.O_ACCMODE != syscall.O_RDONLY
	openFlags := syscall.O_RDONLY
	if writable {
		openFlags = syscall.O_RDWR
	}
	path := "/proc/self/fd/" + strconv.Itoa(fd)
	lf, err := syscall.Open(path, openFlags|syscall.O_CLOEXEC, 0)
	if err != nil {
		// Directories cannot be reopened read-write. An O_PATH description
		// still names the same inode and carries OFD locks; write locks are
		// refused through it.
		writable = false
		if lf, err = syscall.Open(path, oPath|syscall.O_CLOEXEC, 0); err != nil {
			return 0, false, err
		}
	}
	if err := syscall.Fstat(lf, &st2); err != nil {
		syscall.Close(lf)
		return 0, false, err
	}
	if uint64(st2.Ino) != uint64(st.Ino) || uint64(st2.Dev) != uint64(st.Dev) {
		syscall.Close(lf)
		return 0, false, syscall.EINVAL
	}
	return lf, writable, nil
}

// readDirHandle lists the directory the descriptor names through a fresh
// description of the same inode, so the handle's own read offset is untouched.
func readDirHandle(f *os.File) ([]os.DirEntry, error) {
	d, err := syscall.Open("/proc/self/fd/"+strconv.Itoa(int(f.Fd())), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	df := os.NewFile(uintptr(d), "")
	defer df.Close()
	return df.ReadDir(-1)
}

// statTimes returns the native atime, mtime and ctime of a stat, nanoseconds
// included.
func statTimes(st *syscall.Stat_t) (a, m, c syscall.Timespec) {
	return st.Atim, st.Mtim, st.Ctim
}

// statMode returns the full mode with type bits, used verbatim on the wire so
// the Linux type bits survive the round trip.
func statMode(st *syscall.Stat_t) uint32 { return st.Mode }

// statDev returns the device the inode lives on. Together with Ino it is the
// stable identity FUSE reports, because the daemon's / spans filesystems.
func statDev(st *syscall.Stat_t) uint64 { return uint64(st.Dev) }

// statNlink returns the hard link count.
func statNlink(st *syscall.Stat_t) uint32 { return uint32(st.Nlink) }
