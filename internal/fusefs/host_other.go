//go:build !linux

package fusefs

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"rsbx/internal/proto"
)

// Production uses Linux O_PATH pins. The development-host form retains a
// rooted parent descriptor and refuses an inode replacement before applying
// any writable operation; it never falls back to an unrooted host pathname.
func openHostDirectory(filename string) (*os.File, error) {
	fd, err := unix.Open(filename, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), filename), nil
}

func openHostDirectoryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func pinHostAt(parent *os.File, name string) (*hostObject, error) {
	root, err := duplicateFile(parent)
	if err != nil {
		return nil, err
	}
	h := &hostObject{parent: root, name: name}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err == nil {
		h.file = os.NewFile(uintptr(fd), name)
		fi, err := h.file.Stat()
		if err != nil {
			h.close()
			return nil, err
		}
		h.attr = hostAttr(fi)
		return h, nil
	}
	if err != syscall.ELOOP {
		h.close()
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		h.close()
		return nil, err
	}
	buf := make([]byte, int(st.Size)+1)
	n, err := unix.Readlinkat(int(parent.Fd()), name, buf)
	if err != nil {
		h.close()
		return nil, err
	}
	h.link = string(buf[:n])
	h.attr = proto.Attr{Mode: proto.SIFLNK | 0o777, Size: uint64(n), Ino: uint64(st.Ino), Dev: uint64(st.Dev), Nlink: uint32(st.Nlink)}
	return h, nil
}

func reopenHost(h *hostObject, flags uint32) (*os.File, error) {
	if flags&uint32(syscall.O_ACCMODE) == uint32(os.O_RDONLY) && flags&uint32(os.O_TRUNC|os.O_APPEND) == 0 {
		return duplicateFile(h.file)
	}
	fd, err := unix.Openat(int(h.parent.Fd()), h.name, int(flags)&^syscall.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), h.name)
	fi, err := f.Stat()
	if err != nil || !sameIdentity(h.attr, hostAttr(fi)) {
		f.Close()
		if err != nil {
			return nil, err
		}
		return nil, syscall.ESTALE
	}
	if flags&uint32(os.O_TRUNC) != 0 {
		if err := f.Truncate(0); err != nil {
			f.Close()
			return nil, err
		}
	}
	return f, nil
}

func linkHost(h *hostObject, parent *os.File, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.parent == nil {
		return syscall.EBADF
	}
	if err := unix.Linkat(int(h.parent.Fd()), h.name, int(parent.Fd()), name, 0); err != nil {
		return err
	}
	linked, err := pinHostAt(parent, name)
	if err != nil {
		return err
	}
	defer linked.close()
	if !sameIdentity(h.attr, linked.attr) {
		unix.Unlinkat(int(parent.Fd()), name, 0)
		return syscall.ESTALE
	}
	return nil
}

func chmodHost(h *hostObject, mode uint32) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.file == nil {
		return syscall.EBADF
	}
	return h.file.Chmod(os.FileMode(mode & 0o7777))
}

func chownHost(h *hostObject, uid, gid int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.file == nil {
		return syscall.EBADF
	}
	return h.file.Chown(uid, gid)
}

func fillHostTimes(a *proto.Attr, st *syscall.Stat_t) {
	a.Atime, a.AtimeNsec = st.Atimespec.Sec, uint32(st.Atimespec.Nsec)
	a.Mtime, a.MtimeNsec = st.Mtimespec.Sec, uint32(st.Mtimespec.Nsec)
	a.Ctime, a.CtimeNsec = st.Ctimespec.Sec, uint32(st.Ctimespec.Nsec)
}
