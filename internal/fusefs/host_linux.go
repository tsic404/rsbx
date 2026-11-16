//go:build linux

package fusefs

import (
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"rsbx/internal/proto"
)

func openHostDirectory(filename string) (*os.File, error) {
	fd, err := unix.Open(filename, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), filename), nil
}

func openHostDirectoryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func pinHostAt(parent *os.File, name string) (*hostObject, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	h := &hostObject{file: f, attr: hostAttr(fi)}
	if kind(h.attr.Mode) == proto.SIFLNK {
		buf := make([]byte, int(fi.Size())+1)
		n, err := unix.Readlinkat(fd, "", buf)
		if err != nil {
			f.Close()
			return nil, err
		}
		h.link = string(buf[:n])
	}
	return h, nil
}

func hostDescriptorPath(f *os.File) string {
	return "/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10)
}

func reopenHost(h *hostObject, flags uint32) (*os.File, error) {
	// O_NOFOLLOW applies to the selected host inode, not procfs's descriptor
	// symlink. This path is controller-owned and references only the pinned fd.
	f, err := os.OpenFile(hostDescriptorPath(h.file), int(flags)&^syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || !sameIdentity(h.attr, hostAttr(fi)) {
		f.Close()
		if err != nil {
			return nil, err
		}
		return nil, syscall.ESTALE
	}
	return f, nil
}

func linkHost(h *hostObject, parent *os.File, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.file == nil {
		return syscall.EBADF
	}
	return unix.Linkat(unix.AT_FDCWD, hostDescriptorPath(h.file), int(parent.Fd()), name, unix.AT_SYMLINK_FOLLOW)
}

func chmodHost(h *hostObject, mode uint32) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.file == nil {
		return syscall.EBADF
	}
	return os.Chmod(hostDescriptorPath(h.file), os.FileMode(mode&0o7777))
}

func chownHost(h *hostObject, uid, gid int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.file == nil {
		return syscall.EBADF
	}
	return unix.Fchownat(int(h.file.Fd()), "", uid, gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

func fillHostTimes(a *proto.Attr, st *syscall.Stat_t) {
	a.Atime, a.AtimeNsec = st.Atim.Sec, uint32(st.Atim.Nsec)
	a.Mtime, a.MtimeNsec = st.Mtim.Sec, uint32(st.Mtim.Nsec)
	a.Ctime, a.CtimeNsec = st.Ctim.Sec, uint32(st.Ctim.Nsec)
}
