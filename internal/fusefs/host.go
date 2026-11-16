package fusefs

import (
	"errors"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"rsbx/internal/proto"
)

// hostObject is a metadata descriptor for one inode. It is never reopened by
// an unrooted sandbox pathname. Linux IO descriptors reopen this pin through
// /proc/self/fd, so replacing or removing the pathname cannot change its bytes.
type hostObject struct {
	mu     sync.Mutex
	file   *os.File
	parent *os.File // development-host fallback; Linux needs only the inode pin
	name   string
	attr   proto.Attr
	link   string
}

func duplicateFile(f *os.File) (*os.File, error) {
	if f == nil {
		return nil, syscall.EBADF
	}
	fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), f.Name()), nil
}

func (h *hostObject) stat() (proto.Attr, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.file == nil {
		if h.parent != nil && kind(h.attr.Mode) == proto.SIFLNK {
			return h.attr, nil
		}
		return proto.Attr{}, syscall.EBADF
	}
	fi, err := h.file.Stat()
	if err != nil {
		return proto.Attr{}, err
	}
	a := hostAttr(fi)
	if kind(a.Mode) == proto.SIFLNK {
		a.Size = uint64(len(h.link))
	}
	return a, nil
}

func (h *hostObject) open(flags uint32) (*os.File, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if kind(h.attr.Mode) == proto.SIFLNK {
		return nil, syscall.ELOOP
	}
	if h.file == nil {
		return nil, syscall.EBADF
	}
	return reopenHost(h, flags)
}

func (h *hostObject) close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var result error
	if h.file != nil {
		result = h.file.Close()
		h.file = nil
	}
	if h.parent != nil {
		result = errors.Join(result, h.parent.Close())
		h.parent = nil
	}
	return result
}

func hostAttr(fi os.FileInfo) proto.Attr {
	a := proto.Attr{Mode: proto.SIFREG | uint32(fi.Mode().Perm()), Size: uint64(fi.Size()), Mtime: fi.ModTime().Unix(), MtimeNsec: uint32(fi.ModTime().Nanosecond())}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		a.Mode = uint32(st.Mode)
		a.Ino, a.Dev = uint64(st.Ino), uint64(st.Dev)
		a.UID, a.GID, a.Nlink = st.Uid, st.Gid, uint32(st.Nlink)
		fillHostTimes(&a, st)
	}
	return a
}
