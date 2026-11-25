// Package syserrno turns an error into the syscall.Errno a caller should see.
//
// A kernel call already names the errno it returned; a text guess is only a
// fallback for errors that carry none. Defaulting to EIO before asking the
// error itself hides a real EINVAL behind "input/output error", which is how a
// broken lock length looked like a broken filesystem.
package syserrno

import (
	"errors"
	"os"
	"strings"
	"syscall"
)

// Of returns the errno an error carries, unwrapping *os.SyscallError and
// *os.PathError, and falls back to a text match only when it carries none.
func Of(err error) syscall.Errno {
	var en syscall.Errno
	if errors.As(err, &en) {
		return en
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		return syscall.ENOENT
	case errors.Is(err, os.ErrPermission):
		return syscall.EACCES
	case errors.Is(err, os.ErrExist):
		return syscall.EEXIST
	}
	return OfText(err.Error())
}

// OfText maps an error message onto an errno. It exists for transports that
// carry only text; a call whose error has a real errno must use Of.
func OfText(msg string) syscall.Errno {
	for _, probe := range []struct {
		text  string
		errno syscall.Errno
	}{
		{"no such file", syscall.ENOENT},
		{"permission denied", syscall.EACCES},
		{"operation not permitted", syscall.EPERM},
		{"is a directory", syscall.EISDIR},
		{"not a directory", syscall.ENOTDIR},
		{"not empty", syscall.ENOTEMPTY},
		{"file exists", syscall.EEXIST},
		{"invalid argument", syscall.EINVAL},
		{"no space left", syscall.ENOSPC},
		{"read-only file system", syscall.EROFS},
		{"file name too long", syscall.ENAMETOOLONG},
		{"device or resource busy", syscall.EBUSY},
		{"cross-device link", syscall.EXDEV},
	} {
		if strings.Contains(msg, probe.text) {
			return probe.errno
		}
	}
	return syscall.EIO
}
