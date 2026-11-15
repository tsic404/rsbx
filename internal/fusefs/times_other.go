//go:build !linux

package fusefs

import (
	"os"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// setFileTimes is the portable fallback. The FUSE server runs on Linux, where
// UTIME_OMIT is available; this build only exists so the package still
// compiles on a development host.
func setFileTimes(host string, in *fuse.SetAttrIn) error {
	fi, err := os.Lstat(host)
	if err != nil {
		return err
	}
	atime, mtime := fi.ModTime(), fi.ModTime()
	if v, ok := in.GetATime(); ok {
		atime = v
	}
	if v, ok := in.GetMTime(); ok {
		mtime = v
	}
	return os.Chtimes(host, atime, mtime)
}
