//go:build linux

package fusefs

import (
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

// setFileTimes applies the timestamps a Setattr asked for to a host path.
// A side the caller did not mention is left alone, which is exactly
// UTIME_OMIT; without it a chmod that carries only a mode would overwrite the
// file's real atime with "now".
func setFileTimes(host string, in *fuse.SetAttrIn) error {
	var ts [2]unix.Timespec
	ts[0].Nsec = unix.UTIME_OMIT
	ts[1].Nsec = unix.UTIME_OMIT
	if v, ok := in.GetATime(); ok {
		ts[0] = unix.NsecToTimespec(v.UnixNano())
	}
	if v, ok := in.GetMTime(); ok {
		ts[1] = unix.NsecToTimespec(v.UnixNano())
	}
	return unix.UtimesNanoAt(unix.AT_FDCWD, host, ts[:], unix.AT_SYMLINK_NOFOLLOW)
}
