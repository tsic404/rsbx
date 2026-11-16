//go:build linux

package fusefs

import (
	"os"

	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

// setFileTimes applies exactly the requested timestamps to an inode descriptor,
// including O_PATH metadata pins. Rename/unlink cannot redirect it to a name's
// replacement, and UTIME_OMIT preserves an unmentioned side atomically.
func setFileTimes(f *os.File, in *fuse.SetAttrIn) error {
	var ts [2]unix.Timespec
	ts[0].Nsec = unix.UTIME_OMIT
	ts[1].Nsec = unix.UTIME_OMIT
	if v, ok := in.GetATime(); ok {
		ts[0] = unix.NsecToTimespec(v.UnixNano())
	}
	if v, ok := in.GetMTime(); ok {
		ts[1] = unix.NsecToTimespec(v.UnixNano())
	}
	return unix.UtimesNanoAt(int(f.Fd()), "", ts[:], unix.AT_EMPTY_PATH)
}
