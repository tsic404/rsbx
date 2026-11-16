//go:build !linux

package fusefs

import (
	"golang.org/x/sys/unix"
	"os"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// Production uses UTIME_OMIT on Linux. The development-host implementation
// keeps inode identity by using the opened descriptor, never File.Name().
func setFileTimes(f *os.File, in *fuse.SetAttrIn) error {
	var ts [2]unix.Timespec
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	ts[0], ts[1] = st.Atimespec, st.Mtimespec
	if v, ok := in.GetATime(); ok {
		ts[0] = unix.NsecToTimespec(v.UnixNano())
	}
	if v, ok := in.GetMTime(); ok {
		ts[1] = unix.NsecToTimespec(v.UnixNano())
	}
	return unix.Futimes(int(f.Fd()), []unix.Timeval{unix.NsecToTimeval(ts[0].Nano()), unix.NsecToTimeval(ts[1].Nano())})
}
