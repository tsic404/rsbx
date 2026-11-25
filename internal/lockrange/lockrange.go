// Package lockrange converts between FUSE lock ranges and the kernel's Flock_t.
//
// FUSE and the kernel disagree on how "to the end of the file" is spelled: the
// wire carries an inclusive end and spells the end of file as ^uint64(0) or
// LLONG_MAX, while the kernel wants a length of zero. Deriving a length from
// those ends overflows, and the negative result makes fcntl answer EINVAL.
package lockrange

import (
	"math"
	"syscall"
)

// ToFlock converts one inclusive FUSE range into the kernel's Flock_t. A range
// that reaches the end of the file becomes a zero length, the kernel's own
// spelling, so the conversion never overflows.
func ToFlock(typ int16, start, end uint64) (syscall.Flock_t, error) {
	if start > math.MaxInt64 {
		return syscall.Flock_t{}, syscall.EINVAL
	}
	fl := syscall.Flock_t{Type: typ, Whence: 0, Start: int64(start)}
	switch {
	case end == ^uint64(0) || end >= math.MaxInt64:
		fl.Len = 0
	case end < start:
		return syscall.Flock_t{}, syscall.EINVAL
	default:
		fl.Len = int64(end-start) + 1
	}
	return fl, nil
}

// End turns a kernel start and length back into the inclusive end FUSE
// carries. A zero length means "to the end of the file", which must come back
// as the maximum rather than as start-1.
func End(start, length int64) uint64 {
	if length <= 0 {
		return ^uint64(0)
	}
	return uint64(start) + uint64(length) - 1
}

// ReplyEnd spells an end-of-file range the way a Linux FUSE reply must. The
// kernel validates a conflicting lock's end against OFFSET_MAX and answers EIO
// for anything beyond it, so the protocol's own end-of-file sentinel is
// normalized here instead of written through. An unlocked reply skips that
// check, which is why only a real conflict exercises this.
func ReplyEnd(end uint64) uint64 {
	if end >= math.MaxInt64 {
		return math.MaxInt64
	}
	return end
}
