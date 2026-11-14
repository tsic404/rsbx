// Package pty allocates a pseudo terminal without cgo.
package pty

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	tiocgptn   = 0x80045430
	tiocsptlck = 0x40045431
	tiocswinsz = 0x5414
)

type winsize struct{ Rows, Cols, Xpixel, Ypixel uint16 }

func ioctl(fd uintptr, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// Open allocates a pty pair with the slave already unlocked.
func Open() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	var unlock int32
	if err := ioctl(m.Fd(), tiocsptlck, unsafe.Pointer(&unlock)); err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("unlockpt: %w", err)
	}
	var n uint32
	if err := ioctl(m.Fd(), tiocgptn, unsafe.Pointer(&n)); err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("ptsname: %w", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, s, nil
}

// SetWinsize resizes the terminal attached to f.
func SetWinsize(f *os.File, rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return nil
	}
	ws := winsize{Rows: rows, Cols: cols}
	return ioctl(f.Fd(), tiocswinsz, unsafe.Pointer(&ws))
}

// GetWinsize reads the current size; zeroes when unsupported.
func GetWinsize(f *os.File) (rows, cols uint16) {
	var ws winsize
	if ioctl(f.Fd(), 0x5413, unsafe.Pointer(&ws)) != nil {
		return 0, 0
	}
	return ws.Rows, ws.Cols
}
