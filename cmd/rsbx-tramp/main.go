// Command rsbx-tramp executes the supervisor's immutable captured request on
// the daemon. It reads only the fixed private gateway socket, then uses the
// fixed broker transport with inherited stdio. No environment or argv value
// selects a target, request channel or daemon transport.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"rsbx/internal/proto"
	"rsbx/internal/rpc"
	"rsbx/internal/sandbox"
)

func main() {
	req, err := sandbox.ReadGatewayRequest()
	if err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-tramp:", err)
		os.Exit(127)
	}
	if err := configureGatewayTTY(req, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-tramp:", err)
		os.Exit(127)
	}
	code, err := rpc.RunSessionContext(context.Background(), rpc.Target{Socket: sandbox.BrokerSock},
		req, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-tramp:", err)
		os.Exit(127)
	}
	if err := exitGatewayStatus(code); err != nil {
		fmt.Fprintln(os.Stderr, "rsbx-tramp:", err)
		os.Exit(127)
	}
}

func configureGatewayTTY(req *proto.ExecReq, stdin, stdout *os.File) error {
	req.TTY, req.Rows, req.Cols = false, 0, 0
	for _, stream := range [2]*os.File{stdin, stdout} {
		if stream == nil {
			return fmt.Errorf("missing inherited gateway stdio")
		}
		if _, err := unix.IoctlGetTermios(int(stream.Fd()), unix.TCGETS); err != nil {
			if errors.Is(err, unix.ENOTTY) {
				return nil
			}
			return fmt.Errorf("inspect gateway terminal: %w", err)
		}
	}
	size, err := unix.IoctlGetWinsize(int(stdin.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return fmt.Errorf("read gateway terminal size: %w", err)
	}
	req.TTY, req.Rows, req.Cols = true, size.Row, size.Col
	return nil
}

// A negative protocol exit is a signal, not an exit(2) status. Reset both Go's
// signal bookkeeping and the kernel action, unblock it on the pinned thread,
// and signal ourselves so the caller observes WIFSIGNALED with the same signal.
func exitGatewayStatus(code int) error {
	if code >= 0 {
		os.Exit(code)
	}
	if code < -64 {
		return fmt.Errorf("invalid remote signal status %d", code)
	}
	sig := syscall.Signal(-code)
	switch sig {
	case syscall.SIGSTOP, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU,
		syscall.SIGCONT, syscall.SIGCHLD, syscall.SIGURG, syscall.SIGWINCH:
		return fmt.Errorf("remote status names nonterminating signal %d", sig)
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("signal exit is unsupported on linux/%s", runtime.GOARCH)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if sig != syscall.SIGKILL {
		signal.Reset(sig)
		var action struct {
			handler, flags, restorer uintptr
			mask                     uint64
		}
		_, _, errno := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig),
			uintptr(unsafe.Pointer(&action)), 0, 8, 0, 0)
		if errno != 0 {
			return fmt.Errorf("restore remote signal %d default action: %w", sig, errno)
		}
	}
	mask := uint64(1) << uint(sig-1)
	_, _, errno := unix.RawSyscall6(unix.SYS_RT_SIGPROCMASK, unix.SIG_UNBLOCK,
		uintptr(unsafe.Pointer(&mask)), 0, 8, 0, 0)
	if errno != 0 {
		return fmt.Errorf("unblock remote signal %d: %w", sig, errno)
	}
	if err := unix.Tgkill(os.Getpid(), unix.Gettid(), sig); err != nil {
		return fmt.Errorf("propagate remote signal %d: %w", sig, err)
	}
	// Do not race signal delivery with os.Exit, even if the syscall returns
	// before the pending terminating signal is delivered.
	for {
		unix.Ppoll(nil, nil, nil)
	}
}
