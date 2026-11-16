//go:build linux && !amd64 && !arm64

package sandbox

import (
	"fmt"
	"runtime"
)

// InstallExecSeccomp fails closed when the native syscall ABI is unsupported.
func InstallExecSeccomp() error {
	return fmt.Errorf("exec seccomp is unsupported on linux/%s", runtime.GOARCH)
}
