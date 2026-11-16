//go:build linux && amd64

package sandbox

import "golang.org/x/sys/unix"

const execSeccompAuditArch = unix.AUDIT_ARCH_X86_64
