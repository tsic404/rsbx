//go:build linux && arm64

package sandbox

import "golang.org/x/sys/unix"

const execSeccompAuditArch = unix.AUDIT_ARCH_AARCH64
