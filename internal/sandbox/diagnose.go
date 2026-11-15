package sandbox

import (
	"fmt"
	"strings"
)

// Explain renders the plan in a form a user can check without running the
// sandbox: which programs stay local, which are redirected, and what the
// launcher is asked to do.
func (p *Plan) Explain() string {
	var b strings.Builder
	fmt.Fprintf(&b, "mount:       %s\n", p.Mount)
	fmt.Fprintf(&b, "trampoline:  %s\n", p.Trampoline)
	fmt.Fprintf(&b, "daemon:      %s\n", p.Cfg.Daemon.EffectiveEndpoint())
	fmt.Fprintf(&b, "network:     %s\n", networkMode(p.usesHostNetwork()))
	fmt.Fprintf(&b, "user ns:     %v\n", p.Cfg.Sandbox.UnshareUser)
	fmt.Fprintf(&b, "local (%d):\n", len(p.Exec.Local))
	for _, e := range p.Exec.Local {
		fmt.Fprintf(&b, "  %s\n", e)
	}
	fmt.Fprintf(&b, "local trees (%d):\n", len(p.Local.Roots()))
	for _, r := range p.Local.Roots() {
		mode := "rw"
		if !p.Local.Writable(r) {
			mode = "ro"
		}
		fmt.Fprintf(&b, "  %-5s %s\n", mode, r)
	}
	fmt.Fprintf(&b, "landlock (%d):\n", len(p.SandboxExecPaths()))
	for _, e := range p.SandboxExecPaths() {
		fmt.Fprintf(&b, "  %s\n", e)
	}
	fmt.Fprintf(&b, "launcher:    reexec %s -rsbx-launch-fd 3 (namespaces mount,pid,ipc,uts%s)\n",
		selfPath(), namespaces(p))
	return b.String()
}

func networkMode(share bool) string {
	if share {
		return "host (shared)"
	}
	return "private"
}

func namespaces(p *Plan) string {
	out := ",net"
	if p.usesHostNetwork() {
		out = ""
	}
	if p.Cfg.Sandbox.UnshareUser {
		out += ",user"
	}
	return out
}
