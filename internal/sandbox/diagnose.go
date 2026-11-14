package sandbox

import (
	"fmt"
	"os"
	"strings"
)

// Explain renders the plan in a form a user can check without running the
// sandbox: which programs stay local, which are redirected, and what bwrap is
// asked to do.
func (p *Plan) Explain() string {
	var b strings.Builder
	fmt.Fprintf(&b, "mount:       %s\n", p.Mount)
	fmt.Fprintf(&b, "trampoline:  %s\n", p.Trampoline)
	fmt.Fprintf(&b, "daemon:      %s\n", p.Cfg.Daemon.EffectiveEndpoint())
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
	fmt.Fprintf(&b, "bwrap:\n  %s\n", strings.Join(p.BwrapArgs([]string{p.Cfg.Local.Entry}), " "))
	return b.String()
}

var _ = os.Getenv
