//go:build linux && (amd64 || arm64)

package sandbox

import (
	"fmt"
	"slices"

	"golang.org/x/sys/unix"
)

// Kernel script recursion prepends only a small interpreter prefix. Retain
// the captured user tail by reference instead of copying a large argv once
// per shebang hop. A dynamic env transition gets an exact one-shot shape.
type scriptImagePlan struct {
	image  execAsset
	prefix []string
	tail   []string
	permit *scriptPermit
}

func (p scriptPermit) matches(argv []string) bool {
	return len(argv) == len(p.prefix)+len(p.tail) &&
		slices.Equal(argv[:len(p.prefix)], p.prefix) && slices.Equal(argv[len(p.prefix):], p.tail)
}

func (p scriptImagePlan) matches(argv []string) bool {
	return len(argv) == len(p.prefix)+len(p.tail) &&
		slices.Equal(argv[:len(p.prefix)], p.prefix) && slices.Equal(argv[len(p.prefix):], p.tail)
}

func (p *execPolicy) scriptPlan(id executableID, filename string, argv []string) (scriptImagePlan, error) {
	plan := scriptImagePlan{tail: argv[1:]}
	var chain []scriptChain
	seen := map[executableID]bool{}
	for {
		c, ok := p.scripts[id]
		if !ok {
			return plan, fmt.Errorf("script interpreter metadata is missing")
		}
		if seen[id] {
			return plan, unix.ELOOP
		}
		seen[id] = true
		chain = append(chain, c)
		interpreter, ok := p.paths[c.Interp]
		if !ok {
			return plan, fmt.Errorf("script interpreter snapshot is missing: %s", c.Interp)
		}
		id = assetID(interpreter)
		if _, nested := p.scripts[id]; !nested {
			plan.image = interpreter
			break
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		plan.prefix = append(plan.prefix, chain[i].Spelling)
		plan.prefix = append(plan.prefix, chain[i].InterpArgs...)
	}
	plan.prefix = append(plan.prefix, filename)
	last := chain[len(chain)-1]
	if last.Env {
		command, ok := p.paths[last.EnvInterp]
		if !ok || len(last.EnvArgs) == 0 {
			return plan, fmt.Errorf("env command metadata is missing")
		}
		prefix := append([]string(nil), last.EnvArgs...)
		prefix = append(prefix, plan.prefix[1+len(last.InterpArgs):]...)
		plan.permit = &scriptPermit{image: command, prefix: prefix, tail: plan.tail}
	}
	return plan, nil
}
