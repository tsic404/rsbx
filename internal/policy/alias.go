package policy

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ExecPaths returns every absolute path that may execute here, with the real
// target of each alias included: a distribution that keeps /bin/sh as a
// symlink to dash must grant the file the kernel actually loads, or the
// allowlisted name could not start at all.
//
// Only the executable itself is granted. The directories holding these paths
// stay on the daemon: their other content is not part of the grant.
func (p *Policy) ExecPaths() []string {
	out := make([]string, 0, len(p.Local))
	seen := map[string]bool{}
	add := func(path string) {
		if path == "" || !filepath.IsAbs(path) {
			return
		}
		clean := filepath.Clean(path)
		if !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	for _, e := range p.Local {
		add(e)
		// A symlinked executable resolves to its real file, following every
		// link in the chain. A directory entry is a prefix rule and has no
		// single target.
		if fi, err := os.Lstat(e); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			if resolved, err := filepath.EvalSymlinks(e); err == nil {
				if fi, err := os.Stat(resolved); err == nil && !fi.IsDir() {
					add(resolved)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// IsAliasTarget reports whether path is the real file behind an allowlisted
// alias, even though path itself is not allowlisted.
func (p *Policy) IsAliasTarget(path string) bool {
	clean := filepath.Clean(path)
	if p.IsLocal(clean) {
		return true
	}
	for _, e := range p.ExecPaths() {
		if e == clean {
			return true
		}
	}
	return false
}

var _ = strings.HasPrefix
