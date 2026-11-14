// Package policy answers one question: does this executable run here or on the
// daemon? The answer depends only on the absolute path, so it can be baked into
// the rootfs layout and the Landlock ruleset at start-up.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Policy struct {
	// Local is the expanded allowlist of executables that run here.
	Local []string
}

// New expands patterns into absolute paths. A pattern is a directory prefix, a
// glob, or a single file. Directories are kept as prefixes so a binary
// installed later under the same directory is still covered.
func New(patterns []string) (*Policy, error) {
	seen := map[string]bool{}
	var out []string
	add := func(abs string) {
		if abs != "" && !seen[abs] {
			seen[abs] = true
			out = append(out, abs)
		}
	}
	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if strings.ContainsAny(pat, "*?[") {
			matches, err := filepath.Glob(pat)
			if err != nil {
				return nil, fmt.Errorf("bad pattern %q: %w", pat, err)
			}
			for _, m := range matches {
				abs, err := filepath.Abs(m)
				if err == nil {
					add(abs)
				}
			}
			continue
		}
		if strings.HasPrefix(pat, "/") {
			add(filepath.Clean(pat))
			continue
		}
		if exe := Resolve(pat, os.Getenv("PATH")); exe != "" {
			add(exe)
		}
	}
	sort.Strings(out)
	return &Policy{Local: out}, nil
}

// Resolve maps a bare command name to the file PATH would execute.
func Resolve(name, pathVar string) string {
	if strings.ContainsRune(name, '/') {
		return filepath.Clean(name)
	}
	for _, dir := range filepath.SplitList(pathVar) {
		if dir == "" {
			continue
		}
		cand := filepath.Join(dir, name)
		fi, err := os.Stat(cand)
		if err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return cand
		}
	}
	return ""
}

// IsLocal reports whether path may execute on this machine.
func (p *Policy) IsLocal(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	clean := filepath.Clean(path)
	for _, r := range p.Local {
		if r == clean {
			return true
		}
		if strings.HasPrefix(clean, r+"/") {
			return true
		}
	}
	return false
}

// WithExtra returns a copy of the policy with additional local executables.
func (p *Policy) WithExtra(extra ...string) *Policy {
	seen := map[string]bool{}
	out := append([]string(nil), p.Local...)
	for _, e := range out {
		seen[e] = true
	}
	for _, e := range extra {
		if e != "" && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return &Policy{Local: out}
}

// Mounts returns the host directories that must stay visible read-only for the
// allowlist to be usable: every directory holding a local executable.
func (p *Policy) Mounts() []string {
	set := map[string]bool{}
	var out []string
	for _, e := range p.Local {
		dir := e
		if fi, err := os.Stat(e); err == nil && !fi.IsDir() {
			dir = filepath.Dir(e)
		}
		if !set[dir] {
			set[dir] = true
			out = append(out, dir)
		}
	}
	sort.Strings(out)
	return out
}
