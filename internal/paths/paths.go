// Package paths decides which trees the sandbox serves from this machine
// instead of from the daemon.
//
// This is the second half of the policy. The executable list says where a
// program runs; this list says whose files it sees. Matched trees are local
// content: no round trip, no materialisation, no chance of conflicting with the
// daemon, because the daemon is never asked about them.
package paths

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Rule is one configured tree.
type Rule struct {
	// Prefix is the absolute host path, which is also its sandbox path. The
	// two namespaces are kept identical on purpose, so a path a program prints
	// means the same thing anywhere.
	Prefix string
	// ReadOnly marks a tree that must not be modified by the sandbox.
	ReadOnly bool
}

// Set is the resolved list of local trees.
type Set struct {
	rules []Rule
}

// New expands globs and validates that each entry is absolute. Missing entries
// are kept: a directory that appears later, such as a mounted toolchain, still
// matches, and nothing breaks while it is absent.
func New(patterns []string, readOnly bool) (*Set, error) {
	var rules []Rule
	add := func(p string) {
		p = strings.TrimSuffix(p, "/")
		if p != "" {
			rules = append(rules, Rule{Prefix: p, ReadOnly: readOnly})
		}
	}
	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if !strings.HasPrefix(pat, "/") {
			return nil, fmt.Errorf("path %q is not absolute", pat)
		}
		if !strings.ContainsAny(pat, "*?[") {
			add(filepath.Clean(pat))
			continue
		}
		matches, err := filepath.Glob(pat)
		if err != nil {
			return nil, fmt.Errorf("bad pattern %q: %w", pat, err)
		}
		for _, m := range matches {
			add(filepath.Clean(m))
		}
	}
	sortRules(rules)
	return &Set{rules: rules}, nil
}

// sortRules puts the longest prefix first, so a nested entry is considered
// before the tree that contains it.
func sortRules(rules []Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if len(rules[i].Prefix) != len(rules[j].Prefix) {
			return len(rules[i].Prefix) > len(rules[j].Prefix)
		}
		return rules[i].Prefix < rules[j].Prefix
	})
}

// WithReadOnly marks the named prefixes read-only, keeping the order of the
// set so longest-prefix matching still wins.
func (s *Set) WithReadOnly(ro map[string]bool) *Set {
	if s == nil {
		return nil
	}
	out := make([]Rule, 0, len(s.rules))
	for _, r := range s.rules {
		r.ReadOnly = ro[r.Prefix]
		out = append(out, r)
	}
	sortRules(out)
	return &Set{rules: out}
}

// Match reports whether p belongs to a local tree, and whether it is read-only.
func (s *Set) Match(p string) (local, readOnly bool) {
	if s == nil || !strings.HasPrefix(p, "/") {
		return false, false
	}
	clean := filepath.Clean(p)
	for _, r := range s.rules {
		if clean == r.Prefix || strings.HasPrefix(clean, r.Prefix+"/") {
			return true, r.ReadOnly
		}
	}
	return false, false
}

// IsLocal reports whether p is served from this machine.
func (s *Set) IsLocal(p string) bool {
	ok, _ := s.Match(p)
	return ok
}

// Writable reports whether the sandbox may modify p.
func (s *Set) Writable(p string) bool {
	ok, ro := s.Match(p)
	return ok && !ro
}

// Roots returns every configured prefix, longest first.
func (s *Set) Roots() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, r.Prefix)
	}
	return out
}

// ReadOnlyRoots returns the prefixes that must be mounted read-only.
func (s *Set) ReadOnlyRoots() []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, r := range s.rules {
		if r.ReadOnly {
			out = append(out, r.Prefix)
		}
	}
	return out
}
