// Package policy compiles the exact host executable and runtime assets a
// sandbox may use. Files outside that snapshot remain daemon content.
package policy

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Policy is immutable after construction. Local contains the expanded configured
// names; execution checks use the compiled sets, not the mutable exported slice.
type Policy struct {
	Local           []string
	execPaths       []string
	runtimePaths    []string
	localSet        map[string]bool
	execSet         map[string]bool
	interpreters    map[string]scriptInterpreter
	envInterpreters map[string]scriptInterpreter
	aliases         map[string]string
}

// New expands names, globs and directories into concrete executable files.
// A directory is a startup snapshot, never an execution grant for files a user
// can create there later. Runtime dependencies are resolved once, without
// executing the programs or a host dependency-inspection command.
func New(patterns []string) (*Policy, error) {
	seen := map[string]bool{}
	addFile := func(filename string) error {
		abs, err := filepath.Abs(filename)
		if err != nil {
			return err
		}
		fi, err := os.Stat(abs)
		if err != nil {
			return fmt.Errorf("local executable %q: %w", abs, err)
		}
		if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("local executable %q is not an executable regular file", abs)
		}
		seen[filepath.Clean(abs)] = true
		return nil
	}
	expand := func(filename string) error {
		fi, err := os.Stat(filename)
		if err != nil {
			return fmt.Errorf("local allow path %q: %w", filename, err)
		}
		if !fi.IsDir() {
			return addFile(filename)
		}
		return filepath.WalkDir(filename, func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.IsDir() {
				return nil
			}
			info, err := os.Stat(p)
			if err != nil {
				return fmt.Errorf("local allow path %q: %w", p, err)
			}
			if info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
				return addFile(p)
			}
			return nil
		})
	}
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if strings.ContainsAny(pattern, "*?[") {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				return nil, fmt.Errorf("bad pattern %q: %w", pattern, err)
			}
			for _, match := range matches {
				if err := expand(match); err != nil {
					return nil, err
				}
			}
			continue
		}
		if !filepath.IsAbs(pattern) {
			name := pattern
			pattern = Resolve(name, os.Getenv("PATH"))
			if pattern == "" {
				return nil, fmt.Errorf("local executable %q not found in PATH", name)
			}
		}
		if err := expand(pattern); err != nil {
			return nil, err
		}
	}
	local := make([]string, 0, len(seen))
	for filename := range seen {
		local = append(local, filename)
	}
	sort.Strings(local)
	return compile(local)
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
			abs, err := filepath.Abs(cand)
			if err == nil {
				return abs
			}
		}
	}
	return ""
}

// IsLocal reports whether the exact configured executable name may run here.
func (p *Policy) IsLocal(filename string) bool {
	return p != nil && filepath.IsAbs(filename) && p.localSet[filepath.Clean(filename)]
}

// WithExtra compiles a new snapshot including explicit additional executables,
// such as the selected entry program. Unresolvable dependencies are errors, not
// implicit grants to an interpreter or an entire library directory.
func (p *Policy) WithExtra(extra ...string) (*Policy, error) {
	patterns := make([]string, 0, len(p.localSet)+len(extra))
	for filename := range p.localSet {
		patterns = append(patterns, filename)
	}
	patterns = append(patterns, extra...)
	return New(patterns)
}
