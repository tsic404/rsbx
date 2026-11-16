package policy

import "path/filepath"

// ExecPaths returns the compiled exact executable names and every resolved
// alias needed to reach them. Holding directories are not execution grants.
func (p *Policy) ExecPaths() []string {
	if p == nil {
		return nil
	}
	return append([]string(nil), p.execPaths...)
}

// IsAliasTarget also recognises the concrete target of an allowlisted alias.
// Runtime-only interpreters and ELF loaders deliberately do not match.
func (p *Policy) IsAliasTarget(filename string) bool {
	return p != nil && filepath.IsAbs(filename) && p.execSet[filepath.Clean(filename)]
}

// RuntimePaths returns concrete read-only interpreter, loader and library
// assets. They are data dependencies, not permission for arbitrary invocations.
func (p *Policy) RuntimePaths() []string {
	if p == nil {
		return nil
	}
	return append([]string(nil), p.runtimePaths...)
}

// InterpreterFor returns the immediate canonical shebang interpreter and the
// kernel's single optional argument for any compiled executable/runtime script.
// Runtime script metadata does not grant arbitrary local invocations.
func (p *Policy) InterpreterFor(filename string) (string, []string, bool) {
	if p == nil || !filepath.IsAbs(filename) {
		return "", nil, false
	}
	interpreter, ok := p.interpreters[p.aliases[filepath.Clean(filename)]]
	return interpreter.path, append([]string(nil), interpreter.args...), ok
}

// EnvInterpreterFor reports the command a compiled env shebang will exec.
// args is the exact command argv prefix, including argv[0] as env spells it;
// the script pathname and user arguments are appended by the execution router.
// Runtime-only scripts remain non-local despite their queryable metadata.
func (p *Policy) EnvInterpreterFor(filename string) (string, []string, bool) {
	if p == nil || !filepath.IsAbs(filename) {
		return "", nil, false
	}
	interpreter, ok := p.envInterpreters[p.aliases[filepath.Clean(filename)]]
	return interpreter.path, append([]string(nil), interpreter.args...), ok
}

// InterpreterSpellingFor returns the literal immediate shebang interpreter
// spelling, needed when constructing the kernel argv of nested scripts.
func (p *Policy) InterpreterSpellingFor(filename string) (string, bool) {
	if p == nil || !filepath.IsAbs(filename) {
		return "", false
	}
	interpreter, ok := p.interpreters[p.aliases[filepath.Clean(filename)]]
	return interpreter.spelling, ok
}
