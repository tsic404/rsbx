//go:build linux

package sandbox

// scriptChain is controller-compiled metadata for one policy-known script.
// Script is the requested policy path; Interp is the canonical immediate
// interpreter and Spelling is the literal shebang spelling the kernel uses
// for argv[0]. Runtime interpreter scripts carry metadata too, but their
// entry in this list never grants direct local execution by itself.
type scriptChain struct {
	Script     string   `json:"script"`
	Interp     string   `json:"interp"`
	Spelling   string   `json:"spelling"`
	InterpArgs []string `json:"interp_args,omitempty"`
	// Env is an exact optional /usr/bin/env command transition after the
	// kernel loads env. EnvInterp is canonical; EnvArgs is env's complete
	// command prefix including its argv[0] spelling.
	Env       bool     `json:"env"`
	EnvInterp string   `json:"env_interp,omitempty"`
	EnvArgs   []string `json:"env_args,omitempty"`
}
