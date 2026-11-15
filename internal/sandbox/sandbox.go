// Package sandbox assembles the sandbox the caller sees.
//
// Composition, outside in:
//
//	FUSE root   union of the daemon tree, the explicit local trees, and
//	            trampolines for every executable the policy keeps remote
//	broker      a private unix relay, the only host directory bound in, so
//	            ssh and its credentials never enter the sandbox
//	launcher    rsbx reexecuted into new mount/user/pid/ipc/uts namespaces;
//	            it binds the FUSE root as /, provides private /proc and a
//	            minimal /dev, switches root, detaches the old one and runs
//	            the entry as a reaped, signal-forwarded child
//	guard       Landlock exec allowlist, installed once the root is final
//
// Nothing here shells out: the launcher is this same binary. Every setup
// step fails closed, so a kernel that refuses a namespace or a mount is an
// error rather than a quietly weaker sandbox.
package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"rsbx/internal/config"
	"rsbx/internal/fusefs"
	"rsbx/internal/paths"
	"rsbx/internal/policy"
	"rsbx/internal/rpc"
)

// Reserved sandbox paths. All of them are synthetic in the FUSE layout: the
// launcher may mount over them, but nothing is ever created in the daemon
// tree to make room.
const (
	// BrokerDir is the only host directory bound into the sandbox. It holds
	// the relay socket and nothing else.
	BrokerDir  = "/.rsbx-rpc"
	BrokerSock = BrokerDir + "/daemon.sock"
	// HelperDir is the one directory bound in for the local helpers. A
	// directory bind is reliable; per-file binds onto a FUSE placeholder are
	// not, because the placeholder is the filesystem's own entry.
	HelperDir      = "/.rsbx-helpers"
	TrampolinePath = HelperDir + "/rsbx-tramp"
	GuardPath      = HelperDir + "/rsbx-guard"
	// OldRootPath is the pivot_root scratch directory. It is detached as
	// soon as the switch is done.
	OldRootPath = "/.rsbx-oldroot"
)

// synthetic lists paths the sandbox provides as empty mount points. /proc and
// /dev are kernel facilities the launcher fills itself. /tmp is deliberately
// absent: it stays the daemon's directory.
var synthetic = []string{"/proc", "/dev", HelperDir, BrokerDir, OldRootPath}

// syntheticFiles are the bind-mount targets that are files rather than
// directories.
var syntheticFiles = []string{}

type Plan struct {
	Cfg *config.Config
	// Mount is the host mount point of the FUSE root.
	Mount string
	// Cache is disposable scratch the client and its helpers use.
	Cache string
	// Trampoline and Guard are the local helper binaries.
	Trampoline string
	Guard      string
	// Remote is the multiplexed filesystem client the FUSE server serves from.
	Remote *rpc.FS
	// Target is how the broker reaches the daemon: a unix socket or a stdio
	// command such as ssh. It is only ever dialled outside the sandbox root.
	Target rpc.Target
	// Local is the path policy: trees served from this machine.
	Local *paths.Set
	// Exec is the executable policy.
	Exec *policy.Policy
}

// Prepare validates the configuration and prepares directories.
func Prepare(cfg *config.Config, exeDir string) (*Plan, error) {
	pol, err := policy.New(cfg.Local.Allow)
	if err != nil {
		return nil, err
	}
	// The entry program is what the session starts, so it runs locally by
	// definition. Requiring it in local.allow as well would only ever produce
	// "execvp: No such file or directory" at start-up.
	if entry := cfg.Local.Entry; entry != "" {
		if !strings.HasPrefix(entry, "/") {
			return nil, fmt.Errorf("local.entry must be an absolute path: %q", entry)
		}
		pol = pol.WithExtra(entry)
	}
	if len(pol.Local) == 0 {
		return nil, fmt.Errorf("local.allow selects no executable and local.entry is empty: nothing could run locally")
	}
	tramp := filepath.Join(exeDir, "rsbx-tramp")
	guard := filepath.Join(exeDir, "rsbx-guard")
	for _, helper := range []string{tramp, guard} {
		fi, err := os.Stat(helper)
		if err != nil {
			return nil, fmt.Errorf("sandbox helper %s: %w", helper, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("sandbox helper %s is not a regular file", helper)
		}
	}
	local, err := paths.New(cfg.Local.Paths, false)
	if err != nil {
		return nil, err
	}
	// Only explicitly configured read-only trees are local. Host toolchain
	// and loader directories are not pulled in implicitly: a program whose
	// bytes live on the daemon has to be started from there.
	machine, err := paths.New(cfg.Local.ReadOnlyPaths, true)
	if err != nil {
		return nil, err
	}
	p := &Plan{
		Cfg:        cfg,
		Mount:      cfg.Sandbox.Mount,
		Cache:      cfg.Sandbox.Cache,
		Trampoline: tramp,
		Guard:      guard,
		Target:     targetOf(cfg),
		Local:      mergePaths(local, machine),
		Exec:       pol,
	}
	p.Remote = rpc.NewFS(p.Target)
	for _, d := range []string{p.Mount, p.Cache} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// mergePaths combines the writable and read-only trees into one policy, keeping
// the read-only flag of each entry.
func mergePaths(writable, readOnly *paths.Set) *paths.Set {
	merged, _ := paths.New(append(writable.Roots(), readOnly.ReadOnlyRoots()...), false)
	ro := map[string]bool{}
	for _, r := range readOnly.ReadOnlyRoots() {
		ro[r] = true
	}
	return merged.WithReadOnly(ro)
}

func targetOf(cfg *config.Config) rpc.Target {
	if cfg.Daemon.Transport == "ssh" {
		return rpc.Target{Command: transportCommand(cfg.Daemon.Command)}
	}
	return rpc.Target{Socket: cfg.Daemon.Socket}
}

// transportCommand prepares the daemon command. For ssh it turns on connection
// multiplexing, which matters because the broker opens one connection per
// redirected command and a fresh handshake per exec would dominate.
func transportCommand(spec string) []string {
	argv := splitCommand(spec)
	if len(argv) == 0 || filepath.Base(argv[0]) != "ssh" {
		return argv
	}
	for _, a := range argv {
		if strings.HasPrefix(a, "-o") && strings.Contains(a, "ControlMaster") {
			return argv
		}
	}
	ctl := filepath.Join(os.TempDir(), "rsbx-ssh-%C")
	out := []string{argv[0], "-o", "ControlMaster=auto", "-o", "ControlPath=" + ctl, "-o", "ControlPersist=60"}
	return append(out, argv[1:]...)
}

// splitCommand splits a command line into argv, honouring double quotes so a
// transport command can carry arguments with spaces.
func splitCommand(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, escaped, have := false, false, false
	flush := func() {
		if have {
			out = append(out, cur.String())
			cur.Reset()
			have = false
		}
	}
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			have = true
			escaped = false
		case r == '\\' && inQuote:
			escaped = true
		case r == '"':
			inQuote = !inQuote
			have = true
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	flush()
	return out
}

// Layout builds the FUSE layout.
func (p *Plan) Layout() *fusefs.Layout {
	roots := p.Local.Roots()
	hostDirs := map[string]bool{}
	// Every ancestor of a local tree must exist in the view. The launcher
	// creates its mount targets itself, so reserving the ancestors keeps any
	// placeholder out of the daemon tree.
	for _, d := range roots {
		hostDirs[d] = true
		for q := d; q != "/" && q != "."; q = filepath.Dir(q) {
			hostDirs[filepath.Dir(q)] = true
		}
	}
	allSynthetic := append([]string(nil), synthetic...)
	for d := range hostDirs {
		// The root of a local tree is served by the tree itself, not as a
		// placeholder, and a path already listed keeps its meaning.
		if d == "/" || p.Local.IsLocal(d) {
			continue
		}
		allSynthetic = append(allSynthetic, d)
	}
	// Only trees that hold the allowlist need FUSE to arbitrate per name.
	// Everything else that is local is served from the host directly.
	policyDirs := p.PolicyDirs()
	execDirs := make([]string, 0, len(policyDirs))
	for d := range policyDirs {
		execDirs = append(execDirs, d)
	}
	sort.Strings(execDirs)
	return &fusefs.Layout{
		Remote:     p.Remote,
		Local:      p.Local,
		ExecDirs:   execDirs,
		Trampoline: p.Trampoline,
		LocalExec:  p.Exec.IsAliasTarget,
		Cache:      p.Cache,
		TTL:        2 * time.Second,
		// No SystemLinks: the merged-usr symlinks belong to the daemon's
		// tree, and inventing them here would hand the sandbox a host /lib
		// that the policy never granted.
		Synthetic:      dedupePaths(allSynthetic),
		SyntheticFiles: append([]string(nil), syntheticFiles...),
		HostDirs:       hostDirs,
	}
}

// MountRoot mounts the sandbox root and returns the server so the caller can
// wait for it.
func (p *Plan) MountRoot() (*fuse.Server, error) {
	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			AllowOther:        false,
			Debug:             os.Getenv("RSBX_FUSE_DEBUG") != "",
			FsName:            "rsbx",
			DisableSplice:     true,
			EnableLocks:       true,
			ExtraCapabilities: fuse.CAP_DIRECT_IO_ALLOW_MMAP,
		},
		// No dentry caching. A negative entry that lasts a moment is enough to
		// hide a file the same process created microseconds earlier: git makes a
		// directory, writes an object into it and reads it back, and the kernel
		// answers the lookup from a cached "not found". Correctness here is worth
		// the extra lookups, and the tree is remote anyway, so the kernel cache
		// was never going to save the round trip that mattered.
		EntryTimeout: durp(0),
		// The same argument applies to attributes and to the data behind them.
		// A cached mtime or size is a claim about a file another process may
		// already have replaced, and a rename the kernel has not invalidated
		// reads back as the old bytes. Every lookup costs one round trip on a
		// tree that is remote either way.
		AttrTimeout: durp(0),
	}
	srv, err := fs.Mount(p.Mount, fusefs.NewRoot(p.Layout()), opts)
	if err != nil {
		return nil, err
	}
	// Wait until the mount actually answers. The launcher binds the source
	// path immediately, and a freshly mounted FUSE root refuses requests for
	// a moment while the server thread starts.
	if err := waitReady(p.Mount, 5*time.Second); err != nil {
		srv.Unmount()
		return nil, err
	}
	return srv, nil
}

// waitReady blocks until path can be listed, or the deadline passes.
func waitReady(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if _, last = os.ReadDir(path); last == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("sandbox root %s did not become ready: %w", path, last)
}

func durp(sec float64) *time.Duration {
	d := time.Duration(sec * float64(time.Second))
	return &d
}

// SandboxExecPaths lists, in sandbox coordinates, every path Landlock must
// keep executable.
//
// The list is the allowlist itself, not the directories holding it: a
// directory-wide rule would let any name that survived redirection execute.
// The allowlist is expanded with the real target of every alias, so a
// distribution symlink such as /bin/sh -> dash also grants the file it names.
func (p *Plan) SandboxExecPaths() []string {
	out := []string{GuardPath, TrampolinePath}
	if p.Exec == nil {
		return out
	}
	seen := map[string]bool{GuardPath: true, TrampolinePath: true}
	for _, e := range p.Exec.ExecPaths() {
		if e != "" && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}

	sort.Strings(out)
	return out
}

// usesHostNetwork reports whether the sandbox keeps the host network namespace.
func (p *Plan) usesHostNetwork() bool {
	return p.Cfg.Daemon.Transport == "ssh" || p.Cfg.Sandbox.ShareNetwork
}

// hasPath reports whether a host path keeps its meaning inside the sandbox:
// local trees do, daemon paths do (the view is the daemon's tree), reserved
// mount points do not because the launcher replaces them.
func (p *Plan) hasPath(path string) bool {
	if p.Local != nil && p.Local.IsLocal(path) {
		return true
	}
	for _, s := range synthetic {
		if path == s || strings.HasPrefix(path, s+"/") {
			return false
		}
	}
	for _, f := range syntheticFiles {
		if path == f {
			return false
		}
	}
	for _, root := range p.Local.Roots() {
		if strings.HasPrefix(root, path+"/") {
			return true
		}
	}
	return true
}

// dedupePaths removes duplicates.
func dedupePaths(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// PolicyDirs are the directories where the policy must decide per name.
func (p *Plan) PolicyDirs() map[string]bool {
	out := map[string]bool{}
	if p.Exec == nil {
		return out
	}
	for _, e := range p.Exec.Local {
		fi, err := os.Stat(e)
		if err == nil && fi.IsDir() {
			out[e] = true
			continue
		}
		out[filepath.Dir(e)] = true
	}
	return out
}

// Run starts the entry program inside the sandbox.
//
// The FUSE server and the broker stay in this process, outside the namespaces.
// The launcher is this same binary reexecuted with an internal flag; it owns
// namespace setup, root switching, capability removal, signal forwarding and
// reaping. This method only supervises it.
func (p *Plan) Run(argv []string) (int, error) {
	b, err := newBroker(p.Target, filepath.Join(p.Cache, "broker"))
	if err != nil {
		return 127, fmt.Errorf("sandbox broker: %w", err)
	}
	defer b.Close()
	return p.launch(p.launchSpec(argv, b))
}
