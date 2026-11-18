// Package sandbox assembles the sandbox the caller sees.
//
// A controller owns one session: a separate worker serves the remote FUSE
// view, a private broker relays daemon commands, and a fixed-thread launcher
// creates namespaces and remains PID 1. Execution is mediated independently
// from file contents; exact local programs and their read-only runtime assets
// are the only implicit content exceptions. Explicit local trees hold user
// configuration. No component knows any particular agent CLI.
package sandbox

import (
	"context"
	"fmt"
	"net"
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
	"rsbx/internal/workspace"
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
	// Remote is the controller's independent preflight/metadata connection.
	// The filesystem worker constructs and owns its own session connection.
	Remote *rpc.FS
	// Target is how the broker reaches the daemon: a unix socket or a stdio
	// command such as ssh. It is only ever dialled outside the sandbox root.
	Target rpc.Target
	// Local is the path policy: trees served from this machine.
	Local *paths.Set
	// Exec is the executable policy.
	Exec *policy.Policy
	// Reverse is the live reverse-exec channel, once Run opened one. It is
	// exported so the caller can tell the agent where its stubs must dial.
	Reverse *rpc.ReverseChannel
	// reverseToken is this session's capability for local execution. It is
	// generated per session and handed only to the supervisor's sealed spec.
	reverseToken string
	reverseAllow []string
	reverseFile  *os.File
	// Workspace, when set, is the task workspace in the daemon's tree: this
	// session starts there after initializing it from the seed.
	Workspace *workspace.Spec
	// filesystem owns the only mount server for this session. It never pivots.
	filesystem *filesystemWorker
	root       *fusefs.Node
	sessionID  string
	sessionDir string
	mountDir   string
}

// Prepare validates and compiles a session plan without creating a mount or
// allocating shared runtime paths. StartFilesystem allocates owned resources.
func Prepare(cfg *config.Config, exeDir string) (*Plan, error) {
	pol, err := policy.New(cfg.Local.Allow)
	if err != nil {
		return nil, err
	}
	reverseAllow := pol.ExecPaths()
	// local.entry explicitly selects another local program. It has the same
	// compiled dependency and immutable-asset requirements as local.allow.
	if entry := cfg.Local.Entry; entry != "" {
		if !strings.HasPrefix(entry, "/") {
			return nil, fmt.Errorf("local.entry must be an absolute path: %q", entry)
		}
		pol, err = pol.WithExtra(entry)
		if err != nil {
			return nil, err
		}
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
	target, err := targetOf(cfg)
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
		Cfg:          cfg,
		Mount:        cfg.Sandbox.Mount,
		Cache:        cfg.Sandbox.Cache,
		Trampoline:   tramp,
		Guard:        guard,
		Target:       target,
		Local:        mergePaths(local, machine),
		Exec:         pol,
		reverseAllow: reverseAllow,
	}
	p.Remote = rpc.NewFS(p.Target)
	return p, nil
}

// StartupDiagnostics reports plan hazards a user could not see until a task
// fails deep inside the sandbox. Each entry is a warning, never a refusal:
// some sessions deliberately keep an allowlisted program local-only.
func (p *Plan) StartupDiagnostics(ctx context.Context) []string {
	var out []string
	if p.Exec == nil {
		return out
	}
	// An allowlisted program is local-only. A process routed to the daemon
	// (a shell, a build tool) that calls it by absolute path sees ENOENT
	// there, which is hard to attribute without this hint.
	remote := p.Remote
	if remote != nil {
		done := make(chan []string, 1)
		go func() {
			var missing []string
			for _, path := range p.Exec.ExecPaths() {
				if _, err := remote.Stat(path); err != nil {
					missing = append(missing, path)
				}
			}
			done <- missing
		}()
		select {
		case missing := <-done:
			for _, path := range missing {
				out = append(out, fmt.Sprintf(
					"local.allow program %s is not present on the daemon at the same path; "+
						"a non-local process (shell, build tool) calling it there fails with ENOENT", path))
			}
		case <-ctx.Done():
			_ = remote.Close()
			<-done
			return out
		}
	}
	if !shellAllowlisted(p.Exec) {
		out = append(out,
			"no command shell is in local.allow: agent tools that start /bin/sh or /bin/bash "+
				"run on the daemon, so allowlisted programs are unreachable to them by path")
	}
	return out
}

// shellAllowlisted reports whether a POSIX shell is in the local allow set,
// by exact path or by alias.
func shellAllowlisted(pol *policy.Policy) bool {
	for _, path := range pol.ExecPaths() {
		switch filepath.Base(path) {
		case "sh", "bash", "dash", "ash", "zsh", "ksh":
			return true
		}
	}
	return false
}

// SetWorkspace attaches a task workspace. The path is a native path in the
// daemon's tree, so it must stay outside every tree this machine declares
// local; otherwise the session would start in local content that remote
// commands cannot reach.
func (p *Plan) SetWorkspace(path, seed string) error {
	spec := workspace.Spec{Path: path, Seed: seed, Local: p.Local}
	if err := workspace.Validate(spec); err != nil {
		return err
	}
	if path != "" && !p.hasPath(path) {
		return fmt.Errorf("workspace %s is a reserved sandbox path", path)
	}
	p.Workspace = &spec
	return nil
}

// EnsureWorkspace writes the workspace's initial material through the daemon's
// filesystem channel and proves the start directory exists there. It runs
// before the mount exists, so a refused initialization costs no session.
//
// The phase belongs to the session: when ctx ends, this session's connection
// is closed, which releases every pending request, and the call returns
// without waiting for a daemon that stopped answering.
func (p *Plan) EnsureWorkspace(ctx context.Context) error {
	if p.Workspace == nil || p.Workspace.Path == "" {
		return nil
	}
	// Capture the connection once: Close nils the field, so a read from the
	// other goroutine during cancellation would race with it.
	remote := p.Remote
	if remote == nil {
		return fmt.Errorf("workspace %s: session connection is closed", p.Workspace.Path)
	}
	done := make(chan error, 1)
	go func() {
		done <- workspace.Ensure(remote, *p.Workspace)
	}()
	select {
	case err := <-done:
		if err != nil && ctx.Err() != nil {
			return context.Cause(ctx)
		}
		return err
	case <-ctx.Done():
		// Closing the transport unblocks the initializer: every request it is
		// waiting on returns. The goroutine owns no other resource, so its
		// result is collected before this phase reports the interruption.
		_ = remote.Close()
		<-done
		return context.Cause(ctx)
	}
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

// targetOf builds the daemon transport. A TLS transport whose configuration
// cannot be used is reported here, before a session starts, instead of
// surfacing as a handshake failure on the first request.
func targetOf(cfg *config.Config) (rpc.Target, error) {
	if cfg.Daemon.Transport == "tls" {
		tlsConfig, err := rpc.TLSConfig(cfg.Daemon.TLSCA, cfg.Daemon.TLSCert, cfg.Daemon.TLSKey, cfg.Daemon.ServerName, false, cfg.Daemon.TLSSkipVerify)
		if err != nil {
			return rpc.Target{}, fmt.Errorf("daemon TLS: %w", err)
		}
		return rpc.Target{Address: cfg.Daemon.Address, TLSConfig: tlsConfig}, nil
	}
	if cfg.Daemon.Transport == "ssh" {
		return rpc.Target{Command: splitCommand(cfg.Daemon.Command)}, nil
	}
	return rpc.Target{Socket: cfg.Daemon.Socket}, nil
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
	// Local ancestors provide union directories, not synthetic subtrees: their
	// unrelated descendants still belong to the daemon.
	for _, d := range roots {
		hostDirs[d] = true
		for q := d; q != "/" && q != "."; q = filepath.Dir(q) {
			hostDirs[filepath.Dir(q)] = true
		}
	}
	return &fusefs.Layout{
		Remote:       p.Remote,
		Local:        p.Local,
		LocalExec:    p.Exec.IsAliasTarget,
		ExecPaths:    p.Exec.ExecPaths(),
		RuntimePaths: p.Exec.RuntimePaths(),
		// No SystemLinks: the merged-usr symlinks belong to the daemon's
		// tree, and inventing them here would hand the sandbox a host /lib
		// that the policy never granted.
		Synthetic:      append([]string(nil), synthetic...),
		SyntheticFiles: append([]string(nil), syntheticFiles...),
		HostDirs:       hostDirs,
	}
}

// mountRoot is private to the filesystem worker. The controller receives a
// readiness result, not a server that it can accidentally serve or pivot into.
func (p *Plan) mountRoot(layout *fusefs.Layout) (*fuse.Server, error) {
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
		AttrTimeout:     durp(0),
		NullPermissions: true,
	}
	root := fusefs.NewRoot(layout)
	if err := root.Err(); err != nil {
		_ = root.Close()
		return nil, err
	}
	srv, err := fs.Mount(p.Mount, root, opts)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	p.root = root
	// fs.Mount already completes INIT and WaitMount. A second probe adds no
	// readiness guarantee; only this filesystem worker serves the mount.
	return srv, nil
}

func durp(sec float64) *time.Duration {
	d := time.Duration(sec * float64(time.Second))
	return &d
}

// SandboxExecPaths contains concrete program/runtime assets and native helpers.
// Data directories are never execute grants; the exec supervisor routes remote
// programs without replacing their file content or broadening this ruleset.
func (p *Plan) SandboxExecPaths() []string {
	out := []string{GuardPath, TrampolinePath}
	if p.Exec == nil {
		return out
	}
	seen := map[string]bool{GuardPath: true, TrampolinePath: true}
	add := func(e string) {
		if e != "" && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	for _, e := range p.Exec.ExecPaths() {
		add(e)
	}
	for _, asset := range p.Exec.RuntimePaths() {
		add(asset)
	}

	sort.Strings(out)
	return out
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

// Run supervises the namespace launcher while a separate worker serves FUSE.
// Cancellation terminates the local process tree and closes command relays.
func (p *Plan) Run(ctx context.Context, argv []string) (int, error) {
	b, err := newBroker(p.Target, filepath.Join(p.Cache, "broker"))
	if err != nil {
		return 127, fmt.Errorf("sandbox broker: %w", err)
	}
	defer b.Close()
	// A fresh capability binds every reverse command to this exact session.
	// The daemon never receives it: only the controller uses it to talk to
	// the supervisor's private local-exec socket.
	p.reverseToken, err = reverseToken()
	if err != nil {
		return 127, fmt.Errorf("generate reverse execution token: %w", err)
	}
	if p.Cfg.Daemon.Reverse {
		if p.Cfg.Daemon.Address == "" {
			return 127, fmt.Errorf("reverse execution requires daemon transport tls with mTLS")
		}
		bind := "127.0.0.1:0"
		if p.Cfg.Daemon.Transport == "tls" && p.Cfg.Daemon.Reverse {
			bind = "[::]:0"
		}
		listener, err := net.Listen("tcp", bind)
		if err != nil {
			return 127, err
		}
		defer listener.Close()
		tcp := listener.(*net.TCPListener)
		file, err := tcp.File()
		if err != nil {
			return 127, err
		}
		p.reverseFile = file
		go func() { <-ctx.Done(); listener.Close() }()
		client := &ReverseClient{Address: listener.Addr().String(), Token: p.reverseToken}
		reverse, err := rpc.OpenReverse(ctx, p.Target, client)
		if err != nil {
			return 127, err
		}
		p.Reverse = reverse
		defer reverse.Close()
		spec, err := p.launchSpec(argv, b)
		if err != nil {
			return 127, err
		}
		spec.ReverseToken = p.reverseToken
		spec.ReverseAllow = p.reverseAllow
		spec.Env = append(spec.Env, "RSBX_STUB_SOCKET="+reverse.StubSocket)
		fmt.Fprintf(os.Stderr, "rsbx: remote stub socket: %s\n", reverse.StubSocket)
		return p.launch(ctx, spec)
	}
	spec, err := p.launchSpec(argv, b)
	if err != nil {
		return 127, err
	}
	return p.launch(ctx, spec)
}
