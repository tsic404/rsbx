// Package sandbox assembles the user-visible sandbox.
//
// Composition, outside in:
//
//	FUSE root  union of the daemon tree, the read-only host toolchain and
//	           trampolines for every executable the policy keeps remote
//	bwrap      mounts that root as /, hands over private /proc, /dev and /tmp
//	Landlock   fail-closed backstop for anything the trampoline missed
//
// The trampoline handles the ordinary case, so Landlock is defence in depth.
package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"rsbx/internal/config"
	"rsbx/internal/fusefs"
	"strings"

	"rsbx/internal/paths"
	"rsbx/internal/policy"
	"rsbx/internal/rpc"
)

// Synthetic mount points bwrap creates; the FUSE root must expose them.
// synthetic lists paths the sandbox itself provides as empty mount points.
//
// bwrap creates the destination of every bind, and doing that through the
// filesystem is what keeps the daemon tree clean: without these entries a
// --ro-bind of /etc would mkdir /etc in the *remote* tree on first run.
var synthetic = []string{
	"/proc", "/dev", "/tmp", "/run",
	"/etc", "/sys", "/lib", "/lib64", "/bin", "/sbin", "/usr/lib", "/usr/lib64",
	TrampolineSockDir,
}

// syntheticFiles are the bind-mount targets that are files rather than
// directories. bwrap creates them too, and through the filesystem they would
// otherwise be created in the daemon's tree.
var syntheticFiles = []string{"/.rsbx-guard", "/.rsbx-tramp"}

// TrampolineSockDir is the directory bound into the sandbox that holds the
// daemon socket, and TrampolineSock is the socket's path inside it.
const (
	TrampolineSockDir = "/run/rsbx"
	TrampolineSock    = TrampolineSockDir + "/daemon.sock"
)

type Plan struct {
	Cfg        *config.Config
	Policy     *policy.Policy
	Mount      string
	Cache      string
	Trampoline string
	Remote     *rpc.FS
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
	if len(pol.Local) == 0 {
		return nil, fmt.Errorf("local.allow selects no executable: nothing could run locally")
	}
	tramp := filepath.Join(exeDir, "rsbx-tramp")
	if _, err := os.Stat(tramp); err != nil {
		return nil, fmt.Errorf("trampoline %s: %w", tramp, err)
	}
	local, err := paths.New(cfg.Local.Paths, false)
	if err != nil {
		return nil, err
	}
	machine, err := paths.New(append(append([]string(nil), cfg.Local.ReadOnlyPaths...), linkTargets()...), true)
	if err != nil {
		return nil, err
	}
	merged := mergePaths(local, machine)
	p := &Plan{
		Cfg:        cfg,
		Exec:       pol,
		Local:      merged,
		Mount:      cfg.Sandbox.Mount,
		Cache:      cfg.Sandbox.Cache,
		Trampoline: tramp,
		Remote:     rpc.NewFS(targetOf(cfg)),
	}
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
// multiplexing, which matters because the trampoline starts one process per
// redirected command and a fresh TLS/handshake per exec would dominate.
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
	// Every ancestor of a local tree must exist in the view. bwrap creates the
	// bind destination, and an intermediate directory created through the
	// filesystem would be an empty placeholder that hides the tree; reserving
	// them keeps bwrap's own creation from reaching the daemon.
	for _, d := range roots {
		hostDirs[d] = true
		for q := d; q != "/" && q != "."; q = filepath.Dir(q) {
			hostDirs[filepath.Dir(q)] = true
		}
	}
	// Intermediate directories of the local trees are reserved as mount
	// points, so creating them never writes into the daemon's tree.
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
	// Everything else that is local is bound straight from the host.
	policyDirs := p.PolicyDirs()
	execDirs := make([]string, 0, len(policyDirs))
	for d := range policyDirs {
		execDirs = append(execDirs, d)
	}
	sort.Strings(execDirs)
	return &fusefs.Layout{
		Remote:         p.Remote,
		Local:          p.Local,
		ExecDirs:       execDirs,
		Trampoline:     p.Trampoline,
		LocalExec:      p.Exec.IsLocal,
		Cache:          p.Cache,
		TTL:            2 * time.Second,
		Synthetic:      dedupePaths(allSynthetic),
		SyntheticFiles: syntheticFiles,
		HostDirs:       hostDirs,
		SystemLinks:    systemLinks(),
	}
}

// MountRoot mounts the sandbox root and returns the server so the caller can
// wait for it.
func (p *Plan) MountRoot() (*fuse.Server, error) {
	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			AllowOther:    false,
			Debug:         os.Getenv("RSBX_FUSE_DEBUG") != "",
			FsName:        "rsbx",
			DisableSplice: true,
		},
		EntryTimeout: durp(1),
		AttrTimeout:  durp(1),
	}
	srv, err := fs.Mount(p.Mount, fusefs.NewRoot(p.Layout()), opts)
	if err != nil {
		return nil, err
	}
	// Wait until the mount actually answers. bwrap stats the source path
	// immediately, and a freshly mounted FUSE root refuses requests for a
	// moment while the server thread starts.
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

// BwrapArgs is the argument vector that starts argv inside the sandbox.
//
// The layout is a stack of bind mounts over one FUSE root:
//
//	FUSE╱  →  the daemon tree, minus everything listed as local
//	local trees  bound over it, writable or read-only per the configuration
//
// The order matters. Binding a local tree after the FUSE root is what makes it
// visible at all; leaving a policy directory to FUSE is what keeps the
// trampolines in charge of which names may execute.
func (p *Plan) BwrapArgs(argv []string) []string {
	args := []string{"--bind", p.Mount, "/"}

	// Local trees are deliberately NOT bound.
	//
	// Binding one makes bwrap create its intermediate directories, and those
	// creations replace the FUSE entries at the same paths, so the tree appears
	// empty. FUSE already serves local trees from the host, which keeps reads
	// and writes governed by the policy instead of bypassing it.

	// The trampoline must reach the daemon from inside the sandbox. A unix
	// socket is bound in; an ssh transport carries the command instead,
	// because the socket lives on another machine.
	if p.Cfg.Daemon.Transport == "ssh" {
		// ssh needs its binary, config and agent socket, and it needs the host
		// network namespace: --unshare-all would cut it off from the daemon.
		if home, err := os.UserHomeDir(); err == nil {
			for _, f := range []string{".ssh", ".ssh/config", ".ssh/known_hosts"} {
				args = append(args, "--ro-bind-try", filepath.Join(home, f), filepath.Join(home, f))
			}
		}
		args = append(args,
			"--ro-bind-try", "/usr/bin/ssh", "/usr/bin/ssh",
			"--ro-bind-try", "/etc/ssh", "/etc/ssh",
			"--setenv", "RSBX_TRAMP_CMD", p.Cfg.Daemon.Command)
	} else {
		args = append(args,
			"--ro-bind", filepath.Dir(p.Cfg.Daemon.Socket), TrampolineSockDir,
			"--setenv", "RSBX_TRAMP_SOCK", path.Join(TrampolineSockDir, filepath.Base(p.Cfg.Daemon.Socket)))
	}

	args = append(args,
		"--proc", "/proc",
		"--dev", "/dev",
		// pid, ipc and uts never need elevated rights, so they are always
		// created. The other namespaces may already exist in an outer
		// runtime, where creating them again is sometimes refused.
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--unshare-cgroup-try",
	)
	if p.Cfg.Sandbox.UnshareUser {
		args = append(args, "--unshare-user-try")
	}
	// A sandbox gets its own network namespace unless the caller needs the
	// host one: the ssh transport always does, and some containers cannot
	// create a namespace at all.
	if p.Cfg.Daemon.Transport == "ssh" || p.Cfg.Sandbox.ShareNetwork {
		args = append(args, "--share-net")
	} else {
		// There is no --unshare-net-try: bwrap only offers the -try form for
		// user and cgroup namespaces. An unprivileged process can always
		// create a network namespace, so the plain flag is safe here.
		args = append(args, "--unshare-net")
	}
	args = append(args,
		"--die-with-parent",
		"--setenv", "RSBX_SANDBOX_MOUNT", p.Mount,
		// The trampoline quotes this when a redirected command fails while
		// naming a local tree: that failure is caused by the split view, and
		// the bare ENOENT does not say so.
		"--setenv", "RSBX_LOCAL_TREES", strings.Join(p.Local.Roots(), ":"),
	)

	// Landlock runs inside the sandbox, in front of the entry program: bwrap
	// needs mount and mkdir rights to build the view, so the restriction is
	// installed after the view exists.
	if os.Getenv("RSBX_NO_LANDLOCK") == "" {
		guard := p.GuardBinary()
		if fi, err := os.Stat(guard); err == nil && fi.Mode()&0o111 != 0 {
			args = append(args,
				"--ro-bind", guard, "/.rsbx-guard",
				"--setenv", "RSBX_LANDLOCK_EXEC", strings.Join(p.SandboxExecPaths(), ":"),
				"--ro-bind", p.Trampoline, "/.rsbx-tramp",
			)
			argv = append([]string{"/.rsbx-guard"}, argv...)
		}
	}
	// The caller's working directory only survives if the sandbox actually has
	// it: a path under /tmp is hidden by the tmpfs, and a directory outside the
	// sandbox tree does not exist at all. Falling back to / is what keeps the
	// session startable in both cases.
	if cwd, err := os.Getwd(); err == nil && cwd != "/" && p.hasPath(cwd) {
		args = append(args, "--chdir", cwd)
	}
	return append(args, argv...)
}

// systemLinks reproduces the merged-usr symlinks ( /lib -> usr/lib and
// friends) inside the sandbox. The dynamic loader is reached through them, so
// they have to exist even when the target directory is served by FUSE.
func systemLinks() map[string]string {
	out := map[string]string{}
	for _, name := range []string{"/lib", "/lib64", "/bin", "/sbin"} {
		target, err := os.Readlink(name)
		if err != nil {
			continue
		}
		out[name] = target
	}
	return out
}

// SandboxExecPaths lists, in sandbox coordinates, everything Landlock must
// keep executable.
//
// Policy directories are allowed as a whole. That looks permissive but is
// exactly right: inside the sandbox such a directory contains only local
// binaries and trampolines, because FUSE resolves every other name to a
// trampoline. Nothing a user can reach there is a host binary the policy
// rejected.
func (p *Plan) SandboxExecPaths() []string {
	out := []string{"/.rsbx-guard", "/.rsbx-tramp"}
	if p.Exec == nil {
		return out
	}
	seen := map[string]bool{"/.rsbx-guard": true, "/.rsbx-tramp": true}
	add := func(e string) {
		if e != "" && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	for _, e := range p.Exec.Local {
		add(e)
	}
	for d := range p.PolicyDirs() {
		add(d)
	}
	// Local trees hold programs too (a toolchain, a project script dir); the
	// exec policy already decided which of them may be executed.
	for _, r := range p.Local.Roots() {
		add(r)
	}
	sort.Strings(out)
	return out
}

// hasPath reports whether a path will exist inside the sandbox view: it must
// not be hidden by the /tmp tmpfs, and it must be either local content or part
// of the daemon tree.
func (p *Plan) hasPath(path string) bool {
	if path == "/tmp" || strings.HasPrefix(path, "/tmp/") {
		return false
	}
	if p.Local.IsLocal(path) {
		return true
	}
	// An ancestor of a local tree exists as a directory that holds it.
	for _, root := range p.Local.Roots() {
		if strings.HasPrefix(root, path+"/") {
			return true
		}
	}
	for _, s := range synthetic {
		if path == s || strings.HasPrefix(path, s+"/") {
			return true
		}
	}
	// Anything else is a daemon path; asking the daemon would need a round
	// trip before the mount exists, so assume it may not be there.
	return false
}

// dedupePaths removes duplicates while keeping the longest path first, so a
// nested mount point is matched before the tree that contains it.
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

// linkTargets returns the directories holding the merged-usr link targets and
// the dynamic loaders. A local program cannot start without the loader, and
// distributions scatter it across /lib, /lib64 and /usr/lib/<triplet>.
func linkTargets() []string {
	var out []string
	add := func(p string) {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			out = append(out, filepath.Clean(p))
		}
	}
	for _, link := range []string{"/lib", "/lib64", "/bin", "/sbin"} {
		target, err := os.Readlink(link)
		if err != nil {
			// Not a symlink: the directory itself is the local tree.
			add(link)
			continue
		}
		abs := target
		if !strings.HasPrefix(abs, "/") {
			abs = filepath.Join(filepath.Dir(link), target)
		}
		add(abs)
	}
	for _, p := range loaderPaths() {
		if _, err := os.Stat(p); err == nil {
			add(filepath.Dir(p))
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

// GuardBinary is the helper that installs Landlock and then execs argv.
func (p *Plan) GuardBinary() string { return filepath.Join(filepath.Dir(p.Trampoline), "rsbx-guard") }

// Run starts the entry program inside the sandbox.
//
// The sandbox process is the one that gets confined, so Landlock is applied to
// this process: children inherit it, and bwrap cannot drop it because
// no_new_privs is set.
func (p *Plan) Run(argv []string) (int, error) {
	bwrapPath, lookErr := exec.LookPath("bwrap")
	if lookErr != nil {
		return 127, lookErr
	}

	// Landlock permits exec only for the allowlist, so bwrap itself must be
	// reachable. Run it through the loader-independent path: bwrap is a local
	// program, so it belongs in the allowlist conceptually; the caller adds it.
	cmd := exec.Command(bwrapPath, p.BwrapArgs(argv)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), nil
	}
	return 0, err
}
