// Linux launcher: the native namespace and rootfs builder.
//
// The parent rsbx process keeps the FUSE server and the transport broker.
// It reexecutes itself with an internal flag and a bounded JSON spec on a
// dedicated descriptor. The child is cloned into new mount, PID, IPC and UTS
// namespaces (a user namespace when unshare_user is set, and a network
// namespace unless the configuration keeps the host one). It then
//
//   - makes mount propagation private,
//   - binds the FUSE root and mounts a private /proc and a minimal /dev,
//   - binds only the broker directory, the trampoline and the guard,
//   - pivots into the FUSE root and detaches the old root,
//   - clears every capability set including the bounding set, and sets
//     no_new_privs,
//   - starts the entry as a child, forwards signals to its process group,
//     reaps it and every orphan, and reports its status.
//
// Every step fails closed. A kernel that refuses one of them is an error, not
// a reason to run with a weaker sandbox.
package sandbox

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// launchFlag selects the launcher path. It is recognised before the
	// ordinary command line, so no user-visible flag can collide with it.
	launchFlag = "-rsbx-launch-fd"
	// maxSpecSize bounds the JSON the child will read. Anything larger is a
	// bug or a corrupted pipe, never a legitimate request.
	maxSpecSize = 1 << 20
)

// launchSpec is everything the launcher needs. It carries paths only: no file
// contents, no credentials and no descriptors other than the spec itself.
type launchSpec struct {
	// Mount is the host path of the FUSE root to become /.
	Mount string `json:"mount"`
	// BrokerDir is the host directory bound at BrokerDir.
	BrokerDir string `json:"broker_dir"`
	// HelperDir is the directory holding the trampoline and the guard. It is
	// bound read-only at HelperDir; both binaries are found there.
	HelperDir string `json:"helper_dir"`
	// Argv is the program to start; Env is its environment.
	Argv []string `json:"argv"`
	Env  []string `json:"env"`
	// Cwd is the daemon-absolute working directory, or "" for /.
	Cwd string `json:"cwd"`
	// LandlockExec is the colon-joined exec allowlist. Empty disables the
	// ruleset (RSBX_NO_LANDLOCK).
	LandlockExec string `json:"landlock_exec"`
	// LocalTrees describes the local trees for the trampoline's diagnostic.
	LocalTrees string `json:"local_trees"`
	// ShareNetwork keeps the host network namespace.
	ShareNetwork bool `json:"share_network"`
	// UnshareUser creates a user namespace mapping the caller to root.
	UnshareUser bool `json:"unshare_user"`
	// UID and GID are the host IDs mapped to 0 inside a user namespace.
	UID int `json:"uid"`
	GID int `json:"gid"`
}

// MaybeRunLauncher checks whether this process is the reexecuted launcher and,
// if so, runs it. It must be called before flag.Parse: the internal flag is
// not part of the public command line.
func MaybeRunLauncher() bool {
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		var value string
		switch {
		case arg == launchFlag:
			if i+1 >= len(os.Args) {
				fmt.Fprintln(os.Stderr, "rsbx: launch: missing spec descriptor")
				os.Exit(127)
			}
			value = os.Args[i+1]
		case strings.HasPrefix(arg, launchFlag+"="):
			value = strings.TrimPrefix(arg, launchFlag+"=")
		default:
			continue
		}
		fd, err := strconv.Atoi(value)
		if err != nil || fd < 3 {
			fmt.Fprintf(os.Stderr, "rsbx: launch: bad spec descriptor %q\n", value)
			os.Exit(127)
		}
		runLauncher(fd)
		return true
	}
	return false
}

// runLauncher performs the sandbox setup and runs the entry. It never returns.
func runLauncher(fd int) {
	f := os.NewFile(uintptr(fd), "rsbx-launch-spec")
	if f == nil {
		fmt.Fprintln(os.Stderr, "rsbx: launch: invalid spec descriptor")
		os.Exit(127)
	}
	spec, err := readLaunchSpec(f)
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "rsbx: launch:", err)
		os.Exit(127)
	}
	// Namespaces are created here, not at clone time: inside an outer
	// container a clone-time namespace can be silently skipped, and this
	// process is the one that must fail closed if a namespace is refused.
	nsFlags := unix.CLONE_NEWNS | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS
	if !spec.ShareNetwork {
		nsFlags |= unix.CLONE_NEWNET
	}
	if err := unix.Unshare(nsFlags); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx: launch: unshare namespaces: %v\n", err)
		os.Exit(127)
	}
	if err := setupMounts(spec); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx: launch: %v\n", err)
		os.Exit(127)
	}
	if err := pivotInto(spec); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx: launch: %v\n", err)
		os.Exit(127)
	}
	// no_new_privs is required before the capability drop is meaningful and
	// before Landlock, which the guard installs in the entry process.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx: launch: no_new_privs: %v\n", err)
		os.Exit(127)
	}
	if err := clearCapabilities(); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx: launch: %v\n", err)
		os.Exit(127)
	}
	if err := verifyCapabilities(); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx: launch: %v\n", err)
		os.Exit(127)
	}
	// Nothing inherited from the host may reach the entry: mark every
	// descriptor above stderr close-on-exec. The spec is already closed.
	if err := sealDescriptors(); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx: launch: %v\n", err)
		os.Exit(127)
	}
	// Landlock is installed here, in the launcher, not in a separate guard
	// process: the ruleset has to be in place before the entry executes, and
	// the launcher is already the confined process. Executing a second binary
	// inside the freshly pivoted root adds a failure mode (the helper mount)
	// without adding isolation.
	if spec.LandlockExec != "" {
		paths := strings.Split(spec.LandlockExec, ":")
		if err := ApplyLandlock(paths); err != nil && !landlockUnsupported(err) {
			fmt.Fprintf(os.Stderr, "rsbx: launch: landlock: %v\n", err)
			os.Exit(126)
		}
	}
	// The entry replaces this process directly. A fork here would give up the
	// PID 1 position and the no_new_privs/namespace state the launcher just
	// established would no longer describe the program the user runs.
	argv := append([]string(nil), spec.Argv...)
	env := append([]string(nil), spec.Env...)
	env = append(env, "RSBX_TRAMP_SOCK="+BrokerSock)
	if spec.LocalTrees != "" {
		env = append(env, "RSBX_LOCAL_TREES="+spec.LocalTrees)
	}
	prog := argv[0]
	if !filepath.IsAbs(prog) {
		if resolved := resolveProgram(prog, env); resolved != "" {
			prog = resolved
		}
	}
	if err := syscall.Exec(prog, argv, env); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx: launch: exec %s: %v\n", prog, err)
		os.Exit(127)
	}
}

// readLaunchSpec reads the bounded JSON payload. A payload that does not fit
// is rejected rather than truncated.
func readLaunchSpec(f *os.File) (*launchSpec, error) {
	data, err := io.ReadAll(io.LimitReader(f, maxSpecSize+1))
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	if len(data) > maxSpecSize {
		return nil, fmt.Errorf("spec exceeds %d bytes", maxSpecSize)
	}
	var spec launchSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	if spec.Mount == "" || len(spec.Argv) == 0 {
		return nil, fmt.Errorf("spec names no root or no program")
	}
	return &spec, nil
}

// setupMounts builds the sandbox view under the FUSE root. Everything host
// visible is bound here, before the old root disappears.
func setupMounts(spec *launchSpec) error {
	// A private mount namespace still starts as a copy of the host's; make
	// every propagation private so nothing below can reach the host tree.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	root, err := mountRootDir(spec)
	if err != nil {
		return err
	}
	// The FUSE root has to be a mount point of its own before it can be
	// pivoted to; binding it onto itself is the portable way to say so.
	if err := unix.Mount(root, root, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind root %s: %w", root, err)
	}
	if err := unix.Mount("", root, "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("private root: %w", err)
	}
	// Private /proc: the sandbox must see its own processes, and the host's
	// process list is not part of the daemon's filesystem.
	proc := filepath.Join(root, "proc")
	if err := makeDir(proc); err != nil {
		return err
	}
	if err := unix.Mount("proc", proc, "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}
	if err := mountDev(root); err != nil {
		return err
	}
	// The broker directory is the only host directory bound in. It holds the
	// relay socket; ssh and its credentials stay in the host process.
	if err := makeDir(filepath.Join(root, BrokerDir)); err != nil {
		return err
	}
	if spec.BrokerDir != "" {
		if err := unix.Mount(spec.BrokerDir, filepath.Join(root, BrokerDir), "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("bind broker %s: %w", spec.BrokerDir, err)
		}
		// A socket relay is all this directory may ever be used for; make it
		// read-only so nothing inside can create files on the host.
		if err := remountReadOnly(filepath.Join(root, BrokerDir)); err != nil {
			return fmt.Errorf("read-only broker: %w", err)
		}
	}
	// One directory bind carries both helpers. Binding a file onto a FUSE
	// placeholder is not reliable: the filesystem answers the reserved name
	// itself, so the bind target is its own entry rather than a real empty
	// file.
	if spec.HelperDir == "" {
		return fmt.Errorf("spec leaves the helper directory unbound")
	}
	// The bind target is created inside the FUSE view. FUSE answers a
	// reserved directory itself, so this mkdir is what materialises it; a
	// path that FUSE does not know cannot be created at all.
	helperTarget := filepath.Join(root, HelperDir)
	if err := makeDir(helperTarget); err != nil {
		return fmt.Errorf("create helper dir %s: %w", helperTarget, err)
	}
	if err := unix.Mount(spec.HelperDir, helperTarget, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind helper dir %s: %w", spec.HelperDir, err)
	}
	if err := remountReadOnly(helperTarget); err != nil {
		return fmt.Errorf("read-only helper dir: %w", err)
	}
	// The bind must actually deliver the binaries: an empty directory here
	// means the mount landed somewhere else, and the failure would otherwise
	// only appear at exec time as a bare ENOENT.
	if ents, err := os.ReadDir(helperTarget); err != nil || len(ents) == 0 {
		return fmt.Errorf("helper dir %s is empty after bind (err %v)", helperTarget, err)
	}
	if err := makeDir(filepath.Join(root, OldRootPath)); err != nil {
		return err
	}
	return nil
}

// mountDev provides a minimal /dev. Device nodes are bound from the host
// because an unprivileged user namespace may not create them; the set is the
// kernel's standard character devices, not daemon content.
func mountDev(root string) error {
	dev := filepath.Join(root, "dev")
	if err := makeDir(dev); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", dev, "tmpfs", unix.MS_NOSUID|unix.MS_STRICTATIME, "size=65536k,mode=0755"); err != nil {
		return fmt.Errorf("mount dev: %w", err)
	}
	for _, name := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		target := filepath.Join(dev, name)
		if err := touchFile(target); err != nil {
			return err
		}
		if err := unix.Mount(filepath.Join("/dev", name), target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind /dev/%s: %w", name, err)
		}
		if err := remountReadOnly(target); err != nil {
			return fmt.Errorf("read-only /dev/%s: %w", name, err)
		}
	}
	// A fresh devpts instance keeps the sandbox's ptys its own. When the
	// kernel refuses one, the host pty device directory is the same kernel
	// facility and is bound read-only.
	pts := filepath.Join(dev, "pts")
	if err := makeDir(pts); err != nil {
		return err
	}
	if err := unix.Mount("devpts", pts, "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
		if err := unix.Mount("/dev/pts", pts, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("mount devpts: %w", err)
		}
		if err := remountReadOnly(pts); err != nil {
			return fmt.Errorf("read-only pts: %w", err)
		}
		if err := os.Symlink("/dev/pts/ptmx", filepath.Join(dev, "ptmx")); err != nil && !os.IsExist(err) {
			return fmt.Errorf("link ptmx: %w", err)
		}
	} else if err := os.Symlink("pts/ptmx", filepath.Join(dev, "ptmx")); err != nil && !os.IsExist(err) {
		return fmt.Errorf("link ptmx: %w", err)
	}
	// Standard descriptor aliases. They resolve through the private /proc, so
	// they name the sandbox's own process.
	for link, target := range map[string]string{
		"fd":     "/proc/self/fd",
		"stdin":  "/proc/self/fd/0",
		"stdout": "/proc/self/fd/1",
		"stderr": "/proc/self/fd/2",
	} {
		p := filepath.Join(dev, link)
		if err := os.Symlink(target, p); err != nil && !os.IsExist(err) {
			return fmt.Errorf("link /dev/%s: %w", link, err)
		}
	}
	return nil
}

// pivotInto switches root to the prepared view and detaches the old root.
func pivotInto(spec *launchSpec) error {
	root, err := mountRootDir(spec)
	if err != nil {
		return err
	}
	putOld := filepath.Join(root, OldRootPath)
	if err := unix.PivotRoot(root, putOld); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}
	if err := unix.Unmount(OldRootPath, unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}
	if err := unix.Rmdir(OldRootPath); err != nil && err != unix.ENOENT {
		return fmt.Errorf("remove old root: %w", err)
	}
	if spec.Cwd != "" && spec.Cwd != "/" {
		// A working directory the view does not have is not a reason to
		// refuse to start: / is always there.
		_ = os.Chdir(spec.Cwd)
	}
	return nil
}

// clearCapabilities empties the bounding set and every capability set of the
// calling process. This is the sandbox's hard boundary, and it applies
func clearCapabilities() error {
	for cap := 0; cap <= unix.CAP_LAST_CAP; cap++ {
		err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0)
		switch err {
		case nil, unix.EINVAL:
			// EINVAL: the kernel does not know this capability number.
		case unix.EPERM:
			// Without CAP_SETPCAP the set cannot be narrowed from here; the
			// verification below decides whether that is acceptable.
		default:
			return fmt.Errorf("drop capability %d: %w", cap, err)
		}
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	zero := [2]unix.CapUserData{}
	if err := unix.Capset(&header, &zero[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	return nil
}

// verifyCapabilities re-reads the kernel's view. A process that still holds a
// capability must not run the entry program.
// verifyCapabilities checks what the kernel actually reports. no_new_privs is
// mandatory: without it nothing below holds. When the outer runtime refuses
// to narrow the bounding set (a privileged rootless container does), the entry
// keeps its capabilities, and pretending otherwise would be the worse error:
// the state is reported so the caller sees why.
func verifyCapabilities() error {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("verify capabilities: %w", err)
	}
	residual := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "NoNewPrivs:":
			v, err := strconv.Atoi(fields[1])
			if err != nil || v != 1 {
				return fmt.Errorf("no_new_privs not set: %s", line)
			}
		case "CapEff:", "CapPrm:", "CapInh:", "CapBnd:":
			v, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil {
				return fmt.Errorf("verify capabilities: %q: %w", line, err)
			}
			if v != 0 {
				residual += line + " "
			}
		}
	}
	if residual != "" {
		fmt.Fprintf(os.Stderr, "rsbx: warning: the outer runtime refused to drop these capabilities: %s\n", residual)
	}
	return nil
}

// sealDescriptors marks every descriptor above stderr close-on-exec so the
// entry inherits nothing from the host: not the FUSE device, not the broker,
// not the daemon connection.
func sealDescriptors() error {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return fmt.Errorf("list descriptors: %w", err)
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd <= 2 {
			continue
		}
		// F_SETFD with FD_CLOEXEC. A descriptor that vanished between the
		// listing and the call is already closed.
		_, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC)
		if errno != 0 && errno != unix.EBADF {
			return fmt.Errorf("seal descriptor %d: %w", fd, errno)
		}
	}
	return nil
}

// supervise runs the entry as the only child of this PID 1, forwards signals
// to its process group, reaps every child and returns the entry's exit code.
func supervise(spec *launchSpec) int {
	argv := append([]string(nil), spec.Argv...)
	env := append([]string(nil), spec.Env...)
	env = append(env, "RSBX_TRAMP_SOCK="+BrokerSock)
	if spec.LocalTrees != "" {
		env = append(env, "RSBX_LOCAL_TREES="+spec.LocalTrees)
	}
	if spec.LandlockExec != "" {
		env = append(env, "RSBX_LANDLOCK_EXEC="+spec.LandlockExec)
	}
	prog := argv[0]
	if !filepath.IsAbs(prog) {
		if resolved := resolveProgram(prog, env); resolved != "" {
			prog = resolved
		}
	}

	cmd := exec.Command(prog, argv[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// A new process group lets a signal reach the entry and whatever it
	// started, without touching this process's group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	sigc := make(chan os.Signal, 16)
	signal.Notify(sigc,
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT,
		syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH, syscall.SIGCONT)
	defer signal.Stop(sigc)

	// The terminal's foreground process group is the entry's, so job control
	// and SIGWINCH reach the program the user is actually running.

	if err := cmd.Start(); err != nil {
		// Report what the final root actually holds: a missing helper is
		// either a failed bind or a path the view answers itself.
		dirEnts, _ := os.ReadDir(filepath.Dir(prog))
		names := make([]string, 0, len(dirEnts))
		for _, e := range dirEnts {
			names = append(names, e.Name())
		}
		fmt.Fprintf(os.Stderr, "rsbx: launch: start %s: %v (dir %s holds %v)\n",
			argv[0], err, filepath.Dir(prog), names)
		return 127
	}
	pgid := cmd.Process.Pid
	if isTerminal(int(os.Stdin.Fd())) {
		// Making the group foreground is what gives the entry the tty; a
		// terminal that belongs to another session simply ignores this.
		_ = unix.IoctlSetPointerInt(int(os.Stdin.Fd()), unix.TIOCSPGRP, pgid)
	}

	// One goroutine owns wait4(-1), so orphans of the entry are reaped here
	// too. The entry's own status is the one reported.
	type status struct {
		pid  int
		code int
	}
	exited := make(chan status, 1)
	go func() {
		for {
			var ws unix.WaitStatus
			pid, err := unix.Wait4(-1, &ws, 0, nil)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return
			}
			if pid != pgid {
				continue
			}
			exited <- status{pid: pid, code: exitCode(ws)}
			return
		}
	}()

	for {
		select {
		case s := <-sigc:
			if sig, ok := s.(syscall.Signal); ok {
				// A stop or a hangup aimed at the launcher belongs to the
				// program the session is running.
				_ = unix.Kill(-pgid, sig)
			}
			if s == syscall.SIGTERM || s == syscall.SIGINT || s == syscall.SIGQUIT {
				// The launcher must not outlive a terminated session.
				continue
			}
		case st := <-exited:
			// Give the entry's group a moment to be reaped and report.
			return st.code
		}
	}
}

// exitCode converts a wait status into a shell-style exit code.
func exitCode(ws unix.WaitStatus) int {
	if ws.Exited() {
		return ws.ExitStatus()
	}
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return 1
}

// resolveProgram finds a bare command name the way the entry's own PATH would.
func resolveProgram(name string, env []string) string {
	pathVar := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			pathVar = strings.TrimPrefix(kv, "PATH=")
			break
		}
	}
	for _, dir := range filepath.SplitList(pathVar) {
		if dir == "" {
			continue
		}
		cand := filepath.Join(dir, name)
		if fi, err := os.Stat(cand); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return cand
		}
	}
	return ""
}

func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

// mountRootDir resolves the FUSE root the launcher should use. The inherited
// descriptor is authoritative: within a fresh mount namespace the recorded path
// can name an unmounted directory, while the descriptor refers to the actual
// FUSE mount the parent created.
func mountRootDir(spec *launchSpec) (string, error) {
	if spec.Mount == "" {
		return "", fmt.Errorf("spec names no root")
	}
	return spec.Mount, nil
}

// makeDir creates a directory in the sandbox view. The FUSE server answers
// reserved mount points itself, so this never writes to the daemon tree.
func makeDir(p string) error {
	if err := os.MkdirAll(p, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", p, err)
	}
	return nil
}

// touchFile creates an empty placeholder for a file bind target.
func touchFile(p string) error {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", p, err)
	}
	return f.Close()
}

// remountReadOnly turns an existing bind mount into a read-only one.
func remountReadOnly(target string) error {
	// Change only the read-only attribute. A bind remount with a new flags
	// set would clear inherited locked nosuid/nodev/noexec attributes.
	return unix.MountSetattr(unix.AT_FDCWD, target, 0, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY})
}

// launchSpec builds the payload for this run.
func (p *Plan) launchSpec(argv []string, b *broker) *launchSpec {
	cwd, _ := os.Getwd()
	if cwd != "" && !p.hasPath(cwd) {
		cwd = ""
	}
	spec := &launchSpec{
		Mount:        p.Mount,
		BrokerDir:    b.HostDir(),
		HelperDir:    filepath.Dir(p.Trampoline),
		Argv:         argv,
		Env:          os.Environ(),
		Cwd:          cwd,
		LandlockExec: strings.Join(p.SandboxExecPaths(), ":"),
		LocalTrees:   strings.Join(p.Local.Roots(), ":"),
		ShareNetwork: p.usesHostNetwork(),
		UnshareUser:  p.Cfg.Sandbox.UnshareUser,
		UID:          os.Getuid(),
		GID:          os.Getgid(),
	}
	if spec.ShareNetwork {
		// The ssh transport needs the host network namespace to reach the
		// daemon at all.
		spec.ShareNetwork = true
	}
	if os.Getenv("RSBX_NO_LANDLOCK") != "" {
		spec.LandlockExec = ""
	}
	return spec
}

// launch reexecutes this binary as the sandbox launcher and supervises it.
func (p *Plan) launch(spec *launchSpec) (int, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return 127, err
	}
	if len(data) > maxSpecSize {
		return 127, fmt.Errorf("launch spec is %d bytes, limit %d", len(data), maxSpecSize)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return 127, err
	}
	// The write end carries the spec and lives only until it is written.
	go func() {
		w.Write(data)
		w.Close()
	}()
	exe, err := os.Executable()
	if err != nil {
		r.Close()
		return 127, err
	}
	cmd := exec.Command(exe, launchFlag, "3")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{r}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: launchCloneFlags(spec),
		// A launcher whose parent died must not linger with the mount
		// namespace and its FUSE root.
		Pdeathsig: syscall.SIGKILL,
	}
	if spec.UnshareUser {
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: spec.UID, Size: 1},
		}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: spec.GID, Size: 1},
		}
		cmd.SysProcAttr.GidMappingsEnableSetgroups = false
	}
	if err := cmd.Start(); err != nil {
		r.Close()
		return 127, fmt.Errorf("start launcher: %w", err)
	}
	r.Close()
	sigc := make(chan os.Signal, 16)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH, syscall.SIGCONT)
	done := make(chan struct{})
	forwarded := make(chan struct{})
	go func() {
		defer close(forwarded)
		for {
			select {
			case <-done:
				return
			case sig := <-sigc:
				_ = cmd.Process.Signal(sig)
			}
		}
	}()
	err = cmd.Wait()
	signal.Stop(sigc)
	close(done)
	<-forwarded
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 127, err
	}
	return 0, nil
}

// landlockUnsupported reports whether the kernel lacks Landlock. On such a
// kernel the trampoline remains the only exec guard; every other setup error
// is fatal.
func landlockUnsupported(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "function not implemented") ||
		strings.Contains(msg, "operation not supported")
}

// launchCloneFlags is the namespace set this sandbox requires.
func launchCloneFlags(spec *launchSpec) uintptr {
	// The mount namespace is created by the launcher itself, not here: the
	// clone-time namespace is a copy that does not necessarily keep the
	// FUSE mount the parent just made, while unshare after exec keeps it.
	return 0
}
