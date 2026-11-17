//go:build linux

// The controller passes a pinned FUSE root and immutable native assets to
// this reexecuted launcher. Linux creates the user and PID namespaces during
// child setup, before any Go runtime thread exists. The launcher remains PID
// 1: it builds the private view, traces every descendant exec, forwards
// signals, and reaps the session. Every mandatory restriction fails closed.
package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	launchFlag   = "-rsbx-launch-fd"
	maxSpecSize  = 16 << 20
	specFD       = 3
	rootFD       = 4
	assetDirFD   = 5
	sessionGrace = 2 * time.Second
)

// launchSpec is everything the launcher needs. It carries paths and exact
// identities only: no file contents, no credentials, no transport details.
type launchSpec struct {
	Mount string `json:"mount"`
	// RootFD pins the FUSE root inode; RootDev/RootIno let the launcher
	// verify the inherited descriptor names the controller's actual mount.
	RootFD  int    `json:"root_fd"`
	RootDev uint64 `json:"root_dev"`
	RootIno uint64 `json:"root_ino"`
	// BrokerDir is the host directory bound at the reserved broker path.
	BrokerDir string `json:"broker_dir"`
	// HelperDir is diagnostic; AssetDirFD pins the immutable directory bound
	// at the reserved HelperDir, holding the helpers and the asset copies.
	HelperDir  string      `json:"helper_dir"`
	AssetDirFD int         `json:"asset_dir_fd"`
	Assets     []execAsset `json:"assets"`
	// Target starts as the caller's executable spelling. PID 1 resolves it
	// against the final sandbox view; Argv preserves the original argv[0].
	Target     string   `json:"target"`
	Argv       []string `json:"argv"`
	Env        []string `json:"env"`
	Cwd        string   `json:"cwd"`
	ManageTTY  bool     `json:"manage_tty"`
	TerminalFD int      `json:"terminal_fd"`
	// ExecPaths are the exact Landlock grants; LocalAllow alone selects
	// local invocation. RuntimePaths are read-only dependencies and never
	// independently authorize a command.
	ExecPaths    []string      `json:"exec_paths"`
	LocalAllow   []string      `json:"local_allow"`
	RuntimePaths []string      `json:"runtime_paths"`
	Scripts      []scriptChain `json:"scripts"`
	UnshareUser  bool          `json:"unshare_user"`
	// UID and GID are the host IDs mapped to 0 inside a user namespace.
	UID int `json:"uid"`
	GID int `json:"gid"`
	// NamespaceIDs is captured from the pinned controller thread: /proc/ppid
	// is useless once the launcher is alone in its PID namespace.
	NamespaceIDs map[string]string `json:"namespace_ids"`
}

// MaybeRunLauncher checks whether this process is the reexecuted launcher
// and, if so, runs it. It must be called before flag.Parse: the internal
// flag is not part of the public command line.
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

// runLauncher is entered before public flag parsing. It pins its OS thread
// before the first per-thread syscall: mounting, privileges, and ptrace must
// belong to this same thread rather than whichever thread the scheduler
// chooses next.
func runLauncher(fd int) {
	runtime.LockOSThread()
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, "rsbx: launch:", err)
		os.Exit(126)
	}
	f := os.NewFile(uintptr(fd), "rsbx-launch-spec")
	if f == nil {
		fail(fmt.Errorf("invalid spec descriptor"))
	}
	spec, err := readLaunchSpec(f)
	f.Close()
	if err != nil {
		fail(err)
	}
	if err := verifyNamespaces(spec); err != nil {
		fail(err)
	}
	root, err := pinnedRoot(spec)
	if err != nil {
		fail(err)
	}
	if err := setupMounts(spec, root); err != nil {
		fail(err)
	}
	if err := pivotInto(spec, root); err != nil {
		fail(err)
	}
	root.Close()
	unix.Close(spec.AssetDirFD)
	if err := resolveEntryTarget(spec); err != nil {
		fmt.Fprintln(os.Stderr, "rsbx: entry:", err)
		os.Exit(127)
	}
	if err := verifyPrivateProc(); err != nil {
		fail(err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fail(fmt.Errorf("no_new_privs: %w", err))
	}
	// PID 1 retains the authority needed to trace its children. Descendants
	// receive no such authority: their pinned guard clears and verifies every
	// capability set before the first untrusted instruction.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		fail(fmt.Errorf("disable supervisor dumping: %w", err))
	}
	if err := verifyThreadState(); err != nil {
		fail(err)
	}
	if err := sealDescriptors(); err != nil {
		fail(err)
	}
	gateway, err := newGatewayServer(GatewayRequestSock)
	if err != nil {
		fail(err)
	}
	// The socket's dentry must not be removable or replaceable by a sandbox
	// process. devpts is a separate mount and remains usable for private
	// PTYs.
	if err := protectDevMount("/dev"); err != nil {
		gateway.Close()
		fail(fmt.Errorf("protect gateway socket: %w", err))
	}
	code, err := runTraced(spec, gateway)
	gateway.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "rsbx: launch:", err)
		code = 126
	}
	os.Exit(code)
}

// pinnedRoot returns the inherited O_PATH descriptor naming the FUSE root.
// The descriptor plus its device and inode, not the recorded path, is the
// authoritative identity: a remounted or replaced host path cannot
// substitute a different tree.
func pinnedRoot(spec *launchSpec) (*os.File, error) {
	if spec.RootFD != rootFD {
		return nil, fmt.Errorf("unexpected root descriptor %d", spec.RootFD)
	}
	f := os.NewFile(uintptr(spec.RootFD), "rsbx-root")
	var st unix.Stat_t
	if err := unix.Fstat(spec.RootFD, &st); err != nil {
		return nil, fmt.Errorf("stat pinned root: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(st.Dev) != spec.RootDev || st.Ino != spec.RootIno {
		return nil, fmt.Errorf("pinned root identity differs from the controller's root")
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(spec.RootFD, &fs); err != nil {
		return nil, err
	}
	if uint64(fs.Type) != unix.FUSE_SUPER_MAGIC {
		return nil, fmt.Errorf("pinned root is not the prepared FUSE mount")
	}
	return f, nil
}

// rootFDPath names the pinned root through its descriptor. Mount sources
// resolve the descriptor's file, never a path that could have been replaced.
func rootFDPath() string { return fmt.Sprintf("/proc/self/fd/%d", rootFD) }

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
	if !filepath.IsAbs(spec.Mount) || spec.Target == "" || len(spec.Argv) == 0 {
		return nil, fmt.Errorf("spec names no absolute root or no program")
	}
	if len(spec.ExecPaths) == 0 || len(spec.LocalAllow) == 0 {
		return nil, fmt.Errorf("spec carries no executable policy")
	}
	if spec.RootFD != rootFD || spec.AssetDirFD != assetDirFD {
		return nil, fmt.Errorf("spec lacks the pinned root or asset descriptors")
	}
	if len(spec.NamespaceIDs) != len(namespaceNames) || len(spec.Assets) == 0 {
		return nil, fmt.Errorf("spec lacks namespace identities or native assets")
	}
	return &spec, nil
}

var namespaceNames = []string{"mnt", "pid", "ipc", "uts", "net", "user"}

// launchAttrs is the clone-time namespace contract. Linux creates the PID
// and user namespaces at fork; Go's single-threaded child setup applies the
// remaining namespaces through Unshareflags, which exec's error pipe reports
// exactly. Nothing namespace-shaped happens later in the Go runtime, where
// a multi-threaded unshare would silently produce no private PID view.
func launchAttrs(spec *launchSpec) *syscall.SysProcAttr {
	a := &syscall.SysProcAttr{
		Cloneflags:   unix.CLONE_NEWPID,
		Unshareflags: unix.CLONE_NEWNS | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS,
		// A launcher whose controller died must not linger with the mount
		// namespace and its FUSE root.
		Pdeathsig: syscall.SIGKILL,
	}
	if spec.UnshareUser {
		a.Cloneflags |= unix.CLONE_NEWUSER
		a.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: spec.UID, Size: 1}}
		a.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: spec.GID, Size: 1}}
		a.GidMappingsEnableSetgroups = false
	}
	return a
}

// captureNamespaces records the controller thread's namespace identities.
// The launcher compares its own against these: private namespaces must
// differ, shared ones must match.
func captureNamespaces() (map[string]string, error) {
	ids := make(map[string]string, len(namespaceNames))
	for _, name := range namespaceNames {
		id, err := os.Readlink("/proc/thread-self/ns/" + name)
		if err != nil {
			return nil, fmt.Errorf("capture %s namespace: %w", name, err)
		}
		ids[name] = id
	}
	return ids, nil
}

// verifyNamespaces re-reads the kernel's namespace membership and refuses
// to continue if any required namespace is shared with the controller, or
// any shared one was replaced.
func verifyNamespaces(spec *launchSpec) error {
	if os.Getpid() != 1 {
		return fmt.Errorf("launcher pid is %d, not PID 1 in a private namespace", os.Getpid())
	}
	for _, name := range namespaceNames {
		baseline := spec.NamespaceIDs[name]
		if baseline == "" {
			return fmt.Errorf("no controller identity for %s namespace", name)
		}
		own, err := os.Readlink("/proc/thread-self/ns/" + name)
		if err != nil {
			return fmt.Errorf("read %s namespace: %w", name, err)
		}
		// The network namespace is always shared: it is the caller's, so a
		// program's egress follows the machine it runs on.
		private := (name != "net" && name != "user") ||
			(name == "user" && spec.UnshareUser)
		if (own != baseline) != private {
			return fmt.Errorf("unexpected %s namespace membership: %s (controller %s)", name, own, baseline)
		}
	}
	if spec.UnshareUser {
		if os.Getuid() != 0 || os.Getgid() != 0 {
			return fmt.Errorf("user namespace did not map the caller to uid/gid 0")
		}
		for _, m := range []struct {
			name string
			host int
		}{{"uid_map", spec.UID}, {"gid_map", spec.GID}} {
			data, err := os.ReadFile("/proc/thread-self/" + m.name)
			if err != nil {
				return err
			}
			fields := strings.Fields(string(data))
			if len(fields) != 3 || fields[0] != "0" || fields[1] != strconv.Itoa(m.host) || fields[2] != "1" {
				return fmt.Errorf("unexpected %s: %s", m.name, strings.TrimSpace(string(data)))
			}
		}
	}
	return nil
}

// verifyPrivateProc confirms /proc is this session's read-only procfs and
// that it sees the supervisor as PID 1: both the private PID view and its
// process listing are then proven, not assumed.
func verifyPrivateProc() error {
	var st unix.Statfs_t
	if err := unix.Statfs("/proc", &st); err != nil {
		return err
	}
	if uint64(st.Type) != unix.PROC_SUPER_MAGIC || st.Flags&unix.ST_RDONLY == 0 {
		return fmt.Errorf("private /proc is not a read-only procfs mount")
	}
	fd, writeErr := unix.Open("/proc/thread-self/mem", unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if writeErr == nil {
		unix.Close(fd)
		return fmt.Errorf("private procfs permits writable process-memory descriptors")
	}
	data, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "Tgid:" && fields[1] == "1" {
			return nil
		}
	}
	return fmt.Errorf("private procfs does not identify the supervisor as PID 1")
}

// verifyThreadState re-reads the kernel's view of this thread's privilege
// state. no_new_privs and non-dumpable are mandatory; without them nothing
// the session does holds.
func verifyThreadState() error {
	data, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return fmt.Errorf("read launcher thread privileges: %w", err)
	}
	var nnp bool
	for _, line := range strings.Split(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "NoNewPrivs:" {
			nnp = fields[1] == "1"
		}
	}
	if !nnp {
		return fmt.Errorf("launcher thread has no_new_privs unset")
	}
	dump, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_GET_DUMPABLE, 0, 0, 0, 0, 0)
	if errno != 0 || dump != 0 {
		return fmt.Errorf("supervisor remains dumpable (value %d, error %v)", dump, errno)
	}
	return nil
}

// setupMounts builds the sandbox view under the pinned FUSE root. Everything
// host visible is bound here, before the old root disappears.
func setupMounts(spec *launchSpec, root *os.File) error {
	// A private mount namespace still starts as a copy of the host's; make
	// every propagation private so nothing below can reach the host tree.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	// A bind source or destination handed to mount(2) must resolve to a mount
	// object attached in the calling mount namespace; the controller's
	// inherited descriptor names its own namespace's object, and using it as
	// the destination produced EINVAL in the observed smoke run. The
	// descriptor remains the identity authority: the namespace-local mount at
	// spec.Mount must first prove the same device/inode and FUSE superblock.
	rootPath := "/" + strings.TrimPrefix(filepath.Clean(spec.Mount), "/")
	if err := verifyRootMount(rootPath, spec); err != nil {
		return err
	}
	// Bind the verified namespace-local mount onto its own path so it becomes
	// a child-attached mount point, then re-pin rootFD to that object. Later
	// /proc/self/fd/4/... resolutions and pivot_root then name this namespace.
	if err := unix.Mount(rootPath, rootPath, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind root %s: %w", rootPath, err)
	}
	if err := repinRootFD(rootPath, spec); err != nil {
		return err
	}
	if err := unix.Mount("", rootPath, "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("private root: %w", err)
	}
	// Private /proc, read-only: the sandbox sees its own processes and
	// cannot remount it to change what the supervisor relies on.
	proc := filepath.Join(rootPath, "proc")
	if err := makeDir(proc); err != nil {
		return err
	}
	if err := unix.Mount("proc", proc, "proc", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}
	if err := mountDev(rootPath); err != nil {
		return err
	}
	// The broker directory is the only host directory bound in. It holds
	// the relay socket; ssh and its credentials stay in the host process.
	if err := makeDir(filepath.Join(rootPath, BrokerDir)); err != nil {
		return err
	}
	if spec.BrokerDir != "" {
		if err := unix.Mount(spec.BrokerDir, filepath.Join(rootPath, BrokerDir), "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("bind broker %s: %w", spec.BrokerDir, err)
		}
		if err := remountReadOnly(filepath.Join(rootPath, BrokerDir)); err != nil {
			return fmt.Errorf("read-only broker: %w", err)
		}
	}
	// One pinned directory carries both helpers and every native exec asset.
	if spec.HelperDir == "" {
		return fmt.Errorf("spec leaves the helper directory unbound")
	}
	helperTarget := filepath.Join(rootPath, HelperDir)
	if err := makeDir(helperTarget); err != nil {
		return fmt.Errorf("create helper dir %s: %w", helperTarget, err)
	}
	// The inherited descriptor names the controller's vfsmount, like the root,
	// so it stays the identity authority while the bind source is the
	// namespace-local copy of that same directory.
	if err := verifyAssetDir(spec); err != nil {
		return err
	}
	if err := unix.Mount(spec.HelperDir, helperTarget, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind helper dir: %w", err)
	}
	// Re-pin the descriptor to the child-attached helper mount: every later
	// /proc/self/fd/<AssetDirFD>/<asset> source then resolves through this
	// namespace rather than the parent's mount object.
	if err := repinAssetDirFD(helperTarget, spec); err != nil {
		return err
	}
	if err := remountReadOnly(helperTarget); err != nil {
		return fmt.Errorf("read-only helper dir: %w", err)
	}
	if ents, err := os.ReadDir(helperTarget); err != nil || len(ents) == 0 {
		return fmt.Errorf("helper dir %s is empty after bind (err %v)", helperTarget, err)
	}
	// Only exact program/runtime policy files receive native immutable
	// overlays. Remote executable bytes are never replaced by a gateway.
	if err := bindExecAssets(rootPath, spec); err != nil {
		return err
	}
	if err := makeDir(filepath.Join(rootPath, OldRootPath)); err != nil {
		return err
	}
	return nil
}

// bindExecAssets overlays each policy path with its immutable copy.
func bindExecAssets(rootPath string, spec *launchSpec) error {
	for _, a := range spec.Assets {
		target := filepath.Join(rootPath, a.Path)
		var st unix.Stat_t
		if err := unix.Stat(target, &st); err != nil {
			return fmt.Errorf("stat native target %s: %w", a.Path, err)
		}
		if uint64(st.Dev) == a.Dev && st.Ino == a.Ino {
			continue
		}
		if err := verifyAssetBytes(target, a); err != nil {
			return err
		}
		// Before pivot, sources must name the inherited host descriptor,
		// not an unprefixed /.rsbx-helpers path in the old root.
		src := fmt.Sprintf("/proc/self/fd/%d/%s", spec.AssetDirFD, a.Name)
		if err := unix.Mount(src, target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind native asset %s: %w", a.Path, err)
		}
		if err := remountReadOnly(target); err != nil {
			return fmt.Errorf("protect native asset %s: %w", a.Path, err)
		}
		if err := unix.Stat(target, &st); err != nil {
			return err
		}
		if uint64(st.Dev) != a.Dev || st.Ino != a.Ino {
			return fmt.Errorf("native asset %s carries a different inode", a.Path)
		}
	}
	return nil
}

// mountDev provides a minimal /dev. Device nodes are bound from the host
// because an unprivileged user namespace may not create them; the set is
// the kernel's standard character devices, not daemon content. The gateway
// socket lands here before the launcher remounts the whole tmpfs read-only.
func mountDev(root string) error {
	dev := filepath.Join(root, "dev")
	if err := makeDir(dev); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", dev, "tmpfs", unix.MS_NOSUID|unix.MS_STRICTATIME, "size=65536k,mode=0755"); err != nil {
		return fmt.Errorf("mount dev: %w", err)
	}
	devfd, err := unix.Open(dev, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open dev dir: %w", err)
	}
	defer unix.Close(devfd)
	via := func(name string) string {
		return fmt.Sprintf("/proc/self/fd/%d/%s", devfd, name)
	}
	for _, name := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		if err := unix.Mknodat(devfd, name, unix.S_IFREG|0o600, 0); err != nil && err != unix.EEXIST {
			return fmt.Errorf("create /dev/%s: %w", name, err)
		}
		if err := unix.Mount(filepath.Join("/dev", name), via(name), "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind /dev/%s: %w", name, err)
		}
		// Device submounts must remain device-capable. Applying nodev here
		// would make /dev/null, randomness, and terminal opens fail.
		if err := unix.MountSetattr(unix.AT_FDCWD, via(name), 0, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID}); err != nil {
			return fmt.Errorf("read-only /dev/%s: %w", name, err)
		}
	}
	// A private devpts instance is mandatory. Binding the host instance after
	// an error would expose unrelated terminals and weaken this namespace.
	pts := filepath.Join(dev, "pts")
	if err := makeDir(pts); err != nil {
		return err
	}
	if err := unix.Mount("devpts", pts, "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return fmt.Errorf("mount private devpts: %w", err)
	}
	if err := os.Symlink("pts/ptmx", filepath.Join(dev, "ptmx")); err != nil && !os.IsExist(err) {
		return fmt.Errorf("link private ptmx: %w", err)
	}
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
func pivotInto(spec *launchSpec, _ *os.File) error {
	rootPath := "/" + strings.TrimPrefix(filepath.Clean(spec.Mount), "/")
	putOld := filepath.Join(rootPath, OldRootPath)
	if err := unix.PivotRoot(rootPath, putOld); err != nil {
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
		// A working directory the view does not have is a start failure:
		// silently landing in / would run the entry somewhere the caller
		// never asked for.
		if err := os.Chdir(spec.Cwd); err != nil {
			return fmt.Errorf("entry cwd %s: %w", spec.Cwd, err)
		}
	}
	return nil
}

// sealDescriptors marks every descriptor above stderr close-on-exec so the
// entry inherits nothing from the host: not the FUSE device, not the
// broker, not the daemon connection.
func sealDescriptors() error {
	for fd := range 3 {
		name, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err == nil && (strings.HasSuffix(name, "/mem") || strings.HasSuffix(name, "/mem (deleted)")) {
			return fmt.Errorf("standard descriptor %d exposes process memory", fd)
		}
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return fmt.Errorf("list descriptors: %w", err)
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd <= 2 {
			continue
		}
		_, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC)
		if errno != 0 && errno != unix.EBADF {
			return fmt.Errorf("seal descriptor %d: %w", fd, errno)
		}
	}
	return nil
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

// resolveProgram finds a bare command name the way the entry's own PATH
// would. It searches only the requested environment, inside the sandbox
// view, and reports the real failure instead of guessing a host location.
func resolveProgram(name string, env []string) (string, error) {
	pathVar, found := "", false
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, "PATH="); ok {
			pathVar, found = rest, true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("entry %q cannot be resolved: the request has no PATH", name)
	}
	var lastErr error
	for _, dir := range strings.Split(pathVar, ":") {
		if dir == "" {
			dir = "."
		}
		cand := filepath.Join(dir, name)
		fi, err := os.Stat(cand)
		if err != nil {
			lastErr = err
			continue
		}
		if !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
			lastErr = fmt.Errorf("entry candidate %s is not a regular executable file", cand)
			continue
		}
		abs, err := filepath.Abs(cand)
		if err != nil {
			return "", err
		}
		return abs, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("PATH is empty")
	}
	return "", fmt.Errorf("entry %q is not executable on the sandbox PATH: %w", name, lastErr)
}

func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

// verifyRootMount proves the namespace-local path spec.Mount names the same
// FUSE tree as the controller's inherited descriptor. Only this path may be
// used as a mount source: the descriptor's own vfsmount belongs to the parent
// mount namespace, and mount(2) rejects such a source with EINVAL.
func verifyRootMount(rootPath string, spec *launchSpec) error {
	var st unix.Stat_t
	if err := unix.Stat(rootPath, &st); err != nil {
		return fmt.Errorf("stat sandbox root %s: %w", rootPath, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(st.Dev) != spec.RootDev || st.Ino != spec.RootIno {
		return fmt.Errorf("sandbox root %s is not the controller's pinned root", rootPath)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(rootPath, &fs); err != nil {
		return fmt.Errorf("stat filesystem of %s: %w", rootPath, err)
	}
	if uint64(fs.Type) != unix.FUSE_SUPER_MAGIC {
		return fmt.Errorf("sandbox root %s is not on the prepared FUSE mount", rootPath)
	}
	return nil
}

// repinRootFD replaces the inherited descriptor with one naming the mount
// object just attached in this namespace. Every later /proc/self/fd/4 target
// (proc, dev, helpers, assets) and pivot_root then resolves through the child
// mount instead of the parent's, and the same device/inode/FUSE identity is
// re-verified against the pinned controller values before it is installed.
func repinRootFD(rootPath string, spec *launchSpec) error {
	fd, err := unix.Open(rootPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open child-attached root %s: %w", rootPath, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return fmt.Errorf("stat child-attached root: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(st.Dev) != spec.RootDev || st.Ino != spec.RootIno {
		unix.Close(fd)
		return fmt.Errorf("child-attached root %s has a different identity", rootPath)
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		unix.Close(fd)
		return err
	}
	if uint64(fs.Type) != unix.FUSE_SUPER_MAGIC {
		unix.Close(fd)
		return fmt.Errorf("child-attached root %s is not the prepared FUSE mount", rootPath)
	}
	if err := unix.Dup3(fd, rootFD, unix.O_CLOEXEC); err != nil {
		unix.Close(fd)
		return fmt.Errorf("replace root descriptor: %w", err)
	}
	return unix.Close(fd)
}

// verifyAssetDir proves the namespace-local helper directory the launcher
// binds is the same directory as the controller's inherited descriptor. The
// descriptor remains the authority; it just cannot be a mount source.
func verifyAssetDir(spec *launchSpec) error {
	var pinned unix.Stat_t
	if err := unix.Fstat(spec.AssetDirFD, &pinned); err != nil {
		return fmt.Errorf("stat pinned asset directory: %w", err)
	}
	var local unix.Stat_t
	if err := unix.Stat(spec.HelperDir, &local); err != nil {
		return fmt.Errorf("stat helper directory %s: %w", spec.HelperDir, err)
	}
	if local.Mode&unix.S_IFMT != unix.S_IFDIR || pinned.Mode&unix.S_IFMT != unix.S_IFDIR ||
		uint64(local.Dev) != uint64(pinned.Dev) || local.Ino != pinned.Ino {
		return fmt.Errorf("helper directory %s is not the controller's pinned asset directory", spec.HelperDir)
	}
	return nil
}

// repinAssetDirFD replaces the inherited asset-directory descriptor with one
// naming the child-attached helper mount, after re-verifying the identity the
// controller pinned. Native asset bind sources then resolve in this namespace.
func repinAssetDirFD(helperTarget string, spec *launchSpec) error {
	var pinned unix.Stat_t
	if err := unix.Fstat(spec.AssetDirFD, &pinned); err != nil {
		return fmt.Errorf("stat pinned asset directory: %w", err)
	}
	fd, err := unix.Open(helperTarget, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open child-attached helper dir %s: %w", helperTarget, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return fmt.Errorf("stat child-attached helper dir: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(st.Dev) != uint64(pinned.Dev) || st.Ino != pinned.Ino {
		unix.Close(fd)
		return fmt.Errorf("child-attached helper dir %s has a different identity", helperTarget)
	}
	if err := unix.Dup3(fd, spec.AssetDirFD, unix.O_CLOEXEC); err != nil {
		unix.Close(fd)
		return fmt.Errorf("replace asset directory descriptor: %w", err)
	}
	return unix.Close(fd)
}

// makeDir creates a directory in the sandbox view. The FUSE server answers
// reserved mount points itself, so this never writes to the daemon tree.
func makeDir(p string) error {
	if err := os.MkdirAll(p, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", p, err)
	}
	return nil
}

// remountReadOnly hardens an existing bind mount: read-only, nosuid and
// nodev in one locked attribute change.
func remountReadOnly(target string) error {
	attr := &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV}
	return unix.MountSetattr(unix.AT_FDCWD, target, 0, attr)
}

// protectDevMount makes /dev read-only without nodev: the character devices
// bound beneath it must stay usable, and nodev on the containing tmpfs would
// also apply to any file the sandbox could create there.
func protectDevMount(target string) error {
	attr := &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID}
	return unix.MountSetattr(unix.AT_FDCWD, target, 0, attr)
}

// launchSpec builds the payload for this run.
func (p *Plan) launchSpec(argv []string, b *broker) *launchSpec {
	cwd, _ := os.Getwd()
	if cwd != "" && !p.hasPath(cwd) {
		cwd = ""
	}
	target := ""
	if len(argv) > 0 {
		target = argv[0]
	}
	spec := &launchSpec{
		Mount:       p.Mount,
		RootFD:      rootFD,
		AssetDirFD:  assetDirFD,
		BrokerDir:   b.HostDir(),
		HelperDir:   filepath.Dir(p.Trampoline),
		Target:      target,
		Argv:        append([]string(nil), argv...),
		Env:         os.Environ(),
		Cwd:         cwd,
		ExecPaths:   p.SandboxExecPaths(),
		UnshareUser: p.Cfg.Sandbox.UnshareUser,
		UID:         os.Getuid(),
		GID:         os.Getgid(),
	}
	if p.Exec != nil {
		spec.LocalAllow = p.Exec.ExecPaths()
		spec.RuntimePaths = p.Exec.RuntimePaths()
		seen := map[string]bool{}
		for _, list := range [][]string{spec.LocalAllow, spec.RuntimePaths} {
			for _, e := range list {
				if seen[e] {
					continue
				}
				seen[e] = true
				if interp, args, ok := p.Exec.InterpreterFor(e); ok {
					spelling, _ := p.Exec.InterpreterSpellingFor(e)
					c := scriptChain{Script: e, Interp: interp, Spelling: spelling, InterpArgs: args}
					if envInterp, envArgs, env := p.Exec.EnvInterpreterFor(e); env {
						c.Env, c.EnvInterp, c.EnvArgs = true, envInterp, envArgs
					}
					spec.Scripts = append(spec.Scripts, c)
				}
			}
		}
	}
	return spec
}

// Pin Start through Wait: Linux Pdeathsig tracks the creating OS thread,
// not a Go goroutine that could otherwise move to a retiring runtime
// thread.
func (p *Plan) launch(ctx context.Context, spec *launchSpec) (code int, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ctx.Err(); err != nil {
		return 127, err
	}
	if spec.Target == "" || len(spec.Argv) == 0 {
		return 127, fmt.Errorf("entry names no executable")
	}
	ids, err := captureNamespaces()
	if err != nil {
		return 127, err
	}
	spec.NamespaceIDs = ids
	root, err := unix.Open(p.Mount, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 127, fmt.Errorf("pin sandbox root: %w", err)
	}
	rootF := os.NewFile(uintptr(root), "rsbx-root")
	defer rootF.Close()
	var st unix.Stat_t
	if err := unix.Fstat(root, &st); err != nil {
		return 127, err
	}
	spec.RootDev, spec.RootIno = uint64(st.Dev), st.Ino
	assets, err := captureExecAssets(ctx, p, spec)
	if err != nil {
		return 127, err
	}
	defer assets.Close()
	ttyFD, oldGroup := -1, 0
	for fd := range 3 {
		group, owned, err := terminalOwnership(fd)
		if err != nil {
			return 127, err
		}
		if owned {
			ttyFD, oldGroup = fd, group
			spec.ManageTTY, spec.TerminalFD = true, fd
			break
		}
	}
	data, err := json.Marshal(spec)
	if err != nil {
		return 127, err
	}
	if len(data) > maxSpecSize {
		return 127, fmt.Errorf("launch spec exceeds %d bytes", maxSpecSize)
	}
	specFile, err := sealedPayload("rsbx-launch", data)
	if err != nil {
		return 127, err
	}
	defer specFile.Close()
	exe, err := os.Executable()
	if err != nil {
		return 127, err
	}
	cmd := exec.Command(exe, launchFlag, strconv.Itoa(specFD))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{specFile, rootF, assets.dir}
	cmd.SysProcAttr = launchAttrs(spec)
	if err := cmd.Start(); err != nil {
		return 127, fmt.Errorf("start sandbox PID 1: %w", err)
	}
	if ttyFD >= 0 {
		defer func() {
			if restoreErr := setTerminalGroup(ttyFD, oldGroup); restoreErr != nil {
				err = errors.Join(err, fmt.Errorf("restore controlling terminal: %w", restoreErr))
			}
		}()
	}
	sigc := make(chan os.Signal, 16)
	signal.Notify(sigc, forwardedSignals...)
	done, forwarded := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(forwarded)
		var timer *time.Timer
		var kill <-chan time.Time
		cancel := ctx.Done()
		defer func() {
			if timer != nil {
				timer.Stop()
			}
		}()
		terminate := func(sig os.Signal) {
			_ = cmd.Process.Signal(sig)
			if timer == nil {
				timer = time.NewTimer(sessionGrace + 500*time.Millisecond)
				kill = timer.C
			}
		}
		for {
			select {
			case <-done:
				return
			case <-cancel:
				cancel = nil
				terminate(syscall.SIGTERM)
			case sig := <-sigc:
				if terminatingSignal(sig) {
					terminate(sig)
				} else {
					_ = cmd.Process.Signal(sig)
				}
			case <-kill:
				kill = nil
				_ = cmd.Process.Kill()
			}
		}
	}()
	err = cmd.Wait()
	signal.Stop(sigc)
	close(done)
	<-forwarded
	code = 0
	if cmd.ProcessState != nil {
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			code = exitCode(unix.WaitStatus(status))
		}
	}
	if ctx.Err() != nil {
		return code, ctx.Err()
	}
	if _, ok := err.(*exec.ExitError); ok {
		return code, nil
	}
	return code, err
}

var forwardedSignals = []os.Signal{
	syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT,
	syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH, syscall.SIGCONT,
	syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU,
}

func terminatingSignal(sig os.Signal) bool {
	return sig == syscall.SIGTERM || sig == syscall.SIGINT ||
		sig == syscall.SIGQUIT || sig == syscall.SIGHUP
}
