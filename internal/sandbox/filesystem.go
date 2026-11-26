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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"rsbx/internal/config"
)

const filesystemFlag = "-rsbx-filesystem-fd"

// filesystemSpec freezes the configuration's expanded paths. The worker owns
// FUSE and host descriptors, but never joins the entry's namespaces or root.
type filesystemSpec struct {
	Config    config.Config `json:"config"`
	ExeDir    string        `json:"exe_dir"`
	Mount     string        `json:"mount"`
	Cache     string        `json:"cache"`
	SessionID string        `json:"session_id"`
	// Session is the token the controller allocated for this session. The
	// worker's filesystem connection must answer for the same session as the
	// commands the sandbox runs, so it cannot mint its own.
	Session string `json:"session"`
	// Resources pins the directories the controller allocated for this
	// session, so the worker can release them even when the controller is
	// killed and never runs its own cleanup.
	Resources    []sessionResource `json:"resources"`
	RuntimePaths []string          `json:"runtime_paths"`
}

type filesystemReady struct {
	SessionID string `json:"session_id"`
	Error     string `json:"error,omitempty"`
}

type filesystemWorker struct {
	cmd     *exec.Cmd
	control *os.File
	done    chan struct{}
	waitErr error // published by closing done
	once    sync.Once
	stopErr error
}

// sessionDirPrefix is the only prefix allocateSession gives a session
// directory. Cleanup refuses anything else, so the configuration's own cache
// base, its shared asset store, and other sessions' directories are never
// candidates for removal.
const sessionDirPrefix = "session-"

// sessionResource pins one per-session directory the controller allocated: the
// canonical base it lives under, the allocated name, the base's own identity,
// the directory's identity, and whether the directory is disposable scratch.
// The worker removes a resource only while base, name and identity still match
// what the controller allocated.
type sessionResource struct {
	Base    string `json:"base"`
	Name    string `json:"name"`
	BaseDev uint64 `json:"base_dev"`
	BaseIno uint64 `json:"base_ino"`
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	Tree    bool   `json:"tree"`
}

// newSessionResource accepts only a directory the session allocated directly
// below a configured base, and records its identity while nothing else can be
// running in it.
func newSessionResource(base, path string) (sessionResource, error) {
	if base == "" || path == "" {
		return sessionResource{}, errors.New("session resource has no base or path")
	}
	name := filepath.Base(path)
	if !strings.HasPrefix(name, sessionDirPrefix) {
		return sessionResource{}, fmt.Errorf("session resource %s is not an allocated session directory", path)
	}
	if filepath.Clean(path) != filepath.Join(filepath.Clean(base), name) {
		return sessionResource{}, fmt.Errorf("session resource %s is not directly below %s", path, base)
	}
	canonicalBase, err := resolvedPath(base)
	if err != nil {
		return sessionResource{}, err
	}
	bfi, err := os.Lstat(canonicalBase)
	if err != nil {
		return sessionResource{}, fmt.Errorf("inspect session base %s: %w", canonicalBase, err)
	}
	baseDev, baseIno, err := dirIdentity(bfi)
	if err != nil {
		return sessionResource{}, fmt.Errorf("session base %s: %w", canonicalBase, err)
	}
	full := filepath.Join(canonicalBase, name)
	fi, err := os.Lstat(full)
	if err != nil {
		return sessionResource{}, fmt.Errorf("inspect session resource %s: %w", full, err)
	}
	dev, ino, err := dirIdentity(fi)
	if err != nil {
		return sessionResource{}, fmt.Errorf("session resource %s: %w", full, err)
	}
	return sessionResource{
		Base: canonicalBase, Name: name,
		BaseDev: baseDev, BaseIno: baseIno, Dev: dev, Ino: ino,
	}, nil
}

// dirIdentity returns the device and inode of a directory so removal can prove
// it is still looking at the directory this session created, not at a
// replacement chosen by someone else.
func dirIdentity(fi os.FileInfo) (uint64, uint64, error) {
	if !fi.IsDir() {
		return 0, 0, errors.New("not a directory")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("no directory identity")
	}
	return uint64(st.Dev), st.Ino, nil
}

// verify re-authenticates the resource immediately before removal. The base
// must still resolve to the canonical directory the controller named and still
// have the pinned identity, and the entry must still be a real directory with
// the recorded identity: a symlink, a retargeted or replaced base, or a
// replacement directory is reported instead of removed.
func (r sessionResource) verify() (string, error) {
	if r.Base == "" || r.Base != filepath.Clean(r.Base) {
		return "", fmt.Errorf("session resource base %q is not canonical", r.Base)
	}
	if r.Name != filepath.Base(r.Name) || !strings.HasPrefix(r.Name, sessionDirPrefix) {
		return "", fmt.Errorf("session resource name %q is not an allocated session directory", r.Name)
	}
	canonicalBase, err := resolvedPath(r.Base)
	if err != nil {
		return "", err
	}
	if canonicalBase != r.Base {
		return "", fmt.Errorf("session resource base %s now resolves to %s", r.Base, canonicalBase)
	}
	bfi, err := os.Lstat(r.Base)
	if err != nil {
		return "", err
	}
	bdev, bino, err := dirIdentity(bfi)
	if err != nil {
		return "", fmt.Errorf("session resource base %s: %w", r.Base, err)
	}
	if bdev != r.BaseDev || bino != r.BaseIno {
		return "", fmt.Errorf("session resource base %s no longer names the configured base", r.Base)
	}
	full := filepath.Join(r.Base, r.Name)
	fi, err := os.Lstat(full)
	if err != nil {
		return full, err
	}
	dev, ino, err := dirIdentity(fi)
	if err != nil {
		return full, fmt.Errorf("session resource %s: %w", full, err)
	}
	if dev != r.Dev || ino != r.Ino {
		return full, fmt.Errorf("session resource %s no longer names the allocated directory", full)
	}
	return full, nil
}

// removeOwnedSessionDir releases one directory this session allocated. It
// records the directory's identity first and refuses a path that is no longer
// directly below a session base or no longer the allocated directory, so a
// retargeted base or a symlink cannot redirect removal. A directory the worker
// already released is not an error.
func removeOwnedSessionDir(base, path string, tree bool) error {
	if base == "" || path == "" {
		return nil
	}
	r, err := newSessionResource(base, path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	r.Tree = tree
	return r.remove()
}

// remove releases exactly this allocated directory. A mount point is only
// emptied, so an attached or unexpectedly populated mount is reported rather
// than traversed; the session's scratch tree is disposable and removed
// recursively. A directory that is already gone is not an error: the controller
// and the worker both release the same session after a normal shutdown.
func (r sessionResource) remove() error {
	full, err := r.verify()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if r.Tree {
		err = os.RemoveAll(full)
	} else {
		err = os.Remove(full)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove session resource %s: %w", full, err)
	}
	return nil
}

// filesystemResources pins this session's allocated directories for the worker.
// The mount is only ever emptied; the cache directory is disposable scratch.
func (p *Plan) filesystemResources() ([]sessionResource, error) {
	mount, err := newSessionResource(p.Cfg.Sandbox.Mount, p.Mount)
	if err != nil {
		return nil, err
	}
	cache, err := newSessionResource(p.Cfg.Sandbox.Cache, p.Cache)
	if err != nil {
		return nil, err
	}
	cache.Tree = true
	return []sessionResource{mount, cache}, nil
}

// ownedSessionResources authenticates the directories named in a spec. The
// spec arrives over a private pipe from the controller, and the paths are still
// re-checked against the configured bases and the session identity, so a worker
// can never be pointed at the configuration base, the shared asset cache, or
// another session's directory.
func (s *filesystemSpec) ownedSessionResources() ([]sessionResource, error) {
	if s.SessionID == "" || s.SessionID != filepath.Base(s.SessionID) || !strings.HasPrefix(s.SessionID, sessionDirPrefix) {
		return nil, fmt.Errorf("session identity %q is not an allocated session directory", s.SessionID)
	}
	want := []struct{ base, path string }{
		{s.Config.Sandbox.Mount, s.Mount},
		{s.Config.Sandbox.Cache, s.Cache},
	}
	if len(s.Resources) != len(want) {
		return nil, errors.New("filesystem spec does not carry exactly this session's resources")
	}
	if s.Resources[0].Tree || !s.Resources[1].Tree {
		return nil, errors.New("filesystem spec confuses its mount point with its scratch tree")
	}
	out := make([]sessionResource, 0, len(want))
	for i, w := range want {
		if w.base == "" || w.path == "" {
			return nil, errors.New("filesystem spec has an empty session resource path")
		}
		if filepath.Clean(w.path) != filepath.Join(filepath.Clean(w.base), s.SessionID) {
			return nil, fmt.Errorf("session resource %s is not session %s's own directory", w.path, s.SessionID)
		}
		base, err := resolvedPath(w.base)
		if err != nil {
			return nil, err
		}
		r := s.Resources[i]
		if r.Name != s.SessionID || r.Base != base {
			return nil, fmt.Errorf("session resource %s does not belong to session %s", r.Name, s.SessionID)
		}
		if _, err := r.verify(); err != nil {
			return nil, fmt.Errorf("session resource %s: %w", w.path, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// removeSessionResources releases exactly the directories the worker verified
// for this session, after its mount is gone. Every failure is joined and
// reported: a live or foreign directory is never removed to make cleanup look
// clean.
func removeSessionResources(resources []sessionResource) error {
	var errs []error
	for _, r := range resources {
		if err := r.remove(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// MaybeRunFilesystem selects the private worker entry before public CLI parsing.
func MaybeRunFilesystem() bool {
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		var value string
		if arg == filesystemFlag && i+1 < len(os.Args) {
			value = os.Args[i+1]
		} else if strings.HasPrefix(arg, filesystemFlag+"=") {
			value = strings.TrimPrefix(arg, filesystemFlag+"=")
		} else {
			continue
		}
		fd, err := strconv.Atoi(value)
		if err != nil || fd < 3 {
			fmt.Fprintln(os.Stderr, "rsbx: invalid filesystem spec descriptor")
			os.Exit(127)
		}
		os.Exit(runFilesystem(fd))
	}
	return false
}

func runFilesystem(fd int) int {
	input := os.NewFile(uintptr(fd), "filesystem-spec")
	ready := os.NewFile(4, "filesystem-ready")
	lease := os.NewFile(5, "filesystem-lease")
	if input == nil || ready == nil || lease == nil {
		return 127
	}
	defer input.Close()
	defer ready.Close()
	defer lease.Close()
	var spec filesystemSpec
	if err := json.NewDecoder(io.LimitReader(input, maxSpecSize)).Decode(&spec); err != nil {
		_ = json.NewEncoder(ready).Encode(filesystemReady{Error: err.Error()})
		return 127
	}
	// Re-authenticate the session's directories before doing any work. The
	// worker releases them itself after a clean unmount, because the
	// controller may be killed by the group signal before it can clean up.
	resources, err := spec.ownedSessionResources()
	if err != nil {
		_ = json.NewEncoder(ready).Encode(filesystemReady{SessionID: spec.SessionID, Error: err.Error()})
		return 127
	}
	// The same graceful termination set as the controller: a signal that makes
	// the controller shut the session down must also let the worker unmount.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer cancel()
	go func() {
		_, _ = io.Copy(io.Discard, lease)
		cancel() // EOF means the controller has closed or died.
	}()

	plan, err := Prepare(&spec.Config, spec.ExeDir)
	if err != nil {
		_ = json.NewEncoder(ready).Encode(filesystemReady{SessionID: spec.SessionID, Error: err.Error()})
		return 127
	}
	plan.UseSession(spec.Session)
	plan.Mount, plan.Cache = spec.Mount, spec.Cache
	// Capture the connection once: nothing nils it in this process, but a
	// stable reference keeps the cancellation goroutine and the deferred
	// close from racing on a Plan field read.
	remote := plan.Remote
	// An outstanding RPC must be interruptible even during mount preparation.
	go func() {
		<-ctx.Done()
		_ = remote.Close()
	}()
	defer remote.Close()
	layout := plan.Layout()
	layout.ExecPaths = spec.Config.Local.Allow
	layout.RuntimePaths = spec.RuntimePaths
	srv, err := plan.mountRoot(layout)
	if err != nil {
		// No server is available to unmount. Only release the session's
		// directories when kernel state proves this exact path is not
		// attached; a partially attached mount is left for the controller.
		attached, inspectErr := mountAttached(spec.Mount)
		if inspectErr != nil {
			err = errors.Join(err, inspectErr)
		} else if !attached {
			err = errors.Join(err, removeSessionResources(resources))
		}
		_ = json.NewEncoder(ready).Encode(filesystemReady{SessionID: spec.SessionID, Error: err.Error()})
		return 127
	}
	if err := json.NewEncoder(ready).Encode(filesystemReady{SessionID: spec.SessionID}); err != nil {
		cancel()
	} else {
		_ = ready.Close()
	}
	<-ctx.Done()
	// Closing RPC first releases handlers waiting on the daemon. Unmount may
	// wait for those handlers, so reversing these two steps can deadlock.
	_ = plan.Remote.Close()
	if err := srv.Unmount(); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx: session %s: unmount %s: %v\n", spec.SessionID, spec.Mount, err)
		return 1
	}
	if err := plan.root.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx: session %s: close host descriptors: %v\n", spec.SessionID, err)
		return 1
	}
	// The mount is gone and the host tree is closed, so the worker can
	// release the directories it allocated even when the controller died.
	// This is idempotent with the controller's own cleanup.
	if err := removeSessionResources(resources); err != nil {
		fmt.Fprintf(os.Stderr, "rsbx: session %s: %v\n", spec.SessionID, err)
		return 1
	}
	return 0
}

func (p *Plan) allocateSession() error {
	if p.sessionID != "" {
		return errors.New("session resources already allocated")
	}
	if p.Cfg.Sandbox.Cache == "" || p.Cfg.Sandbox.Mount == "" {
		return errors.New("sandbox mount/cache base directories must be configured")
	}
	// Check both visible and resolved coordinates: a configured local tree
	// may be a symlink alias to a control directory even when names differ.
	if p.Local != nil {
		for _, base := range []string{p.Cfg.Sandbox.Cache, p.Cfg.Sandbox.Mount} {
			canonicalBase, err := resolvedPath(base)
			if err != nil {
				return err
			}
			for _, root := range p.Local.Roots() {
				canonicalRoot, err := resolvedPath(root)
				if err != nil {
					return err
				}
				if within(canonicalBase, canonicalRoot) || within(canonicalRoot, canonicalBase) {
					return fmt.Errorf("session control directory %s overlaps local content tree %s", base, root)
				}
			}
		}
	}
	if err := os.MkdirAll(p.Cfg.Sandbox.Cache, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(p.Cfg.Sandbox.Mount, 0o700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(p.Cfg.Sandbox.Cache, "session-")
	if err != nil {
		return err
	}
	mount := filepath.Join(p.Cfg.Sandbox.Mount, filepath.Base(dir))
	if err := os.Mkdir(mount, 0o700); err != nil {
		_ = os.Remove(dir)
		return err
	}
	p.sessionID, p.sessionDir, p.mountDir = filepath.Base(dir), dir, mount
	p.Mount, p.Cache = mount, dir
	return nil
}

// within reports whether filename is root itself or lies below it. The prefix
// comparison always includes a separator, so a sibling that merely shares a
// name prefix is not contained; the filesystem root still contains every
// absolute path instead of matching only the literal "//" prefix.
func within(filename, root string) bool {
	if filename == root {
		return true
	}
	prefix := strings.TrimSuffix(root, string(filepath.Separator)) + string(filepath.Separator)
	return strings.HasPrefix(filename, prefix)
}

// resolvedPath resolves the existing prefix without requiring a session base or
// a new configuration directory to exist yet.
func resolvedPath(filename string) (string, error) {
	filename, err := filepath.Abs(filename)
	if err != nil {
		return "", err
	}
	var tail []string
	for {
		resolved, err := filepath.EvalSymlinks(filename)
		if err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) || filepath.Dir(filename) == filename {
			return "", fmt.Errorf("resolve session boundary %s: %w", filename, err)
		}
		tail = append(tail, filepath.Base(filename))
		filename = filepath.Dir(filename)
	}
}

// StartFilesystem starts exactly one mount server and waits for its INIT/ready
// result. The controller never serves requests, pivots, or borrows worker fds.
// Any failure releases this session's resources: the caller may return without
// ever calling Close.
func (p *Plan) StartFilesystem(ctx context.Context) error {
	if err := p.allocateSession(); err != nil {
		return fmt.Errorf("allocate session: %w", err)
	}
	if err := p.startFilesystem(ctx); err != nil {
		return p.abortStart(err)
	}
	return nil
}

func (p *Plan) startFilesystem(ctx context.Context) error {
	cfg := *p.Cfg
	cfg.Local = p.Cfg.Local
	cfg.Local.Allow = p.Exec.ExecPaths()
	cfg.Local.Paths, cfg.Local.ReadOnlyPaths = nil, nil
	for _, root := range p.Local.Roots() {
		if p.Local.Writable(root) {
			cfg.Local.Paths = append(cfg.Local.Paths, root)
		} else {
			cfg.Local.ReadOnlyPaths = append(cfg.Local.ReadOnlyPaths, root)
		}
	}
	spec := filesystemSpec{
		Config: cfg, ExeDir: filepath.Dir(p.Trampoline), Mount: p.Mount,
		Cache: p.Cache, SessionID: p.sessionID, Session: p.sessionToken,
		RuntimePaths: p.Exec.RuntimePaths(),
	}
	// Pin this session's allocated directories so the worker can release
	// them itself when the controller is killed before its own cleanup.
	resources, err := p.filesystemResources()
	if err != nil {
		return err
	}
	spec.Resources = resources
	data, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	if len(data) > maxSpecSize {
		return fmt.Errorf("filesystem spec exceeds %d bytes", maxSpecSize)
	}
	inputR, inputW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer inputR.Close()
	readyR, readyW, err := os.Pipe()
	if err != nil {
		inputW.Close()
		return err
	}
	defer readyR.Close()
	defer readyW.Close()
	leaseR, leaseW, err := os.Pipe()
	if err != nil {
		inputW.Close()
		return err
	}
	defer leaseR.Close()
	cmd := exec.Command(selfPath(), filesystemFlag, "3")
	// The worker must live outside the controller's process group: a group
	// SIGKILL aimed at the controller (or a terminal process group) closes
	// the lease but must not kill the worker before it unmounts and removes
	// this session's directories. stop's exact-PID kill still reaches it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.ExtraFiles = []*os.File{inputR, readyW, leaseR}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		inputW.Close()
		leaseW.Close()
		return fmt.Errorf("start filesystem worker: %w", err)
	}
	_ = readyW.Close()
	worker := &filesystemWorker{cmd: cmd, control: leaseW, done: make(chan struct{})}
	p.filesystem = worker
	go func() {
		worker.waitErr = cmd.Wait()
		close(worker.done)
	}()
	go func() {
		_, _ = inputW.Write(data)
		_ = inputW.Close()
	}()
	result := make(chan filesystemReady, 1)
	go func() {
		var status filesystemReady
		if err := json.NewDecoder(io.LimitReader(readyR, 4096)).Decode(&status); err != nil {
			status.Error = fmt.Sprintf("filesystem ready handshake: %v", err)
		}
		result <- status
	}()
	select {
	case status := <-result:
		if status.Error != "" {
			return fmt.Errorf("session %s: %s", p.sessionID, status.Error)
		}
		if status.SessionID != p.sessionID {
			return errors.New("filesystem worker returned a different session identity")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-worker.done:
		return fmt.Errorf("filesystem worker exited before ready: %v", worker.waitErr)
	}
}

// abortStart tears down a session whose worker never became ready. The caller
// may never reach Close, so a failed handshake must not leave a running worker,
// a stale mount, or this session's directories behind.
func (p *Plan) abortStart(cause error) error {
	if err := p.Close(); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func (w *filesystemWorker) stop() error {
	w.once.Do(func() {
		_ = w.control.Close()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-w.done:
			w.stopErr = w.waitErr
		case <-timer.C:
			_ = w.cmd.Process.Kill()
			select {
			case <-w.done:
				if w.waitErr != nil {
					w.stopErr = fmt.Errorf("filesystem worker required forced termination: %w", w.waitErr)
				} else {
					w.stopErr = errors.New("filesystem worker required forced termination")
				}
			case <-time.After(time.Second):
				w.stopErr = errors.New("filesystem worker did not exit after forced termination")
			}
		}
	})
	return w.stopErr
}

// FilesystemDone notifies the controller that its mount server exited.
func (p *Plan) FilesystemDone() <-chan struct{} {
	if p.filesystem == nil {
		return nil
	}
	return p.filesystem.done
}

// StopFilesystem cancels RPC before waiting for the server's unmount. It can be
// used while Run is shutting down to release kernel IO waits in the entry.
func (p *Plan) StopFilesystem() error {
	if p.filesystem == nil {
		return nil
	}
	return p.filesystem.stop()
}

// Close releases only this session's resources. A worker that failed or was
// killed can leave its FUSE mount behind, so this session's own mount path is
// detached before it is removed. Every error is joined: a failed unmount is
// never reported as a clean shutdown, and no other session's path is touched.
// Close is single-shot: a start that already cleaned up does not report the
// same worker failure twice through the caller's deferred Close.
func (p *Plan) Close() error {
	worker, remote := p.filesystem, p.Remote
	p.filesystem, p.Remote = nil, nil
	var errs []error
	if remote != nil {
		if err := remote.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if worker != nil {
		if err := worker.stop(); err != nil {
			errs = append(errs, err)
		}
		// A worker only unmounts when it exits cleanly. After a failure or a
		// forced kill the kernel mount is still attached, and removing the
		// directory underneath it would either fail with EBUSY or hide the
		// stale mount. Detaching is targeted: only this session's exact path.
		if err := p.detachOwnedMount(); err != nil {
			// The mount may still be live, so its directory and the scratch
			// tree behind it stay in place: cleanup must not turn a failed
			// unmount into removed, inspectable state.
			errs = append(errs, err)
			return errors.Join(errs...)
		}
	}
	mountDir, sessionDir := p.mountDir, p.sessionDir
	p.mountDir, p.sessionDir = "", ""
	if mountDir != "" {
		// Releasing the directories is only safe once kernel state confirms
		// this exact path is no longer attached: a live mount and the tree
		// behind it stay inspectable instead of deleted.
		attached, err := mountAttached(mountDir)
		if err != nil {
			errs = append(errs, err)
			return errors.Join(errs...)
		}
		if attached {
			errs = append(errs, fmt.Errorf("owned mount %s is still attached", mountDir))
			return errors.Join(errs...)
		}
		if err := removeOwnedSessionDir(p.Cfg.Sandbox.Mount, mountDir, false); err != nil {
			errs = append(errs, err)
		}
	}
	if sessionDir != "" {
		if err := removeOwnedSessionDir(p.Cfg.Sandbox.Cache, sessionDir, true); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// mountEscaper decodes the octal escapes mountinfo uses for spaces, tabs,
// newlines and backslashes in a mount point.
var mountEscaper = strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\")

// mountEntries returns the mountinfo records whose mount point is exactly the
// given path. It never matches a parent or sibling, so callers only ever act on
// this session's own directory.
func mountEntries(path string) ([][]string, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	var entries [][]string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 7 && mountEscaper.Replace(fields[4]) == path {
			entries = append(entries, fields)
		}
	}
	return entries, nil
}

// mountAttached reports whether this exact path is currently a mount point.
func mountAttached(path string) (bool, error) {
	entries, err := mountEntries(path)
	if err != nil {
		return false, err
	}
	return len(entries) > 0, nil
}

func (p *Plan) detachOwnedMount() error {
	if p.mountDir == "" {
		return nil
	}
	entries, err := mountEntries(p.mountDir)
	if err != nil {
		return err
	}
	mounted := false
	for _, fields := range entries {
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+1 >= len(fields) || (fields[separator+1] != "fuse" && !strings.HasPrefix(fields[separator+1], "fuse.")) {
			return fmt.Errorf("owned mount path %s no longer names a FUSE mount", p.mountDir)
		}
		mounted = true
	}
	if !mounted {
		return nil
	}
	err = unix.Unmount(p.mountDir, unix.MNT_DETACH)
	if err == nil || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
		return nil
	}
	if !errors.Is(err, unix.EPERM) {
		return fmt.Errorf("detach owned mount %s: %w", p.mountDir, err)
	}
	// fusermount3 is already the unprivileged mount dependency. Invoke it
	// directly, with this session's exact path; no global mount cleanup.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "fusermount3", "-u", "-z", "--", p.mountDir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("detach owned mount %s: %w: %s", p.mountDir, err, out)
	}
	return nil
}
