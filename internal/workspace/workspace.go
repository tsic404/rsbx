// Package workspace establishes a task workspace in the daemon's tree.
//
// The workspace belongs to the remote side: remote commands address it by its
// native daemon path, and the session starts there. Initial material is
// written through the daemon's filesystem channel before the session starts,
// so no local directory has to be visible to the daemon and no remote content
// is copied back.
//
// This is the only channel that carries content into the remote tree, and it
// carries the workspace's own material: a tree this machine declares local is
// refused as a source, because sending it would move private configuration
// across the boundary the sandbox exists to keep.
package workspace

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"rsbx/internal/paths"
	"rsbx/internal/proto"
)

// FS is the daemon filesystem channel the workspace is written through.
type FS interface {
	Do(*proto.FxReq) (*proto.FxResp, error)
}

// Spec describes one workspace.
type Spec struct {
	// Path is the absolute native path of the workspace on the daemon.
	Path string
	// Seed is a local directory whose content initializes the workspace.
	// Empty means the workspace must already exist there.
	Seed string
	// Local declares the trees that belong to this machine. They are not a
	// valid source and not a valid workspace location.
	Local *paths.Set
}

// Validate checks the parts of the specification that need no daemon: the
// paths are absolute, the seed is a directory, and neither side crosses a
// tree declared local.
//
// The two sides are different machines, so their paths are never compared:
// the seed is checked against this machine's declared trees, the workspace
// path against the sandbox view's written ownership. A daemon path is never
// resolved through this machine's filesystem.
func Validate(spec Spec) error {
	if spec.Path == "" {
		return errors.New("workspace path is empty")
	}
	if !filepath.IsAbs(spec.Path) {
		return fmt.Errorf("workspace path %q is not absolute: it names a directory in the daemon's tree", spec.Path)
	}
	if spec.Seed != "" {
		if !filepath.IsAbs(spec.Seed) {
			return fmt.Errorf("workspace seed %q is not absolute", spec.Seed)
		}
		fi, err := os.Stat(spec.Seed)
		if err != nil {
			return fmt.Errorf("workspace seed: %w", err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("workspace seed %s is not a directory", spec.Seed)
		}
	}
	if spec.Local == nil {
		return nil
	}
	for _, tree := range spec.Local.Roots() {
		// Ownership in the sandbox view is decided by the written path, so
		// this comparison is textual. Resolving the daemon path on this
		// machine would let a local directory decide what the daemon's tree
		// contains.
		if within(spec.Path, tree) || within(tree, spec.Path) {
			return fmt.Errorf("workspace %s overlaps local tree %s: a task workspace belongs to the daemon's tree, not to this machine", spec.Path, tree)
		}
		if spec.Seed != "" && overlaps(spec.Seed, tree) {
			return fmt.Errorf("workspace seed %s overlaps local tree %s: private local material must not be sent to the daemon", spec.Seed, tree)
		}
	}
	return nil
}

// Ensure initializes the workspace from the seed, then verifies the start
// directory exists as a directory in the daemon's tree. Initialization is
// additive: seeded paths get the seed's content and mode, while anything the
// agent already wrote stays where it is.
func Ensure(fs FS, spec Spec) error {
	if err := Validate(spec); err != nil {
		return err
	}
	if spec.Seed == "" {
		return CheckStart(fs, spec)
	}
	if err := writeSeed(fs, spec); err != nil {
		return err
	}
	return CheckStart(fs, spec)
}

// CheckStart verifies the start directory exists in the daemon's tree. A
// missing directory is a start failure: the session must not run the entry
// somewhere the caller never asked for.
func CheckStart(fs FS, spec Spec) error {
	resp, err := fs.Do(&proto.FxReq{Op: proto.FxStat, Path: spec.Path})
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("workspace %s: no such directory in the daemon's tree", spec.Path)
		}
		return fmt.Errorf("workspace %s: %w", spec.Path, err)
	}
	if resp.Attr.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("workspace %s: not a directory in the daemon's tree", spec.Path)
	}
	return nil
}

// seedDir records a directory whose final mode is set after its children:
// writing into a directory that is already read-only would fail.
type seedDir struct {
	path string
	mode os.FileMode
}

func writeSeed(fs FS, spec Spec) error {
	// The seed names a directory; a symlink at its root is followed so the
	// caller can pass the path it normally uses. Links inside the seed are
	// material and are copied, never followed.
	seed, err := filepath.EvalSymlinks(spec.Seed)
	if err != nil {
		return fmt.Errorf("workspace seed: %w", err)
	}
	// The listing is fixed before the daemon's tree changes. The two sides
	// are different filesystems, so a seed path that happens to equal the
	// workspace path names unrelated content; scanning first keeps the walk
	// from ever observing what initialization itself wrote.
	entries, err := scanSeed(seed, spec.Path)
	if err != nil {
		return err
	}
	if err := mkdirAll(fs, spec.Path, 0o755); err != nil {
		return fmt.Errorf("initialize workspace %s: %w", spec.Path, err)
	}
	var dirs []seedDir
	verified := map[string]bool{spec.Path: true}
	for _, e := range entries {
		// A seed's own symlinks are material, but nothing may be created
		// through one: a link planted at an ancestor would put the rest of
		// the initialization somewhere else in the daemon's tree.
		if err := checkRealParents(fs, spec.Path, e.remote, verified); err != nil {
			return err
		}
		switch {
		case e.dir:
			if err := mkdirAll(fs, e.remote, 0o755); err != nil {
				return fmt.Errorf("initialize %s: %w", e.remote, err)
			}
			// A directory left read-only by an earlier run must still accept
			// its children now. The seed's own mode is applied last.
			ownerMode := e.mode | 0o700
			if _, err := fs.Do(&proto.FxReq{Op: proto.FxChmod, Path: e.remote, Arg: fmt.Sprintf("%o", ownerMode)}); err != nil {
				return fmt.Errorf("initialize %s: make writable: %w", e.remote, err)
			}
			verified[e.remote] = true
			dirs = append(dirs, seedDir{e.remote, e.mode})
		case e.link:
			if err := symlink(fs, e.remote, e.target); err != nil {
				return fmt.Errorf("initialize %s: %w", e.remote, err)
			}
		default:
			if err := writeFile(fs, e.local, e.remote, e.mode); err != nil {
				return fmt.Errorf("initialize %s: %w", e.remote, err)
			}
		}
	}
	// Deepest first, so a read-only directory no longer blocks its siblings'
	// creation above it.
	for i := len(dirs) - 1; i >= 0; i-- {
		if _, err := fs.Do(&proto.FxReq{Op: proto.FxChmod, Path: dirs[i].path, Arg: fmt.Sprintf("%o", dirs[i].mode)}); err != nil {
			return fmt.Errorf("initialize %s: set mode: %w", dirs[i].path, err)
		}
	}
	return nil
}

// seedEntry is one planned write, resolved before the daemon's tree changes.
type seedEntry struct {
	local  string
	remote string
	mode   os.FileMode
	dir    bool
	link   bool
	target string
}

// scanSeed lists what the seed holds, in walk order, without writing anything.
func scanSeed(seed, workspace string) ([]seedEntry, error) {
	var entries []seedEntry
	err := filepath.WalkDir(seed, func(local string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(seed, local)
		if err != nil {
			return err
		}
		remote := workspace
		if rel != "." {
			remote = filepath.Join(workspace, rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			entries = append(entries, seedEntry{remote: remote, mode: info.Mode().Perm(), dir: true})
		case d.Type()&os.ModeSymlink != 0:
			// The link text is the material. Its target is not read, so a
			// seed cannot pull local file content into the remote tree by
			// pointing at it.
			target, err := os.Readlink(local)
			if err != nil {
				return err
			}
			entries = append(entries, seedEntry{remote: remote, link: true, target: target})
		case d.Type().IsRegular():
			entries = append(entries, seedEntry{local: local, remote: remote, mode: info.Mode().Perm()})
		default:
			return fmt.Errorf("initialize %s: %s is a %s, and only files, directories and symlinks can be workspace material", remote, local, d.Type())
		}
		return nil
	})
	return entries, err
}

// writeFile streams one regular file into the remote tree and checks the
// daemon stored every byte before closing the descriptor.
func writeFile(fs FS, local, remote string, mode os.FileMode) error {
	src, err := os.Open(local)
	if err != nil {
		return err
	}
	defer src.Close()
	open := &proto.FxReq{
		Op:    proto.FxOpen,
		Path:  remote,
		Flags: uint32(os.O_WRONLY | os.O_CREATE | os.O_TRUNC | syscall.O_NOFOLLOW),
		Mode:  uint32(mode),
	}
	// A seeded file may have been left read-only by an earlier run. The open
	// would fail on its mode, so the existing file is made writable first; a
	// link is removed rather than written through.
	if st, statErr := fs.Do(&proto.FxReq{Op: proto.FxStat, Path: remote}); statErr == nil {
		switch st.Attr.Mode & syscall.S_IFMT {
		case syscall.S_IFREG:
			if _, err := fs.Do(&proto.FxReq{Op: proto.FxChmod, Path: remote, Arg: "600"}); err != nil {
				return err
			}
		case syscall.S_IFLNK:
			if _, err := fs.Do(&proto.FxReq{Op: proto.FxUnlink, Path: remote}); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s exists and is not a regular file", remote)
		}
	} else if !errors.Is(statErr, syscall.ENOENT) {
		return statErr
	}
	resp, err := fs.Do(open)
	if errors.Is(err, syscall.ELOOP) {
		// The destination is a link. Replace the name rather than writing
		// through it: the bytes belong to the workspace, not to whatever the
		// link points at.
		if _, err := fs.Do(&proto.FxReq{Op: proto.FxUnlink, Path: remote}); err != nil {
			return err
		}
		resp, err = fs.Do(open)
	}
	if err != nil {
		return err
	}
	if resp.Kind != proto.KHandle {
		return fmt.Errorf("daemon returned no descriptor for %s", remote)
	}
	h := resp.Handle
	closeHandle := func() {
		_, _ = fs.Do(&proto.FxReq{Op: proto.FxClose, Handle: h})
	}
	var offset int64
	buf := make([]byte, proto.MaxIO)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			out, err := fs.Do(&proto.FxReq{Op: proto.FxPwrite, Handle: h, Offset: offset, Data: buf[:n]})
			if err != nil {
				closeHandle()
				return err
			}
			if int(out.Count) != n {
				closeHandle()
				return fmt.Errorf("daemon accepted %d of %d bytes", out.Count, n)
			}
			offset += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			closeHandle()
			return readErr
		}
	}
	// The size on the descriptor is the daemon's own answer about what it
	// stored; a short write must not be reported as a complete workspace.
	st, err := fs.Do(&proto.FxReq{Op: proto.FxFstat, Handle: h})
	if err != nil {
		closeHandle()
		return err
	}
	if st.Attr.Size != uint64(offset) {
		closeHandle()
		return fmt.Errorf("daemon stored %d of %d bytes", st.Attr.Size, offset)
	}
	// The mode is set through the descriptor: the open mode is subject to the
	// daemon's umask, and an executable seed file has to stay executable.
	if _, err := fs.Do(&proto.FxReq{Op: proto.FxFchmod, Handle: h, Mode: uint32(mode)}); err != nil {
		closeHandle()
		return err
	}
	_, err = fs.Do(&proto.FxReq{Op: proto.FxClose, Handle: h})
	return err
}

// checkRealParents proves every component between the workspace root and path
// is a directory in its own right, not a symbolic link to one. Directories
// that were just created (or already checked) are skipped.
func checkRealParents(fs FS, root, path string, verified map[string]bool) error {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return err
	}
	cur := root
	parts := strings.Split(rel, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, part)
		if verified[cur] {
			continue
		}
		resp, err := fs.Do(&proto.FxReq{Op: proto.FxStat, Path: cur})
		if err != nil {
			return fmt.Errorf("initialize %s: %w", cur, err)
		}
		if resp.Attr.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			return fmt.Errorf("initialize %s: %s is a symbolic link, so the rest of the seed would land outside the workspace", path, cur)
		}
		if resp.Attr.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			return fmt.Errorf("initialize %s: %s is not a directory", path, cur)
		}
		verified[cur] = true
	}
	return nil
}

// mkdirAll creates the directory and any missing ancestors. An existing
// directory is the idempotent case; an existing non-directory is a conflict
// the caller has to resolve, not something to delete.
func mkdirAll(fs FS, path string, mode os.FileMode) error {
	_, err := fs.Do(&proto.FxReq{Op: proto.FxMkdir, Path: path, Mode: uint32(mode)})
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, syscall.EEXIST):
		return requireDir(fs, path)
	case errors.Is(err, syscall.ENOENT) && path != "/":
		parent := filepath.Dir(path)
		if parent == path {
			return err
		}
		if err := mkdirAll(fs, parent, 0o755); err != nil {
			return err
		}
		if _, err := fs.Do(&proto.FxReq{Op: proto.FxMkdir, Path: path, Mode: uint32(mode)}); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				return requireDir(fs, path)
			}
			return err
		}
		return nil
	default:
		return err
	}
}

// requireDir accepts an existing directory and refuses any other occupant.
func requireDir(fs FS, path string) error {
	resp, err := fs.Do(&proto.FxReq{Op: proto.FxStat, Path: path})
	if err != nil {
		return err
	}
	if resp.Attr.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("%s exists and is not a directory", path)
	}
	return nil
}

// symlink replaces a name that already exists with a link to target. An
// existing directory is refused: initialization does not delete agent work.
func symlink(fs FS, path, target string) error {
	_, err := fs.Do(&proto.FxReq{Op: proto.FxSymlink, Path: path, Arg: target})
	if err == nil || !errors.Is(err, syscall.EEXIST) {
		return err
	}
	if _, err := fs.Do(&proto.FxReq{Op: proto.FxUnlink, Path: path}); err != nil {
		return err
	}
	_, err = fs.Do(&proto.FxReq{Op: proto.FxSymlink, Path: path, Arg: target})
	return err
}

// overlaps reports whether either path contains the other, comparing both the
// written form and the resolved one: a declared local tree reached through a
// symlink alias is the same tree.
func overlaps(a, b string) bool {
	if within(a, b) || within(b, a) {
		return true
	}
	ra, rb := resolve(a), resolve(b)
	return within(ra, rb) || within(rb, ra)
}

func within(child, parent string) bool {
	child, parent = filepath.Clean(child), filepath.Clean(parent)
	if child == parent {
		return true
	}
	if parent == "/" {
		return strings.HasPrefix(child, "/")
	}
	return strings.HasPrefix(child, parent+"/")
}

// resolve resolves the longest existing ancestor and reattaches the rest, so
// a path that is about to be created still compares against real locations.
func resolve(path string) string {
	path = filepath.Clean(path)
	var tail []string
	for {
		if real, err := filepath.EvalSymlinks(path); err == nil {
			return filepath.Join(append([]string{real}, tail...)...)
		}
		parent := filepath.Dir(path)
		if parent == path {
			return filepath.Clean(path)
		}
		tail = append([]string{filepath.Base(path)}, tail...)
		path = parent
	}
}
