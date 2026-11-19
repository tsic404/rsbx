//go:build linux

package sandbox

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// Executable snapshots are shared immutable cache objects pinned by their
// host inode identity. Every launch hardlinks the exact entries it needs
// into a private per-session directory, then the launcher binds that
// directory and each policy path read-only before a sandbox child exists.
type execAsset struct {
	Path   string `json:"path"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Dev    uint64 `json:"dev"`
	Ino    uint64 `json:"ino"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

func (a execAsset) helperPath() string { return filepath.Join(HelperDir, a.Name) }

type execAssets struct {
	dir  *os.File
	path string
}

func (a *execAssets) Close() {
	if a.dir != nil {
		a.dir.Close()
	}
	if a.path != "" {
		os.RemoveAll(a.path)
	}
}

// Specs are sealed: they carry session policy, unlike executable assets,
// which must be ordinary inodes for reliable native binds and Landlock.
func sealedPayload(name string, data []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("memfd %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return nil, err
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		f.Close()
		return nil, fmt.Errorf("seal %s: %w", name, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func nativeHelper(f *os.File) error {
	e, err := elf.NewFile(f)
	if err != nil {
		return fmt.Errorf("helper is not an ELF binary: %w", err)
	}
	defer e.Close()
	var machine elf.Machine
	switch runtime.GOARCH {
	case "amd64":
		machine = elf.EM_X86_64
	case "arm64":
		machine = elf.EM_AARCH64
	default:
		return fmt.Errorf("exec tracing requires native Linux amd64 or arm64")
	}
	if e.Class != elf.ELFCLASS64 || e.Machine != machine ||
		e.Type != elf.ET_EXEC && e.Type != elf.ET_DYN {
		return fmt.Errorf("helper is not a native 64-bit executable")
	}
	for _, p := range e.Progs {
		if p.Type == elf.PT_INTERP {
			return fmt.Errorf("helper has a dynamic ELF interpreter; build with CGO_ENABLED=0")
		}
	}
	if e.SectionByType(elf.SHT_DYNAMIC) != nil {
		libs, err := e.ImportedLibraries()
		if err != nil {
			return err
		}
		if len(libs) != 0 {
			return fmt.Errorf("helper has dynamic library dependencies")
		}
	}
	return nil
}

func sameAssetSource(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size &&
		a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

type assetIdentity struct {
	dev, ino uint64
	size     int64
	mtim     unix.Timespec
	ctim     unix.Timespec
}

func statIdentity(st unix.Stat_t) assetIdentity {
	return assetIdentity{dev: uint64(st.Dev), ino: st.Ino, size: st.Size, mtim: st.Mtim, ctim: st.Ctim}
}

func assetKey(id assetIdentity) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x-%x-%x",
		id.dev, id.ino, uint64(id.size),
		uint64(id.mtim.Sec), uint64(id.mtim.Nsec), uint64(id.ctim.Sec), uint64(id.ctim.Nsec))
}

type assetInput struct{ path, source, name, kind string }

type cachedSnapshot struct {
	asset  execAsset
	object string
	source unix.Stat_t
}

func captureExecAssets(ctx context.Context, p *Plan, spec *launchSpec) (_ *execAssets, err error) {
	if p.Cfg == nil || p.Cfg.Sandbox.Cache == "" || p.Cache == "" {
		return nil, fmt.Errorf("sandbox cache locations are unset")
	}
	store := filepath.Join(p.Cfg.Sandbox.Cache, "exec-assets")
	if err := os.MkdirAll(store, 0o700); err != nil {
		return nil, err
	}
	for _, path := range []string{store, p.Cache} {
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, err
		}
		if p.Local != nil && (p.Local.Writable(path) || p.Local.Writable(real)) {
			return nil, fmt.Errorf("sandbox cache overlaps a writable local tree: %s", path)
		}
	}
	if err := os.Chmod(store, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(p.Cache, "native-")
	if err != nil {
		return nil, err
	}
	owner := &execAssets{path: dir}
	defer func() {
		if err != nil {
			owner.Close()
		}
	}()
	if err := os.Mkdir(filepath.Join(dir, "assets"), 0o700); err != nil {
		return nil, err
	}
	todo := []assetInput{
		{TrampolinePath, p.Trampoline, "rsbx-tramp", "gateway"},
		{GuardPath, p.Guard, "rsbx-guard", "guard"},
	}
	for _, path := range spec.LocalAllow {
		todo = append(todo, assetInput{path: path, source: path, kind: "local"})
	}
	for _, path := range spec.RuntimePaths {
		todo = append(todo, assetInput{path: path, source: path, kind: "runtime"})
	}
	seenPaths, linked := map[string]bool{}, map[string]bool{}
	byInode := map[[2]uint64]cachedSnapshot{}
	for _, in := range todo {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !filepath.IsAbs(in.path) || !filepath.IsAbs(in.source) {
			return nil, fmt.Errorf("native asset names a nonabsolute path %q", in.source)
		}
		if seenPaths[in.path] {
			continue
		}
		seenPaths[in.path] = true
		if in.kind == "local" && p.Local != nil && p.Local.Writable(in.path) {
			return nil, fmt.Errorf("local executable %s overlaps a writable local tree: "+
				"an allowlisted program must be immutable, so move it out of the local.paths tree it is in", in.path)
		}
		src, err := os.Open(in.source)
		if err != nil {
			return nil, fmt.Errorf("open native asset %s: %w", in.source, err)
		}
		var before unix.Stat_t
		if err := unix.Fstat(int(src.Fd()), &before); err != nil {
			src.Close()
			return nil, err
		}
		if before.Mode&unix.S_IFMT != unix.S_IFREG {
			src.Close()
			return nil, fmt.Errorf("native asset %s is not a concrete regular file", in.source)
		}
		if in.kind != "runtime" && before.Mode&0o111 == 0 {
			src.Close()
			return nil, fmt.Errorf("native program %s is not executable", in.source)
		}
		key := [2]uint64{uint64(before.Dev), before.Ino}
		cached, exists := byInode[key]
		if exists {
			src.Close()
			if !sameAssetSource(before, cached.source) {
				return nil, fmt.Errorf("native alias changed during capture: %s", in.source)
			}
		} else {
			if in.kind == "guard" || in.kind == "gateway" {
				if err := nativeHelper(src); err != nil {
					src.Close()
					return nil, fmt.Errorf("%s: %w", in.source, err)
				}
			}
			cached, err = cacheSnapshot(ctx, store, src, before)
			src.Close()
			if err != nil {
				return nil, fmt.Errorf("snapshot %s: %w", in.source, err)
			}
			byInode[key] = cached
		}
		a := cached.asset
		a.Path, a.Kind = in.path, in.kind
		a.Name = in.name
		if a.Name == "" {
			a.Name = filepath.Join("assets", assetKey(statIdentity(before)))
		}
		if !linked[a.Name] {
			if err := os.Link(cached.object, filepath.Join(dir, a.Name)); err != nil {
				return nil, fmt.Errorf("pin snapshot: %w", err)
			}
			linked[a.Name] = true
		}
		var pinned unix.Stat_t
		if err := unix.Stat(filepath.Join(dir, a.Name), &pinned); err != nil {
			return nil, err
		}
		if uint64(pinned.Dev) != a.Dev || pinned.Ino != a.Ino {
			return nil, fmt.Errorf("snapshot inode changed before it was pinned")
		}
		spec.Assets = append(spec.Assets, a)
	}
	dfd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	owner.dir = os.NewFile(uintptr(dfd), "rsbx-native-assets")
	spec.HelperDir = dir
	return owner, nil
}

type contextAssetReader struct {
	ctx  context.Context
	file *os.File
}

func (r contextAssetReader) Read(dst []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.file.Read(dst)
}

// A per-source flock prevents N simultaneous sessions from copying the same
// large native CLI N times. Cache reads validate both digests and source
// identity; a replaced/corrupt cache object is recreated, never trusted.
func cacheSnapshot(ctx context.Context, store string, src *os.File, before unix.Stat_t) (cachedSnapshot, error) {
	var out cachedSnapshot
	key := assetKey(statIdentity(before))
	object := filepath.Join(store, key)
	lock, err := unix.Open(object+".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return out, err
	}
	defer unix.Close(lock)
	wake := time.NewTicker(10 * time.Millisecond)
	defer wake.Stop()
	for {
		err := unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			return out, err
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-wake.C:
		}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return out, err
	}
	fd, err := unix.Open(object, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		cached := os.NewFile(uintptr(fd), "rsbx-cached-executable")
		var st unix.Stat_t
		statErr := unix.Fstat(fd, &st)
		valid := statErr == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0o222 == 0 && st.Size == before.Size && st.Uid == uint32(os.Getuid())
		if valid {
			cachedHash, sourceHash := sha256.New(), sha256.New()
			_, hashErr := io.Copy(cachedHash, contextAssetReader{ctx, cached})
			if hashErr == nil {
				_, hashErr = io.Copy(sourceHash, contextAssetReader{ctx, src})
			}
			var after unix.Stat_t
			if hashErr == nil {
				hashErr = unix.Fstat(int(src.Fd()), &after)
			}
			cached.Close()
			if hashErr != nil {
				return out, hashErr
			}
			if !sameAssetSource(before, after) {
				return out, fmt.Errorf("source identity changed while checking cached executable")
			}
			if bytesEqual(cachedHash.Sum(nil), sourceHash.Sum(nil)) {
				out = cachedSnapshot{asset: execAsset{Dev: uint64(st.Dev), Ino: st.Ino, Size: st.Size, Digest: hex.EncodeToString(cachedHash.Sum(nil))}, object: object, source: before}
				return out, nil
			}
		} else {
			cached.Close()
		}
		if err := os.Remove(object); err != nil {
			return out, err
		}
	} else if err != unix.ENOENT {
		if err != unix.ELOOP {
			return out, err
		}
		if err := os.Remove(object); err != nil {
			return out, err
		}
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return out, err
	}
	tmp, err := os.CreateTemp(store, "capture-")
	if err != nil {
		return out, err
	}
	defer os.Remove(tmp.Name())
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, hash), contextAssetReader{ctx, src})
	var after, snapshot unix.Stat_t
	if copyErr == nil {
		copyErr = unix.Fstat(int(src.Fd()), &after)
	}
	if copyErr == nil && (!sameAssetSource(before, after) || n != before.Size) {
		copyErr = fmt.Errorf("source changed while being captured")
	}
	if copyErr == nil {
		copyErr = tmp.Chmod(os.FileMode(before.Mode & 0o555))
	}
	if copyErr == nil {
		copyErr = unix.Fstat(int(tmp.Fd()), &snapshot)
	}
	closeErr := tmp.Close()
	if copyErr != nil {
		return out, copyErr
	}
	if closeErr != nil {
		return out, closeErr
	}
	if err := os.Rename(tmp.Name(), object); err != nil {
		return out, err
	}
	out = cachedSnapshot{asset: execAsset{Dev: uint64(snapshot.Dev), Ino: snapshot.Ino, Size: n, Digest: hex.EncodeToString(hash.Sum(nil))}, object: object, source: before}
	return out, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Verify the worker's actual read bytes before replacing a policy inode with
// its native snapshot. A host/daemon ancestor-link mismatch is an error, not
// a reason to bind the native program over a different remote file.
func verifyAssetBytes(path string, a execAsset) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != a.Size {
		return fmt.Errorf("filesystem worker exposes a different file for %s", a.Path)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != a.Digest {
		return fmt.Errorf("filesystem worker's bytes differ from captured host asset %s", a.Path)
	}
	return nil
}
