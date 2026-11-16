//go:build linux && (amd64 || arm64)

package sandbox

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type executableID struct{ dev, ino uint64 }

func assetID(a execAsset) executableID { return executableID{a.Dev, a.Ino} }

func pathIdentity(path string) (executableID, uint32, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return executableID{}, 0, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return executableID{}, 0, err
	}
	return executableID{uint64(st.Dev), st.Ino}, st.Mode, nil
}

type execPolicy struct {
	local          map[executableID]bool
	paths          map[string]execAsset
	identities     map[executableID]execAsset
	scripts        map[executableID]scriptChain
	guard, gateway execAsset
}

// pinnedExecPolicy proves every asset in the spec is the exact regular inode
// it claims and then classifies them. The kernel stat is the only authority;
// a name or pathname alone never grants execution.
func pinnedExecPolicy(spec *launchSpec) (*execPolicy, error) {
	for _, a := range spec.Assets {
		id, mode, err := pathIdentity(a.Path)
		if err != nil || id != assetID(a) || mode&unix.S_IFMT != unix.S_IFREG {
			return nil, fmt.Errorf("native asset identity mismatch for %s (error %v)", a.Path, err)
		}
	}
	return newExecPolicy(spec)
}

// newExecPolicy classifies already-pinned assets: which inodes are local
// programs, which are the helpers, and which script metadata applies.
func newExecPolicy(spec *launchSpec) (*execPolicy, error) {
	p := &execPolicy{local: map[executableID]bool{}, paths: map[string]execAsset{}, identities: map[executableID]execAsset{}, scripts: map[executableID]scriptChain{}}
	for _, a := range spec.Assets {
		id := assetID(a)
		p.paths[a.Path] = a
		if old, exists := p.identities[id]; !exists || old.Kind != "local" && a.Kind == "local" {
			p.identities[id] = a
		}
		switch a.Kind {
		case "local":
			p.local[id] = true
		case "guard":
			p.guard = a
		case "gateway":
			p.gateway = a
		case "runtime":
		default:
			return nil, fmt.Errorf("unknown native asset class %q", a.Kind)
		}
	}
	if p.guard.Path != GuardPath || p.gateway.Path != TrampolinePath {
		return nil, fmt.Errorf("native execution helpers are missing")
	}
	for _, c := range spec.Scripts {
		a, ok := p.paths[c.Script]
		if !ok || a.Kind != "local" && a.Kind != "runtime" || c.Spelling == "" {
			return nil, fmt.Errorf("script metadata is not attached to a pinned policy asset: %s", c.Script)
		}
		if _, ok := p.paths[c.Interp]; !ok {
			return nil, fmt.Errorf("script interpreter has no runtime snapshot: %s", c.Interp)
		}
		if c.Env {
			if _, ok := p.paths[c.EnvInterp]; !ok || len(c.EnvArgs) == 0 {
				return nil, fmt.Errorf("env script command has no pinned runtime metadata: %s", c.Script)
			}
		}
		p.scripts[assetID(a)] = c
	}
	return p, nil
}

func (p *execPolicy) imageMatches(pid int, expected execAsset) error {
	id, mode, err := pathIdentity(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return fmt.Errorf("read committed executable identity: %w", err)
	}
	if mode&unix.S_IFMT != unix.S_IFREG || id != assetID(expected) {
		name, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		return fmt.Errorf("tracee %d loaded unapproved inode %v (%s), expected %s inode %v", pid, id, name, expected.Path, assetID(expected))
	}
	return nil
}
