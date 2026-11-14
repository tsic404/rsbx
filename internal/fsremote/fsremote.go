// Package fsremote serves filesystem operations for the daemon-side root.
package fsremote

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"rsbx/internal/proto"
)

// Server answers file operations rooted at Root.
type Server struct {
	Root string
}

// Resolve maps an absolute sandbox path into Root.
//
// Cleaning happens first, so ".." never escapes: the result is always inside
// the root, and the caller cannot ask for a path above it.
func (s *Server) Resolve(p string) (string, bool) {
	if p == "" {
		p = "/"
	}
	clean := filepath.Clean("/" + p)
	if clean == "/" {
		return s.Root, true
	}
	full := filepath.Join(s.Root, clean)
	rel, err := filepath.Rel(s.Root, full)
	if err != nil || rel == ".." || len(rel) > 2 && rel[:3] == "../" {
		return "", false
	}
	return full, true
}

func attrOf(fi os.FileInfo) proto.Attr {
	a := proto.Attr{
		Size:  uint64(fi.Size()),
		Mtime: fi.ModTime().Unix(),
		Mode:  uint32(fi.Mode().Perm()),
	}
	switch {
	case fi.IsDir():
		a.Mode |= proto.SIFDIR
	case fi.Mode()&os.ModeSymlink != 0:
		a.Mode |= proto.SIFLNK
	default:
		a.Mode |= proto.SIFREG
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		a.UID = st.Uid
		a.GID = st.Gid
		a.Ino = st.Ino
	}
	return a
}

// Handle answers one request.
func (s *Server) Handle(req *proto.FxReq) *proto.FxResp {
	full, ok := s.Resolve(req.Path)
	if !ok {
		return &proto.FxResp{ID: req.ID, Kind: proto.KErr, Err: "path escapes the remote root"}
	}
	switch req.Op {
	case proto.FxStat, proto.FxAccess:
		fi, err := os.Lstat(full)
		if err != nil {
			return errResp(req.ID, err)
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KStat, Attr: attrOf(fi)}

	case proto.FxRead:
		data, err := os.ReadFile(full)
		if err != nil {
			return errResp(req.ID, err)
		}
		a := proto.Attr{Mode: proto.SIFREG | 0o644, Size: uint64(len(data))}
		if fi, err := os.Stat(full); err == nil {
			a = attrOf(fi)
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KFile, Data: data, Attr: a}

	case proto.FxWrite:
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return errResp(req.ID, err)
		}
		mode := os.FileMode(0o644)
		if fi, err := os.Lstat(full); err == nil && fi.Mode().IsRegular() {
			mode = fi.Mode().Perm()
		}
		if err := os.WriteFile(full, req.Data, mode); err != nil {
			return errResp(req.ID, err)
		}
		fi, err := os.Lstat(full)
		if err != nil {
			return &proto.FxResp{ID: req.ID, Kind: proto.KOk}
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KStat, Attr: attrOf(fi)}

	case proto.FxList:
		des, err := os.ReadDir(full)
		if err != nil {
			return errResp(req.ID, err)
		}
		ents := make([]proto.DirEntry, 0, len(des))
		for _, de := range des {
			mode := uint32(proto.SIFREG)
			if info, err := de.Info(); err == nil {
				switch {
				case info.IsDir():
					mode = proto.SIFDIR
				case info.Mode()&os.ModeSymlink != 0:
					mode = proto.SIFLNK
				}
				mode |= uint32(info.Mode().Perm())
			}
			ents = append(ents, proto.DirEntry{Name: de.Name(), Mode: mode})
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KDir, Ents: ents}

	case proto.FxReadlink:
		target, err := os.Readlink(full)
		if err != nil {
			return errResp(req.ID, err)
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KLink, Data: []byte(target)}

	case proto.FxMkdir:
		mode := os.FileMode(0o755)
		if m, err := strconv.ParseUint(req.Arg, 8, 32); err == nil && req.Arg != "" {
			mode = os.FileMode(m)
		}
		if err := os.Mkdir(full, mode); err != nil {
			return errResp(req.ID, err)
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KOk}

	case proto.FxUnlink:
		if err := os.RemoveAll(full); err != nil {
			return errResp(req.ID, err)
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KOk}

	case proto.FxRename:
		dst, ok := s.Resolve(req.Arg)
		if !ok {
			return &proto.FxResp{ID: req.ID, Kind: proto.KErr, Err: "rename target escapes the remote root"}
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return errResp(req.ID, err)
		}
		if err := os.Rename(full, dst); err != nil {
			return errResp(req.ID, err)
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KOk}

	case proto.FxTruncate:
		size, err := strconv.ParseInt(req.Arg, 10, 64)
		if err != nil {
			return errResp(req.ID, err)
		}
		if err := os.Truncate(full, size); err != nil {
			return errResp(req.ID, err)
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KOk}

	case proto.FxAppend:
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return errResp(req.ID, err)
		}
		f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			return errResp(req.ID, err)
		}
		_, werr := f.Write(req.Data)
		cerr := f.Close()
		if werr != nil {
			return errResp(req.ID, werr)
		}
		if cerr != nil {
			return errResp(req.ID, cerr)
		}
		fi, err := os.Lstat(full)
		if err != nil {
			return &proto.FxResp{ID: req.ID, Kind: proto.KOk}
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KStat, Attr: attrOf(fi)}

	case proto.FxWriteAt:
		off, err := strconv.ParseInt(req.Arg, 10, 64)
		if err != nil {
			return errResp(req.ID, err)
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return errResp(req.ID, err)
		}
		f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			return errResp(req.ID, err)
		}
		_, werr := f.WriteAt(req.Data, off)
		cerr := f.Close()
		if werr != nil {
			return errResp(req.ID, werr)
		}
		if cerr != nil {
			return errResp(req.ID, cerr)
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KOk}

	case proto.FxChmod:
		mode, err := strconv.ParseUint(req.Arg, 8, 32)
		if err != nil {
			return errResp(req.ID, err)
		}
		if err := os.Chmod(full, os.FileMode(mode)); err != nil {
			return errResp(req.ID, err)
		}
		return &proto.FxResp{ID: req.ID, Kind: proto.KOk}
	}
	return &proto.FxResp{ID: req.ID, Kind: proto.KErr, Err: "unknown filesystem operation"}
}

func errResp(id uint32, err error) *proto.FxResp {
	if errors.Is(err, os.ErrNotExist) {
		return &proto.FxResp{ID: id, Kind: proto.KNone}
	}
	return &proto.FxResp{ID: id, Kind: proto.KErr, Err: err.Error()}
}
