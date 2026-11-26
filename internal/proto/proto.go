// Package proto is the wire format shared by the client, daemon and trampoline.
//
// A frame is [u32 BE payload length][u8 type][payload]; every integer inside a
// payload is big endian. Filesystem requests carry an id so one connection can
// serve many concurrent FUSE calls.
package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	TExec  = 0x01 // client -> daemon: ExecReq opens a session
	TReady = 0x02 // daemon -> client: process started
	TExit  = 0x03 // daemon -> client: i32 exit status, or -(signal) when killed
	TErr   = 0x04 // daemon -> client: UTF-8 message
	TTty   = 0x05 // both ways: raw pty bytes
	TWinch = 0x06 // client -> daemon: u16 rows, u16 cols
	TSig   = 0x07 // client -> daemon: i32 signal

	// TExecLocal is daemon -> client on an exec session connection: the
	// daemon relays a stub's request for a command to run in the client's
	// sandbox. Stdio/status reuse TStdin/TStdout/TStderr/TExit, and the
	// session ends when both directions are drained.
	TExecLocal = 0x08

	// THello is client -> daemon and opens a reverse-exec channel. The daemon
	// answers TReady with the path of the stub socket it published on its own
	// host, then serves that channel until the client disconnects.
	THello = 0x09

	// Reverse-exec frames multiplex every stub the daemon serves over one
	// session connection, so each carries a u32 request id before its payload.
	// TExecLocal is daemon -> client and asks for one command; the rest carry
	// stdio and status for that id in either direction.
	TLocalData   = 0x0A
	TLocalCancel = 0x0B

	TStdin  = 0x10
	TStdout = 0x11
	TStderr = 0x12

	TFxReq  = 0x20
	TFxResp = 0x21

	// TSession is client -> daemon and opens a filesystem connection for one
	// session. Every connection that belongs to the same session carries the
	// same token, so the daemon can answer for the session as a whole instead
	// of for one connection at a time.
	TSession = 0x22
	// TInvalidate is daemon -> client: the session's own command has begun and
	// may change any name the view retained, so the view must stop answering
	// from results it obtained before. The payload carries the epoch the view
	// must adopt; replies stamped with an older epoch are not retainable.
	TInvalidate = 0x23
)

const (
	// Path operations act on native absolute paths in the daemon's own
	// filesystem. The daemon's / is the remote tree: there is no alternate
	// root and no path translation. Arg carries a path or textual argument.
	FxStat     = 1
	FxList     = 4
	FxReadlink = 5
	FxMkdir    = 6
	FxUnlink   = 7
	FxRename   = 8
	FxTruncate = 9
	FxChmod    = 10
	FxAccess   = 11
	// FxSymlink creates a symbolic link named by Path pointing at Arg. The
	// link text travels as data: it is never resolved as a path here.
	FxSymlink = 14
	// FxLink creates a hard link: Path is the new name, Arg the existing file.
	FxLink = 15
	// FxRmdir removes an empty directory. Unlink must not: a build tool that
	// deletes a directory and one that deletes a file are asking different
	// questions, and answering both with RemoveAll silently destroys data.
	FxRmdir = 16
	// FxUtimes sets access and modification times. Arg is "<atime>,<mtime>" in
	// decimal nanoseconds; a negative field is UTIME_OMIT, which keeps the
	// timestamp that is actually there rather than inventing a current one.
	FxUtimes = 17
	// FxGetlk asks whether a lock would conflict; FxSetlk takes or drops one
	// without waiting; FxSetlkw waits. Handle names the open file and Owner
	// the caller's lock identity. Locks are arbitrated by the kernel on the
	// real file, so a program on the daemon and every client contend for one
	// lock, not one per lock table.
	FxGetlk  = 18
	FxSetlk  = 19
	FxSetlkw = 20

	// Handle operations act on a descriptor the daemon opened. A handle keeps
	// the inode it opened across rename and unlink: reopening the current path
	// would redirect writes to a replacement file or resurrect a name its
	// owner removed.
	FxOpen      = 21 // Path, Flags (Linux O_*), Mode -> KHandle
	FxClose     = 22 // Handle
	FxFstat     = 23 // Handle -> KStat
	FxPread     = 24 // Handle, Offset, Size (<= MaxIO) -> KData
	FxPwrite    = 25 // Handle, Data, Offset -> KOk with Count
	FxFsync     = 26 // Handle (file or directory fd)
	FxFtruncate = 27 // Handle, Offset (new length)
	FxFchmod    = 28 // Handle, Mode (permission bits)
	FxFutimes   = 29 // Handle, Arg "<atime>,<mtime>" ns, negative field = omit
)

const (
	// KNone answers a metadata lookup that found nothing. It is never a
	// mutation's success: a failed open, write or close is KErr with Errno.
	KNone = 0
	KDir  = 2
	// KErr is a failure. Errno is the authoritative syscall errno; Err is a
	// detail message for logs, never a value to parse back.
	KErr = 3
	// KStat carries a filled Attr.
	KStat = 4
	// KOk is a successful operation whose payload is Count and optional Lock.
	KOk = 5
	// KLink carries readlink's target in Data.
	KLink = 6
	// KHandle carries an open descriptor in Handle and its Attr.
	KHandle = 7
	// KData carries read bytes in Data, their number in Count.
	KData = 8
)

const (
	SIFDIR = 0o040000
	SIFREG = 0o100000
	SIFLNK = 0o120000

	MaxFrame = 32 << 20
	// MaxIO caps one Pread/Pwrite payload; transfers are chunked below MaxFrame.
	MaxIO = 1 << 20
)

type Frame struct {
	Type    byte
	Payload []byte
}

func WriteFrame(w io.Writer, typ byte, p []byte) error {
	if len(p) > MaxFrame {
		return fmt.Errorf("frame too large (%d bytes)", len(p))
	}
	var h [5]byte
	binary.BigEndian.PutUint32(h[:4], uint32(len(p)))
	h[4] = typ
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

func ReadFrame(r io.Reader) (Frame, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(h[:4])
	if n > MaxFrame {
		return Frame{}, fmt.Errorf("frame too large (%d bytes)", n)
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return Frame{}, err
	}
	return Frame{Type: h[4], Payload: p}, nil
}

type Enc struct{ B []byte }

func (e *Enc) U8(v byte)    { e.B = append(e.B, v) }
func (e *Enc) U16(v uint16) { e.B = append(e.B, byte(v>>8), byte(v)) }
func (e *Enc) U32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	e.B = append(e.B, b[:]...)
}
func (e *Enc) U64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	e.B = append(e.B, b[:]...)
}
func (e *Enc) I32(v int32)  { e.U32(uint32(v)) }
func (e *Enc) Str(s string) { e.U32(uint32(len(s))); e.B = append(e.B, s...) }
func (e *Enc) Raw(p []byte) { e.B = append(e.B, p...) }

type Dec struct {
	B   []byte
	Off int
	Err error
}

func (d *Dec) need(n int) bool {
	if d.Err != nil {
		return false
	}
	if n < 0 || d.Off+n > len(d.B) {
		d.Err = io.ErrUnexpectedEOF
		return false
	}
	return true
}

func (d *Dec) U8() byte {
	if !d.need(1) {
		return 0
	}
	v := d.B[d.Off]
	d.Off++
	return v
}

func (d *Dec) U16() uint16 {
	if !d.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(d.B[d.Off:])
	d.Off += 2
	return v
}

func (d *Dec) U32() uint32 {
	if !d.need(4) {
		return 0
	}
	v := binary.BigEndian.Uint32(d.B[d.Off:])
	d.Off += 4
	return v
}

func (d *Dec) U64() uint64 {
	if !d.need(8) {
		return 0
	}
	v := binary.BigEndian.Uint64(d.B[d.Off:])
	d.Off += 8
	return v
}

func (d *Dec) I32() int32 { return int32(d.U32()) }

func (d *Dec) Str() string {
	n := int(d.U32())
	if !d.need(n) {
		return ""
	}
	s := string(d.B[d.Off : d.Off+n])
	d.Off += n
	return s
}

func (d *Dec) Raw(n int) []byte {
	if !d.need(n) {
		return nil
	}
	b := d.B[d.Off : d.Off+n]
	d.Off += n
	return b
}

// ExecReq asks the daemon to execute Target with an independently supplied argv.
// Target is not inferred from argv[0]: exec callers may choose that string.
type ExecReq struct {
	Target     string
	Argv       []string
	Env        []string
	Dir        string
	TTY        bool
	Rows, Cols uint16
	// Session names the session this command belongs to. The daemon runs the
	// command itself, so this is the only way it learns that a command of that
	// session may change names the session's view has retained.
	Session string
}

func (r *ExecReq) Encode() []byte {
	var e Enc
	e.U8(2)
	if r.TTY {
		e.U8(1)
	} else {
		e.U8(0)
	}
	e.U16(r.Rows)
	e.U16(r.Cols)
	e.Str(r.Dir)
	e.Str(r.Target)
	e.U32(uint32(len(r.Argv)))
	for _, a := range r.Argv {
		e.Str(a)
	}
	e.U32(uint32(len(r.Env)))
	for _, a := range r.Env {
		e.Str(a)
	}
	e.Str(r.Session)
	return e.B
}

func DecodeExecReq(p []byte) (*ExecReq, error) {
	d := &Dec{B: p}
	if version := d.U8(); version != 2 {
		return nil, fmt.Errorf("unsupported exec protocol version %d", version)
	}
	r := &ExecReq{TTY: d.U8()&1 != 0}
	r.Rows, r.Cols = d.U16(), d.U16()
	r.Dir = d.Str()
	r.Target = d.Str()
	n := int(d.U32())
	for i := 0; i < n && d.Err == nil; i++ {
		r.Argv = append(r.Argv, d.Str())
	}
	n = int(d.U32())
	for i := 0; i < n && d.Err == nil; i++ {
		r.Env = append(r.Env, d.Str())
	}
	r.Session = d.Str()
	if d.Err != nil {
		return nil, d.Err
	}
	if r.Target == "" || len(r.Argv) == 0 {
		return nil, fmt.Errorf("exec request requires an executable target and argv")
	}
	if d.Off != len(p) {
		return nil, fmt.Errorf("exec request contains trailing payload bytes")
	}
	return r, nil
}

// Attr mirrors the subset of stat the sandbox needs, in Linux st_mode layout.
type Attr struct {
	Mode  uint32
	Size  uint64
	Mtime int64
	Ino   uint64
	UID   uint32
	GID   uint32
	Nlink uint32
	// Nanosecond precision for all three times; Ctime/Atime are seconds.
	MtimeNsec uint32
	Ctime     int64
	CtimeNsec uint32
	Atime     int64
	AtimeNsec uint32
	// Dev plus Ino give stable identity across mounted filesystems.
	Dev uint64
}

func (a *Attr) encode(e *Enc) {
	e.U32(a.Mode)
	e.U64(a.Size)
	e.U64(uint64(a.Mtime))
	e.U64(a.Ino)
	e.U32(a.UID)
	e.U32(a.GID)
	e.U32(a.Nlink)
	e.U32(a.MtimeNsec)
	e.U64(uint64(a.Ctime))
	e.U32(a.CtimeNsec)
	e.U64(uint64(a.Atime))
	e.U32(a.AtimeNsec)
	e.U64(a.Dev)
}

func decodeAttr(d *Dec) Attr {
	var a Attr
	a.Mode = d.U32()
	a.Size = d.U64()
	a.Mtime = int64(d.U64())
	a.Ino = d.U64()
	a.UID = d.U32()
	a.GID = d.U32()
	a.Nlink = d.U32()
	a.MtimeNsec = d.U32()
	a.Ctime = int64(d.U64())
	a.CtimeNsec = d.U32()
	a.Atime = int64(d.U64())
	a.AtimeNsec = d.U32()
	a.Dev = d.U64()
	return a
}

type DirEntry struct {
	Name string
	Mode uint32
	// Attr carries the child's full attributes when the daemon could read them
	// with the listing. A zero Ino means the entry was listed by type only and
	// the child has to be resolved separately.
	Attr Attr
	// Created marks a child this session established, so the view never
	// answers its resolution from a listing or a retained result.
	Created bool
}

// FxReq is one filesystem operation against the remote tree.
type FxReq struct {
	ID   uint32
	Op   byte
	Path string
	Arg  string
	Data []byte

	Handle uint64 // open descriptor for handle ops
	Offset int64  // Pread/Pwrite position, Ftruncate length
	Size   uint32 // Pread request size, <= MaxIO
	Flags  uint32 // FxOpen Linux O_* flags
	Mode   uint32 // FxOpen/FxFchmod permission bits
	Owner  uint64 // lock owner identity, meaningful across clients
	// LkFlags carries the FUSE LkIn flags for lock ops. Bit 0 (FUSE_LK_FLOCK)
	// marks a flock(2) whole-file lock rather than a POSIX byte-range lock;
	// the two namespaces are independent on Linux and must not be mixed.
	LkFlags uint32
	Lock    *LockInfo
}

func (r *FxReq) Encode() []byte {
	var e Enc
	e.U32(r.ID)
	e.U8(r.Op)
	e.Str(r.Path)
	e.Str(r.Arg)
	e.U32(uint32(len(r.Data)))
	e.Raw(r.Data)
	e.U64(r.Handle)
	e.U64(uint64(r.Offset))
	e.U32(r.Size)
	e.U32(r.Flags)
	e.U32(r.Mode)
	e.U64(r.Owner)
	e.U32(r.LkFlags)
	if r.Lock != nil {
		e.U8(1)
		e.U32(r.Lock.Typ)
		e.U64(r.Lock.Start)
		e.U64(r.Lock.End)
		e.U32(r.Lock.Pid)
	} else {
		e.U8(0)
	}
	return e.B
}

func DecodeFxReq(p []byte) (*FxReq, error) {
	d := &Dec{B: p}
	r := &FxReq{ID: d.U32(), Op: d.U8()}
	r.Path = d.Str()
	r.Arg = d.Str()
	r.Data = d.Raw(int(d.U32()))
	r.Handle = d.U64()
	r.Offset = int64(d.U64())
	r.Size = d.U32()
	r.Flags = d.U32()
	r.Mode = d.U32()
	r.Owner = d.U64()
	r.LkFlags = d.U32()
	if d.U8() != 0 {
		r.Lock = &LockInfo{Typ: d.U32(), Start: d.U64(), End: d.U64(), Pid: d.U32()}
	}
	if d.Err != nil {
		return nil, d.Err
	}
	return r, nil
}

type FxResp struct {
	ID   uint32
	Kind byte
	Attr Attr
	Data []byte
	Ents []DirEntry
	Err  string

	Handle uint64 // KHandle, and echoed for handle ops
	Count  uint32 // bytes transferred (KData, KOk)
	Errno  uint32 // numeric errno; non-zero only for failures
	// Created marks a stat or open reply whose path was established by this
	// connection. The daemon is the only side that can answer it: the session
	// also creates names through commands it runs there, which never pass
	// through the view's own callbacks.
	Created bool
	// Epoch is the session's mutation epoch when this reply was produced. A
	// command the session runs on the daemon may change any name, and the
	// daemon announces the new epoch before the command starts; a reply from
	// an older epoch may describe a tree that command has since changed.
	Epoch uint64
	// Volatile marks a reply produced while one of the session's commands is
	// running. The daemon cannot tell which names that command touches, so the
	// view must not retain such an answer at all.
	Volatile bool
	// DirPath, DirDev and DirIno identify the directory a listing describes.
	// The names are relative to DirPath, and (DirDev, DirIno) is the inode the
	// listing was read from: a listing asked for through a descriptor answers
	// for that descriptor, which may live at another name than it was opened
	// under. DirPath is empty when the daemon cannot confirm that the path still
	// names that inode; the view then fills no per-path cache from the reply.
	DirPath string
	DirDev  uint64
	DirIno  uint64
	// Lock reports the conflicting lock for FxGetlk, if any.
	Lock *LockInfo
}

// LockInfo describes one byte-range lock in FUSE's terms.
type LockInfo struct {
	Typ   uint32 // 0 read, 1 write, 2 unlock
	Start uint64
	End   uint64
	Pid   uint32
}

func (r *FxResp) Encode() []byte {
	var e Enc
	e.U32(r.ID)
	e.U8(r.Kind)
	switch r.Kind {
	case KStat, KHandle:
		r.Attr.encode(&e)
	case KLink:
		e.Str(string(r.Data))
	case KDir:
		e.U32(uint32(len(r.Ents)))
		for _, it := range r.Ents {
			e.Str(it.Name)
			e.U32(it.Mode)
			it.Attr.encode(&e)
			if it.Created {
				e.U8(1)
			} else {
				e.U8(0)
			}
		}
	case KData:
		e.U32(uint32(len(r.Data)))
		e.Raw(r.Data)
	case KErr:
		e.Str(r.Err)
	case KOk:
		// Count and optional Lock are in the fixed tail below.
	}
	e.U64(r.Handle)
	e.U32(r.Count)
	e.U32(r.Errno)
	if r.Created {
		e.U8(1)
	} else {
		e.U8(0)
	}
	e.U64(r.Epoch)
	if r.Volatile {
		e.U8(1)
	} else {
		e.U8(0)
	}
	if r.Lock != nil {
		e.U8(1)
		e.U32(r.Lock.Typ)
		e.U64(r.Lock.Start)
		e.U64(r.Lock.End)
		e.U32(r.Lock.Pid)
	} else {
		e.U8(0)
	}
	e.Str(r.DirPath)
	e.U64(r.DirDev)
	e.U64(r.DirIno)
	return e.B
}

func DecodeFxResp(p []byte) (*FxResp, error) {
	d := &Dec{B: p}
	r := &FxResp{ID: d.U32(), Kind: d.U8()}
	switch r.Kind {
	case KStat, KHandle:
		r.Attr = decodeAttr(d)
	case KLink:
		r.Data = []byte(d.Str())
	case KDir:
		n := int(d.U32())
		for i := 0; i < n && d.Err == nil; i++ {
			name := d.Str()
			mode := d.U32()
			attr := decodeAttr(d)
			created := d.U8() != 0
			r.Ents = append(r.Ents, DirEntry{Name: name, Mode: mode, Attr: attr, Created: created})
		}
	case KData:
		n := int(d.U32())
		r.Data = append([]byte(nil), d.Raw(n)...)
	case KErr:
		r.Err = d.Str()
	}
	r.Handle = d.U64()
	r.Count = d.U32()
	r.Errno = d.U32()
	r.Created = d.U8() != 0
	r.Epoch = d.U64()
	r.Volatile = d.U8() != 0
	if d.U8() != 0 {
		r.Lock = &LockInfo{Typ: d.U32(), Start: d.U64(), End: d.U64(), Pid: d.U32()}
	}
	r.DirPath = d.Str()
	r.DirDev = d.U64()
	r.DirIno = d.U64()
	if d.Err != nil {
		return nil, d.Err
	}
	return r, nil
}

// ExitPayload builds the TExit payload.
func ExitPayload(status int) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(int32(status)))
	return b[:]
}

// SessionPayload builds the TSession payload: the session token a connection
// belongs to. The token is an opaque correlation key, never an authorization:
// the daemon serves the same tree with or without it.
func SessionPayload(token string) []byte {
	var e Enc
	e.Str(token)
	return e.B
}

// DecodeSessionPayload reads a TSession payload. An empty or malformed token
// leaves the connection outside any session, which is the pre-existing
// behaviour for a client that does not send one.
func DecodeSessionPayload(p []byte) (string, error) {
	d := &Dec{B: p}
	token := d.Str()
	if d.Err != nil {
		return "", d.Err
	}
	if len(token) > 128 {
		return "", fmt.Errorf("session token is too long")
	}
	if d.Off != len(p) {
		return "", fmt.Errorf("session token contains trailing payload bytes")
	}
	return token, nil
}

// InvalidatePayload builds the TInvalidate payload: the epoch the view adopts
// and the names whose retained answers are no longer usable. An announcement
// without names only moves the epoch, which is what a command start does.
func InvalidatePayload(epoch uint64, names []string) []byte {
	var e Enc
	e.U64(epoch)
	e.U32(uint32(len(names)))
	for _, name := range names {
		e.Str(name)
	}
	return e.B
}

// DecodeInvalidate reads a TInvalidate payload. Exactly eight bytes is an
// epoch-only announcement from a peer that predates the name list.
func DecodeInvalidate(p []byte) (uint64, []string, error) {
	if len(p) == 8 {
		return binary.BigEndian.Uint64(p), nil, nil
	}
	d := &Dec{B: p}
	epoch := d.U64()
	n := int(d.U32())
	var names []string
	for i := 0; i < n && d.Err == nil; i++ {
		names = append(names, d.Str())
	}
	if d.Err != nil {
		return 0, nil, d.Err
	}
	return epoch, names, nil
}

func ParseExit(p []byte) int {
	if len(p) < 4 {
		return -1
	}
	return int(int32(binary.BigEndian.Uint32(p)))
}
