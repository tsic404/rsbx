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

	TStdin  = 0x10
	TStdout = 0x11
	TStderr = 0x12

	TFxReq  = 0x20
	TFxResp = 0x21
)

const (
	FxStat     = 1
	FxRead     = 2 // whole file: the sandbox materialises on open
	FxWrite    = 3 // whole file, replaces content
	FxList     = 4
	FxReadlink = 5
	FxMkdir    = 6
	FxUnlink   = 7
	FxRename   = 8
	FxTruncate = 9
	FxChmod    = 10
	FxAccess   = 11
	// FxAppend adds bytes to the end of a file on the daemon. Appends cannot be
	// replayed from a local copy: the end position must be decided where the
	// file actually lives, or two writers tell each other's tail from nothing.
	FxAppend = 12
	// FxWriteAt writes at an explicit offset; Arg carries the decimal offset.
	FxWriteAt = 13
)

const (
	KNone = 0
	KFile = 1
	KDir  = 2
	KErr  = 3
	KStat = 4
	KOk   = 5
	KLink = 6
)

const (
	SIFDIR = 0o040000
	SIFREG = 0o100000
	SIFLNK = 0o120000

	MaxFrame = 32 << 20
)

type Frame struct {
	Type    byte
	Payload []byte
}

func WriteFrame(w io.Writer, typ byte, p []byte) error {
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

// ExecReq asks the daemon to run argv.
type ExecReq struct {
	Argv       []string
	Env        []string
	Dir        string
	TTY        bool
	Rows, Cols uint16
}

func (r *ExecReq) Encode() []byte {
	var e Enc
	e.U8(1)
	if r.TTY {
		e.U8(1)
	} else {
		e.U8(0)
	}
	e.U16(r.Rows)
	e.U16(r.Cols)
	e.Str(r.Dir)
	e.U32(uint32(len(r.Argv)))
	for _, a := range r.Argv {
		e.Str(a)
	}
	e.U32(uint32(len(r.Env)))
	for _, a := range r.Env {
		e.Str(a)
	}
	return e.B
}

func DecodeExecReq(p []byte) (*ExecReq, error) {
	d := &Dec{B: p}
	_ = d.U8()
	r := &ExecReq{TTY: d.U8()&1 != 0}
	r.Rows, r.Cols = d.U16(), d.U16()
	r.Dir = d.Str()
	n := int(d.U32())
	for i := 0; i < n && d.Err == nil; i++ {
		r.Argv = append(r.Argv, d.Str())
	}
	n = int(d.U32())
	for i := 0; i < n && d.Err == nil; i++ {
		r.Env = append(r.Env, d.Str())
	}
	if d.Err != nil {
		return nil, d.Err
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
}

func (a *Attr) encode(e *Enc) {
	e.U32(a.Mode)
	e.U64(a.Size)
	e.U64(uint64(a.Mtime))
	e.U64(a.Ino)
	e.U32(a.UID)
	e.U32(a.GID)
}

func decodeAttr(d *Dec) Attr {
	var a Attr
	a.Mode = d.U32()
	a.Size = d.U64()
	a.Mtime = int64(d.U64())
	a.Ino = d.U64()
	a.UID = d.U32()
	a.GID = d.U32()
	return a
}

type DirEntry struct {
	Name string
	Mode uint32
}

// FxReq is one filesystem operation against the remote tree.
type FxReq struct {
	ID   uint32
	Op   byte
	Path string
	Arg  string
	Data []byte
}

func (r *FxReq) Encode() []byte {
	var e Enc
	e.U32(r.ID)
	e.U8(r.Op)
	e.Str(r.Path)
	e.Str(r.Arg)
	e.U32(uint32(len(r.Data)))
	e.Raw(r.Data)
	return e.B
}

func DecodeFxReq(p []byte) (*FxReq, error) {
	d := &Dec{B: p}
	r := &FxReq{ID: d.U32(), Op: d.U8()}
	r.Path = d.Str()
	r.Arg = d.Str()
	r.Data = d.Raw(int(d.U32()))
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
}

func (r *FxResp) Encode() []byte {
	var e Enc
	e.U32(r.ID)
	e.U8(r.Kind)
	switch r.Kind {
	case KFile:
		e.U32(uint32(len(r.Data)))
		e.Raw(r.Data)
		r.Attr.encode(&e)
	case KStat:
		r.Attr.encode(&e)
	case KLink:
		e.Str(string(r.Data))
	case KDir:
		e.U32(uint32(len(r.Ents)))
		for _, it := range r.Ents {
			e.Str(it.Name)
			e.U32(it.Mode)
		}
	case KErr:
		e.Str(r.Err)
	}
	return e.B
}

func DecodeFxResp(p []byte) (*FxResp, error) {
	d := &Dec{B: p}
	r := &FxResp{ID: d.U32(), Kind: d.U8()}
	switch r.Kind {
	case KFile:
		n := int(d.U32())
		r.Data = append([]byte(nil), d.Raw(n)...)
		r.Attr = decodeAttr(d)
	case KStat:
		r.Attr = decodeAttr(d)
	case KLink:
		r.Data = []byte(d.Str())
	case KDir:
		n := int(d.U32())
		for i := 0; i < n && d.Err == nil; i++ {
			name := d.Str()
			mode := d.U32()
			r.Ents = append(r.Ents, DirEntry{Name: name, Mode: mode})
		}
	case KErr:
		r.Err = d.Str()
	}
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

func ParseExit(p []byte) int {
	if len(p) < 4 {
		return -1
	}
	return int(int32(binary.BigEndian.Uint32(p)))
}
