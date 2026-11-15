package proto

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello frame")
	if err := WriteFrame(&buf, TStdout, payload); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TStdout || string(f.Payload) != string(payload) {
		t.Fatalf("got %#x %q", f.Type, f.Payload)
	}
}

func TestOversizeWriteFrameRejected(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, TStdout, make([]byte, MaxFrame+1)); err == nil {
		t.Fatal("oversized payload accepted")
	}
	if buf.Len() != 0 {
		t.Fatalf("bytes written before rejection: %d", buf.Len())
	}
}

func TestExecReqRoundTrip(t *testing.T) {
	in := &ExecReq{
		Argv: []string{"/bin/ls", "-l", "/"},
		Env:  []string{"A=1", "B=2"},
		Dir:  "/proj",
		TTY:  true,
		Rows: 40, Cols: 120,
	}
	got, err := DecodeExecReq(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Dir != in.Dir || got.Rows != 40 || !got.TTY || len(got.Argv) != 3 || got.Argv[2] != "/" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestFxRespKinds(t *testing.T) {
	cases := []*FxResp{
		{ID: 1, Kind: KData, Data: []byte("body"), Count: 4},
		{ID: 2, Kind: KDir, Ents: []DirEntry{{Name: "a", Mode: SIFREG}, {Name: "b", Mode: SIFDIR}}},
		{ID: 3, Kind: KErr, Err: "no such file"},
		{ID: 4, Kind: KLink, Data: []byte("target")},
		{ID: 5, Kind: KStat, Attr: Attr{Mode: SIFDIR | 0o755, Ino: 42}},
	}
	for _, want := range cases {
		got, err := DecodeFxResp(want.Encode())
		if err != nil {
			t.Fatalf("kind %d: %v", want.Kind, err)
		}
		if got.ID != want.ID || got.Kind != want.Kind {
			t.Fatalf("kind %d: got id=%d kind=%d", want.Kind, got.ID, got.Kind)
		}
		if want.Kind == KData && string(got.Data) != "body" {
			t.Errorf("data body lost: %q", got.Data)
		}
		if want.Kind == KDir && len(got.Ents) != 2 {
			t.Errorf("entries lost: %d", len(got.Ents))
		}
		if want.Kind == KErr && got.Err != "no such file" {
			t.Errorf("error text lost: %q", got.Err)
		}
	}
}

func TestFxReqRoundTrip(t *testing.T) {
	in := &FxReq{
		ID:     7,
		Op:     FxPwrite,
		Path:   "/proj/a.txt",
		Arg:    "",
		Data:   []byte{1, 2, 3},
		Handle: 0xdeadbeef,
		Offset: -1 << 33,
		Size:   MaxIO,
		Flags:  0o1002, // O_CREAT|O_RDWR
		Mode:   0o600,
		Owner:  1 << 40,
	}
	in.Lock = &LockInfo{Typ: 1, Start: 5, End: 1 << 32, Pid: 999}
	got, err := DecodeFxReq(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Handle != in.Handle || got.Offset != in.Offset || got.Size != in.Size ||
		got.Flags != in.Flags || got.Mode != in.Mode || got.Owner != in.Owner {
		t.Fatalf("numeric fields lost: %+v", got)
	}
	if got.Path != in.Path || string(got.Data) != string(in.Data) {
		t.Fatalf("path/data lost: %+v", got)
	}
	if got.Lock == nil || *got.Lock != *in.Lock {
		t.Fatalf("lock lost: %+v", got.Lock)
	}
	in.Lock = nil
	got, err = DecodeFxReq(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Lock != nil {
		t.Fatalf("absent lock decoded as present: %+v", got.Lock)
	}
}

func TestFxRespRoundTrip(t *testing.T) {
	in := &FxResp{
		ID:     9,
		Kind:   KHandle,
		Attr:   Attr{Mode: SIFREG | 0o644, Size: 8, Mtime: 100, MtimeNsec: 7, Ctime: 101, CtimeNsec: 9, Atime: 102, AtimeNsec: 11, Ino: 5, Dev: 1 << 20, UID: 2, GID: 3, Nlink: 4},
		Handle: 1 << 50,
	}
	got, err := DecodeFxResp(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Handle != in.Handle {
		t.Fatalf("handle lost: %d", got.Handle)
	}
	if got.Attr != in.Attr {
		t.Fatalf("attr lost: %+v", got.Attr)
	}

	in = &FxResp{ID: 10, Kind: KData, Data: []byte("chunk"), Count: 5, Handle: 3}
	got, err = DecodeFxResp(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "chunk" || got.Count != 5 || got.Handle != 3 {
		t.Fatalf("KData lost: %+v", got)
	}

	in = &FxResp{ID: 11, Kind: KOk, Count: 12}
	got, err = DecodeFxResp(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Count != 12 || got.Lock != nil {
		t.Fatalf("KOk lost: %+v", got)
	}
	in.Lock = &LockInfo{Typ: 0, Start: 1, End: 2, Pid: 3}
	got, err = DecodeFxResp(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Lock == nil || *got.Lock != *in.Lock {
		t.Fatalf("lock lost: %+v", got.Lock)
	}

	in = &FxResp{ID: 12, Kind: KErr, Err: "interrupted", Errno: 4}
	got, err = DecodeFxResp(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Err != "interrupted" || got.Errno != 4 {
		t.Fatalf("error lost: %+v", got)
	}
}
