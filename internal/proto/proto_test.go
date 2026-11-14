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
		{ID: 1, Kind: KFile, Data: []byte("body"), Attr: Attr{Mode: SIFREG | 0o644, Size: 4}},
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
		if want.Kind == KFile && string(got.Data) != "body" {
			t.Errorf("file body lost: %q", got.Data)
		}
		if want.Kind == KDir && len(got.Ents) != 2 {
			t.Errorf("entries lost: %d", len(got.Ents))
		}
		if want.Kind == KErr && got.Err != "no such file" {
			t.Errorf("error text lost: %q", got.Err)
		}
	}
}

func TestOversizedFrameRejected(t *testing.T) {
	var buf bytes.Buffer
	hdr := []byte{0x7f, 0xff, 0xff, 0xff, TStdout} // ~2 GiB
	buf.Write(hdr)
	if _, err := ReadFrame(&buf); err == nil {
		t.Fatal("oversized frame accepted")
	}
}
