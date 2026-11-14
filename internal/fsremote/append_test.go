package fsremote

import (
	"os"
	"path/filepath"
	"testing"

	"rsbx/internal/proto"
)

func TestAppendCreatesAndExtends(t *testing.T) {
	s, root := newServer(t)
	// empty payload creates the file
	if resp := s.Handle(&proto.FxReq{Op: proto.FxAppend, Path: "/new.log"}); resp.Kind == proto.KErr {
		t.Fatalf("create failed: %s", resp.Err)
	}
	if _, err := os.Stat(filepath.Join(root, "new.log")); err != nil {
		t.Fatalf("append did not create the file: %v", err)
	}
	// real appends accumulate in order
	for _, line := range []string{"a\n", "b\n", "c\n"} {
		if resp := s.Handle(&proto.FxReq{Op: proto.FxAppend, Path: "/new.log", Data: []byte(line)}); resp.Kind == proto.KErr {
			t.Fatalf("append %q failed: %s", line, resp.Err)
		}
	}
	got, err := os.ReadFile(filepath.Join(root, "new.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "a\nb\nc\n" {
		t.Fatalf("append order lost: %q", got)
	}
}

func TestAppendKeepsExistingContent(t *testing.T) {
	s, root := newServer(t)
	path := filepath.Join(root, "keep.log")
	if err := os.WriteFile(path, []byte("existing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if resp := s.Handle(&proto.FxReq{Op: proto.FxAppend, Path: "/keep.log"}); resp.Kind == proto.KErr {
		t.Fatalf("empty append failed: %s", resp.Err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "existing\n" {
		t.Fatalf("empty append truncated the file: %q", got)
	}
	s.Handle(&proto.FxReq{Op: proto.FxAppend, Path: "/keep.log", Data: []byte("added\n")})
	got, _ = os.ReadFile(path)
	if string(got) != "existing\nadded\n" {
		t.Fatalf("append result: %q", got)
	}
}
