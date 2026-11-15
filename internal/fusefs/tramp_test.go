package fusefs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"

	"rsbx/internal/proto"
)

// The handle opened for a trampolined name has to report the program it
// stands for, not the file it was opened from: Getattr on that descriptor
// answers the kernel's exec check, and a mode without an execute bit makes the
// second exec of the same name fail with EACCES while the first one succeeded.
//
// It is the shape a real git triggers: one session runs `git` several times,
// and every call after the first was refused.
func TestTrampolineHandleReportsExecutableAttrs(t *testing.T) {
	dir := t.TempDir()
	tramp := filepath.Join(dir, "tramp")
	// A real trampoline is executable, but the mode served for the name it
	// replaces is the policy's (0555), which is what this asserts. The file
	// mode is not consulted, so a read-only trampoline must not leak through.
	if err := os.WriteFile(tramp, []byte("\x7fELF"), 0o444); err != nil {
		t.Fatal(err)
	}
	lay := &Layout{
		Remote:     &stubRemote{found: true, attr: proto.Attr{Mode: proto.SIFREG | 0o755, Size: 100}},
		Local:      stubLocal{},
		ExecDirs:   []string{"/opt/tools"},
		Trampoline: tramp,
		LocalExec:  func(string) bool { return false },
	}
	n := &Node{lay: lay, path: "/opt/tools/remote-tool"}

	fh, _, errno := n.Open(context.Background(), uint32(os.O_RDONLY))
	if errno != 0 {
		t.Fatalf("open trampolined name: %v", errno)
	}
	h, ok := fh.(*handle)
	if !ok {
		t.Fatalf("open returned %T, want *handle", fh)
	}
	defer h.Release(context.Background())

	var out fuse.AttrOut
	if err := n.Getattr(context.Background(), h, &out); err != 0 {
		t.Fatalf("getattr on the handle: %v", err)
	}
	if out.Attr.Mode&0o111 != 0o111 {
		t.Errorf("descriptor mode %#o is not executable: a second exec of this name would be refused", out.Attr.Mode)
	}
	if out.Attr.Size != 4 {
		t.Errorf("descriptor size %d, want the trampoline's 4", out.Attr.Size)
	}
}
