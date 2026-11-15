package fusefs

import (
	"os"
	"path/filepath"
	"testing"

	"rsbx/internal/proto"
)

// stubRemote answers stat from a fixed attribute and counts calls, so a test
// can tell a cache hit from a round trip.
type stubRemote struct {
	attr  proto.Attr
	found bool
	stats int
	reads int
	body  []byte
}

func (s *stubRemote) Do(req *proto.FxReq) (*proto.FxResp, error) {
	switch req.Op {
	case proto.FxStat:
		s.stats++
		if !s.found {
			return &proto.FxResp{Kind: proto.KNone}, nil
		}
		return &proto.FxResp{Kind: proto.KStat, Attr: s.attr}, nil
	case proto.FxRead:
		s.reads++
		return &proto.FxResp{Kind: proto.KFile, Data: s.body, Attr: s.attr}, nil
	}
	return &proto.FxResp{Kind: proto.KOk}, nil
}

func (s *stubRemote) ReadFile(string) ([]byte, proto.Attr, error) {
	s.reads++
	return s.body, s.attr, nil
}

func (s *stubRemote) WriteFile(string, []byte) error { return nil }

type stubLocal struct{}

func (stubLocal) IsLocal(string) bool  { return false }
func (stubLocal) Writable(string) bool { return false }
func (stubLocal) Roots() []string      { return nil }

// seed writes a cache entry the way Open does: the body plus a metadata stamp.
func seed(t *testing.T, lay *Layout, p string, attr proto.Attr, body []byte) {
	t.Helper()
	if err := os.MkdirAll(lay.Cache, 0o700); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(lay.Cache, hash(p))
	if err := os.WriteFile(full, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full+".meta", []byte(stampOf(attr)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newLayout(t *testing.T, r *stubRemote) *Layout {
	t.Helper()
	return &Layout{Remote: r, Local: stubLocal{}, Cache: filepath.Join(t.TempDir(), "cache")}
}

// A copy whose metadata still matches the daemon is served locally.
func TestCacheHitWhenMetadataMatches(t *testing.T) {
	attr := proto.Attr{Mode: proto.SIFREG | 0o644, Size: 4, Mtime: 100, Ino: 7}
	r := &stubRemote{attr: attr, found: true}
	lay := newLayout(t, r)
	seed(t, lay, "/a", attr, []byte("body"))

	got, gotAttr, err := lay.cached("/a")
	if err != nil {
		t.Fatalf("expected a hit: %v", err)
	}
	if got == "" || gotAttr.Mtime != 100 {
		t.Fatalf("hit returned %q %+v", got, gotAttr)
	}
}

// The daemon changing the file must invalidate the copy. Comparing the copy's
// own age instead, as the previous implementation did, cannot detect this.
func TestCacheMissWhenDaemonChangedFile(t *testing.T) {
	original := proto.Attr{Mode: proto.SIFREG | 0o644, Size: 4, Mtime: 100, Ino: 7}
	changed := original
	changed.Mtime = 200
	changed.Size = 9

	r := &stubRemote{attr: changed, found: true}
	lay := newLayout(t, r)
	seed(t, lay, "/a", original, []byte("body"))

	if _, _, err := lay.cached("/a"); err == nil {
		t.Fatal("stale copy served as current")
	}
}

// Only the modification time changing (same size) must also invalidate: this
// is the case a size-only comparison would miss.
func TestCacheMissWhenOnlyMtimeChanged(t *testing.T) {
	original := proto.Attr{Mode: proto.SIFREG | 0o644, Size: 4, Mtime: 100, Ino: 7}
	touched := original
	touched.Mtime = 101

	r := &stubRemote{attr: touched, found: true}
	lay := newLayout(t, r)
	seed(t, lay, "/a", original, []byte("body"))

	if _, _, err := lay.cached("/a"); err == nil {
		t.Fatal("same-size modification served as current")
	}
}

// A file deleted on the daemon must not be served from the cache.
func TestCacheMissWhenRemoteGone(t *testing.T) {
	attr := proto.Attr{Mode: proto.SIFREG | 0o644, Size: 4, Mtime: 100, Ino: 7}
	r := &stubRemote{attr: attr, found: false}
	lay := newLayout(t, r)
	seed(t, lay, "/a", attr, []byte("body"))

	if _, _, err := lay.cached("/a"); err == nil {
		t.Fatal("deleted file served from cache")
	}
}

// A copy without a stamp cannot be validated and must not be used.
func TestCacheMissWithoutStamp(t *testing.T) {
	attr := proto.Attr{Mode: proto.SIFREG | 0o644, Size: 4, Mtime: 100, Ino: 7}
	r := &stubRemote{attr: attr, found: true}
	lay := newLayout(t, r)
	if err := os.MkdirAll(lay.Cache, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lay.Cache, hash("/a")), []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lay.cached("/a"); err == nil {
		t.Fatal("unstamped copy served")
	}
}
