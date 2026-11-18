//go:build linux

package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func openStat(t *testing.T, path string) (*os.File, unix.Stat_t) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		t.Fatal(err)
	}
	return f, st
}

// A session's executable snapshot is a copy of the bytes, not a link to the
// live file. Replacing the source after capture must leave the snapshot's
// content and digest unchanged: a session that re-read the host file would
// execute whatever a later writer put there.
func TestCacheSnapshotKeepsStartupBytesAfterSourceReplaced(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "exec-assets")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "program")
	original := []byte("#!/bin/sh\necho VERSION-ONE\n")
	replacement := []byte("#!/bin/sh\necho VERSION-TWO\n")
	if len(replacement) != len(original) {
		t.Fatalf("the check needs equal lengths: %d vs %d", len(replacement), len(original))
	}
	if err := os.WriteFile(src, original, 0o755); err != nil {
		t.Fatal(err)
	}
	f, identity := openStat(t, src)
	snapshot, err := cacheSnapshot(context.Background(), store, f, identity)
	f.Close()
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	wantDigest := sha256.Sum256(original)
	if snapshot.asset.Digest != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("snapshot digest = %s, want the source's bytes", snapshot.asset.Digest)
	}

	if err := os.WriteFile(src, replacement, 0o755); err != nil {
		t.Fatal(err)
	}
	captured, err := os.ReadFile(snapshot.object)
	if err != nil {
		t.Fatal(err)
	}
	if string(captured) != string(original) {
		t.Fatalf("snapshot object followed the replacement: %q", captured)
	}
	// The cached object is read-only, so a session cannot rewrite the snapshot
	// it was started from.
	info, err := os.Stat(snapshot.object)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Errorf("snapshot object is writable: %v", info.Mode())
	}
}

// A cache object whose bytes no longer match its source is rebuilt rather
// than trusted: a corrupted snapshot would otherwise run in every later
// session.
func TestCacheSnapshotRebuildsCorruptObject(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "exec-assets")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "program")
	original := []byte("#!/bin/sh\necho GOOD\n")
	if err := os.WriteFile(src, original, 0o755); err != nil {
		t.Fatal(err)
	}
	capture := func() cachedSnapshot {
		t.Helper()
		f, identity := openStat(t, src)
		snapshot, err := cacheSnapshot(context.Background(), store, f, identity)
		f.Close()
		if err != nil {
			t.Fatalf("capture: %v", err)
		}
		return snapshot
	}
	first := capture()
	// Corrupt the cached object without touching the source: this is the
	// corrupted-cache case, not a replaced source.
	if err := os.Chmod(first.object, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first.object, []byte("#!/bin/sh\necho BAD!\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	second := capture()
	captured, err := os.ReadFile(second.object)
	if err != nil {
		t.Fatal(err)
	}
	if string(captured) != string(original) {
		t.Fatalf("corrupt cache object was trusted: %q", captured)
	}
}
