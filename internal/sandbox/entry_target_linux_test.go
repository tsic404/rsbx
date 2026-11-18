//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A command target that does not exist is an executability error naming the
// path. It is never turned into "run something else": this is the launcher's
// only chance to refuse a missing target, and the session must fail here.
func TestVerifyEntryTargetRejectsMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-target")
	err := verifyEntryTarget(missing)
	if err == nil {
		t.Fatal("a missing target was accepted")
	}
	if !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("failure does not name the missing target: %v", err)
	}
}

// A directory is not an executable target even when it exists.
func TestVerifyEntryTargetRejectsDirectory(t *testing.T) {
	if err := verifyEntryTarget(t.TempDir()); err == nil {
		t.Fatal("a directory was accepted as an executable target")
	}
}

// A regular file without any execute bit is refused as well: "exists" is not
// the criterion, "is an executable file" is.
func TestVerifyEntryTargetRejectsNonExecutableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(path, []byte("not a program"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyEntryTarget(path); err == nil {
		t.Fatal("a non-executable file was accepted as a target")
	}
}

// An absolute path to an executable file is the accepted case; the negative
// tests above are only meaningful if this one passes.
func TestVerifyEntryTargetAcceptsExecutableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "program")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyEntryTarget(path); err != nil {
		t.Fatalf("an executable file was rejected: %v", err)
	}
}

// A relative spelling that contains a slash is resolved against the launcher's
// working directory after pivot, so the check sees the sandbox view rather
// than the caller's host cwd.
func TestResolveEntryTargetResolvesRelativeSpelling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "program")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	spec := &launchSpec{Target: "./program"}
	if err := resolveEntryTarget(spec); err != nil {
		t.Fatalf("relative target was rejected: %v", err)
	}
	if !filepath.IsAbs(spec.Target) {
		t.Fatalf("relative target was not made absolute: %q", spec.Target)
	}
}
