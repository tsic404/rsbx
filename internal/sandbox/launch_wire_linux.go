//go:build linux

package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Metadata is ordinary configuration text. Unix exec strings are byte
// vectors: JSON's default string encoding would replace non-UTF-8 argv/env.
type launchSpecMetadata launchSpec

type launchSpecWire struct {
	launchSpecMetadata
	TargetBytes []byte   `json:"target"`
	ArgvBytes   [][]byte `json:"argv"`
	EnvBytes    [][]byte `json:"env"`
	CwdBytes    []byte   `json:"cwd"`
}

func (spec launchSpec) MarshalJSON() ([]byte, error) {
	if err := validateExecFields(spec.Target, spec.Argv, spec.Env); err != nil {
		return nil, err
	}
	if strings.IndexByte(spec.Cwd, 0) >= 0 {
		return nil, fmt.Errorf("cwd contains NUL")
	}
	return json.Marshal(launchSpecWire{
		launchSpecMetadata: launchSpecMetadata(spec),
		TargetBytes:        []byte(spec.Target), ArgvBytes: guardByteVector(spec.Argv),
		EnvBytes: guardByteVector(spec.Env), CwdBytes: []byte(spec.Cwd),
	})
}

func (spec *launchSpec) UnmarshalJSON(data []byte) error {
	var wire launchSpecWire
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return err
	}
	if len(bytes.TrimSpace(data[dec.InputOffset():])) != 0 {
		return fmt.Errorf("trailing launch specification")
	}
	candidate := launchSpec(wire.launchSpecMetadata)
	candidate.Target, candidate.Cwd = string(wire.TargetBytes), string(wire.CwdBytes)
	candidate.Argv, candidate.Env = guardStringVector(wire.ArgvBytes), guardStringVector(wire.EnvBytes)
	if err := validateExecFields(candidate.Target, candidate.Argv, candidate.Env); err != nil {
		return err
	}
	if strings.IndexByte(candidate.Cwd, 0) >= 0 {
		return fmt.Errorf("cwd contains NUL")
	}
	*spec = candidate
	return nil
}

// Entry search happens in the completed daemon/local view, not on the host.
// A daemon-only PATH entry and a relative project executable therefore reach
// the same exec supervisor as an explicit local entry. Argv is never
// rewritten: argv[0] stays exactly as the caller spelled it.
func resolveEntryTarget(spec *launchSpec) error {
	if filepath.IsAbs(spec.Target) {
		return verifyEntryTarget(spec.Target)
	}
	if strings.ContainsRune(spec.Target, '/') {
		// filepath.Abs resolves against the working directory the launcher
		// installed after pivot, so the relative spelling is interpreted in
		// the sandbox view rather than the host tree.
		abs, err := filepath.Abs(spec.Target)
		if err != nil {
			return err
		}
		abs = filepath.Clean(abs)
		if err := verifyEntryTarget(abs); err != nil {
			return err
		}
		spec.Target = abs
		return nil
	}
	resolved, err := resolveProgram(spec.Target, spec.Env)
	if err != nil {
		return err
	}
	spec.Target = resolved
	return nil
}

func verifyEntryTarget(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("entry %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
		return fmt.Errorf("entry %s is not a regular executable file", path)
	}
	return nil
}
