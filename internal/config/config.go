// Package config loads the sandbox definition.
//
// Format: a deliberately small TOML subset (tables, string/bool/integer/array
// values, comments). Parsing it directly keeps the binary dependency free.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	// Daemon is where non-whitelisted commands execute.
	Daemon Daemon `json:"daemon"`
	// Local lists executables that run on this machine.
	Local Local `json:"local"`
	// Remote describes the daemon-side tree.
	Remote Remote `json:"remote"`
	// Sandbox controls the local view.
	Sandbox Sandbox `json:"sandbox"`
}

type Daemon struct {
	// Transport is "unix" (socket) or "ssh" (spawn Command).
	Transport string `json:"transport"`
	Socket    string `json:"socket"`
	Command   string `json:"command"`
}

// EffectiveEndpoint names the daemon for error messages.
func (d Daemon) EffectiveEndpoint() string {
	if d.Transport == "ssh" {
		return d.Command
	}
	return d.Socket
}

type Local struct {
	// Allow is the list of executables permitted to run on this machine.
	// A directory prefix, a glob or a single file.
	Allow []string `json:"allow"`
	// Paths are trees served straight from this machine instead of the
	// daemon: they are local content. Matched paths are read and written
	// locally, with no round trip.
	Paths []string `json:"paths"`
	// ReadOnlyPaths are served locally but cannot be modified. Toolchain
	// directories belong here; anything holding user state does not.
	ReadOnlyPaths []string `json:"read_only_paths"`
	// Entry is the shell started inside the sandbox.
	Entry string `json:"entry"`
}

type Remote struct {
	// Root is the daemon-side directory that maps to / inside the sandbox.
	// For the ssh transport it is passed to rsbxd on the command line, so the
	// value here is only a sanity check.
	Root string `json:"root"`
}

type Sandbox struct {
	// Mount is where the sandbox view appears on this machine.
	Mount string `json:"mount"`
	// Share is the directory that mirrors the remote tree locally (FUSE).
	Share string `json:"share"`
	// ShareNetwork keeps the host network namespace inside the sandbox
	// instead of creating a private one. Set it when the daemon is reached
	// over the network (the ssh transport does this automatically), or when
	// the host cannot create a network namespace, as some containers cannot.
	ShareNetwork bool `json:"share_network"`
	// UnshareUser creates a user namespace for the sandbox. Outside a
	// container that is what allows it to run unprivileged. Inside one the
	// runtime has already done it, and nested creation is refused on some
	// hosts (GitHub Actions refuses the uid map outright), so it is skipped.
	UnshareUser bool `json:"unshare_user"`
}

// Default returns a working configuration for a first run.
func Default() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		Daemon: Daemon{Transport: "unix", Socket: filepath.Join(home, ".rsbx", "daemon.sock")},
		Local: Local{
			Allow: []string{"/usr/bin", "/bin", "/usr/lib", "/lib", "/usr/lib64", "/lib64"},
			Entry: "/bin/sh",
		},
		Remote: Remote{Root: "/"},
		Sandbox: Sandbox{
			Mount:       filepath.Join(home, ".rsbx", "sandbox"),
			Share:       filepath.Join(home, ".rsbx", "share"),
			UnshareUser: true,
		},
	}
}

// Load reads path; a missing file yields Default().
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return nil, err
	}
	return Parse(string(data))
}

// Parse understands the subset described in parseValue.
func Parse(src string) (*Config, error) {
	cfg := Default()
	cfg.Local.Allow = nil
	table := ""
	lines := strings.Split(src, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("line %d: unterminated table", i+1)
			}
			table = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", i+1)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])

		// An array may span lines; keep consuming until the brackets balance,
		// counting only brackets that are outside a quoted string.
		if strings.HasPrefix(val, "[") && !balanced(val) {
			start := i + 1
			for i+1 < len(lines) {
				i++
				val += "\n" + strings.TrimSpace(stripComment(lines[i]))
				if balanced(val) {
					break
				}
			}
			if !balanced(val) {
				return nil, fmt.Errorf("line %d: unterminated array", start)
			}
		}
		if err := assign(cfg, table, key, val); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
	}
	expandHome(cfg)
	return cfg, nil
}

func expandHome(cfg *Config) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	fix := func(s string) string {
		if s == "~" {
			return home
		}
		if strings.HasPrefix(s, "~/") {
			return filepath.Join(home, s[2:])
		}
		return s
	}
	cfg.Daemon.Socket = fix(cfg.Daemon.Socket)
	cfg.Sandbox.Mount = fix(cfg.Sandbox.Mount)
	cfg.Sandbox.Share = fix(cfg.Sandbox.Share)
	for i := range cfg.Local.Paths {
		cfg.Local.Paths[i] = fix(cfg.Local.Paths[i])
	}
	for i := range cfg.Local.ReadOnlyPaths {
		cfg.Local.ReadOnlyPaths[i] = fix(cfg.Local.ReadOnlyPaths[i])
	}
}

func assign(cfg *Config, table, key, raw string) error {
	str := func(dst *string) error {
		v, err := parseString(raw)
		if err != nil {
			return err
		}
		*dst = v
		return nil
	}
	list := func(dst *[]string) error {
		v, err := parseArray(raw)
		if err != nil {
			return err
		}
		*dst = v
		return nil
	}
	switch table {
	case "daemon":
		switch key {
		case "transport":
			return str(&cfg.Daemon.Transport)
		case "socket":
			return str(&cfg.Daemon.Socket)
		case "command":
			return str(&cfg.Daemon.Command)
		}
	case "local":
		switch key {
		case "allow":
			return list(&cfg.Local.Allow)
		case "paths":
			return list(&cfg.Local.Paths)
		case "read_only_paths":
			return list(&cfg.Local.ReadOnlyPaths)
		case "entry":
			return str(&cfg.Local.Entry)
		}
	case "remote":
		if key == "root" {
			return str(&cfg.Remote.Root)
		}
	case "sandbox":
		switch key {
		case "mount":
			return str(&cfg.Sandbox.Mount)
		case "share":
			return str(&cfg.Sandbox.Share)
		case "share_network":
			v, err := parseBool(raw)
			if err != nil {
				return err
			}
			cfg.Sandbox.ShareNetwork = v
			return nil
		case "unshare_user":
			v, err := parseBool(raw)
			if err != nil {
				return err
			}
			cfg.Sandbox.UnshareUser = v
			return nil
		}
	case "":
		return fmt.Errorf("key %q outside a table", key)
	}
	return fmt.Errorf("unknown key %s.%s", table, key)
}

// balanced reports whether every '[' in s is matched by a ']', ignoring
// brackets inside double quotes.
func balanced(s string) bool {
	depth, inQuote, escaped := 0, false, false
	for _, r := range s {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && inQuote:
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case inQuote:
		case r == '[':
			depth++
		case r == ']':
			depth--
		}
	}
	return depth == 0 && !inQuote
}

// stripComment removes a trailing # comment that is outside a quoted string.
func stripComment(s string) string {
	inQuote, escaped := false, false
	for i, r := range s {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && inQuote:
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case r == '#' && !inQuote:
			return s[:i]
		}
	}
	return s
}

func parseBool(raw string) (bool, error) {
	switch strings.TrimSpace(raw) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("expected true or false")
}

func parseString(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "\"") || !strings.HasSuffix(raw, "\"") || len(raw) < 2 {
		return "", fmt.Errorf("expected a quoted string")
	}
	s, err := strconv.Unquote(raw)
	if err != nil {
		return "", err
	}
	return s, nil
}

func parseArray(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "[") || !strings.HasSuffix(raw, "]") {
		return nil, fmt.Errorf("expected [ ... ]")
	}
	inner := strings.TrimSpace(raw[1 : len(raw)-1])
	if inner == "" {
		return nil, nil
	}
	var out []string
	for _, part := range splitTop(inner) {
		s, err := parseString(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// splitTop splits on commas that are outside quotes.
func splitTop(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, escaped := false, false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			cur.WriteRune(r)
			escaped = true
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ',' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}
