package sandbox

import (
	"reflect"
	"strings"
	"testing"

	"rsbx/internal/config"
)

func TestSessionEnvironmentAddsBuiltinEmulationSwitch(t *testing.T) {
	got := sessionEnvironment([]string{"HOME=/home/agent", "PATH=/usr/bin"})
	want := []string{"HOME=/home/agent", "PATH=/usr/bin", builtinEmulationEnv}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("session environment = %q, want %q", got, want)
	}
}

func TestSessionEnvironmentKeepsCallerValue(t *testing.T) {
	base := []string{"HOME=/home/agent", "PI_DISABLE_UUTILS_BUILTINS=0"}
	got := sessionEnvironment(base)
	if !reflect.DeepEqual(got, base) {
		t.Fatalf("session environment = %q, want the caller's %q", got, base)
	}
}

func TestSessionEnvironmentDoesNotAliasCaller(t *testing.T) {
	base := []string{"HOME=/home/agent"}
	got := sessionEnvironment(base)
	got[0] = "HOME=/changed"
	if base[0] != "HOME=/home/agent" {
		t.Fatalf("session environment modified the caller's slice: %q", base)
	}
}

func TestLaunchSpecCarriesSessionEnvironment(t *testing.T) {
	t.Setenv("RSBX_SESSION_ENV_TEST", "kept")
	spec, err := (&Plan{Cfg: &config.Config{}}).launchSpec(nil, &broker{})
	if err != nil {
		t.Fatalf("launchSpec: %v", err)
	}
	for _, want := range []string{"RSBX_SESSION_ENV_TEST=kept", builtinEmulationEnv} {
		found := false
		for _, kv := range spec.Env {
			if kv == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("entry environment lacks %q: %q", want, spec.Env)
		}
	}
	if strings.Count(strings.Join(spec.Env, "\n"), builtinEmulationKey) > 1 {
		t.Errorf("entry environment repeats the emulation switch: %q", spec.Env)
	}
}
