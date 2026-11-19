package sandbox

import "strings"

// builtinEmulationEnv turns off in-process command emulation in local agent
// runtimes. A tool command answered inside the runtime never reaches execve,
// so execution supervision cannot route it and the command stays local.
const builtinEmulationEnv = "PI_DISABLE_UUTILS_BUILTINS=1"

const builtinEmulationKey = "PI_DISABLE_UUTILS_BUILTINS="

// sessionEnvironment is the environment the entry starts with. The caller's
// environment is preserved; the emulation switch is added only when the caller
// did not set it, so an explicit choice is not overwritten.
func sessionEnvironment(base []string) []string {
	env := append([]string(nil), base...)
	for _, kv := range env {
		if strings.HasPrefix(kv, builtinEmulationKey) {
			return env
		}
	}
	return append(env, builtinEmulationEnv)
}
