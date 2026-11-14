package fusefs

import "testing"

// The dynamic loader is executed by the kernel for every dynamically linked
// program. Trapping it would make every local program unrunnable, which is
// exactly the bug that made the sandbox exec a trampoline instead of bash.
func TestLoaderIsNeverTrapped(t *testing.T) {
	for _, p := range []string{
		"/lib64/ld-linux-x86-64.so.2",
		"/lib/ld-musl-x86_64.so.1",
		"/usr/lib/libc.so.6",
		"/lib/x86_64-linux-gnu/libz.so.1",
	} {
		if !isLoader(p) {
			t.Errorf("%s not recognised as a loader", p)
		}
	}
	for _, p := range []string{"/usr/bin/bash", "/usr/bin/cat", "/work/prog.lua"} {
		if isLoader(p) {
			t.Errorf("%s wrongly treated as a loader", p)
		}
	}
}
