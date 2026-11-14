# rsbx layout

The sandbox is assembled from four independent mechanisms, each of which can
be tested on its own:

| layer | file | responsibility |
|---|---|---|
| policy | `internal/policy` | absolute-path allowlist, pure function |
| filesystem | `internal/fusefs` | union of daemon tree, host toolchain, trampolines |
| transport | `internal/rpc`, `internal/proto` | frames over a unix socket or ssh stdio |
| daemon | `internal/daemon`, `internal/fsremote` | executes commands, owns the remote tree |

The trampoline (`cmd/rsbx-tramp`) is what makes redirection hold for every
program, including statically linked ones: the name in the sandbox simply *is*
the trampoline, so there is no host binary left to run by accident.
