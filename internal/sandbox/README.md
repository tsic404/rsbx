# rsbx boundaries

The sandbox is assembled from independently testable owners. Nothing in these
boundaries knows a particular agent CLI.

| owner | file | responsibility |
|---|---|---|
| policy | `internal/policy` | compile configured local executables plus their verified runtime assets; no hidden PATH grants |
| filesystem | `internal/fusefs` | one immutable file source per inode: daemon bytes, exact native asset, or explicit local tree |
| transport | `internal/rpc`, `internal/proto` | session-owned file and command connections with permanent close semantics |
| daemon | `internal/daemon`, `internal/fsremote` | run commands and own the remote tree, with no jail or path rewrite |
| controller | `cmd/rsbx`, `internal/sandbox/filesystem.go` | allocate one session, own cancellation, report teardown failures |
| launcher | `internal/sandbox/launch.go`, `exectrap_linux.go` | create real namespaces, remain PID 1, mediate every descendant exec |
| guard/gateway | `cmd/rsbx-guard`, `cmd/rsbx-tramp` | trusted exec restriction entry and remote command gateway |

Execution routing is not file substitution. A remote executable read through
FUSE remains the daemon's bytes; PID 1's exec supervisor decides whether an
execve/execveat is an exact local program or a remote daemon command.
