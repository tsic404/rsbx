# Sandbox probes

Two static C programs that exercise what a real program does to its own state
files. They exist because these patterns are hard to reach from a unit test —
they need a live FUSE mount and a running daemon — but trivial to describe.

| probe | what it does | what it catches |
|---|---|---|
| `atomic_write.c` | create temp, write, rename over the target, reopen | a rename that leaves the moved inode pointing at the old path |
| `durable_write.c` | write, `fsync`, write a `-wal` sidecar, `fsync` | a filesystem that answers `EOPNOTSUPP` to `fsync` |

Build them static, point them at a directory inside the sandbox, and check both
the exit status and the files that land on the host:

```sh
gcc -static -O1 -o atomic_write testdata/probe/atomic_write.c
gcc -static -O1 -o durable_write testdata/probe/durable_write.c
```
