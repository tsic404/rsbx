# Sandbox probes

What a real program does to its own files, exercised through a live mount. They
exist because these patterns are hard to reach from a unit test — they need a
running daemon and a FUSE mount — but trivial to describe.

| probe | what it does | what it catches |
|---|---|---|
| `atomic_write.c` | create temp, write, rename over the target, reopen | a rename that leaves the moved inode pointing at the old path |
| `durable_write.c` | write, `fsync`, write a `-wal` sidecar, `fsync` | a filesystem that answers `EOPNOTSUPP` to `fsync` |
| `workload.sh` | 23 checks: atomic write, append, truncate, symlink, hard link, chmod, utimes, `rm -rf`, directory rename, sqlite, large files, `seek` writes, 100 small files, tar roundtrip, git commit, readdir, concurrent appenders | everything a coding agent does to its project, which is where the filesystem's edges actually show |

`workload.sh` is the wider net: run it inside the sandbox and count `OK` lines.
Each check is annotated with the bug it was written for, so a failure names the
system call that regressed.

Build them static, point them at a directory inside the sandbox, and check both
the exit status and the files that land on the host:

```sh
gcc -static -O1 -o atomic_write testdata/probe/atomic_write.c
gcc -static -O1 -o durable_write testdata/probe/durable_write.c
```
