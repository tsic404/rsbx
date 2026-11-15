# Sandbox probes

What a real program does to its own files, exercised through a live mount. They
exist because these patterns are hard to reach from a unit test — they need a
running daemon and a FUSE mount — but trivial to describe.

| probe | what it does | what it catches |
|---|---|---|
| `atomic_write.c` | create temp, write, rename over the target, reopen | a rename that leaves the moved inode pointing at the old path |
| `durable_write.c` | write, `fsync`, write a `-wal` sidecar, `fsync` | a filesystem that answers `EOPNOTSUPP` to `fsync` |
| `workload.sh` | 23 checks: atomic write, append, truncate, symlink, hard link, chmod, utimes, `rm -rf`, directory rename, sqlite, large files, `seek` writes, 100 small files, tar roundtrip, git commit, readdir, concurrent appenders | everything a coding agent does to its project, which is where the filesystem's edges actually show |
| `semantics.sh` | 22 checks: rename over an existing file, rename across directories, dangling and looping symlinks, `O_EXCL`, `rmdir` on a non-empty directory, 60-level nesting, unusual names, sparse extension, concurrent append to one file, zero-byte files, listing under mutation, `mmap` reads, `stat` after `chmod`, hard link surviving a rename, deep directory rename, `fsync` on a directory, `cp -p`, symlink to a directory, racing `mkdir`/`rmdir`, write-read-many, write through a deleted name | the POSIX edges: each one is a way a program expects to be told "no", or expects its data to survive |

`workload.sh` is the wider net: run it inside the sandbox and count `OK` lines.
Each check is annotated with the bug it was written for, so a failure names the
system call that regressed.

`semantics.sh` goes after the edges that only show up under a real workload: a
descriptor outliving its name, a rename over an open file, a symlink that loops.
A check whose program is missing (no `python3` in the slim image) reports
`SKIP` rather than passing, so an unimplemented path cannot hide behind a
missing tool.

Build them static, point them at a directory inside the sandbox, and check both
the exit status and the files that land on the host:

```sh
gcc -static -O1 -o atomic_write testdata/probe/atomic_write.c
gcc -static -O1 -o durable_write testdata/probe/durable_write.c
```
