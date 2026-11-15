# Sandbox probes

What a real program does to its own files, exercised through a live mount. They
exist because these patterns are hard to reach from a unit test — they need a
running daemon and a FUSE mount — but trivial to describe.

| probe | what it does | what it catches |
|---|---|---|
| `atomic_write.c` | create temp, write, rename over the target, reopen | a rename that leaves the moved inode pointing at the old path |
| `durable_write.c` | write, `fsync`, write a `-wal` sidecar, `fsync` | a filesystem that answers `EOPNOTSUPP` to `fsync` |
| `workload.sh` | 23 checks: atomic write, append, truncate, symlink, hard link, chmod, utimes, `rm -rf`, directory rename, sqlite, large files, `seek` writes, 100 small files, tar roundtrip, git commit, readdir, concurrent appenders | everything a coding agent does to its project, which is where the filesystem's edges actually show |
| `agents.sh` | 8 checks: four sessions working side by side, one shared file under a lock, an open descriptor surviving a rewrite, a 200-entry cache directory, a tree removed while it is being read, a durable state file replaced by rename, interleaved reads and writes, a process exiting mid-write | concurrent sessions in one project, which is what a shared sandbox actually runs |
| `dual.sh` | 8 checks: two sandboxes appending to their own files, both appending to one shared file, one session's file visible to the other, a whole tree built by one session complete for the other, racing directory creation, four sessions at once, separate cache directories, an open descriptor reading the OLD bytes after another session replaced the file by rename | two `rsbx` clients sharing one daemon tree, which is what an agent team in a repo is; the daemon has to arbitrate without losing bytes or letting one session see a half-written file |
| `runtime.sh` | 9 checks: a large dynamically linked program starts and reports its version, the CPU feature flags a prebuilt library checks, `ldd` resolves every library, the agent's own state directory is writable, state survives a reopen, the visible tree is the sandbox's, forty short-lived programs in sequence, a config file written and re-read, an 8 MB state file | the facts an agent depends on before any model is involved; point `RSBX_AGENT` at a real agent binary to include the startup checks |
| `execloc.sh` | 6 checks: a new file in an exec directory, a non-executable blob, a helper script read back verbatim, a subdirectory, twenty files created in sequence, an in-place edit | an exec directory holds both programs and data. Serving the second as the trampoline turns every file a session creates there into a 3 MB copy of this binary |
| `cache.sh` | 6 checks: eight sessions reading one file, a file rewritten between reads, a file deleted while open, a same-size same-timestamp rewrite, a 200 KB file read in pieces, twenty write-then-read cycles | the read cache: a stale or half-written entry serves wrong bytes, and every tool depends on not being lied to |
| `process.sh` | 10 checks: exit status 0/1/42/255, a signalled process, stdout and stderr kept apart, stdin through a pipe, binary through a pipe, 20000 output lines, exported environment, working directory, output from a program that then fails, an interrupted job | the session, not the filesystem: the status and streams a program reports back have to survive the bridge unchanged |
| `semantics.sh` | 22 checks: rename over an existing file, rename across directories, dangling and looping symlinks, `O_EXCL`, `rmdir` on a non-empty directory, 60-level nesting, unusual names, sparse extension, concurrent append to one file, zero-byte files, listing under mutation, `mmap` reads, `stat` after `chmod`, hard link surviving a rename, deep directory rename, `fsync` on a directory, `cp -p`, symlink to a directory, racing `mkdir`/`rmdir`, write-read-many, write through a deleted name | the POSIX edges: each one is a way a program expects to be told "no", or expects its data to survive |

`workload.sh` is the wider net: run it inside the sandbox and count `OK` lines.
Each check is annotated with the bug it was written for, so a failure names the
system call that regressed.

`semantics.sh` goes after the edges that only show up under a real workload: a
descriptor outliving its name, a rename over an open file, a symlink that loops.
A check whose program is missing (no `python3` in the slim image) reports
`SKIP` rather than passing, so an unimplemented path cannot hide behind a
missing tool.

Every probe is destructive: each check wipes its working directory clean. Set
the scratch parameters explicitly, never a host `/proj`:

* the single-session probes take `RSBX_PROJ` — a disposable directory on the
  remote tree (e.g. `RSBX_PROJ=/proj/probe-run`, where `/proj` is a throwaway
  volume in the daemon's own container);
* `execloc.sh` additionally takes `RSBX_EXEC_DIR`, the writable exec directory
  under test;
* `dual.sh` takes `TREE` (the daemon project tree as the sandbox sees it),
  `MNT` (a disposable client scratch home), and `F` (the client binary). Every
  result is verified through a session, not a host path, so it can run from a
  client container that has no bind of the project at all.

A probe that would wipe a default or system root refuses to start.

Build the two C probes static; the image carries no compiler, so build them on
the host and mount or copy them into the sandbox:

```sh
gcc -static -O1 -o atomic_write testdata/probe/atomic_write.c
gcc -static -O1 -o durable_write testdata/probe/durable_write.c
```
