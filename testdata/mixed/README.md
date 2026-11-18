# The mixed-execution model

What a session looks like when a host-side CLI drives work that happens on the
daemon: an allowlisted CLI runs here, everything it touches is the daemon's
tree, and any program that is not allowlisted runs on the daemon.

Two facts have to hold at once, and each is measured rather than asserted:

* **Where a program ran.** `/proc/1/comm` is the init of the machine the
  process really runs on. A host program sees this session's `rsbx` PID 1; a
  program the daemon started sees the daemon's own init. A pid number cannot
  show this: both sides number their processes from a small sequence. The
  expected names are passed as `CLIENT_INIT`/`DAEMON_INIT` and compared against
  what the kernel reports, so a different deployment is a visible failure
  rather than a silent pass.
* **What a program sees.** A marker file written only on the daemon is
  readable through the session and absent from the client's own view of that
  path. A local configuration file is the reverse: present in the local tree
  and never visible to a remote program.

| probe | what it does | what it catches |
|---|---|---|
| `lab.sh` | 12 checks: the stand-in CLI runs here, sees the daemon tree, `git` is absent here yet runs, `git` runs on the daemon, its work lands on the daemon tree and survives, startup diagnostics are reported on stderr and never as command output, the agent's config tree is local, its work product is remote, every agent CLI runs here, the CLI and `git` see one tree | a policy that runs the wrong program on the wrong side, leaves a local tree on the daemon, or turns a warning into command output |
| `stress.sh` | 4 concurrent checks at N sessions sharing **one** configuration file: parallel commits, host and daemon programs interleaved 20 times with placement measured each round, agent config local while its product is remote, one shared remote file rewritten and re-read 10 times | contention that only appears when several sessions share one daemon, and any per-session resource that the caller accidentally shares |
| `real.sh` | the real-CLI gate: installed Multica/OMP/Codex/Claude startups, real `multica config set/get` file IO, and the native substrate fixture's boundary checks (local config vs remote artifact, executable byte preservation, custom argv[0], named execveat, deleted descriptor refusal, remote git clone visibility, detached-child and canceled-session cleanup) | a native snapshot that cannot start, or a boundary that substitutes local bytes, loses argv[0], uploads anonymous descriptors, leaks remote paths into local trees, or leaks session descendants |

`multica`, `omp`, `codex` and `claude` in this directory are **shell
stand-ins**, not the real programs. They exist to make placement observable in
the two purpose-built images; they prove the sandbox's placement and file-source
policy only. They prove nothing about real CLI compatibility.

`native-proof.c` (built by `native-build.sh`) is the **native substrate
fixture**. It is a small statically linked program, explicitly allowlisted as
an exact local executable, that measures the boundary itself. It is not an
agent and is not a substitute for one.

The real binaries are checked by `real.sh` against binaries installed on the
client (see `REAL_TOOLS` below). The gate names seven checks and reports one
`OK` line each; every check must pass for the exit status to be zero.

Observed on a Linux amd64 client against a live daemon in separate disposable
containers, every gate clean with no leftover mount or session directory:

- `real.sh` **7/7**: the four `--version` startups, the real `multica config
  set/get` round trip (proof URL in the client-side JSON under an isolated
  local `HOME`, that same path absent from the daemon's view), the
  local-versus-remote split, placement including a custom `argv[0]` (the
  daemon's own init answers; the caller's name does not replace the target),
  a named `execveat` descriptor routed remotely, a deleted descriptor refused
  with `EPERM` (no upload, no local fallback), exact project executable and
  `.so` byte preservation, the remote `git` clone visible through the local
  view, detached-child cleanup, and canceled-session cleanup.
- `lab.sh` **12/12** and `stress.sh` **4/4 at N=16**, the stress sessions all
  sharing one configuration file.
- Interactive PTY: typed input consumed by the local shell, Ctrl-C (`0x03`)
  delivered as a signal, the shell reporting `130`, `rsbx` exiting with the
  entry's own status `23`, and termios flags, `c_cc` and speeds restored
  exactly.
- Crash teardown: `SIGKILL` of the controller after shell boot closed the
  worker, the terminal reported `EIO`, this session's own mount and cache
  directories were removed, and a fresh session on the same configuration
  read the daemon's marker.

None of this proves authenticated model workflows or plugin loading: no model
call is made and no existing host credential is touched.

## Running it

The client image must carry the stand-ins and **not** git, and the daemon image
must carry git and **not** the stand-ins. `lab.sh`, `stress.sh` and `real.sh`
take their paths from the environment:

```sh
MNT=<client scratch home> F=<rsbx binary> SOCK=<daemon socket> \
  AGENT_HOME=<local agent config tree> DAEMON_TREE=/proj \
  CLIENT_INIT=rsbx DAEMON_INIT=rsbxd bash lab.sh
```

`AGENT_HOME` must also appear in `local.paths`, or the config tree is served by
the daemon and stops being local.

`real.sh` additionally takes the real binaries and a place to build the
substrate fixture:

```sh
MNT=<client scratch home> F=<rsbx binary> SOCK=<daemon socket> \
  AGENT_HOME=<local agent config tree> REAL_TOOLS=/opt/real \
  FIXTURE_DIR=/opt/real bash real.sh
```

`REAL_TOOLS` must contain the installed `multica`, `omp`, `codex` and `claude`
binaries. `FIXTURE_DIR` receives `native-proof`, built at invocation from
`native-proof.c`; it must be writable where `real.sh` runs and readable inside
the sandbox view, because the fixture is allowlisted as an exact local
executable. Nothing in the repository build produces that binary, and
`real.sh` does not depend on any parent build artifact.

## The configuration these probes assume

```toml
[local]
# Named one by one: these run here.
allow = ["/usr/local/bin/multica", "/usr/local/bin/omp",
         "/usr/local/bin/codex", "/usr/local/bin/claude",
         "/bin/sh"]
entry = "/bin/sh"
# The agent's own state: local content, so it never lands on the daemon.
paths = ["/work/agent"]
```

The names in `allow` are exact executable identities captured at startup, not
directory prefixes. A file created later in the same directory is not thereby
local: it is a named program like any other and is routed to the daemon unless
it was part of the startup snapshot. For the same reason, listing a directory
snapshots the executables in it at startup; it does not grant future ones.

The two images keep the placement observable: the client has no git, the
daemon has it, and the stand-ins exist only on the client. `real.sh` instead
uses real installed binaries and does not depend on those images.

## Shared configuration under load

`lab.sh` and `stress.sh` write one `lab.toml`, and every concurrent session
reads that same file. They still do not share a sandbox: each invocation
allocates its own mount, cache, broker and process tree under the configured
base directories, and the daemon arbitrates the one shared remote tree.

Do not "fix" a failing concurrent run by wiping state between rounds, killing
processes by name, or aborting FUSE connections. Each of those hides the bug
the run exists to find:

* `pkill`/`killall` of sandbox or guest processes can kill another session's
  work (or the operator's), and it makes a leaked descendant look cleaned up.
  `real.sh` measures cleanup by having the child carry a nonce argument and
  observing from the host, read-only, that no process with that nonce remains.
* Aborting a FUSE connection whose session is still live turns every later
  syscall in it into `ENOTCONN`, which then reads as a sandbox defect.
* Draining or ignoring a `D`-state process between rounds hides a teardown
  that never completed. A session that exits only after an uninterruptible
  wait is a defect in the session, and the harness should fail, not wait it out.

If a run leaves a specific session behind, report that session's own mount,
cache directory and output. Never remove the shared base directories while
another session may be using them.
