# The mixed-execution model

What a session looks like when a host-side CLI drives work that happens on the
daemon: `multica` and the agent CLIs run here, everything they touch is the
daemon's tree, and any program that is not allowlisted runs on the daemon.

Two facts have to hold at once, and each is measured rather than asserted:

* **Where a program ran.** `/proc/1/cmdline` is the init of the machine the
  process really runs on. A host program sees this container's init; a program
  the daemon started sees `rsbxd`. A pid number cannot show this: both sides
  number their processes from a small sequence.
* **What a program sees.** A marker file written only on the daemon has to be
  readable through the session, and absent from the client's own filesystem.

| probe | what it does | what it catches |
|---|---|---|
| `lab.sh` | 10 checks: multica runs here, sees the daemon tree, git is absent here yet runs, git runs on the daemon, git's work lands on the daemon tree and survives, the agent's config tree is local, the agent's work product is remote, every agent CLI runs here, multica and git see one tree | a policy that runs the wrong program on the wrong side, or leaves a local tree on the daemon |
| `stress.sh` | 4 concurrent checks at N sessions: parallel commits, host and daemon programs interleaved 20 times in one session, agent config local while its product is remote, one shared remote file rewritten and re-read 10 times | contention that only appears when several sessions share one daemon |

`multica`, `omp`, `codex` and `claude` are stand-ins, not the real programs.
They exist to make placement observable; the real CLIs behave the same way as
far as the sandbox is concerned, because it only ever sees a path.

## Running it

The client image must carry the stand-ins and **not** git, and the daemon image
must carry git and **not** the stand-ins. `lab.sh` and `stress.sh` take their
paths from the environment:

```sh
MNT=<client scratch home> F=<rsbx binary> SOCK=<daemon socket> \
  AGENT_HOME=<local agent config tree> DAEMON_TREE=/proj bash lab.sh
```

`AGENT_HOME` must also appear in `local.paths`, or the config tree is served by
the daemon and stops being local.

## The configuration these probes assume

```toml
[local]
# Named one by one: these run here.
allow = ["/usr/local/bin/multica", "/usr/local/bin/omp",
         "/usr/local/bin/codex", "/usr/local/bin/claude",
         "/bin/sh",
         # A directory: the names inside it are arbitrated per program, so
         # multica above runs here and git below runs on the daemon.
         "/usr/bin"]
entry = "/bin/sh"
# The agent's own state: local content, so it never lands on the daemon.
paths = ["/work/agent"]
```

Redirection is limited to the directories the allowlist names. A program in a
directory that was never listed — `/usr/local/bin` when only single files in
it are allowlisted — is ordinary host content and runs here. That is why
`/usr/bin` is listed as a directory above: it is what makes `git` remote.
