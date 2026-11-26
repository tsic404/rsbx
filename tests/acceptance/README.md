# Acceptance carriers

One directory per design test case, named by its TC number. Each `TC-*/run.sh`
is an executable carrier for the criterion written in the frozen design's
`docs/03-acceptance.md`; the header of every carrier quotes the clause it
judges and names the observable it asserts.

## Running

```sh
bash tests/acceptance/run-all.sh                 # every carrier
bash tests/acceptance/run-all.sh TC-1 TC-13      # a subset
bash tests/acceptance/TC-10a/run.sh              # one carrier, on its own
```

Each carrier builds its own disposable docker rig: a daemon container serving a
throwaway project volume, and a client container that shares only the socket
volume and its own scratch state. The client never mounts the project, so its
only view of the daemon's tree is the one `rsbx` serves. Carriers run from the
host with `docker exec`; nothing is left behind (`docker rm`/`volume rm` on
exit), and a carrier can be read and run in isolation.

Environment (all optional):

| variable | default | meaning |
|---|---|---|
| `ACC_BIN` | `/tmp/tcbuild` | directory holding `rsbx`, `rsbxd`, `rsbx-stub`, `rsbx-tramp`, `rsbx-guard`; copied into both containers so the revision under test is the one that runs |
| `ACC_CLIENT_IMG` | `rsbx:ci` | client image (needs `fuse3` and `/bin/bash`) |
| `ACC_DAEMON_IMG` | `rsbx-daemon:full` | daemon image (needs `git`, `python3` for the carriers that check them) |
| `PTY_IMAGE` | `rsbx-pty-client:ci` | client image carrying `python3` for TC-13 |
| `MIXED_CLIENT_IMAGE` | `rsbx-mixed-client:ci` | client image carrying the stand-in CLIs for the TC-15 load exercise |
| `CLIENT_INIT` / `DAEMON_INIT` | measured | expected `/proc/1/comm` on each side |

## Results

Three outcomes, and they are never merged:

```
OK   <check>              the design criterion holds
SKIP <check>: <reason>    this environment cannot express the check
FAIL <check>: <reason>    the design criterion does not hold
SUMMARY <TC> ok=N skip=N fail=N
```

A carrier exits `0` when every check held, `1` when any failed, and `77` when
nothing could be judged. `run-all.sh` prints the same distinction for the suite:
`0` all passed, `1` any failed, `77` none failed but something was skipped. A
SKIP is never counted as a pass.

The difference matters: a client image without `python3`, a host without
`/dev/fuse`, or a container without `CAP_SYS_ADMIN` says nothing about the
implementation, while a session that starts without Landlock or a write that
succeeds into a read-only tree is a defect. Prerequisites are checked in the
carrier that needs them — daemon-side `git`/`python3`, `/dev/fuse` plus
`--privileged`, a writable exec directory, the agent CLIs in the image — and a
missing one produces SKIP at that carrier.

The exec directory is reported per side. It is one path in two different
trees, and the daemon and the client are not the same user, so a check that
only asked one side — or that merged both into "not writable on both sides" —
could miss the side that actually broke.

## Placement is measured, not asserted

Where a program ran is read from `/proc/1/comm` of the machine the process
really ran on: a local program sees the session's own init (`rsbx`), a program
the daemon started sees the daemon's init (`rsbxd`). Both names are read from
the deployment at run time and compared, so a different deployment is a visible
failure rather than a silent pass. A pid number cannot show this: both sides
number their processes from a small sequence.

## Carriers

### Where each check belongs

The three layers are decided by what the assertion needs, not by taste:

- **A** — the observable is *which machine* ran the process, and the design
  defines that by the init each process really sees. `internal/daemon`'s
  `runClient` drives both ends over `net.Pipe` in one process
  (`lifecycle_test.go`), so a unit test cannot express it.
- **B** — one machine, but a real process, real kernel facility, or real
  mount. A pure function would not prove the behaviour.
- **C** — a decision with a real seam: a policy function, a refusal, an
  injectable dial. Running it in a container would only make the same
  assertion slower.

Every check in the tree, with the code seam behind it:

| # | TC / check | layer | judged by | code evidence |
|---|---|---|---|---|
| 1 | TC-1 `four-spellings-local` | A | `TC-1/run.sh` | routing picks the target, but placement is read from `/proc/1/comm`; `runClient` has one machine |
| 2 | TC-1 `alternating-rounds-one-placement-each` | A | `TC-1/run.sh` | same; a live command line alternating both sides needs two inits |
| 3 | TC-1 `unlisted-child-remote` | A | `TC-1/run.sh` | the parent is local and the child is not; one process cannot have two pid-1s |
| 4 | TC-1 `custom-argv0-remote` | A | `TC-1/run.sh` | the claim is *where* the named process ran |
| 5 | TC-1 `directory-startup-snapshot` | A | `TC-1/run.sh` | policy half in `TestExecPathsSnapshotDirectoryRules`; placement half needs a daemon-only name |
| 6 | TC-6 `readonly-write-fails-both-sides-unchanged` | A | `TC-6/run.sh` | the daemon's same path must be checked as a second tree |
| 7 | TC-6 `remote-cannot-observe-local-tree` | A | `TC-6/run.sh` | a real remote process has to answer |
| 8 | TC-6 `local-control-reads-the-tree` | A | `TC-6/run.sh` | the control that makes check 7 meaningful needs the local mount |
| 9 | TC-6a `asset-and-dependency-writes-readonly` | B | `TC-6a/run.sh` | `captureExecAssets` pins a read-only snapshot; needs a real mount to write against |
| 10 | TC-6a `program-runs-from-startup-snapshot` | B | `TC-6a/run.sh` | the pinned bytes have to run through the launcher |
| 11 | TC-6a `daemon-has-no-local-bytes` | A | `TC-6a/run.sh` | only a second tree can prove it never held this content |
| 12 | TC-7 `daemon-unreachable-no-process` | C + A | `TestSessionDialFailureIsExplicit` + `TC-7/run.sh` | `runSession`'s dial is injected (internal/rpc `session.go`); the carrier keeps the real absent socket and the absence of a process |
| 13 | TC-7 `remote-workdir-missing-explicit` | C | `TestCwdValidationNoFallback` | drives the daemon's own `resolveCwd`, asserts `TErr` + 127 |
| 14 | TC-7 `missing-startdir-no-fallback` | C + A | `TestEnsureRefusesMissingStartDirectory` + `TC-7/run.sh` | `workspace.CheckStart` refuses a missing path; the carrier keeps the real `-workspace` start |
| 15 | TC-8 `missing-target-executability-error` | C | `TestExecMissingTargetIsAnExecutabilityError`, `TestExecNonExecutableTargetIsRefused`, `TestVerifyEntryTarget*` | daemon `exec.Command` refusal and launcher `verifyEntryTarget` |
| 16 | TC-8 `unresolvable-dependency-start-fails` | C | `TestPrepareRejectsUnresolvableRuntimeDependency`, `TestMissingDependencyFailsPolicyConstruction` | `sandbox.Prepare` calls `policy.New` first and returns; no dial exists yet |
| 17 | TC-10 `failed-remote-exec-no-local-fallback` | A | `TC-10/run.sh` | the same-named local program's absence of side effects is a local fact |
| 18 | TC-10 `no-local-bytes-uploaded` | A | `TC-10/run.sh` | the daemon's own tree is the evidence |
| 19 | TC-10a `disconnect-fails-read-command-and-access` | A | `TC-10a/run.sh` | needs a real daemon container killed mid-read |
| 20 | TC-10a `replaced-program-keeps-startup-snapshot` | B + C | `TC-10a/run.sh` + `TestCacheSnapshotKeepsStartupBytesAfterSourceReplaced` | content identity is `cacheSnapshot`; the live-session half needs a real mount |
| 21 | TC-11 `missing-landlock-refuses-start` | B | `TC-11/run.sh` | a real kernel answer is the criterion; seccomp removes it |
| 22 | TC-11 `control-starts-with-capability` | B | `TC-11/run.sh` | the control that makes check 21 attributable needs the real capability |
| 23 | TC-12 `mount-inside-local-tree-rejected` | C | `TestSessionControlRejectsEachBaseInsideLocalTree` | `allocateSession` checks both bases, visible and resolved |
| 24 | TC-12 `cache-inside-local-tree-rejected` | C | same + `TestSessionControlCannotBeExposedThroughLocalSymlink` | the cache base, direct and via alias |
| 25 | TC-12 `concurrent-sessions-no-shared-child` | C | `TestSessionsOwnDisjointResources` | two plans get distinct mount and cache children |
| 26 | TC-12 `normal-end-leaves-no-resources` | C | `TestFilesystemWorkerReleasesOnlyOwnedSessionResources` | the worker removes only its own session directories |
| 27 | TC-13 `pty_typed_input_consumed` | B | `TC-13/tc13_pty.py` | typed input consumed by the foreground process requires a real terminal |
| 28 | TC-13 `pty_ctrlc_is_signal` | B | `TC-13/tc13_pty.py` | interrupt delivery through the line discipline |
| 29 | TC-13 `pty_entry_status_propagated` | B | `TC-13/tc13_pty.py` | daemon half in `TestTTYNaturalExit`; the caller's own status needs the real client |
| 30 | TC-13 `pty_foreground_handoff` | B | `TC-13/tc13_pty.py` | foreground ownership is a terminal-driver fact |
| 31 | TC-13 `pty_termios_restored` | B | `TC-13/tc13_pty.py` | the caller's termios is only observable from the caller's terminal |
| 32 | TC-13 `pipe_stdin_order` | B | `TC-13/tc13_pty.py` | order through the real session |
| 33 | TC-13 `pipe_exit_status_normal` | B | `TC-13/tc13_pty.py` | daemon half in `TestExecPipesReportsRealStatus`; the pipe end state needs the client |
| 34 | TC-13 `pipe_signal_exit_distinguishable` | B | `TC-13/tc13_pty.py` | 137 vs 7 is a caller-visible distinction |
| 35 | TC-15 `dual-concurrent-sessions` | A | `TC-15/run.sh` → `testdata/probe/dual.sh` | live concurrent sessions on one daemon tree |
| 36 | TC-15 `stress-shared-configuration` | A | `TC-15/run.sh` → `testdata/mixed/stress.sh` | live concurrent sessions at load |
| 37 | TC-17 `allowed-target-runs-in-sandbox` | A | `TC-17/run.sh` | the reverse channel's placement is `/proc/1/comm` on the machine that ran the program; one process cannot hold two inits |
| 38 | TC-17 `symlink-spelling-runs-in-sandbox` | A | `TC-17/run.sh` | the same placement fact through the target's symlink spelling |
| 39 | TC-17 `exit-status-preserved` | A | `TC-17/run.sh` | the caller's own status is only observable across the real channel |
| 40 | TC-17 `unlisted-target-refused` | C + A | `TC-17/run.sh` | the refusal names `local.allow`; the carrier keeps the real session and the absent daemon-side marker |
| 41 | TC-17 `missing-capability-refused` | C + A | `TC-17/run.sh` | refusal names the missing `RSBX_STUB_SOCKET`; the carrier keeps the real stub invocation |
| 42 | TC-17 `wrong-capability-refused` | C + A | `TC-17/run.sh` | refusal names the socket it tried; the carrier keeps a live session that must stay untouched |
| 43 | TC-17 `relative-cwd-refused` | C + A | `TC-17/run.sh` | refusal names the working directory; a relative cwd can only arrive on the wire |
| 44 | TC-17 `tty-refused` | C + A | `TC-17/run.sh` | refusal names PTY support; the terminal flag is only expressible on the wire |
| 45 | TC-17 `loader-injection-refused` | C + A | `TC-17/run.sh` | refusal names the variable; the environment is only expressible on the wire |
| 46 | TC-17 `session-still-works` | A | `TC-17/run.sh` | the session that survived the refusals must still place work in this sandbox |
| 47 | TC-18 `trusted-pair-establishes-session-and-runs` | A | `TC-18/run.sh` | two ends of a real mutual-TLS handshake; the command's placement is the daemon's init |
| 48 | TC-18 `untrusted-client-certificate-rejected` | A | `TC-18/run.sh` | the rejection happens inside the handshake, which one process cannot stage as two ends |
| 49 | TC-18 `missing-client-certificate-rejected` | A | `TC-18/run.sh` | same, with the certificate omitted rather than distrusted |
| 50 | TC-18 `untrusted-server-certificate-rejected` | A | `TC-18/run.sh` | the client's own verdict on the server certificate needs the real client |
| 51 | TC-14 `cancel-scene-live-and-escaped` | A | `TC-14/run.sh` | the scene needs a live remote command and a local descendant in its own session, both placed by the init each one really sees |
| 52 | TC-14 `cancel-terminates-remote-command` | A | `TC-14/run.sh` | the command runs on the daemon; only a real cancel across the channel can stop it, and its heartbeat is the evidence |
| 53 | TC-14 `cancel-reaps-detached-local-descendant` | A | `TC-14/run.sh` | a descendant that left the entry's process group must still die; one process cannot stage a real `setsid` escape |
| 54 | TC-14 `cancel-leaves-no-session-process` | A | `TC-14/run.sh` | "no process on either machine" is a count over two real `/proc` trees |
| 55 | TC-14 `cancel-releases-session-resources` | A | `TC-14/run.sh` | the per-session mount and `session-*` directories live in two trees; only the real teardown removes them |
| 56 | TC-14 `crash-scene-live-and-escaped` | A | `TC-14/run.sh` | same scene, with the caller killed by SIGKILL so no cleanup of its own can run |
| 57 | TC-14 `crash-terminates-remote-command` | A | `TC-14/run.sh` | the daemon must notice a dead connection; a unit test drives one pipe, not a killed caller |
| 58 | TC-14 `crash-reaps-detached-local-descendant` | A | `TC-14/run.sh` | the escaped descendant's reclamation is owned by the launcher's death signal, observable only with a real process |
| 59 | TC-14 `crash-leaves-no-session-process` | A | `TC-14/run.sh` | same two-tree count after an abnormal end |
| 60 | TC-14 `crash-releases-session-resources` | A | `TC-14/run.sh` | the mount and session directories must be gone after a crash, not only after a clean cancel |
| 61 | TC-14 `crash-keeps-new-sessions-working` | A | `TC-14/run.sh` | a session started after the crash must still place a command on the daemon |
| 62 | TC-2 `executable-bytes-match-daemon` | A | `TC-2/run.sh` | two real trees: this machine's copy and the daemon's, compared as bytes |
| 63 | TC-2 `library-bytes-match-daemon` | A | `TC-2/run.sh` | the shared library has its own comparison; the executable's result never stands in for it |
| 64 | TC-2 `execution-lands-on-daemon` | A | `TC-2/run.sh` | the program is not allowlisted; both sides' `/proc/1/comm` are measured and required to differ, and a declared name may only confirm the measurement |
| 65 | TC-19 `missing-name-not-remembered` | B + A | `TC-19/run.sh` + `TestMissingNameIsNeverRemembered` | the request count is a fact about the client's own stream, asserted at the mount; the real second client that creates the name is a carrier fact |
| 66 | TC-19 `removed-name-visible-after-window-and-held-descriptor-keeps-bytes` | A | `TC-19/run.sh` | a name removed by another client during one live session, and a descriptor opened before the removal |
| 67 | TC-19 `enumeration-does-not-hide-new-names` | A | `TC-19/run.sh` | a child added by another client after this view enumerated the directory, looked up by name and by a later listing |
| 68 | TC-19 `repeat-resolution-inside-and-after-the-window` | B | `TestRepeatResolveWithinWindowAsksDaemonNothing` + `TestMountOptionsKeepOneSecondWindow` | the request count per resolution and the window itself are both client-side facts |
| 69 | TC-19 `read-only-close-sends-no-sync` | B | `TestReadOnlyCloseSkipsImplicitSyncButStillCloses` | the close-time request stream is only visible at the mount |
| 70 | TC-10a `failed-read-fails-the-reader` | B | `TestFailedReadIsNotPresentedAsEndOfFile` | a failing daemon request must not be flattened into a clean end of file; the carrier cannot control the reply |
| 71 | TC-19 `command-created-name-keeps-the-ordinary-window` | B | `TestCommandCreatedNameExpiryStartsAtItsResult` | the window begins when the result is obtained, and a later delete by the command does not restart it; both bounds are client-side request facts |
| 72 | TC-19 `recreated-name-does-not-inherit-an-old-creation-record` | B | `TestRecreatedNameDoesNotInheritAnOldCreationRecord` | the record belongs to the removed name, not the spelling; a name the command creates at the same path afterwards keeps the ordinary window |
| 73 | TC-19 `unreadable-parent-keeps-the-creation-record` | B | `TestUnreadableParentKeepsTheCreationRecord` + `TestUnreadableDirectoryKeepsItsCreatedRecords` | a lookup that failed for lack of permission is not an absence; after the permission returns, a name this session created is still asked for on every query |

TC-16's eight workspace checks are an external-rig gate run by the CI job; they
are not part of this count.

Deleted from the scripts, with the criterion now carried by a unit test:
TC-12's four checks (rows 23–26), TC-8's two (rows 15–16), and TC-7's
`remote-workdir-missing-explicit` (row 13). Nothing was removed without a test
that asserts the same decision; where the cited test covered only part of the
criterion, the missing part was added first.

### Carriers

| entry | TC | design clause | checks |
|---|---|---|---|
| `TC-1/run.sh` | TC-1 | AC-1 | placement in a real two-machine rig (see the classification above) |
| `TC-2/run.sh` | TC-2 | AC-2 | the daemon's executable and its shared library, read back through the view, are byte-for-byte the daemon's own, and the executable's run lands on the daemon |
| `TC-6/run.sh` | TC-6 | AC-4 | read-only declared tree rejects writes and changes neither side, remote view cannot observe local content |
| `TC-6a/run.sh` | TC-6a | AC-4a | writes to a snapshot program and its runtime dependency fail read-only, the program still runs its startup bytes |
| `TC-7/run.sh` | TC-7 | AC-5 | unreachable daemon produces no session (the two unit-test cases are listed above) |
| `TC-10/run.sh` | TC-10 | AC-5 | a failed remote exec never runs the same-named local program and uploads no local bytes |
| `TC-10a/run.sh` | TC-10a | AC-5a | a mid-read disconnect fails the read, kills the long command and fails later access; a replaced program still runs the startup snapshot |
| `TC-11/run.sh` | TC-11 | AC-6 | without Landlock the session is refused and names the capability; the control starts where it is present |
| `TC-13/run.sh` | TC-13 | AC-7 | eight pty/pipe assertions (input, signal, foreground, exit status, termios, stdin order, two end states) |
| `TC-14/run.sh` | TC-14 | AC-8 | cancel and crash: the remote command terminates, the detached local descendant is reclaimed, no session process, mount or cache is left on either machine, and a new session still works |
| `TC-15/run.sh` | TC-15 | AC-8 / AC-9 | entry only: drives the in-repo `testdata/probe/dual.sh` (8 checks) and `testdata/mixed/stress.sh` (4 checks) |
| `TC-16/run.sh` | TC-16 | AC-10 | task-workspace gate; driven by the CI job with its own rig (`runner: external-rig`) |
| `TC-17/run.sh` | TC-17 | AC-11 | ten checks on the reverse channel: placement, symlink spelling, exit status, four refusals with their reasons, and the session that survives them |
| `TC-18/run.sh` | TC-18 | AC-12 | four mutual-TLS combinations: a trusted pair establishes a session and runs a command; an untrusted client certificate, a missing one and an untrusted server certificate are each rejected with the certificate named |
| `TC-19/run.sh` | TC-19 | AC-9 | second-client visibility across one live session: a name created after two failed lookups is found with its bytes, a name removed after the view confirmed it is gone after the window while the held descriptor keeps its bytes, and a child added after an enumeration is found by name and by a later listing |

## Fixed or reported

The carriers assert the design; they do not assume a passing implementation. A
FAIL here is a finding, and the carrier's own output is the evidence: the
session log, the exit statuses, and the bytes each side actually held are
printed above the verdict. Nothing is retried to make a flaky check pass, and
no assertion is relaxed to match current behaviour.
