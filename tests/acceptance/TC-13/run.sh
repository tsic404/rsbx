#!/bin/bash
# TC-13 (AC-7) — terminal and pipe semantics.
#
# Design `docs/03-acceptance.md` §TC-13: an interactive session behaves as a
# real terminal (typed input consumed, an interrupt arrives as a signal, the
# foreground job holds the terminal, the session ends with the entry's own
# status, terminal attributes are restored), and a pipe session carries input
# in order and makes a normal end distinguishable from a signalled one.
#
# The eight assertions live in tc13_pty.py, one `OK`/`FAIL` line each; this
# entry owns the rig and the environment decisions.
#
# The parts a unit test can reach are already covered there:
# `TestOpenReturnsUsableTerminalPair` and the winsize round trip in
# internal/pty prove the terminal pair and geometry, while
# `TestSignalForwardedToProcessGroup`, `TestTTYNaturalExit`,
# `TestExecPipesReportsRealStatus`, and `TestOutputTailNotLost` in
# internal/daemon prove signal delivery, TTY exit status, and pipe tail loss.
# What remains here is the caller-visible interaction: typed input, foreground
# control, termios restoration, and the two distinct pipe end states.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
ACC_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$ACC_DIR" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc13-$$
acc_init TC-13
trap acc_rig_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

PTY_IMAGE=${PTY_IMAGE:-rsbx-pty-client:ci}
if ! docker image inspect "$PTY_IMAGE" >/dev/null 2>&1; then
  acc_skip_all pty_image "image $PTY_IMAGE not present (it carries python3 for the pty harness)"
  exit 77
fi

# The harness needs a real terminal and a python3. Both are prerequisites of
# this carrier, not properties of the implementation: a client without python3
# cannot express the check, so it is a SKIP and never a FAIL.
if ! docker run --rm --entrypoint /bin/bash "$PTY_IMAGE" -c 'command -v python3 >/dev/null' >/dev/null 2>&1; then
  acc_skip_all client_python3 "no python3 in $PTY_IMAGE, so the pty harness cannot run"
  exit 77
fi

# --- the container the harness runs in ------------------------------------
# The pty harness opens its own pseudo-terminals, so it needs a client with
# the binary under test and the same daemon socket. Its own container keeps
# the checks independent of the long-lived client above.
CONTAINER=$ACC_PREFIX-pty
docker run -d --name "$CONTAINER" --privileged --user 0 \
  --network "$ACC_PREFIX-net" -v "$ACC_PREFIX-run:/run/rsbx" \
  --entrypoint /bin/bash "$PTY_IMAGE" -c 'while :; do sleep 5; done' >/dev/null
cleanup_pty(){ docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap 'cleanup_pty; acc_rig_cleanup' EXIT

for b in rsbx rsbxd rsbx-tramp rsbx-guard; do
  if [ -f "$ACC_BIN/$b" ]; then
    docker cp "$ACC_BIN/$b" "$CONTAINER:/usr/local/bin/$b" >/dev/null 2>&1
  fi
done
docker exec "$CONTAINER" chmod 755 /usr/local/bin/rsbx /usr/local/bin/rsbx-tramp /usr/local/bin/rsbx-guard

docker exec "$CONTAINER" mkdir -p /state
docker cp "$ACC_DIR/tc13_pty.py" "$CONTAINER:/state/tc13_pty.py" >/dev/null

cat <<CFG | docker exec -i "$CONTAINER" /bin/bash -c 'mkdir -p /state/sb-pty /state/cache-pty && cat > /state/pty.toml'
[daemon]
transport = "unix"
socket = "$ACC_SOCK"

[local]
allow = ["/usr/bin/cat"]
entry = "/bin/sh"
paths = []
read_only_paths = []

[sandbox]
mount = "/state/sb-pty"
cache = "/state/cache-pty"
unshare_user = false
CFG

out=$(docker exec "$CONTAINER" /bin/bash -c \
  'RSBX=/usr/local/bin/rsbx CFG=/state/pty.toml timeout 180 python3 -u /state/tc13_pty.py' 2>&1)
rc=$?
# acc_absorb echoes each result line and tallies it, so the failure text the
# harness printed survives into this entry's output unchanged.
acc_absorb <<< "$(printf '%s\n' "$out" | grep -E '^(OK|SKIP|FAIL) ')"
printf '%s\n' "$out" | grep -vE '^(OK|SKIP|FAIL) ' | sed 's/^/    harness: /'

# The summary line is the harness's own count; a run that stopped early is a
# carrier failure, not a partial pass.
expected=8
got=$(printf '%s\n' "$out" | grep -cE '^(OK|SKIP|FAIL) ')
if [ "$got" -ne "$expected" ]; then
  acc_fail pty-harness-complete "the harness reported $got of $expected checks (rc=$rc)"
fi

acc_finish
