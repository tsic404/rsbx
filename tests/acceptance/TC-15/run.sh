#!/bin/bash
# TC-15 (AC-8 / AC-9) — concurrent sessions on one daemon.
#
# Design `docs/03-acceptance.md` §TC-15: several sessions share one daemon and
# one remote tree; each does its own writes, local and remote commands
# alternate over many rounds, and several of them rewrite one remote file and
# read it back. Every session's result is correct and none leaks into another;
# one session ending does not disturb the rest; a re-read returns the tree's
# current content rather than bytes from an earlier round (AC-9).
#
# The concurrent exercises already live in this repository and are proven on
# this tree: `testdata/probe/dual.sh` (8 checks, two to four sessions sharing
# one daemon tree) and `testdata/mixed/stress.sh` (4 checks at N sessions
# sharing one configuration file). This entry only supplies the rig, the
# prerequisites and the translation between their result lines and the
# acceptance protocol — it does not re-implement them.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
ACC_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$ACC_DIR/../../.." && pwd)
cd "$ACC_DIR" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc15-$$
acc_init TC-15
trap acc_rig_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

DUAL=$REPO/testdata/probe/dual.sh
STRESS=$REPO/testdata/mixed/stress.sh
for f in "$DUAL" "$STRESS"; do
  [ -f "$f" ] || { acc_skip_all concurrent_carriers "missing $f"; exit 77; }
done

# --- dual.sh: 2-4 sessions, one shared daemon tree ------------------------
# It needs a client home and four mount points; each session gets its own, so
# the checks measure the daemon's arbitration rather than two clients fighting
# over one directory.
check_dual(){
  local out
  docker exec "$ACC_CLIENT" mkdir -p /state/dual
  docker cp "$DUAL" "$ACC_CLIENT:/state/dual.sh" >/dev/null
  # dual.sh keeps everything under $TREE/shared. It gets its own subtree so the
  # two carriers can share one daemon without one's scratch looking like the
  # other's data (stress.sh writes /proj/shared as a file).
  acc_boot "mkdir -p $ACC_PROJ/concurrent && chmod 777 $ACC_PROJ/concurrent" >/dev/null 2>&1
  out=$(docker exec "$ACC_CLIENT" /bin/bash -c "
    TREE=$ACC_PROJ/concurrent MNT=/state/dual F=/usr/local/bin/rsbx SOCK=$ACC_SOCK \
      timeout 600 /bin/bash /state/dual.sh" 2>&1)
  printf '%s\n' "$out" | sed 's/^/    dual: /'
  printf '%s\n' "$out" | grep -q '^FAIL' && return 1
  # All eight checks must have reported; a run that stopped early is a
  # carrier failure, not a partial pass.
  local got
  got=$(printf '%s\n' "$out" | grep -c '^OK ')
  [ "$got" -eq 8 ] || { echo "    dual.sh reported $got of 8 checks"; return 1; }
  return 0
}

# --- stress.sh: N sessions sharing one configuration file ----------------
# The stand-in CLIs (multica/omp/codex/claude) exist only in the mixed client
# image; without that image the load exercise cannot express its checks, which
# is a SKIP and not a verdict on the implementation.
check_stress(){
  local image=${MIXED_CLIENT_IMAGE:-rsbx-mixed-client:ci} out
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "    image $image absent"
    return 2
  fi
  local c=$ACC_PREFIX-mixed
  docker run -d --name "$c" --privileged --user 0 --network "$ACC_PREFIX-net" \
    -v "$ACC_PREFIX-run:/run/rsbx" -v "$ACC_PREFIX-work:/work" \
    --entrypoint /bin/bash "$image" -c 'while :; do sleep 5; done' >/dev/null
  docker exec "$c" mkdir -p /state /work/agent/omp
  docker exec "$c" chmod -R 777 /state /work
  # The binary under test is the same one the rest of this carrier runs.
  if [ -f "$ACC_BIN/rsbx" ]; then
    for b in rsbx rsbx-tramp rsbx-guard; do
      docker cp "$ACC_BIN/$b" "$c:/usr/local/bin/$b" >/dev/null 2>&1
    done
    docker exec "$c" chmod 755 /usr/local/bin/rsbx /usr/local/bin/rsbx-tramp /usr/local/bin/rsbx-guard
  fi
  docker cp "$STRESS" "$c:/state/stress.sh" >/dev/null
  out=$(docker exec "$c" /bin/bash -c "
    MNT=/state F=/usr/local/bin/rsbx SOCK=$ACC_SOCK AGENT_HOME=/work/agent \
      N=${STRESS_N:-8} timeout 600 /bin/bash /state/stress.sh" 2>&1)
  local rc=$?
  printf '%s\n' "$out" | sed 's/^/    stress: /'
  docker rm -f "$c" >/dev/null 2>&1
  printf '%s\n' "$out" | grep -q '^FAIL' && return 1
  local got
  got=$(printf '%s\n' "$out" | grep -c '^OK ')
  [ "$got" -eq 4 ] || { echo "    stress.sh reported $got of 4 checks (rc=$rc)"; return 1; }
  return 0
}

if check_dual; then
  acc_ok dual-concurrent-sessions
else
  acc_fail dual-concurrent-sessions "output above"
fi

check_stress
stress_rc=$?
case $stress_rc in
  0) acc_ok stress-shared-configuration ;;
  2) acc_skip stress-shared-configuration "the mixed client image is not present" ;;
  *) acc_fail stress-shared-configuration "output above" ;;
esac

acc_finish
