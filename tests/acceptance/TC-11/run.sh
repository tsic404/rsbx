#!/bin/bash
# TC-11 (AC-6) — a missing kernel capability refuses the session.
#
# Design `docs/03-acceptance.md` §TC-11: in an environment without Landlock or
# without execution tracing, starting a session fails explicitly, names the
# missing capability, and nothing runs on either side.
#
# The capability is removed with a seccomp profile that answers ENOSYS to the
# three Landlock calls, which is exactly how a kernel without the feature
# answers. That makes the refusal observable without needing an old kernel.
# No check is weakened: the assertion is that the session does not start.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
ACC_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$ACC_DIR" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc11-$$
acc_init TC-11
trap acc_rig_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

MARKER=tc11-should-not-run-$$
PROFILE=$ACC_DIR/landlock-block.json

# --- the session is refused, and the refusal names the capability ---------
# The client container is re-entered with the seccomp profile applied. A
# separate throwaway container keeps the carrier's main client intact for the
# control run afterwards.
check_capability_refusal(){
  local out rc
  [ -f "$PROFILE" ] || { echo "    missing seccomp profile: $PROFILE"; return 1; }
  out=$(docker run --rm --privileged --user 0 \
    --security-opt seccomp="$PROFILE" \
    --network "$ACC_PREFIX-net" -v "$ACC_PREFIX-run:/run/rsbx" \
    -v "$ACC_PREFIX-state:/state" \
    --entrypoint /bin/bash "$ACC_CLIENT_IMG" -c "
      mkdir -p /state/sb-tc11 /state/cache-tc11
      cat > /state/tc11.toml <<'CFG'
[daemon]
transport = \"unix\"
socket = \"$ACC_SOCK\"
[local]
allow = []
entry = \"/bin/sh\"
paths = []
[sandbox]
mount = \"/state/sb-tc11\"
cache = \"/state/cache-tc11\"
unshare_user = false
CFG
      timeout 60 /usr/local/bin/rsbx -config /state/tc11.toml -- /bin/sh -c 'echo $MARKER' 2>&1
      echo RC=\$?
    " 2>&1)
  rc=$?
  printf '%s\n' "$out" | sed 's/^/    /'
  printf '%s\n' "$out" | grep -q "RC=0" \
    && { echo "    the session started without Landlock"; return 1; }
  printf '%s\n' "$out" | grep -q "$MARKER" \
    && { echo "    a command ran inside a session that should not exist"; return 1; }
  printf '%s\n' "$out" | grep -qiE 'landlock|not implemented|capabilit' \
    || { echo "    the refusal does not name the missing capability: [$out]"; return 1; }
  # Nothing was created in the daemon's tree by the refused session.
  acc_daemon "test -e $ACC_PROJ/tc11-marker" >/dev/null 2>&1 \
    && { echo "    the refused session wrote to the daemon"; return 1; }
  return 0
}

# --- control: the same configuration starts where the capability exists ----
# Without this, a configuration error would look exactly like a capability
# refusal, and the check above would prove nothing.
check_control_starts(){
  local cfg out
  cfg=$(acc_config control '[]' '[]')
  acc_session "$cfg" /bin/sh -c "echo CONTROL-RAN"
  local rc=$?; out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  [ $rc -eq 0 ] || { echo "    the control session failed, so the refusal above is not attributable to the capability (rc=$rc)"; return 1; }
  printf '%s\n' "$out" | grep -qx 'CONTROL-RAN' \
    || { echo "    the control session did not run its command"; return 1; }
  return 0
}

check(){ local n=$1; shift; if "$@"; then acc_ok "$n"; else acc_fail "$n" "output above"; fi; }

check missing-landlock-refuses-start check_capability_refusal
check control-starts-with-capability check_control_starts

acc_finish
