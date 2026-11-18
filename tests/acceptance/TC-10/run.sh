#!/bin/bash
# TC-10 (AC-5) — no silent fallback.
#
# Design `docs/03-acceptance.md` §TC-10: after a remote execution fails, the
# system must not try a same-named program on this machine, and no local bytes
# may be uploaded. Three observable consequences are checked:
#   a. the failure is explicit and non-zero, never a successful run;
#   b. a program of the same name that exists only here is not executed — the
#      proof is its side effect never appearing;
#   c. the daemon never receives this machine's file content.
#
# (c) is judged by placing a marker file here and asking the daemon to read the
# same path: whatever it answers, it cannot be these bytes.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
cd "$(dirname "$0")" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc10-$$
acc_init TC-10
trap acc_rig_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

MARKER=tc10-local-bytes-$$
RAN=ran-$MARKER

# A local-only program with the same name as the remote target that will fail.
# It writes a side-effect file next to itself: if the fallback ever executes
# it, that file exists and the check can see it.
NAME=fallback-probe
acc_put "$ACC_LOCAL_DIR/$NAME" "#!/bin/sh
printf '%s\n' $RAN > $ACC_LOCAL_DIR/$RAN
echo $RAN
" 755

# --- a + b. explicit failure, and the same-named local program never runs ---
check_no_fallback(){
  local cfg out
  # Nothing in this configuration names the probe, so the command is a remote
  # target — which does not exist on the daemon.
  cfg=$(acc_config nofallback '[]' '[]')
  acc_session "$cfg" "$ACC_LOCAL_DIR/$NAME"
  local rc=$?; out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  [ $rc -ne 0 ] || { echo "    the session succeeded instead of failing"; return 1; }
  printf '%s\n' "$out" | grep -q "$RAN" \
    && { echo "    the local same-named program was executed as a fallback"; return 1; }
  acc_exists "$ACC_LOCAL_DIR/$RAN" \
    && { echo "    the local program ran: its side effect exists"; return 1; }
  printf '%s\n' "$out" | grep -qiE 'no such file|not found|does not exist' \
    || { echo "    the failure is not explicit about the missing target: [$out]"; return 1; }
  return 0
}

# --- c. no local bytes reach the daemon -----------------------------------
# A local tree declared through local.paths holds bytes the daemon must never
# see. A remote program reading the same path either fails or reads something
# else; what it must never read is this content.
check_no_upload(){
  local cfg out localdir=$ACC_WORK/tc10-secret secret=$MARKER-LOCAL-SECRET
  acc_exec "mkdir -p $localdir"
  acc_put "$localdir/only-here.txt" "$secret
"
  cfg=$(acc_config noload '[]' '["'"$localdir"'"]')
  # `head` is a daemon program (nothing allowlists it), so this read is answered
  # by the daemon at a path that exists only here.
  acc_session "$cfg" /bin/head -c 200 "$localdir/only-here.txt"
  local rc=$?; out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  printf '%s\n' "$out" | grep -q "$secret" \
    && { echo "    the daemon read this machine's file content — local bytes were served remotely"; return 1; }
  # The daemon's own tree must not have received the file either.
  local daemon_bytes
  daemon_bytes=$(acc_daemon "cat $localdir/only-here.txt 2>/dev/null")
  [ -z "$daemon_bytes" ] \
    || { echo "    the daemon's tree holds the local file's content"; return 1; }
  # A control: the same read succeeds through the local view, so the file is
  # genuinely present and readable here. Without this the check above could
  # pass merely because the file never existed.
  acc_session "$cfg" /bin/sh -c "IFS= read -r v < $localdir/only-here.txt; echo \"LOCALVIEW=\$v\""
  printf '%s\n' "$ACC_OUT" | grep -qx "LOCALVIEW=$secret" \
    || { echo "    the control read failed, so the negative result is meaningless: [$ACC_OUT]"; return 1; }
  return 0
}

check(){ local n=$1; shift; if "$@"; then acc_ok "$n"; else acc_fail "$n" "output above"; fi; }

check failed-remote-exec-no-local-fallback check_no_fallback
check no-local-bytes-uploaded check_no_upload

acc_finish
