#!/bin/bash
# TC-6a (AC-4a) — writing to a snapshot asset fails, and the snapshot survives.
#
# Design `docs/03-acceptance.md` §TC-6a: inside a session, a write to a program
# that belongs to the local execution set — and to one of its runtime
# dependencies — ends in a read-only failure. Neither silently takes effect nor
# lands somewhere else, and the program still runs from the bytes it was
# started with.
#
# The program here is a shell script, so its shebang interpreter is the runtime
# dependency: both files are part of the snapshot, and both writes are tried.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
ACC_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$ACC_DIR" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc6a-$$
acc_init TC-6a
trap acc_rig_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

PROG=$ACC_LOCAL_DIR/tc6a-prog
MARKER=TC6A-PROG-$$

acc_put "$PROG" "#!/usr/bin/bash
echo $MARKER
" 755

hash_of(){ acc_exec "sha256sum $(printf '%q' "$1") 2>/dev/null | cut -d' ' -f1"; }

# --- both writes fail with a read-only error ------------------------------
# The session's entry shell is local, so these writes reach this machine's own
# filesystem — the snapshot asset — rather than a daemon path with the same
# name.
check_writes_fail(){
  local cfg out before after
  before=$(hash_of "$PROG")
  cfg=$(acc_config writes '["'"$PROG"'","/bin/bash"]' '[]' /bin/bash)
  acc_session "$cfg" /bin/bash -c "
    printf 'X\n' > $PROG 2>&1; echo \"PROG-WRITE-RC=\$?\"
    printf 'X\n' > /usr/bin/bash 2>&1; echo \"DEP-WRITE-RC=\$?\"
  "
  local rc=$?; out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  printf '%s\n' "$out" | grep -q 'PROG-WRITE-RC=0' \
    && { echo "    the program's own file was writable in the session"; return 1; }
  printf '%s\n' "$out" | grep -q 'DEP-WRITE-RC=0' \
    && { echo "    the runtime dependency was writable in the session"; return 1; }
  printf '%s\n' "$out" | grep -qiE 'read-only|permission denied' \
    || { echo "    the failures do not say read-only: [$out]"; return 1; }
  after=$(hash_of "$PROG")
  [ "$before" = "$after" ] \
    || { echo "    the program's bytes changed: $before -> $after"; return 1; }
  return 0
}

# --- the program still runs, from the bytes it started with ----------------
# The assertion is the program's own output: an in-place rewrite that had
# silently succeeded would replace the marker with the bytes just written.
check_program_still_runs(){
  local cfg out
  cfg=$(acc_config runs '["'"$PROG"'","/bin/bash"]' '[]' /bin/bash)
  acc_session "$cfg" "$PROG"
  local rc=$?; out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  [ $rc -eq 0 ] || { echo "    the program did not run (rc=$rc)"; return 1; }
  printf '%s\n' "$out" | grep -qx "$MARKER" \
    || { echo "    the program did not print its own marker: [$out]"; return 1; }
  return 0
}

# --- the daemon's same path is not where the snapshot came from ------------
# A snapshot asset is this machine's file. If the daemon had a copy at that
# path with the local bytes, a "local" run would be indistinguishable from an
# upload, so the daemon's tree is checked for the content directly.
check_daemon_has_no_copy(){
  local bytes
  bytes=$(acc_daemon "cat $(printf '%q' "$PROG") 2>/dev/null")
  [ -z "$bytes" ] \
    || { echo "    the daemon's tree holds the local program's bytes"; return 1; }
  return 0
}

check(){ local n=$1; shift; if "$@"; then acc_ok "$n"; else acc_fail "$n" "output above"; fi; }

check asset-and-dependency-writes-readonly check_writes_fail
check program-runs-from-startup-snapshot check_program_still_runs
check daemon-has-no-local-bytes check_daemon_has_no_copy

acc_finish
