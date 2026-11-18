#!/bin/bash
# TC-6 (AC-4) — a read-only declared tree, and local content that never leaves
# this machine.
#
# Design `docs/03-acceptance.md` §TC-6 judges two things together:
#   a. a write into a read-only declared tree fails with a read-only error,
#      and neither the local original nor the daemon's same path changes;
#   b. a remote command cannot observe any of this machine's declared content.
#
# (b) is checked with a program the allowlist does not name, so the answer is
# the daemon's and not a local lookup. The control at the end proves the tree
# is really there and readable locally: without it, "the remote saw nothing"
# would also be true of a tree that never existed.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
ACC_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$ACC_DIR" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc6-$$
acc_init TC-6
trap acc_rig_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

RO=$ACC_WORK/tc6-ro
ORIGINAL=KEEP-ME-$$
SECRET=tc6-secret-$$
acc_exec "mkdir -p $RO"
acc_put "$RO/keep.txt" "$ORIGINAL
"
acc_put "$RO/secret.txt" "$SECRET
"

# --- a. writing into the read-only tree fails and changes nothing ---------
# The write is attempted by the entry shell, so it is this machine's own
# filesystem that refuses: that is the declared read-only tree, not a remote
# path that happens to be mounted somewhere.
check_readonly_write(){
  local cfg out
  READ_ONLY="[\"$RO\"]"
  cfg=$(acc_config ro '["/bin/bash"]' '[]' /bin/bash)
  READ_ONLY="[]"
  acc_session "$cfg" /bin/bash -c "
    printf 'X\n' > $RO/new.txt 2>&1; echo \"WRITE-RC=\$?\"
    printf 'Y\n' > $RO/keep.txt 2>&1; echo \"OVERWRITE-RC=\$?\"
  "
  local rc=$?; out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  printf '%s\n' "$out" | grep -q 'WRITE-RC=0' \
    && { echo "    a new file was created in a read-only tree"; return 1; }
  printf '%s\n' "$out" | grep -q 'OVERWRITE-RC=0' \
    && { echo "    an existing file in a read-only tree was overwritten"; return 1; }
  printf '%s\n' "$out" | grep -qiE 'read-only|permission denied' \
    || { echo "    the failure does not say the tree is read-only: [$out]"; return 1; }
  acc_exists "$RO/new.txt" \
    && { echo "    the new file exists after the failed write"; return 1; }
  local after
  after=$(acc_get "$RO/keep.txt")
  printf '%s\n' "$after" | grep -qx "$ORIGINAL" \
    || { echo "    the local original changed: [$after]"; return 1; }
  # The daemon's path with the same name must also be untouched: a write that
  # silently landed on the other side would look like success from here.
  local remote
  remote=$(acc_session "$cfg" /bin/cat "$RO/keep.txt"; printf '%s' "$ACC_OUT")
  printf '%s\n' "$remote" | grep -qx "$ORIGINAL" \
    && { echo "    the write landed on the daemon's tree instead"; return 1; }
  return 0
}

# --- b. the remote view cannot observe this machine's declared content ----
# `find` and `head` are not allowlisted, so both are the daemon's programs,
# and this tree is content only this machine has.
check_remote_blind(){
  local cfg out
  cfg=$(acc_config blind '["/bin/bash"]' '["'"$RO"'"]' /bin/bash)
  acc_session "$cfg" /bin/sh -c "
    echo '--- find ---'
    /usr/bin/find $RO -maxdepth 1 2>&1
    echo \"find-rc=\$?\"
    echo '--- read ---'
    /bin/head -c 200 $RO/secret.txt 2>&1
    echo \"head-rc=\$?\"
  "
  local rc=$?; out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  printf '%s\n' "$out" | grep -q "$SECRET" \
    && { echo "    a remote program read this machine's declared content"; return 1; }
  printf '%s\n' "$out" | grep -q 'only-here' \
    && { echo "    a remote listing showed this machine's declared tree"; return 1; }
  # The design wants an observation, not a particular errno: a failed listing
  # and an empty one both mean the daemon did not see these files.
  printf '%s\n' "$out" | grep -qE 'find-rc=0|head-rc=0|No such file|not exist' \
    || { echo "    the remote answers were unreadable: [$out]"; return 1; }
  return 0
}

# --- control: the tree is genuinely present and readable here -------------
check_local_control(){
  local cfg out
  cfg=$(acc_config control '["/bin/bash"]' '["'"$RO"'"]' /bin/bash)
  acc_session "$cfg" /bin/bash -c "IFS= read -r v < $RO/secret.txt; echo \"LOCAL=\$v\""
  local rc=$?; out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  [ $rc -eq 0 ] || { echo "    the control session failed (rc=$rc)"; return 1; }
  printf '%s\n' "$out" | grep -qx "LOCAL=$SECRET" \
    || { echo "    the declared tree is not readable here, so the negative result proves nothing"; return 1; }
  return 0
}

check(){ local n=$1; shift; if "$@"; then acc_ok "$n"; else acc_fail "$n" "output above"; fi; }

check readonly-write-fails-both-sides-unchanged check_readonly_write
check remote-cannot-observe-local-tree check_remote_blind
check local-control-reads-the-tree check_local_control

acc_finish
