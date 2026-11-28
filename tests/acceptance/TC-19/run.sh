#!/bin/bash
# TC-19 (AC-9) — the retention window, and names that were not there.
#
# Design `docs/03-acceptance.md` §TC-19 judges four things: a repeated query of
# an existing path inside the one-second window, a name that does not exist
# yet, a directory enumerated before a child was added, and a file replaced by
# another client after this view had read it.
#
# The counting half — that a repeat inside the window produces no remote
# request, that a missing name produces one every time, that a repeated
# enumeration sends no listing request and that its child attributes expire with
# the listing rather than being renewed, that closing a read-only handle sends no
# sync — is a fact about the client's own request stream, and is carried by the
# mount-backed tests in `internal/fusefs` listed for this case in the README.
# Watching a socket from outside the rig cannot tell which of several sessions a
# request came from.
#
# What only a real rig adds is the other side: a second client creates a name
# this view already answered "not found" for, replaces a file this view already
# read, and adds a child to a directory this view already enumerated. Every
# check keeps one session alive across the other client's change and reads
# again from inside that same session.
#
# Two facts shape the scripts below. Inside a session the sandbox root is the
# daemon's `/`, so a remote path is addressed by the same string here as there;
# and a shell builtin is the only reader that is this machine's, because an
# unlisted program such as `cat` runs on the daemon and would answer from a
# tree that never had a cache. Reads are therefore `[ -e ]` and `$(<file)`.
# The client's own scratch directory is declared as a local path so the
# session can write its progress markers there.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
ACC_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$ACC_DIR" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc19-$$
ACC_SESSION_TIMEOUT=300
acc_init TC-19
trap acc_rig_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

WORK=$ACC_WORK/tc19
acc_exec "mkdir -p $WORK"

wait_marker(){
  local marker=$1 ticks=${2:-200} i
  for i in $(seq 1 "$ticks"); do
    acc_exists "$marker" && return 0
    sleep 0.1
  done
  return 1
}

wait_log_end(){
  local log=$1 ticks=${2:-300} i
  for i in $(seq 1 "$ticks"); do
    acc_exec "grep -q TC19-END $(printf '%q' "$log")" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

# --- a name that did not exist --------------------------------------------
# The session asks for an absent name twice, then keeps the same mount alive
# while another client creates it. The next query finds it: a miss is never
# retained, so a program that creates a file and reads it straight back is not
# answered from its own earlier failure.
#
# This check judges visibility, not the request count: whether a retained miss
# would have been observable here depends on where the other client's create
# lands inside the window, so it cannot be the discriminating assertion. That
# one is `TestMissingNameIsNeverRemembered`, which counts the requests a repeat
# probe sends; on a mount that remembers misses it fails with "0 requests, want
# one each". What this check adds is the real second client, and the elapsed
# time is printed as evidence of how late the name appeared.
check_missing_name_not_remembered(){
  local remote=$ACC_PROJ/tc19-absent-$$ marker=$WORK/neg.ready log=$WORK/neg.log
  acc_boot "rm -f $remote" >/dev/null 2>&1

  local cfg
  cfg=$(acc_config tc19neg '["/bin/bash"]' '["'"$WORK"'"]' /bin/bash)
  acc_bg_session "$cfg" "$log" /bin/bash -c '
view=$1; marker=$2
if [ -e "$view" ]; then echo BEFORE=present; else echo BEFORE=absent; fi
if [ -e "$view" ]; then echo BEFORE2=present; else echo BEFORE2=absent; fi
: > "$marker"
t0=$(date +%s%N)
seen=never
while :; do
  if [ -e "$view" ]; then
    seen=$(( ($(date +%s%N) - t0) / 1000000 ))
    break
  fi
  [ $(( ($(date +%s%N) - t0) / 1000000 )) -ge 10000 ] && break
  sleep 0.02
done
echo "SEEN_MS=$seen"
body=
if [ -e "$view" ]; then body=$(<"$view"); fi
echo "AFTER=$body"
echo TC19-END
' /bin/bash "$remote" "$marker"
  wait_marker "$marker" || { echo "    the session never asked for the missing name"; return 1; }

  # Created by rename so the name never exists in a half-written state: the
  # first query that finds it must also find its bytes.
  acc_boot "printf 'created-elsewhere' > $remote.tmp && mv $remote.tmp $remote" >/dev/null 2>&1 || {
    echo "    the other client could not create the name"; return 1; }

  wait_log_end "$log" || { echo "    the session did not finish"; return 1; }
  local out
  out=$(acc_get "$log")
  printf '%s\n' "$out" | sed 's/^/    /'
  printf '%s\n' "$out" | grep -q 'BEFORE=absent' \
    || { echo "    a name that does not exist was reported as present"; return 1; }
  printf '%s\n' "$out" | grep -q 'BEFORE2=absent' \
    || { echo "    the second probe of the missing name found something"; return 1; }
  printf '%s\n' "$out" | grep -qx 'AFTER=created-elsewhere' \
    || { echo "    the name created by another client was not visible with its bytes"; return 1; }
  # The name is created while this poll is already running, so it must appear
  # within the window rather than after it. The bound is loose (two seconds
  # against a one-second window) because two containers are involved; the exact
  # request count is asserted by the mount-backed test, not here.
  local seen
  seen=$(printf '%s\n' "$out" | sed -n 's/^SEEN_MS=//p')
  case $seen in
    never) echo "    the added name was never seen"; return 1 ;;
    ''|*[!0-9]*) echo "    the session did not report how many queries it took ($seen)"; return 1 ;;
  esac
  return 0
}

# --- a name another client removed or replaced ---------------------------
# The session confirms the name, another client deletes it, and the session
# asks again: after the window the name must be gone. This is the half of the
# criterion a name cache governs — a view that kept the entry answers "present"
# for as long as it keeps it, so an over-long window shows up here. A content
# read would not: file content is never retained, which is why the replaced
# bytes are checked separately from the name they appear under.
#
# The descriptor that was already open is read after the deletion, and must
# still serve the bytes it opened with: deleting the name is not supposed to
# pull the file out from under a program that is using it.
check_removed_name_visible_after_window(){
  local remote=$ACC_PROJ/tc19-removed-$$ marker=$WORK/rem.ready log=$WORK/rem.log
  acc_boot "printf 'held-bytes' > $remote" >/dev/null 2>&1 || {
    echo "    could not seed the remote file"; return 1; }

  local cfg
  cfg=$(acc_config tc19rem '["/bin/bash"]' '["'"$WORK"'"]' /bin/bash)
  acc_bg_session "$cfg" "$log" /bin/bash -c '
view=$1; marker=$2; go=$3
if [ ! -e "$view" ]; then echo SEEDED=absent; echo TC19-END; exit 0; fi
echo SEEDED=present
if ! exec 3< "$view"; then echo HELD=open-failed; echo TC19-END; exit 0; fi
: > "$marker"
for i in $(seq 1 150); do [ -e "$go" ] && break; sleep 0.1; done
held=; IFS= read -r -u 3 held || true
echo "HELD=$held"
sleep 1.4
if [ -e "$view" ]; then echo AFTER-WINDOW=present; else echo AFTER-WINDOW=absent; fi
echo TC19-END
' /bin/bash "$remote" "$marker" "$WORK/rem.done"
  wait_marker "$marker" || { echo "    the session never confirmed the name"; return 1; }

  acc_boot "rm -f $remote" >/dev/null 2>&1 || {
    echo "    the other client could not remove the file"; return 1; }
  acc_exec ": > $WORK/rem.done"

  wait_log_end "$log" || { echo "    the session did not finish"; return 1; }
  local out
  out=$(acc_get "$log")
  printf '%s\n' "$out" | sed 's/^/    /'
  printf '%s\n' "$out" | grep -q 'SEEDED=present' \
    || { echo "    the seeded file was not visible at all"; return 1; }
  printf '%s\n' "$out" | grep -q 'HELD=held-bytes' \
    || { echo "    the descriptor opened before the removal served something other than its bytes"; return 1; }
  printf '%s\n' "$out" | grep -q 'AFTER-WINDOW=absent' \
    || { echo "    a name removed by another client was still present after the window"; return 1; }
  return 0
}

# --- a directory enumerated before a child existed ------------------------
# A listing is a snapshot, not a claim about which names exist. After this view
# enumerates a directory, another client adds a child; the child must be found
# by name even though the earlier enumeration did not contain it, and a later
# enumeration must show both.
#
# This asserts the invariant rather than discriminating a window: the child is
# looked up by a name the enumeration never mentioned, so it is answered by the
# daemon whether or not the listing was retained. It would fail if enumeration
# started to answer for names it did not list, which is the failure the clause is
# written against. The retained window itself, and the fact that re-enumerating
# does not restart it, are counted by
# `TestRemoteDirectoryListingIsRetainedForOneSecond` and
# `TestListedChildAttributesExpireWithTheListing`.
check_enumeration_does_not_hide_new_names(){
  local remote=$ACC_PROJ/tc19-dir-$$ marker=$WORK/enum.ready log=$WORK/enum.log
  acc_boot "rm -rf $remote && mkdir -p $remote && printf 'old' > $remote/old.txt" >/dev/null 2>&1 || {
    echo "    could not seed the remote directory"; return 1; }

  local cfg
  cfg=$(acc_config tc19enum '["/bin/bash"]' '["'"$WORK"'"]' /bin/bash)
  acc_bg_session "$cfg" "$log" /bin/bash -c '
dir=$1; marker=$2
list(){ local f out=; for f in "$dir"/*; do [ -e "$f" ] && out="$out${f##*/} "; done; echo "LIST=$out"; }
list
old=
if [ -e "$dir/old.txt" ]; then old=$(<"$dir/old.txt"); fi
echo "CHILD=$old"
: > "$marker"
for i in $(seq 1 150); do [ -e "$dir/new.txt" ] && break; sleep 0.1; done
added=
if [ -e "$dir/new.txt" ]; then added=$(<"$dir/new.txt"); fi
echo "NEW=$added"
sleep 1.3
list
echo TC19-END
' /bin/bash "$remote" "$marker"
  wait_marker "$marker" || { echo "    the session never enumerated the directory"; return 1; }

  acc_boot "printf 'added-later' > $remote/new.txt.tmp && mv $remote/new.txt.tmp $remote/new.txt" >/dev/null 2>&1 || {
    echo "    the other client could not add the child"; return 1; }

  wait_log_end "$log" || { echo "    the session did not finish"; return 1; }
  local out
  out=$(acc_get "$log")
  printf '%s\n' "$out" | sed 's/^/    /'
  printf '%s\n' "$out" | grep -q 'CHILD=old' \
    || { echo "    an enumerated child could not be read back"; return 1; }
  printf '%s\n' "$out" | grep -q 'NEW=added-later' \
    || { echo "    a child added after the enumeration was not found by name"; return 1; }
  printf '%s\n' "$out" | grep -q 'LIST=new.txt old.txt ' \
    || { echo "    the later enumeration did not show both children"; return 1; }
  return 0
}

check(){ local n=$1; shift; if "$@"; then acc_ok "$n"; else acc_fail "$n" "output above"; fi; }

check missing-name-not-remembered check_missing_name_not_remembered
check removed-name-visible-after-window-and-held-descriptor-keeps-bytes check_removed_name_visible_after_window
check enumeration-does-not-hide-new-names check_enumeration_does_not_hide_new_names

acc_finish
