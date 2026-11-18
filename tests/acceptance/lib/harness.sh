#!/bin/bash
# Result protocol shared by every acceptance carrier.
#
#   OK <check>              the design criterion holds
#   SKIP <check>: <reason>  this environment cannot express the check
#   FAIL <check>: <reason>  the design criterion does not hold
#
# The two non-passing results are different facts and never merge: a missing
# /dev/fuse or a client image without python3 says nothing about the
# implementation, while a session that starts anyway or a write that succeeds
# is a defect. A carrier exits 0 when every check held, 1 when any check
# failed, and 77 when nothing could be judged (every check skipped).
set -u

acc_init(){
  ACC_TC=${1:?carrier name}
  acc_ok_n=0
  acc_skip_n=0
  acc_fail_n=0
}

acc_ok(){ acc_ok_n=$((acc_ok_n + 1)); printf 'OK %s\n' "$1"; }
acc_skip(){ acc_skip_n=$((acc_skip_n + 1)); printf 'SKIP %s: %s\n' "$1" "$2"; }
acc_fail(){ acc_fail_n=$((acc_fail_n + 1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

# acc_absorb relays a payload's result lines and counts them. The payload is
# the part that runs next to the session; the carrier only aggregates, so the
# three outcomes are tallied in one place.
acc_absorb(){
  local line
  while IFS= read -r line; do
    printf '%s\n' "$line"
    case $line in
      "OK "*) acc_ok_n=$((acc_ok_n + 1)) ;;
      "SKIP "*) acc_skip_n=$((acc_skip_n + 1)) ;;
      "FAIL "*) acc_fail_n=$((acc_fail_n + 1)) ;;
    esac
  done
}

# acc_skip_all ends a carrier whose prerequisites this environment does not
# meet. It is a SKIP, never a FAIL.
acc_skip_all(){
  acc_skip "$1" "$2"
  acc_finish
}

acc_finish(){
  printf 'SUMMARY %s ok=%d skip=%d fail=%d\n' "$ACC_TC" "$acc_ok_n" "$acc_skip_n" "$acc_fail_n"
  if [ "$acc_fail_n" -gt 0 ]; then exit 1; fi
  if [ "$acc_ok_n" -eq 0 ]; then exit 77; fi
  if [ "$acc_skip_n" -gt 0 ]; then exit 77; fi
  exit 0
}

# acc_require_tool reports an in-container helper the carrier itself needs.
acc_require_tool(){
  local tool=$1 check=$2
  command -v "$tool" >/dev/null 2>&1 || return 1
  return 0
}
