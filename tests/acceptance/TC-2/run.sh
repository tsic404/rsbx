#!/bin/bash
# TC-2 (AC-2) — the view serves the daemon's own bytes, and the program runs
# on the daemon.
#
# Design `docs/03-acceptance.md` §TC-2 judges two things:
#   a. an executable and a shared library prepared on the daemon, read back
#      through the sandbox view, are byte-for-byte the daemon's own files;
#   b. executing that executable lands on the daemon.
#
# (a) is judged on the actual bytes: `cmp` against a copy taken straight out of
# the daemon's container, and `sha256sum` computed independently on each side.
# The shared library is compared on its own; the executable's result never
# stands in for it. Both daemon files carry a per-run nonce, so a match cannot
# come from a copy that merely happened to be identical.
#
# (b) is read from /proc/1/comm of the machine that really ran the program and
# compared with the value measured on each side; a hostname, `uname` or a path
# proves nothing here. The same read from an allowlisted program is the
# control: it must see this machine's init, so the two answers are known to
# differ before the placement verdict means anything.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
cd "$(dirname "$0")" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc2-$$
ACC_CLIENT_IMG=${ACC_CLIENT_IMG:-rsbx:ci}
acc_init TC-2
ACC_TMP=
acc_cleanup(){ [ -n "$ACC_TMP" ] && rm -rf "$ACC_TMP"; acc_rig_cleanup; }
trap acc_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

ENTRY=/bin/bash
WORK=$ACC_WORK/tc2
BIN_DIR=$ACC_PROJ/tc2/bin
LIB_DIR=$ACC_PROJ/tc2/lib
PROG=$BIN_DIR/tc2prog
LIB=$LIB_DIR/libc.so.6
NONCE=tc2-$$-$RANDOM

acc_exec "mkdir -p $WORK"

# The program is a copy of the daemon's own `head`, and the library is a copy
# of the C library it names as a dependency. Both get a per-run nonce appended,
# which leaves them loadable and makes the daemon's bytes unique: an appended
# nonce cannot appear in any other copy of the same program.
prepare_daemon(){
  local out
  out=$(acc_daemon "
    mkdir -p $BIN_DIR $LIB_DIR &&
    cp /usr/bin/head $PROG &&
    cp /lib/x86_64-linux-gnu/libc.so.6 $LIB &&
    printf 'TC2NONCE-%s' '$NONCE' >> $PROG &&
    printf 'TC2NONCE-%s' '$NONCE' >> $LIB &&
    chmod 755 $PROG && chmod 644 $LIB &&
    echo PREPARED
  " 2>&1)
  printf '%s\n' "$out" | sed 's/^/    prepare: /'
  printf '%s\n' "$out" | grep -qx 'PREPARED' || return 1
  acc_daemon "grep -aq 'TC2NONCE-$NONCE' $PROG && grep -aq 'TC2NONCE-$NONCE' $LIB"
}

prepare_daemon || { acc_skip_all prepare "could not place the program and its library on the daemon"; }

# The comparison is only attributable to the daemon if this machine has no
# copy of that path of its own.
acc_exists "$ACC_PROJ/tc2" \
  && { acc_skip_all client_view "this machine's own tree holds $ACC_PROJ/tc2, so a matching read would prove nothing"; }

ACC_TMP=$(mktemp -d)

sum_client(){ acc_exec "sha256sum $(printf '%q' "$1") 2>/dev/null" | awk '{print $1}'; }
sum_daemon(){ acc_daemon "sha256sum $(printf '%q' "$1") 2>/dev/null" | awk '{print $1}'; }

# read_through_view copies both daemon files into this machine's own scratch
# tree. `cp` and `sha256sum` are named in the allowlist, so they run here, and
# the bytes they read are the ones the view serves for the daemon's path.
read_through_view(){
  local cfg out
  cfg=$(acc_config view \
    '["'"$ENTRY"'","/usr/bin/cp","/usr/bin/sha256sum"]' \
    '["'"$WORK"'"]' "$ENTRY")
  acc_session "$cfg" "$ENTRY" -c "
    cp $PROG $WORK/prog.fromview
    cp $LIB $WORK/lib.fromview
    sha256sum $PROG $LIB
  "
  local rc=$?; out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  [ $rc -eq 0 ] || { echo "    the read through the view did not complete (rc=$rc)"; return 1; }
  return 0
}

# compare_side PATH_IN_VIEW PATH_ON_DAEMON — pull the daemon's own bytes out of
# its container, put them next to what the view served, and cmp the two. The
# digest of each side is computed where the bytes live, as a second method.
compare_side(){
  local view_copy=$1 daemon_path=$2 label=$3 out
  docker cp "$ACC_DAEMON:$daemon_path" "$ACC_TMP/daemon.$label" >/dev/null 2>&1 \
    || { echo "    could not take $daemon_path out of the daemon container"; return 1; }
  docker cp "$ACC_TMP/daemon.$label" "$ACC_CLIENT:$view_copy.daemon" >/dev/null 2>&1 \
    || { echo "    could not place the daemon's bytes beside the view copy"; return 1; }
  out=$(acc_exec "cmp $(printf '%q' "$view_copy") $(printf '%q' "$view_copy.daemon") 2>&1")
  [ -z "$out" ] || { echo "    cmp: $out"; return 1; }

  local view_digest daemon_digest
  view_digest=$(sum_client "$view_copy")
  daemon_digest=$(sum_daemon "$daemon_path")
  printf '    %s view sha256=%s\n' "$label" "${view_digest:-<none>}"
  printf '    %s daemon sha256=%s\n' "$label" "${daemon_digest:-<none>}"
  [ -n "$view_digest" ] && [ -n "$daemon_digest" ] \
    || { echo "    a digest could not be computed on one side"; return 1; }
  [ "$view_digest" = "$daemon_digest" ] \
    || { echo "    the digests differ, so the bytes are not the daemon's"; return 1; }
  return 0
}

# --- a. the executable's bytes are the daemon's own ------------------------
check_program_bytes(){
  read_through_view || return 1
  local bytes
  bytes=$(acc_exec "stat -c%s $(printf '%q' "$WORK/prog.fromview") 2>/dev/null || echo 0")
  [ "${bytes:-0}" -gt 0 ] 2>/dev/null \
    || { echo "    the view returned no bytes for the program"; return 1; }
  echo "    program bytes through the view: $bytes"
  compare_side "$WORK/prog.fromview" "$PROG" program
}

# --- b. the shared library's bytes are the daemon's own, judged separately -
# The library is not inferred from the executable: it has its own comparison,
# its own copy and its own digest pair.
check_library_bytes(){
  read_through_view || return 1
  local bytes
  bytes=$(acc_exec "stat -c%s $(printf '%q' "$WORK/lib.fromview") 2>/dev/null || echo 0")
  [ "${bytes:-0}" -gt 0 ] 2>/dev/null \
    || { echo "    the view returned no bytes for the shared library"; return 1; }
  echo "    library bytes through the view: $bytes"
  compare_side "$WORK/lib.fromview" "$LIB" library
}

# --- c. the execution lands on the daemon ---------------------------------
# The fixture is not in the allowlist, so the session's routing must hand it to
# the daemon. It is run with the prepared library on its search path, so the
# bytes compared above are the bytes it loads; the loader's own answer is
# printed as evidence of that.
#
# The control is the same read from a program that IS allowlisted: it sees this
# machine's init, so the two answers are distinguishable.

# measure_daemon_init prints the daemon's own /proc/1/comm and fails when the
# read itself did not happen. A failed or empty read is not an identity.
measure_daemon_init(){
  local out
  out=$(acc_daemon 'cat /proc/1/comm' 2>/dev/null) || return 1
  [ -n "$out" ] || return 1
  printf '%s' "$out"
}

# check_declaration NAME DECLARED MEASURED — a declared name may only confirm
# what the kernel showed. An environment that declares a different identity
# cannot pass: the declaration is evidence about the deployment, never a
# substitute for the measurement.
check_declaration(){
  local name=$1 declared=$2 measured=$3
  [ -n "$declared" ] || return 0
  if [ "$declared" != "$measured" ]; then
    echo "    $name=$declared disagrees with the measured $measured"
    return 1
  fi
  echo "    $name=$declared agrees with the measurement"
  return 0
}

check_execution(){
  local cfg out rc daemon_init client_init remote local_init

  daemon_init=$(measure_daemon_init) || daemon_init=
  if [ -z "$daemon_init" ]; then
    echo "    the daemon's /proc/1/comm could not be measured"
    return 77
  fi

  cfg=$(acc_config run '["'"$ENTRY"'","/usr/bin/head"]' '["'"$WORK"'"]' "$ENTRY")
  acc_session "$cfg" "$ENTRY" -c "
    echo LOADER-TRACE:
    LD_LIBRARY_PATH=$LIB_DIR LD_TRACE_LOADED_OBJECTS=1 $PROG 2>&1
    if IFS= read -r c < /proc/1/comm && [ -n \"\$c\" ]; then
      echo \"CLIENT_MEASURED=\$c\"
    else
      echo CLIENT_MEASURED_FAILED
    fi
    echo \"REMOTE=\$(LD_LIBRARY_PATH=$LIB_DIR $PROG /proc/1/comm)\"
    echo \"LOCAL=\$(/usr/bin/head -c 64 /proc/1/comm)\"
  "
  rc=$?; out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  [ $rc -eq 0 ] || { echo "    the session did not complete (rc=$rc)"; return 1; }

  client_init=$(printf '%s\n' "$out" | sed -n 's/^CLIENT_MEASURED=//p')
  if [ -z "$client_init" ] || printf '%s\n' "$out" | grep -qxF CLIENT_MEASURED_FAILED; then
    echo "    this machine's /proc/1/comm could not be measured"
    return 77
  fi

  check_declaration DAEMON_INIT "${DAEMON_INIT:-}" "$daemon_init" || return 1
  check_declaration CLIENT_INIT "${CLIENT_INIT:-}" "$client_init" || return 1

  if [ "$client_init" = "$daemon_init" ]; then
    echo "    both sides measured the same init ($client_init), so placement cannot be judged"
    return 77
  fi

  remote=$(printf '%s\n' "$out" | sed -n 's/^REMOTE=//p')
  local_init=$(printf '%s\n' "$out" | sed -n 's/^LOCAL=//p')
  [ "$remote" = "$daemon_init" ] \
    || { echo "    the program ran with init '$remote', not the daemon's '$daemon_init'"; return 1; }
  [ "$local_init" = "$client_init" ] \
    || { echo "    the allowlisted control read '$local_init', not this machine's '$client_init'"; return 1; }
  return 0
}

check(){
  local n=$1 rc; shift
  "$@"; rc=$?
  case $rc in
    0) acc_ok "$n" ;;
    77) acc_skip "$n" "the environment could not be measured; see the lines above" ;;
    *) acc_fail "$n" "output above" ;;
  esac
}

check executable-bytes-match-daemon check_program_bytes
check library-bytes-match-daemon check_library_bytes
check execution-lands-on-daemon check_execution

acc_finish
