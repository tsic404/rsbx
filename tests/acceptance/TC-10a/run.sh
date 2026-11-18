#!/bin/bash
# TC-10a (AC-5a) — a broken connection, and a replaced program mid-session.
#
# Design `docs/03-acceptance.md` §TC-10a judges two independent situations:
#
#   a. while a session holds a slow remote read and a long remote command, the
#      daemon connection is interrupted. The uncompleted read must end in an
#      explicit failure (not stale or truncated content presented as success),
#      the running remote command must be terminated, and a later remote access
#      from the same session must fail explicitly.
#
#   b. a local-set program's file is replaced while a session is running. That
#      session must keep executing the bytes it started with, which are the
#      bytes that were readable when the session began.
#
# For (a) the daemon is killed from the host while the read is demonstrably in
# flight: the carrier waits for the session's own in-flight marker before
# touching the daemon, so the read is not merely "expected" to be running.
#
# The content half of (b) is carried by `TestCacheSnapshotKeepsStartupBytes...
# AfterSourceReplaced` in internal/sandbox: it drives the same capture path the
# launcher uses and proves the snapshot object keeps the startup bytes after
# the source file is replaced. This carrier adds the part only a real mount can
# show: the replaced file is still visible on this machine while the session
# keeps executing the older snapshot.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
ACC_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$ACC_DIR" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc10a-$$
ACC_SESSION_TIMEOUT=300
acc_init TC-10a
trap acc_rig_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

WORK=$ACC_WORK/tc10a
acc_exec "mkdir -p $WORK"

# The remote object of the slow read. 256 MiB at 4 KiB blocks is slow enough
# that the read is still running when the marker appears, and large enough that
# a truncated copy is distinguishable from a complete one.
SEED_BYTES=268435456
seed_big(){
  local out bytes
  out=$(acc_boot "dd if=/dev/zero of=$ACC_PROJ/big.bin bs=1M count=256 status=none; stat -c%s $ACC_PROJ/big.bin" 2>&1)
  printf '%s\n' "$out" | sed 's/^/    seed: /'
  bytes=$(printf '%s\n' "$out" | tail -1)
  [ "$bytes" = "$SEED_BYTES" ] \
    || { acc_skip_all seed "could not place a $SEED_BYTES-byte remote file (got [$bytes])"; return 1; }
  return 0
}
seed_big || exit 77

# ---------------------------------------------------------------------------
# a. connection interrupted mid-read

check_disconnect(){
  local cfg rc out
  cfg=$(acc_config disc '["/bin/dd","/bin/bash"]' '["'"$WORK"'"]' /bin/bash)
  acc_exec "rm -f $WORK/inflight $WORK/session.log"

  # Health control with the daemon up: the same read of the same file must
  # complete. Without it, a short read after the kill would be uninformative.
  acc_session "$cfg" /bin/bash -c "
    /bin/dd if=$ACC_PROJ/big.bin of=$WORK/health.out bs=4194304 2>$WORK/health.err
    echo \"HEALTH-RC=\$? BYTES=\$(stat -c%s $WORK/health.out 2>/dev/null)\"
  " >/dev/null
  local health_bytes; health_bytes=$(acc_exec "stat -c%s $WORK/health.out 2>/dev/null || echo 0")
  [ "$health_bytes" = "$SEED_BYTES" ] \
    || { echo "    the health control read $health_bytes of $SEED_BYTES bytes; the slow read would not be meaningful"; return 1; }

  # The session: a slow read, a long remote command, and a later remote access.
  # Each step reports on stdout, which is local content, so the report survives
  # the disconnect itself.
  acc_session_log "$cfg" "$WORK/session.log" /bin/bash -c "
    /bin/dd if=$ACC_PROJ/big.bin of=$WORK/read.out bs=4096 2>$WORK/dd.err &
    RD=\$!
    /bin/sleep 300 &
    SL=\$!
    : > $WORK/inflight
    wait \$RD; echo \"READ-RC=\$?\"
    wait \$SL; echo \"SLEEP-RC=\$?\"
    /bin/cat $ACC_PROJ/big.bin > /dev/null 2>&1; echo \"AFTER-RC=\$?\"
    echo TC10A-SESSION-END
  " &
  local sp=$!

  # Wait for the session's own marker, then confirm bytes are already flowing.
  local i
  for i in $(seq 1 200); do
    acc_exists "$WORK/inflight" && break
    sleep 0.2
  done
  acc_exists "$WORK/inflight" \
    || { echo "    the session never reached its in-flight marker"; wait $sp 2>/dev/null; return 1; }
  local inflight_bytes
  inflight_bytes=$(acc_exec "stat -c%s $WORK/read.out 2>/dev/null || echo 0")
  [ "$inflight_bytes" -gt 0 ] 2>/dev/null \
    || { echo "    no bytes had been read when the marker appeared, so the read was not in flight"; return 1; }
  echo "    in-flight at kill: $inflight_bytes of $SEED_BYTES bytes"

  acc_daemon_kill
  # Kill the daemon's container for good: `docker kill` on a running container
  # ends it, so the socket cannot answer again during this check.
  wait $sp 2>/dev/null
  for i in $(seq 1 200); do
    acc_exec "grep -q TC10A-SESSION-END $WORK/session.log" >/dev/null 2>&1 && break
    sleep 0.2
  done

  out=$(acc_get "$WORK/session.log")
  printf '%s\n' "$out" | sed 's/^/    /'

  printf '%s\n' "$out" | grep -qx 'READ-RC=0' \
    && { echo "    the interrupted read reported success"; return 1; }
  printf '%s\n' "$out" | grep -q 'READ-RC=' \
    || { echo "    the interrupted read never reported an outcome"; return 1; }
  local read_bytes
  read_bytes=$(acc_exec "stat -c%s $WORK/read.out 2>/dev/null || echo 0")
  [ "$read_bytes" != "$SEED_BYTES" ] \
    || { echo "    the read completed in full after the daemon was killed"; return 1; }
  echo "    partial copy: $read_bytes bytes, and it is not presented as a complete read"

  printf '%s\n' "$out" | grep -qx 'SLEEP-RC=0' \
    && { echo "    the long remote command survived the disconnect"; return 1; }
  printf '%s\n' "$out" | grep -q 'SLEEP-RC=' \
    || { echo "    the long remote command never reported termination"; return 1; }

  printf '%s\n' "$out" | grep -qx 'AFTER-RC=0' \
    && { echo "    remote access still succeeded after the connection was lost"; return 1; }
  printf '%s\n' "$out" | grep -q 'AFTER-RC=' \
    || { echo "    the later remote access never reported an outcome"; return 1; }

  # No process from this session may still be running here. /proc is readable
  # in the image; ps is not, and a missing ps would make this pass unseen.
  acc_proc_match client read.out >/dev/null 2>&1 \
    && { echo "    a reader survived the disconnect"; return 1; }
  acc_proc_match client 'sleep 300' >/dev/null 2>&1 \
    && { echo "    the long command's process survived the disconnect"; return 1; }
  return 0
}

# The daemon that part (a) killed is a container that cannot answer again, so
# part (b) needs a fresh one. It is the same image and the same project volume,
# which is what makes it the same deployment rather than a different test.
restart_daemon(){
  docker rm -f "$ACC_DAEMON" >/dev/null 2>&1 || true
  # `docker rm -f` returns before the name is released when the container was
  # killed rather than exited; wait for the name to be free.
  local i
  for i in $(seq 1 100); do
    docker inspect "$ACC_DAEMON" >/dev/null 2>&1 || break
    sleep 0.2
  done
  docker run -d --rm --name "$ACC_DAEMON" --network "$ACC_PREFIX-net" \
    -v "$ACC_PREFIX-proj:$ACC_PROJ" -v "$ACC_PREFIX-run:/run/rsbx" \
    --entrypoint rsbxd "$ACC_DAEMON_IMG" -socket "$ACC_SOCK" >/dev/null
  docker run --rm --network "$ACC_PREFIX-net" -v "$ACC_PREFIX-run:/run/rsbx" \
    --entrypoint /bin/bash "$ACC_DAEMON_IMG" \
    -c 'for i in $(seq 1 100); do [ -S /run/rsbx/daemon.sock ] && exit 0; sleep 0.2; done; exit 1' \
    >/dev/null 2>&1
  [ -f "$ACC_BIN/rsbxd" ] && docker cp "$ACC_BIN/rsbxd" "$ACC_DAEMON:/usr/local/bin/rsbxd" >/dev/null 2>&1
  docker restart "$ACC_DAEMON" >/dev/null 2>&1
  docker run --rm --network "$ACC_PREFIX-net" -v "$ACC_PREFIX-run:/run/rsbx" \
    --entrypoint /bin/bash "$ACC_DAEMON_IMG" \
    -c 'for i in $(seq 1 100); do [ -S /run/rsbx/daemon.sock ] && exit 0; sleep 0.2; done; exit 1' \
    >/dev/null 2>&1
  # A session that answers proves the socket is being served again.
  local cfg; cfg=$(acc_config restart-probe '[]' '[]')
  acc_session "$cfg" /bin/sh -c 'echo DAEMON-BACK'
  printf '%s\n' "$ACC_OUT" | grep -qx 'DAEMON-BACK'
}

# ---------------------------------------------------------------------------
# b. a replaced program, mid-session

check_snapshot_stable(){
  local cfg rc out
  local prog=$ACC_LOCAL_DIR/tc10a-snap.sh
  acc_put "$prog" "#!/bin/bash
echo VERSION-ONE
" 755
  local started
  started=$(acc_exec "sha256sum $prog | cut -d' ' -f1")

  cfg=$(acc_config snap '["'"$prog"'","/bin/bash"]' '["'"$WORK"'"]' /bin/bash)
  acc_exec "rm -f $WORK/swapped $WORK/snap.log"
  acc_session_log "$cfg" "$WORK/snap.log" /bin/bash -c "
    echo \"R1=\$($prog)\"
    echo SESSION-START
    i=0
    while [ ! -f $WORK/swapped ]; do sleep 0.2; i=\$((i+1)); [ \$i -gt 400 ] && { echo TIMEOUT; exit 1; }; done
    echo \"CTRL=\$(/bin/head -1 $prog 2>&1)\"
    echo \"R2=\$($prog)\"
    echo SESSION-END
  " &
  local sp=$!

  local i
  for i in $(seq 1 300); do
    acc_exec "grep -q SESSION-START $WORK/snap.log" >/dev/null 2>&1 && break
    sleep 0.2
  done
  acc_exec "grep -q SESSION-START $WORK/snap.log" >/dev/null 2>&1 \
    || { echo "    the session never started"; wait $sp 2>/dev/null; return 1; }

  # Replace the program's bytes on this machine while the session is live.
  acc_put "$prog" "#!/bin/bash
echo VERSION-TWO
" 755
  local replaced
  replaced=$(acc_exec "sha256sum $prog | cut -d' ' -f1")
  [ "$started" != "$replaced" ] \
    || { echo "    the program file was not actually replaced"; wait $sp 2>/dev/null; return 1; }
  acc_exec ": > $WORK/swapped"
  wait $sp 2>/dev/null
  for i in $(seq 1 200); do
    acc_exec "grep -q SESSION-END $WORK/snap.log" >/dev/null 2>&1 && break
    sleep 0.2
  done

  out=$(acc_get "$WORK/snap.log")
  printf '%s\n' "$out" | sed 's/^/    /'
  printf '%s\n' "$out" | grep -qx 'R1=VERSION-ONE' \
    || { echo "    the first run did not use the startup bytes"; return 1; }
  printf '%s\n' "$out" | grep -qx 'R2=VERSION-ONE' \
    || { echo "    the session picked up the replaced file instead of its startup snapshot"; return 1; }
  # The replacement really happened where it should be visible: a remote read
  # of the same path still answers from the daemon, which never had these
  # bytes, so the local file is the only place the new content exists.
  printf '%s\n' "$out" | grep -q 'VERSION-TWO' \
    && { echo "    the session observed the replacement"; return 1; }
  local now
  now=$(acc_exec "tail -1 $prog")
  printf '%s\n' "$now" | grep -qx 'echo VERSION-TWO' \
    || { echo "    the file on this machine does not hold the new bytes: [$now]"; return 1; }
  return 0
}

check(){ local n=$1; shift; if "$@"; then acc_ok "$n"; else acc_fail "$n" "output above"; fi; }

check disconnect-fails-read-command-and-access check_disconnect
if restart_daemon; then
  check replaced-program-keeps-startup-snapshot check_snapshot_stable
else
  acc_skip replaced-program-keeps-startup-snapshot "the daemon could not be restarted after the disconnect check"
fi

acc_finish
