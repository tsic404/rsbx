#!/bin/bash
# TC-14 (AC-8) — cancellation, and a caller that dies abruptly.
#
# Design `docs/03-acceptance.md` §TC-14 judges two endings of a session that
# holds a long command on the daemon and a local descendant which has left the
# entry's process group:
#
#   a. the caller cancels the session. The remote command must have
#      terminated, the detached descendant must have been reclaimed as well,
#      and neither machine may hold a live process or a resource of that
#      session;
#   b. another session is live and its caller process terminates abnormally
#      (SIGKILL, so no cleanup of its own can run). The same absence must
#      follow, and a session started afterwards must still work.
#
# `internal/daemon`'s lifecycle tests cover neither fact: `TestDisconnectKills-
# Child` drives one command over one pipe in one process, and `TestSignal-
# ForwardedToProcessGroup` signals one process group. Neither can express a
# descendant that left the group, and neither can show that two machines are
# clean afterwards.
#
# Placement is measured, never inferred from a container name: every process
# records the `/proc/1/comm` it really sees, and the carrier compares that with
# the init measured on each side. Every process also heartbeats, so
# "terminated" is a counter that stopped, not only a name that disappeared.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
ACC_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$ACC_DIR" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc14-$$
ACC_SESSION_TIMEOUT=300
acc_init TC-14
trap acc_rig_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

# The descendant that leaves the entry's process group needs setsid(1); the
# loop it runs needs a sleep. Their absence is a gap in the image, not in the
# implementation, and the scene cannot be staged at all.
SETSID=/usr/bin/setsid
acc_exec "test -x $SETSID && test -x /bin/sleep" >/dev/null 2>&1 \
  || { acc_skip_all detach_tools "$SETSID or /bin/sleep is absent in $ACC_CLIENT_IMG, so a descendant leaving the process group cannot be staged"; exit 77; }

SESSION_SCRIPT=$ACC_LOCAL_DIR/tc14-session
DETACH_SCRIPT=$ACC_LOCAL_DIR/tc14-detach
PROBE_SCRIPT=/tmp/tc14-probe

docker cp "$ACC_DIR/session.sh" "$ACC_CLIENT:$SESSION_SCRIPT" >/dev/null 2>&1 \
  || { acc_skip_all fixture "could not stage the session entry"; exit 77; }
docker cp "$ACC_DIR/detach.sh" "$ACC_CLIENT:$DETACH_SCRIPT" >/dev/null 2>&1 \
  || { acc_skip_all fixture "could not stage the detached descendant"; exit 77; }
docker cp "$ACC_DIR/probe.sh" "$ACC_CLIENT:$PROBE_SCRIPT" >/dev/null 2>&1 \
  || { acc_skip_all fixture "could not stage the state probe on this machine"; exit 77; }
docker cp "$ACC_DIR/probe.sh" "$ACC_DAEMON:$PROBE_SCRIPT" >/dev/null 2>&1 \
  || { acc_skip_all fixture "could not stage the state probe on the daemon"; exit 77; }
acc_exec "chmod 755 $SESSION_SCRIPT $DETACH_SCRIPT $PROBE_SCRIPT" >/dev/null 2>&1
acc_daemon "chmod 755 $PROBE_SCRIPT" >/dev/null 2>&1

# /bin/sh is deliberately absent: that is what routes the long command to the
# daemon. /bin/sleep and setsid are present so the detached descendant's own
# loop stays on this machine.
ALLOW='["'"$SESSION_SCRIPT"'","'"$DETACH_SCRIPT"'","'"$SETSID"'","/bin/sleep"]'

# ---------------------------------------------------------------------------
# measurement helpers

# tc14_kv RECORD KEY — the value of one KEY=... line.
tc14_kv(){
  printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -1
}

# tc14_beat SIDE PATH — the heartbeat's current size on that side.
tc14_beat(){
  case $1 in
    client) acc_exec "stat -c%s $(printf '%q' "$2") 2>/dev/null || echo 0" ;;
    daemon) acc_daemon "stat -c%s $(printf '%q' "$2") 2>/dev/null || echo 0" ;;
  esac
}

# tc14_client_state PREFIX LOCAL_MARK MOUNT_PREFIX MOUNT_BASE CACHE_BASE —
# processes of this session still alive on this machine, processes whose mount
# table still names its mount, and session directories still allocated.
tc14_client_state(){
  docker exec -e PROBE_PREFIX="$1" -e PROBE_LOCAL="$2" -e PROBE_MOUNT="$3" \
    -e PROBE_MOUNT_BASE="$4" -e PROBE_CACHE_BASE="$5" \
    "$ACC_CLIENT" /bin/bash "$PROBE_SCRIPT" client 2>/dev/null
}

# tc14_daemon_procs MARK — processes carrying MARK on the daemon.
tc14_daemon_procs(){
  local n
  n=$(docker exec -e PROBE_PAT="$1" "$ACC_DAEMON" /bin/bash "$PROBE_SCRIPT" procs 2>/dev/null |
    sed -n 's/^procs=//p')
  printf '%s' "${n:-unknown}"
}

# tc14_caller_alive PID CFG — whether PID still names the session's caller.
tc14_caller_alive(){
  acc_exec "if [ -e /proc/$1 ] && tr '\0' ' ' < /proc/$1/cmdline 2>/dev/null | grep -qF $2; then echo alive; else echo gone; fi"
}

# The probe is a fixture: it has to answer before anything else is judged.
probe_smoke=$(tc14_client_state "$ACC_PREFIX-nomatch" "$ACC_PREFIX-nomatch-local" \
  "$ACC_STATE/nomatch/session-" "$ACC_STATE/nomatch" "$ACC_STATE/nomatch")
[ -n "$(tc14_kv "$probe_smoke" procs)" ] && [ -n "$(tc14_kv "$probe_smoke" cachedirs)" ] \
  || { acc_skip_all probe "the state probe did not answer on this machine"; exit 77; }
[ "$(tc14_daemon_procs "$ACC_PREFIX-nomatch")" != unknown ] \
  || { acc_skip_all probe "the state probe did not answer on the daemon"; exit 77; }

# A resource in the daemon's tree must not be reachable from this machine: the
# rig never mounts the project volume here, so anything the carrier finds under
# $ACC_PROJ was written by the daemon side, not by a local process.
if acc_exec "test -e $ACC_PROJ" >/dev/null 2>&1; then
  acc_skip_all cross_machine "this machine can see $ACC_PROJ, so content there would not prove daemon-side execution"
  exit 77
fi

# ---------------------------------------------------------------------------
# one scene: start, judge the live facts, end it, judge the aftermath

tc14_scenario(){
  local prefix=$1 sig=$2
  local work=$ACC_WORK/tc14-$prefix
  local remote=$ACC_PROJ/tc14-$prefix
  local mount_base=$ACC_STATE/sb-$prefix
  local cache_base=$ACC_STATE/cache-$prefix
  local mark="tc14m-$prefix-$$"
  local local_mark=$mark-local remote_mark=$mark-remote
  local cfg pid i state started= caller_gone= settled=
  local entry_rec detached_rec remote_rec
  local entry_init detached_init remote_init
  local entry_pgrp detached_pid detached_pgrp detached_sid
  local live local_live remote_live mount_live cache_live
  local rb_start rb_end lb_start lb_end
  local final procs local_procs mounts mountdirs cachedirs
  local remote_left rb_stop_a rb_stop_b lb_stop_a lb_stop_b
  local why_scene= why_remote= why_detached= why_process= why_resource=

  acc_exec "rm -rf $work && mkdir -p $work" >/dev/null 2>&1
  acc_daemon "rm -rf $remote && mkdir -p $remote" >/dev/null 2>&1
  cfg=$(acc_config "$prefix" "$ALLOW" '["'"$work"'"]' /bin/bash)

  # The caller is the rsbx process itself. It records its own pid before
  # replacing itself, so the carrier ends the session the way a caller does:
  # one signal to that exact process, not to the container or a group.
  docker exec -d "$ACC_CLIENT" /bin/bash -c \
    "echo \$\$ > $work/caller.pid; exec /usr/local/bin/rsbx -config $cfg -- $SESSION_SCRIPT $mark $work $remote $DETACH_SCRIPT $SETSID > $work/session.log 2>&1" \
    >/dev/null 2>&1

  for i in $(seq 1 300); do
    if acc_exec "test -s $work/caller.pid" >/dev/null 2>&1 &&
       acc_daemon "test -s $remote/remote.beat" >/dev/null 2>&1 &&
       acc_exec "test -s $work/detached.beat" >/dev/null 2>&1; then
      started=1
      break
    fi
    sleep 0.1
  done
  if [ -z "$started" ]; then
    echo "    the session never brought both processes up; its log:"
    acc_get "$work/session.log" | sed 's/^/    /'
    acc_fail "$prefix-scene-live-and-escaped" "the session never brought its remote command and detached descendant up"
    acc_skip "$prefix-terminates-remote-command" "not judged: the scene never started"
    acc_skip "$prefix-reaps-detached-local-descendant" "not judged: the scene never started"
    acc_skip "$prefix-leaves-no-session-process" "not judged: the scene never started"
    acc_skip "$prefix-releases-session-resources" "not judged: the scene never started"
    return 1
  fi

  entry_rec=$(acc_get "$work/entry.record")
  detached_rec=$(acc_get "$work/detached.record")
  remote_rec=$(acc_daemon "cat $remote/remote.record 2>/dev/null")
  entry_init=$(tc14_kv "$entry_rec" INIT)
  detached_init=$(tc14_kv "$detached_rec" INIT)
  remote_init=$(tc14_kv "$remote_rec" INIT)
  entry_pgrp=$(tc14_kv "$entry_rec" PGRP)
  detached_pid=$(tc14_kv "$detached_rec" PID)
  detached_pgrp=$(tc14_kv "$detached_rec" PGRP)
  detached_sid=$(tc14_kv "$detached_rec" SID)

  live=$(tc14_client_state "$mark" "$local_mark" "$mount_base/session-" "$mount_base" "$cache_base")
  local_live=$(tc14_kv "$live" local)
  mount_live=$(tc14_kv "$live" mountdirs)
  cache_live=$(tc14_kv "$live" cachedirs)
  remote_live=$(tc14_daemon_procs "$remote_mark")

  rb_start=$(tc14_beat daemon "$remote/remote.beat")
  lb_start=$(tc14_beat client "$work/detached.beat")
  sleep 0.6
  rb_end=$(tc14_beat daemon "$remote/remote.beat")
  lb_end=$(tc14_beat client "$work/detached.beat")

  printf '    entry:    %s\n' "$(printf '%s' "$entry_rec" | tr '\n' ' ')"
  printf '    detached: %s\n' "$(printf '%s' "$detached_rec" | tr '\n' ' ')"
  printf '    remote:   %s\n' "$(printf '%s' "$remote_rec" | tr '\n' ' ')"
  printf '    inits: this=%s daemon=%s entry=%s detached=%s remote=%s\n' \
    "$ACC_CLIENT_INIT" "$ACC_DAEMON_INIT" "$entry_init" "$detached_init" "$remote_init"
  printf '    processes: local=%s remote=%s; dirs mount=%s cache=%s\n' \
    "$local_live" "$remote_live" "$mount_live" "$cache_live"
  printf '    beats: remote=%s->%s detached=%s->%s\n' \
    "$rb_start" "$rb_end" "$lb_start" "$lb_end"
  printf '    detached pid/pgrp/sid: %s/%s/%s (entry pgrp %s)\n' \
    "$detached_pid" "$detached_pgrp" "$detached_sid" "$entry_pgrp"

  # --- the scene the design names, while it is live -----------------------
  if [ "$entry_init" != "$ACC_CLIENT_INIT" ]; then
    why_scene="the entry measured init [$entry_init], not this machine's session init [$ACC_CLIENT_INIT]"
  elif [ "$remote_init" != "$ACC_DAEMON_INIT" ]; then
    why_scene="the remote command measured init [$remote_init], not the daemon init [$ACC_DAEMON_INIT]"
  elif [ "$detached_init" != "$ACC_CLIENT_INIT" ]; then
    why_scene="the detached descendant measured init [$detached_init], not this machine's session init [$ACC_CLIENT_INIT]"
  elif [ "$detached_pid" != "$detached_pgrp" ] || [ "$detached_sid" != "$detached_pgrp" ]; then
    why_scene="the descendant is not its own session leader (pid $detached_pid pgrp $detached_pgrp sid $detached_sid)"
  elif [ "$detached_pgrp" = "$entry_pgrp" ]; then
    why_scene="the descendant stayed in the entry's process group $entry_pgrp, so leaving the group was never staged"
  elif [ "${local_live:-0}" -lt 1 ]; then
    why_scene="no process on this machine carried the descendant's marker while the session was up"
  elif [ "${remote_live:-0}" -lt 1 ]; then
    why_scene="no process on the daemon carried the remote command's marker while the session was up"
  elif [ "$rb_end" -le "$rb_start" ] || [ "$lb_end" -le "$lb_start" ]; then
    why_scene="the long command or the descendant was not executing before the ending"
  elif [ "${mount_live:-0}" -lt 1 ] || [ "${cache_live:-0}" -lt 1 ]; then
    why_scene="the live session allocated no mount/cache directory to release (mount=$mount_live cache=$cache_live)"
  elif [ "$(tc14_caller_alive "$(acc_exec "cat $work/caller.pid")" "$cfg")" != alive ]; then
    why_scene="the caller process was not running before the ending"
  fi

  # --- the ending ---------------------------------------------------------
  pid=$(acc_exec "cat $work/caller.pid")
  echo "    ending $prefix with SIG$sig at caller $pid"
  acc_exec "kill -s $sig $pid" >/dev/null 2>&1
  for i in $(seq 1 300); do
    if [ "$(tc14_caller_alive "$pid" "$cfg")" = gone ]; then
      caller_gone=1
      break
    fi
    sleep 0.1
  done
  [ -n "$caller_gone" ] || echo "    the caller process did not exit"

  # Reclamation is asynchronous in the callee (signal grace, unmount,
  # directory removal, remote reap). Wait for the state the design describes,
  # with a bound: it is the settled state that is judged, not one instant.
  for i in $(seq 1 300); do
    state=$(tc14_client_state "$mark" "$local_mark" "$mount_base/session-" "$mount_base" "$cache_base")
    if [ "$(tc14_kv "$state" procs)" = 0 ] &&
       [ "$(tc14_kv "$state" mounts)" = 0 ] &&
       [ "$(tc14_kv "$state" mountdirs)" = 0 ] &&
       [ "$(tc14_kv "$state" cachedirs)" = 0 ] &&
       [ "$(tc14_daemon_procs "$remote_mark")" = 0 ]; then
      settled=1
      break
    fi
    sleep 0.1
  done

  final=$(tc14_client_state "$mark" "$local_mark" "$mount_base/session-" "$mount_base" "$cache_base")
  procs=$(tc14_kv "$final" procs)
  local_procs=$(tc14_kv "$final" local)
  mounts=$(tc14_kv "$final" mounts)
  mountdirs=$(tc14_kv "$final" mountdirs)
  cachedirs=$(tc14_kv "$final" cachedirs)
  remote_left=$(tc14_daemon_procs "$remote_mark")
  rb_stop_a=$(tc14_beat daemon "$remote/remote.beat")
  lb_stop_a=$(tc14_beat client "$work/detached.beat")
  sleep 0.6
  rb_stop_b=$(tc14_beat daemon "$remote/remote.beat")
  lb_stop_b=$(tc14_beat client "$work/detached.beat")

  printf '    after: settled=%s processes=%s (local=%s) mounts=%s dirs mount=%s cache=%s remote=%s\n' \
    "${settled:-0}" "$procs" "$local_procs" "$mounts" "$mountdirs" "$cachedirs" "$remote_left"
  printf '    after beats: remote=%s->%s detached=%s->%s\n' \
    "$rb_stop_a" "$rb_stop_b" "$lb_stop_a" "$lb_stop_b"
  acc_get "$work/session.log" | sed 's/^/    session: /'

  # --- the settled state the design asks for ------------------------------
  if [ -n "$why_scene" ]; then
    acc_fail "$prefix-scene-live-and-escaped" "$why_scene"
    acc_skip "$prefix-terminates-remote-command" "not judged: $why_scene"
    acc_skip "$prefix-reaps-detached-local-descendant" "not judged: $why_scene"
    acc_skip "$prefix-leaves-no-session-process" "not judged: $why_scene"
    acc_skip "$prefix-releases-session-resources" "not judged: $why_scene"
    return 0
  fi
  acc_ok "$prefix-scene-live-and-escaped"

  if [ "${remote_left:-0}" -gt 0 ]; then
    why_remote="a daemon process still carries $remote_mark"
  elif [ "$rb_stop_b" != "$rb_stop_a" ]; then
    why_remote="the remote command kept executing after the session ended ($rb_stop_a -> $rb_stop_b)"
  fi
  if [ "${local_procs:-0}" -gt 0 ]; then
    why_detached="a process on this machine still carries $local_mark"
  elif [ "$lb_stop_b" != "$lb_stop_a" ]; then
    why_detached="the detached descendant kept executing after the session ended ($lb_stop_a -> $lb_stop_b)"
  fi
  if [ -z "$caller_gone" ]; then
    why_process="the caller process $pid never exited"
  elif [ "${procs:-0}" -gt 0 ]; then
    why_process="a process carrying this session's marker is still alive ($procs)"
  elif [ "${mounts:-0}" -gt 0 ]; then
    why_process="a process of this session still holds its mount ($mounts)"
  fi
  if [ "${mountdirs:-1}" -ne 0 ]; then
    why_resource="the session's mount directory is still allocated"
  elif [ "${cachedirs:-1}" -ne 0 ]; then
    why_resource="the session's cache directory is still allocated"
  fi

  if [ -z "$why_remote" ]; then
    acc_ok "$prefix-terminates-remote-command"
  else
    acc_fail "$prefix-terminates-remote-command" "$why_remote"
  fi
  if [ -z "$why_detached" ]; then
    acc_ok "$prefix-reaps-detached-local-descendant"
  else
    acc_fail "$prefix-reaps-detached-local-descendant" "$why_detached"
  fi
  if [ -z "$why_process" ]; then
    acc_ok "$prefix-leaves-no-session-process"
  else
    acc_fail "$prefix-leaves-no-session-process" "$why_process"
  fi
  if [ -z "$why_resource" ]; then
    acc_ok "$prefix-releases-session-resources"
  else
    acc_fail "$prefix-releases-session-resources" "$why_resource"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# a. the caller cancels the session

echo "--- a. cancel: SIGTERM to the caller"
tc14_scenario cancel TERM

# ---------------------------------------------------------------------------
# b. the caller terminates abnormally

echo "--- b. crash: SIGKILL to the caller"
tc14_scenario crash KILL

# A session established after the crash must still work: its remote command
# runs on the daemon, it can read the crashed session's tree, and it releases
# its own resources when it ends.
check_after_crash(){
  local cfg work=$ACC_WORK/tc14-after state
  acc_exec "rm -rf $work && mkdir -p $work" >/dev/null 2>&1
  cfg=$(acc_config after "$ALLOW" '["'"$work"'"]' /bin/bash)
  acc_session "$cfg" /bin/sh -c "
    IFS= read -r i < /proc/1/comm
    echo \"AFTER-INIT=\$i\"
    cat $ACC_PROJ/tc14-crash/remote.record
    echo AFTER-SESSION-OK
  "
  printf '%s\n' "$ACC_OUT" | sed 's/^/    /'
  printf '%s\n' "$ACC_OUT" | grep -qx "AFTER-INIT=$ACC_DAEMON_INIT" \
    || { echo "    the new session's command did not run on the daemon"; return 1; }
  printf '%s\n' "$ACC_OUT" | grep -qx 'AFTER-SESSION-OK' \
    || { echo "    the new session did not finish its remote command"; return 1; }
  printf '%s\n' "$ACC_OUT" | grep -q '^INIT=' \
    || { echo "    the new session could not read the crashed session's tree"; return 1; }
  state=$(tc14_client_state "$ACC_PREFIX-after" "$ACC_PREFIX-after-local" \
    "$ACC_STATE/sb-after/session-" "$ACC_STATE/sb-after" "$ACC_STATE/cache-after")
  [ "$(tc14_kv "$state" mountdirs)" = 0 ] && [ "$(tc14_kv "$state" cachedirs)" = 0 ] \
    || { echo "    the session that ran after the crash left its directories behind"; return 1; }
  return 0
}

if check_after_crash; then
  acc_ok crash-keeps-new-sessions-working
else
  acc_fail crash-keeps-new-sessions-working "output above"
fi

acc_finish
