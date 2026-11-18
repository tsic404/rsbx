#!/bin/bash
# TC-1 (AC-1) — mixed placement.
#
# Design `docs/03-acceptance.md` §TC-1 judges four things:
#   a. one allowlisted program under four spellings — absolute path, symlink,
#      relative path, PATH lookup — runs on this machine every time;
#   b. an unlisted child started by a local program runs on the daemon;
#   c. a custom process name does not move the placement of the target it
#      names: the daemon still runs it;
#   d. a name added to an allowlisted directory after startup is served by the
#      daemon, while a name that was there at startup stayed here.
#
# Placement is read from /proc/1/comm of the machine the process really ran
# on: the client container's init for a local program, the daemon's init for
# a remote one. The two names are read from the deployment, never assumed.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
cd "$(dirname "$0")" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc1-$$
ACC_CLIENT_IMG=${ACC_CLIENT_IMG:-rsbx:ci}
# The entry shell is the one local program every check starts from, so it is
# allowlisted explicitly: without it /bin/bash itself runs on the daemon and
# the whole command — including these probes — measures the wrong machine.
ENTRY=/bin/bash
acc_init TC-1
trap acc_rig_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

# One stand-in program, installed here and named individually by the config.
# Its only job is to say which machine ran it.
acc_put "$ACC_LOCAL_DIR/tc1-probe" "#!/bin/sh
IFS= read -r p < /proc/1/comm 2>/dev/null
echo \"PROBE-INIT=\$p\"
" 755

# --- a. four spellings, one placement -------------------------------------
# The allowlist names the exact file. A spelling that ran remotely would mean
# the routing decision looked at the caller's string, not the target it
# resolves to.
check_spellings(){
  local cfg out
  cfg=$(acc_config spellings '["'"$ACC_LOCAL_DIR"'/tc1-probe","'"$ENTRY"'"]' '[]' "$ENTRY")
  acc_session "$cfg" "$ENTRY" -c "
    echo \"abs=\$($ACC_LOCAL_DIR/tc1-probe)\"
    ln -sf $ACC_LOCAL_DIR/tc1-probe /tmp/tc1-link
    echo \"symlink=\$(/tmp/tc1-link)\"
    cd $ACC_LOCAL_DIR && echo \"relative=\$(./tc1-probe)\"
    echo \"path=\$(PATH=$ACC_LOCAL_DIR:\$PATH tc1-probe)\"
  "
  out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  local form
  for form in abs symlink relative path; do
    printf '%s\n' "$out" | grep -qx "$form=PROBE-INIT=$ACC_CLIENT_INIT" \
      || { echo "    spelling $form did not run here"; return 1; }
  done
}

# --- b. the unlisted child of a local program runs remotely ----------------
# The parent is named in the allowlist; nothing names /bin/sh, so the child
# it starts is served by the daemon.
check_unlisted_child(){
  local cfg out
  acc_put "$ACC_LOCAL_DIR/tc1-parent" "#!/bin/sh
p=\"\"; IFS= read -r p < /proc/1/comm 2>/dev/null
echo \"SELF-INIT=\$p\"
/usr/bin/env sh -c 'IFS= read -r q < /proc/1/comm 2>/dev/null; echo CHILD-INIT=\$q'
" 755
  cfg=$(acc_config child '["'"$ACC_LOCAL_DIR"'/tc1-parent","'"$ENTRY"'"]' '[]' "$ENTRY")
  acc_session "$cfg" "$ACC_LOCAL_DIR/tc1-parent"
  out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  printf '%s\n' "$out" | grep -qx "SELF-INIT=$ACC_CLIENT_INIT" \
    || { echo "    the parent did not run here"; return 1; }
  printf '%s\n' "$out" | grep -qx "CHILD-INIT=$ACC_DAEMON_INIT" \
    || { echo "    an unlisted child did not run on the daemon"; return 1; }
}

# --- a'. alternating calls, several rounds, one placement each -------------
# The design's scene is one command line that alternates an allowlisted
# program and a command outside the set, many times. Each round must keep its
# own answer, including the entry program itself, which runs here.
check_alternating_rounds(){
  local cfg out
  cfg=$(acc_config rounds '["'"$ACC_LOCAL_DIR"'/tc1-probe","'"$ENTRY"'"]' '[]' "$ENTRY")
  acc_session "$cfg" "$ENTRY" -c '
    IFS= read -r entry < /proc/1/comm
    i=0
    while [ $i -lt 4 ]; do
      l=$('"$ACC_LOCAL_DIR"'/tc1-probe)
      r=$(/bin/cat /proc/1/comm)
      echo "ROUND$i local=$l remote=$r"
      i=$((i+1))
    done
    echo "ENTRY=$entry"
  '
  out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  local i
  for i in 0 1 2 3; do
    printf '%s\n' "$out" | grep -qx "ROUND$i local=PROBE-INIT=$ACC_CLIENT_INIT remote=$ACC_DAEMON_INIT" \
      || { echo "    round $i placed a process on the wrong machine"; return 1; }
  done
  printf '%s\n' "$out" | grep -qx "ENTRY=$ACC_CLIENT_INIT" \
    || { echo "    the session entry did not run here: [$out]"; return 1; }
}

# --- c. a custom process name does not change placement --------------------
# The name is set with exec -a and the target is a program the allowlist does
# not name, so the daemon must run it regardless of what the caller called it.
check_custom_argv0(){
  local cfg out
  cfg=$(acc_config argv0 '["'"$ENTRY"'"]' '[]' "$ENTRY")
  acc_session "$cfg" "$ENTRY" -c "
    exec -a custom-remote-name /bin/dash -c '
      IFS= read -r p < /proc/1/comm 2>/dev/null
      echo \"ARGV0=\$0 INIT=\$p\"'
  "
  out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  printf '%s\n' "$out" | grep -q 'ARGV0=custom-remote-name' \
    || { echo "    the custom name never reached the program"; return 1; }
  printf '%s\n' "$out" | grep -q "INIT=$ACC_DAEMON_INIT" \
    || { echo "    a custom argv[0] moved the target onto this machine"; return 1; }
}

# --- d. a directory allowlist is a startup snapshot ------------------------
# The session starts with tc1-pre present locally and tc1-newafter absent from
# this machine. The name is created on the daemon while the session is live;
# the check then runs both names in that same session. Only the snapshot
# boundary can explain one running here and the other not.
check_directory_snapshot(){
  local cfg out i agent=$ACC_WORK/agent
  acc_put "$ACC_EXEC_DIR/tc1-pre" "#!/bin/sh
echo PRE-LOCAL
" 755
  acc_rm "$ACC_EXEC_DIR/tc1-newafter"
  acc_exec "mkdir -p $agent"
  # The payload lives in a tree declared local, so the entry shell can read it
  # without a round trip. It waits for a flag file the host writes, so the
  # directory mutation lands strictly after the allowlist snapshot is taken.
  acc_put "$agent/payload.sh" "#!/bin/bash
echo \"PRE=\$(PATH=$ACC_EXEC_DIR:\$PATH tc1-pre 2>&1)\"
echo SESSION-START
i=0
while [ ! -f $agent/go ]; do
  sleep 0.2; i=\$((i+1)); [ \$i -gt 200 ] && { echo WAIT-TIMEOUT; exit 1; }
done
echo \"CTRL=\$(cat $ACC_EXEC_DIR/tc1-newafter 2>&1 | tail -1)\"
echo \"NEW=\$(PATH=$ACC_EXEC_DIR:\$PATH tc1-newafter 2>&1 | tail -1)\"
echo SESSION-END
" 755
  cfg=$(acc_config snapshot '["'"$ACC_EXEC_DIR"'","'"$ENTRY"'"]' '["'"$agent"'"]' "$ENTRY")
  acc_boot_cfg=$(acc_config snapshot-boot '[]' '[]' "$ENTRY")
  acc_rm "$agent/go"
  acc_exec "rm -f $agent/snapshot.log $ACC_STATE/seed.log"
  acc_bg_session "$cfg" "$agent/snapshot.log" "$ENTRY" "$agent/payload.sh"
  acc_wait_file "$agent/snapshot.log" 300 || { echo "    the session never started"; return 1; }
  # The new name is written through a session with an empty allowlist: on the
  # daemon, /usr/local/bin is a different tree that this container never
  # mounts, so the bytes are genuinely remote content.
  acc_session_log "$acc_boot_cfg" "$ACC_STATE/seed.log" /bin/sh -c \
    "mkdir -p $ACC_EXEC_DIR; printf '#!/bin/sh\necho NEW-REMOTE\n' > $ACC_EXEC_DIR/tc1-newafter; chmod 755 $ACC_EXEC_DIR/tc1-newafter; echo SEEDED-REMOTE"
  local seeded
  seeded=$(acc_get "$ACC_STATE/seed.log")
  printf '%s\n' "$seeded" | sed 's/^/    seed: /'
  printf '%s\n' "$seeded" | grep -q SEEDED-REMOTE \
    || { echo "    could not seed the daemon-side name"; return 1; }
  acc_exists "$ACC_EXEC_DIR/tc1-newafter" \
    && { echo "    the seeded name also exists on this machine; the snapshot boundary is untestable here"; return 1; }
  # Confirm from a separate session that the daemon really serves these bytes.
  acc_session "$acc_boot_cfg" /bin/sh -c "cat $ACC_EXEC_DIR/tc1-newafter"
  printf '%s\n' "$ACC_OUT" | sed 's/^/    seedcheck: /'
  printf '%s\n' "$ACC_OUT" | grep -qx 'echo NEW-REMOTE' \
    || { echo "    the daemon-side name is not readable as remote content"; return 1; }
  acc_exec ": > $agent/go"
  for i in $(seq 1 200); do
    acc_exec "grep -q SESSION-END $agent/snapshot.log" >/dev/null 2>&1 && break
    sleep 0.2
  done
  out=$(acc_get "$agent/snapshot.log")
  printf '%s\n' "$out" | sed 's/^/    /'
  printf '%s\n' "$out" | grep -qx 'PRE=PRE-LOCAL' \
    || { echo "    a program present at startup did not run here"; return 1; }
  printf '%s\n' "$out" | grep -qx 'CTRL=echo NEW-REMOTE' \
    || { echo "    the daemon-side bytes were not what the control read"; return 1; }
  printf '%s\n' "$out" | grep -qx 'NEW=NEW-REMOTE' \
    || { echo "    a name added after startup ran from this machine"; return 1; }
}

check(){ local n=$1; shift; if "$@"; then acc_ok "$n"; else acc_fail "$n" "output above"; fi; }

check four-spellings-local check_spellings
check alternating-rounds-one-placement-each check_alternating_rounds
check unlisted-child-remote check_unlisted_child
check custom-argv0-remote check_custom_argv0
check directory-startup-snapshot check_directory_snapshot

acc_finish
