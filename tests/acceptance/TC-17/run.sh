#!/bin/bash
# TC-17 (AC-11) — where the reverse channel puts a command, and what it refuses.
#
# Design `docs/03-acceptance.md` §TC-17 judges one session and a series of
# stub requests: a program in the local allowlist, the same file under its
# symlink spelling, a program outside the allowlist, a request with no
# session capability, one with a capability that names no live session, a
# relative working directory, a terminal request and a loader-injection
# environment. The allowlisted target must run in the sandbox with complete
# output and its own exit status; every other request must end in a
# distinguishable failure that names the reason, with no process on this
# machine; and a command run in the session afterwards must still work.
#
# The channel itself (C-23) is only opened when the session is declared with
# `reverse = true`, and that requires the authenticated network transport, so
# this carrier runs the session against the rig's mutual-TLS daemon. The
# daemon publishes a per-session unix socket there; the stub is a program on
# the daemon side, and its request travels back into this sandbox.
#
# `probe.py` is the caller that expresses what rsbx-stub cannot: its request
# comes from argv, cwd and environment, so a terminal flag, a relative
# directory and an LD_* variable have to be written on the wire directly.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
ACC_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$ACC_DIR" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc17-$$
acc_init TC-17
trap acc_rig_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

acc_tls_prepare || { acc_skip_all tls_material "$ACC_TLS_WHY"; exit 77; }
acc_tls_client_install || { acc_skip_all tls_material "could not install client certificate material"; exit 77; }
if ! acc_tls_daemon_start; then
  acc_tls_daemon_diag
  acc_fail tls_daemon "the mutual-TLS daemon container could not be created"
  acc_finish
fi
if ! acc_tls_wait; then
  # A daemon that cannot serve here is a defect, not a missing prerequisite:
  # the images, /dev/fuse, git and python3 were all provisioned above.
  acc_tls_daemon_diag
  acc_fail tls_daemon "the mutual-TLS daemon never accepted a connection on :$ACC_TLS_PORT"
  acc_finish
fi

# The daemon judges the crafted requests, so it needs the probe's language.
if ! docker exec "$ACC_TLS_DAEMON" /bin/sh -c 'command -v python3 >/dev/null 2>&1'; then
  acc_skip_all daemon_python3 "no python3 in $ACC_DAEMON_IMG, so the crafted requests cannot be sent"
  exit 77
fi

STUB=/usr/local/bin/rsbx-stub
if ! docker exec "$ACC_TLS_DAEMON" test -x "$STUB"; then
  acc_skip_all daemon_stub "rsbx-stub is not installed in $ACC_DAEMON_IMG"
  exit 77
fi

TC17=/proj/tc17
REAL=$ACC_EXEC_DIR/tc17-real.sh
EXIT7=$ACC_EXEC_DIR/tc17-exit.sh
UNLISTED=$ACC_EXEC_DIR/tc17-unlisted.sh
ECHO=$ACC_EXEC_DIR/tc17-echo

# --- fixtures -------------------------------------------------------------
# The client keeps the real programs under a declared local tree; the daemon
# keeps stubs under the same names, so a daemon-side exec of any of them
# comes back into this sandbox. The two trees are different, which is exactly
# what makes the placement observable.

acc_put "$REAL" '#!/bin/sh
IFS= read -r init < /proc/1/comm
echo "INIT=$init"
echo "ARGS=$*"
if [ -n "$2" ]; then : > "$2"; fi
' 755
acc_put "$EXIT7" '#!/bin/sh
exit 7
' 755
acc_put "$UNLISTED" '#!/bin/sh
: > "$1"
echo UNLISTED-RAN
' 755
acc_exec "ln -sfn tc17-real.sh $ECHO"

docker exec --user 0 "$ACC_TLS_DAEMON" /bin/sh -c \
  "mkdir -p $ACC_EXEC_DIR && chmod 777 $ACC_EXEC_DIR" >/dev/null 2>&1
for name in tc17-echo tc17-real.sh tc17-exit.sh tc17-unlisted.sh; do
  docker exec "$ACC_TLS_DAEMON" /bin/sh -c "ln -sfn $STUB $ACC_EXEC_DIR/$name" >/dev/null 2>&1
done
docker exec "$ACC_TLS_DAEMON" /bin/sh -c "mkdir -p $TC17 && chmod 777 $TC17" >/dev/null 2>&1
docker exec -i "$ACC_TLS_DAEMON" /bin/sh -c "cat > $TC17/probe.py" < "$ACC_DIR/probe.py"
docker exec -i "$ACC_TLS_DAEMON" /bin/sh -c "cat > $TC17/session.sh" <<'SESSION'
#!/bin/sh
# Every remote invocation goes through a daemon program: /usr/bin/env and
# /usr/bin/python3 are not allowlisted, so they run on the daemon, and what
# they start there is the stub under the same name.
/usr/bin/env /usr/local/tcbin/tc17-echo ONE TWO
echo "CASE-allowed-rc=$?"
/usr/bin/env /usr/local/tcbin/tc17-real.sh THREE
echo "CASE-symlink-rc=$?"
/usr/bin/env /usr/local/tcbin/tc17-exit.sh
echo "CASE-exit-rc=$?"
/usr/bin/env /usr/local/tcbin/tc17-unlisted.sh /proj/tc17/unlisted-ran
echo "CASE-unlisted-rc=$?"
/usr/bin/env -u RSBX_STUB_SOCKET /usr/local/bin/rsbx-stub /usr/local/tcbin/tc17-echo NOENV
echo "CASE-noenv-rc=$?"
/usr/bin/env RSBX_STUB_SOCKET=/tmp/tc17-no-session.sock /usr/local/bin/rsbx-stub /usr/local/tcbin/tc17-echo STALE
echo "CASE-stale-rc=$?"
/usr/bin/python3 /proj/tc17/probe.py --socket "$RSBX_STUB_SOCKET" \
  --target /usr/local/tcbin/tc17-echo --cwd relative/dir \
  --arg tc17-echo --arg /proj/tc17/cwd-ran
echo "CASE-cwd-rc=$?"
/usr/bin/python3 /proj/tc17/probe.py --socket "$RSBX_STUB_SOCKET" \
  --target /usr/local/tcbin/tc17-echo --tty \
  --arg tc17-echo --arg /proj/tc17/tty-ran
echo "CASE-tty-rc=$?"
/usr/bin/python3 /proj/tc17/probe.py --socket "$RSBX_STUB_SOCKET" \
  --target /usr/local/tcbin/tc17-echo --env LD_PRELOAD=/tmp/evil.so \
  --arg tc17-echo --arg /proj/tc17/loader-ran
echo "CASE-loader-rc=$?"
/usr/bin/env /usr/local/tcbin/tc17-echo STILL-ALIVE
echo "CASE-alive-rc=$?"
SESSION

# The fixtures are allowlisted locally, so they must stay outside any
# writable local tree: reverse execution runs the exact same path on this
# machine, and an allowlisted program is required to be immutable.
cfg=$(acc_tls_config reverse \
  "[\"$ECHO\", \"$EXIT7\"]" /bin/sh ca.pem client.pem client.key "reverse = true")

# --- the one session that drives every request ----------------------------
run_session(){
  acc_session_split "$cfg" /bin/sh "$TC17/session.sh"
}

check(){
  local name=$1
  shift
  if "$@"; then acc_ok "$name"; else acc_fail "$name" "output above"; fi
}

check_allowed_runs_in_sandbox(){
  printf '%s\n' "$ACC_OUT" | sed 's/^/    /'
  printf '%s\n' "$ACC_OUT" | grep -qx "INIT=$ACC_CLIENT_INIT" \
    || { echo "    the allowlisted target did not run in this sandbox (want init $ACC_CLIENT_INIT)"; return 1; }
  printf '%s\n' "$ACC_OUT" | grep -qx 'ARGS=ONE TWO' \
    || { echo "    the target's arguments or output did not arrive complete"; return 1; }
  printf '%s\n' "$ACC_OUT" | grep -qx 'CASE-allowed-rc=0' \
    || { echo "    the target's exit status did not come back"; return 1; }
  return 0
}

check_symlink_spelling(){
  local count
  count=$(printf '%s\n' "$ACC_OUT" | grep -cx "INIT=$ACC_CLIENT_INIT")
  [ "$count" -ge 2 ] \
    || { echo "    the target's symlink spelling did not run in the sandbox (local init seen $count time(s))"; return 1; }
  printf '%s\n' "$ACC_OUT" | grep -qx 'ARGS=THREE' \
    || { echo "    the symlink spelling answered nothing"; return 1; }
  printf '%s\n' "$ACC_OUT" | grep -qx 'CASE-symlink-rc=0' || {
    echo "    the symlink spelling's exit status did not come back"; return 1; }
  return 0
}

check_exit_status(){
  printf '%s\n' "$ACC_OUT" | grep -qx 'CASE-exit-rc=7' \
    || { echo "    the target's status 7 was not preserved"; return 1; }
  return 0
}

check_unlisted_refused(){
  printf '%s\n' "$ACC_OUT" | grep -qx 'CASE-unlisted-rc=126' \
    || { echo "    an unlisted target did not fail with 126"; return 1; }
  printf '%s\n' "$ACC_ERR" | grep -Eq 'not in local.allow|not an allowlisted local executable' \
    || { echo "    the refusal does not name the allowlist"; return 1; }
  docker exec "$ACC_TLS_DAEMON" test -e "$TC17/unlisted-ran" \
    && { echo "    the refused program ran anyway"; return 1; }
  return 0
}

check_missing_capability(){
  printf '%s\n' "$ACC_OUT" | grep -qx 'CASE-noenv-rc=126' \
    || { echo "    a stub with no session capability did not fail with 126"; return 1; }
  printf '%s\n' "$ACC_ERR" | grep -q 'missing absolute RSBX_STUB_SOCKET' \
    || { echo "    the failure does not name the missing capability"; return 1; }
  return 0
}

check_wrong_capability(){
  printf '%s\n' "$ACC_OUT" | grep -qx 'CASE-stale-rc=126' \
    || { echo "    a stub pointed at no live session did not fail with 126"; return 1; }
  printf '%s\n' "$ACC_ERR" | grep -q 'tc17-no-session.sock' \
    || { echo "    the failure does not name the socket it tried"; return 1; }
  return 0
}

check_relative_cwd_refused(){
  printf '%s\n' "$ACC_OUT" | grep -q 'PROBE-TERR:invalid callback working directory' \
    || { echo "    a relative working directory was not refused with its reason"; return 1; }
  printf '%s\n' "$ACC_OUT" | grep -qx 'PROBE-EXIT:126' \
    || { echo "    the relative-directory refusal did not end with 126"; return 1; }
  docker exec "$ACC_TLS_DAEMON" test -e "$TC17/cwd-ran" \
    && { echo "    the refused request ran anyway"; return 1; }
  return 0
}

check_tty_refused(){
  printf '%s\n' "$ACC_OUT" | grep -q 'PROBE-TERR:reverse PTY requests are not supported' \
    || { echo "    a terminal request was not refused with its reason"; return 1; }
  printf '%s\n' "$ACC_OUT" | grep -qx 'PROBE-EXIT:126' \
    || { echo "    the terminal refusal did not end with 126"; return 1; }
  docker exec "$ACC_TLS_DAEMON" test -e "$TC17/tty-ran" \
    && { echo "    the refused terminal request ran anyway"; return 1; }
  return 0
}

check_loader_refused(){
  printf '%s\n' "$ACC_OUT" | grep -q 'PROBE-TERR:unsafe loader environment: LD_PRELOAD' \
    || { echo "    a loader-injection request was not refused with its reason"; return 1; }
  printf '%s\n' "$ACC_OUT" | grep -qx 'PROBE-EXIT:126' \
    || { echo "    the loader refusal did not end with 126"; return 1; }
  docker exec "$ACC_TLS_DAEMON" test -e "$TC17/loader-ran" \
    && { echo "    the refused loader request ran anyway"; return 1; }
  return 0
}

check_session_survives(){
  printf '%s\n' "$ACC_OUT" | grep -qx 'CASE-alive-rc=0' \
    || { echo "    the session did not accept another command after the refusals"; return 1; }
  local count
  count=$(printf '%s\n' "$ACC_OUT" | grep -cx "INIT=$ACC_CLIENT_INIT")
  [ "$count" -ge 3 ] \
    || { echo "    the last command did not run in the sandbox (local init seen $count time(s))"; return 1; }
  return 0
}

if ! run_session; then
  printf '%s\n' "$ACC_OUT" | sed 's/^/    /'
  printf '%s\n' "$ACC_ERR" | sed 's/^/    /'
fi

check allowed-target-runs-in-sandbox check_allowed_runs_in_sandbox
check symlink-spelling-runs-in-sandbox check_symlink_spelling
check exit-status-preserved check_exit_status
check unlisted-target-refused check_unlisted_refused
check missing-capability-refused check_missing_capability
check wrong-capability-refused check_wrong_capability
check relative-cwd-refused check_relative_cwd_refused
check tty-refused check_tty_refused
check loader-injection-refused check_loader_refused
check session-still-works check_session_survives

acc_finish
