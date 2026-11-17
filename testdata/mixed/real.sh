#!/bin/bash
# The real-CLI gate for the mixed-execution model.
#
# What this proves, and what it deliberately does not:
#
#   * The installed Multica, OMP, Codex and Claude binaries start inside the
#     sandbox from controller-compiled native snapshots, with their runtime
#     dependencies resolved and pinned. Their startup output is echoed so a
#     human can see which build answered.
#   * The real Multica binary performs genuine local file IO through
#     `multica config`: it writes its own JSON config under a local HOME and
#     reads the value back. That path needs no authentication, no server and
#     no model call.
#   * An explicitly named NATIVE SUBSTRATE FIXTURE (native-proof.c, built at
#     invocation by native-build.sh, never by this repository's build) makes
#     the boundary itself observable: a local program's config write versus a
#     daemon-side artifact write, byte preservation of the project executable
#     and its .so, a custom argv[0] on a remote exec, a real remote git clone
#     visible through the session, a named execveat descriptor routed
#     remotely, a deleted descriptor refused, and cleanup of a detached local
#     child and of a canceled session.
#   * Placement is measured from /proc/1 of the machine a process really runs
#     on. Expected init names come from the deployment (CLIENT_INIT and
#     DAEMON_INIT), so the harness reports what the kernel says instead of
#     assuming a marker.
#   * It does NOT prove authenticated model workflows or agent plugins. No
#     model call is made, and no existing host credential is touched.
#
# Every invocation shares one configuration file: the sandbox, not the caller,
# allocates the unique per-session mount/cache/broker under the configured
# bases. Failures exit nonzero; no check is filtered or relaxed.
#
# Environment:
#   MNT          client scratch home (config, mount/cache bases live here)
#   F            the rsbx client binary
#   SOCK         daemon socket path
#   AGENT_HOME   local agent configuration tree (must be in local.paths)
#   REAL_TOOLS   directory holding the installed multica/omp/codex/claude
#                binaries (default /opt/real)
#   FIXTURE_DIR  destination for the compiled substrate fixture
#                (default $REAL_TOOLS); must be writable here and readable in
#                the sandbox view, and is allowlisted as $FIXTURE_DIR/native-proof
#   CLIENT_INIT  expected /proc/1/comm for local programs   (default rsbx)
#   DAEMON_INIT  expected /proc/1/comm for remote programs  (default rsbxd)
#   PROJ         remote project tree path                   (default /proj)
#
# Exit status is nonzero if any check fails.
set -u
MNT=${MNT:?}; F=${F:?}; SOCK=${SOCK:?}; AGENT_HOME=${AGENT_HOME:?}
REAL_TOOLS=${REAL_TOOLS:-/opt/real}
FIXTURE_DIR=${FIXTURE_DIR:-$REAL_TOOLS}
CLIENT_INIT=${CLIENT_INIT:-rsbx}
DAEMON_INIT=${DAEMON_INIT:-rsbxd}
PROJ=${PROJ:-/proj}
FIXTURE="$FIXTURE_DIR/native-proof"
here=$(cd "$(dirname "$0")" && pwd)
id=real

ok(){ echo "OK $1"; }
bad(){ echo "FAIL $1: $2"; }

# ---- fixture ---------------------------------------------------------------
mkdir -p "$MNT" "$AGENT_HOME" "$FIXTURE_DIR"
if [ ! -x "$FIXTURE" ] || [ "$here/native-proof.c" -nt "$FIXTURE" ]; then
  FIXTURE_DIR="$FIXTURE_DIR" bash "$here/native-build.sh" || {
    echo "FAIL fixture: native-build.sh could not build native-proof" >&2
    exit 1
  }
fi

mkcfg(){
  cat > "$MNT/real.toml" <<CFG
[daemon]
transport = "unix"
socket = "$SOCK"

[local]
# The four installed CLIs and the substrate fixture run here. Their runtime
# dependencies are compiled with them and never become independent commands.
allow = ["$REAL_TOOLS/multica", "$REAL_TOOLS/omp", "$REAL_TOOLS/codex",
         "$REAL_TOOLS/claude", "$FIXTURE"]
entry = "/bin/sh"
paths = ["$AGENT_HOME"]
read_only_paths = []

[sandbox]
mount = "$MNT/sb"
cache = "$MNT/cache"
unshare_user = false
CFG
}
mkcfg

# run executes a shell line in the session. The entry shell is local; every
# plain program it starts (ls, cat, git, mkdir) is routed by the sandbox.
run(){ timeout 240 "$F" -config "$MNT/real.toml" -- /bin/sh -c "$1" 2>&1; }
fixture(){ timeout 240 "$F" -config "$MNT/real.toml" -- "$FIXTURE" "$@" 2>&1; }
# host runs the same fixture outside the sandbox. `find` only reads /proc; it
# never signals a process, so observing cleanup cannot cause it.
host(){ timeout 60 "$FIXTURE" "$@" 2>&1; }

# gone_after waits for a process carrying the exact nonce argument to
# disappear. A successful wait is the only evidence of cleanup: the harness
# does not kill anything itself.
gone_after(){
  local nonce=$1 i
  for i in $(seq 1 100); do
    host find "$nonce" >/dev/null 2>&1 || return 0
    sleep 0.2
  done
  echo "process carrying $nonce is still alive"
  return 1
}

# alive_after waits for a process carrying the exact nonce argument to exist,
# so a hold session that never started is a failure, not a silent pass.
alive_after(){
  local nonce=$1 i
  for i in $(seq 1 100); do
    if host find "$nonce" >/dev/null 2>&1; then return 0; fi
    sleep 0.2
  done
  echo "process carrying $nonce never appeared"
  return 1
}

# prepare seeds the remote tree once through a session. install writes this
# fixture's exact bytes to the daemon's project tree from a local program; put
# writes the .so payload (plus its trailing newline) the byte check expects.
# Both are reseeded every run: a leftover file from an earlier build would
# otherwise be compared against the current contract and fail for the wrong
# reason. The bare repository is made by the daemon's own git, which is not
# allowlisted, so the clone in check_git_flow really happens remotely.
prepare(){
  local out rc
  out=$(run "set -e
    mkdir -p $PROJ
    $FIXTURE install $PROJ/remote-native 755
    $FIXTURE put $PROJ/project-lib.so 644 'remote shared-object data'
    if [ ! -d $PROJ/origin.git ]; then
      rm -rf $PROJ/src
      mkdir -p $PROJ/src
      printf 'lib code\\n' > $PROJ/src/lib.c
      cd $PROJ/src
      git init -q .
      git add lib.c
      git -c user.email=a@b -c user.name=n commit -qm src
      git init -q --bare $PROJ/origin.git
      cd $PROJ/origin.git
      git fetch -q $PROJ/src '+refs/heads/*:refs/heads/*'
    fi
    true")
  rc=$?
  [ $rc -eq 0 ] || { echo "prepare failed (rc=$rc): $out"; return 1; }
  return 0
}

# 1. Every installed real CLI starts through its compiled native snapshot.
check_versions(){
  local name arg out rc
  for name in multica omp codex claude; do
    arg=--version
    [ "$name" = multica ] && arg=version
    out=$(timeout 240 "$F" -config "$MNT/real.toml" -- "$REAL_TOOLS/$name" "$arg" 2>&1)
    rc=$?
    [ $rc -eq 0 ] || { echo "$name startup failed (rc=$rc): $out"; return 1; }
    [ -n "$out" ] || { echo "$name printed nothing"; return 1; }
    printf '%s: %s\n' "$name" "$out"
  done
  return 0
}

# 2. Real CLI file IO without auth: multica config set/get under a HOME that is
#    inside the explicit local tree. The exact installed binary is named, the
#    same identity the versions check runs: PATH is the session's real
#    environment and nothing in the sandbox grants a bare `multica` by name.
#    The client-side JSON must contain the value, and the daemon's own view of
#    that path must not (local content is never copied remote).
check_multica_config_io(){
  local out rc cfg="$AGENT_HOME/multica-home/.multica/config.json"
  rm -rf "$AGENT_HOME/multica-home"
  mkdir -p "$AGENT_HOME/multica-home"
  out=$(run "export HOME=$AGENT_HOME/multica-home
    $REAL_TOOLS/multica config set server_url https://rsbx-proof.invalid")
  rc=$?
  [ $rc -eq 0 ] || { echo "multica config set failed (rc=$rc): $out"; return 1; }
  [ -f "$cfg" ] || { echo "config.json was not written locally"; return 1; }
  grep -q "rsbx-proof.invalid" "$cfg" || {
    echo "client config lacks the proof URL: $(cat "$cfg" 2>/dev/null)"; return 1; }
  out=$(run "export HOME=$AGENT_HOME/multica-home
    $REAL_TOOLS/multica config get server_url")
  rc=$?
  [ $rc -eq 0 ] || { echo "multica config get failed (rc=$rc): $out"; return 1; }
  printf '%s\n' "$out" | grep -q "https://rsbx-proof.invalid" || {
    echo "config get did not read the value back: $out"; return 1; }
  # `ls` is not allowlisted, so it runs on the daemon; its view of the local
  # config path must be absent. This is a daemon-side answer, not this host's.
  if run "ls -d $cfg" >/dev/null 2>&1; then
    echo "local config is visible in the daemon tree"; return 1
  fi
  return 0
}

# 3. Substrate fixture: local config write vs remote artifact write, project
#    executable byte preservation.
check_local_remote_split(){
  local out rc
  mkdir -p "$AGENT_HOME/state"
  out=$(fixture writecfg "$AGENT_HOME/state" "$id"); rc=$?
  [ $rc -eq 0 ] || { echo "writecfg failed (rc=$rc): $out"; return 1; }
  [ -f "$AGENT_HOME/state/cfg-$id" ] || { echo "configuration was not local"; return 1; }
  if run "ls -d $AGENT_HOME/state/cfg-$id" >/dev/null 2>&1; then
    echo "local config is visible in the daemon tree"; return 1
  fi
  out=$(run "cat $PROJ/artifact-$id"); rc=$?
  [ $rc -eq 0 ] || { echo "artifact unreadable (rc=$rc): $out"; return 1; }
  [ "$out" = "remote artifact" ] || { echo "artifact not remote: $out"; return 1; }
  out=$(fixture bytes); rc=$?
  [ $rc -eq 0 ] || { echo "byte preservation failed (rc=$rc): $out"; return 1; }
  return 0
}

# 4. Placement from /proc/1, custom argv[0], named execveat routed remote,
#    deleted descriptor refused.
check_placement(){
  local out rc
  out=$(fixture identity); rc=$?
  [ $rc -eq 0 ] || { echo "local identity failed (rc=$rc): $out"; return 1; }
  [ "$out" = "init=$CLIENT_INIT argv0=$FIXTURE" ] || { echo "local identity: $out"; return 1; }
  out=$(run "$PROJ/remote-native identity"); rc=$?
  [ $rc -eq 0 ] || { echo "remote identity failed (rc=$rc): $out"; return 1; }
  [ "$out" = "init=$DAEMON_INIT argv0=$PROJ/remote-native" ] || { echo "remote identity: $out"; return 1; }
  out=$(fixture argv0); rc=$?
  [ $rc -eq 0 ] || { echo "custom argv[0] failed (rc=$rc): $out"; return 1; }
  out=$(fixture fd); rc=$?
  [ $rc -eq 0 ] || { echo "named execveat failed (rc=$rc): $out"; return 1; }
  out=$(fixture deleted); rc=$?
  [ $rc -eq 0 ] || { echo "deleted descriptor not refused (rc=$rc): $out"; return 1; }
  return 0
}

# 5. A remote program's fetched work is visible through the local view.
check_git_flow(){
  local out rc
  out=$(fixture gitflow "$id"); rc=$?
  [ $rc -eq 0 ] || { echo "git flow failed (rc=$rc): $out"; return 1; }
  out=$(run "cat $PROJ/clone-$id/lib.c"); rc=$?
  [ $rc -eq 0 ] || { echo "clone unreadable (rc=$rc): $out"; return 1; }
  [ "$out" = "lib code" ] || { echo "git did not run remote or work is invisible: $out"; return 1; }
  [ ! -e "$AGENT_HOME/clone-$id" ] || { echo "remote clone leaked into local config"; return 1; }
  return 0
}

# 6. A detached local child that left the entry's process group is still owned
#    by the session: after the session exits, no process carries the nonce
#    anymore. The harness only observes; nothing is pkilled globally.
check_detached_child_cleanup(){
  local ready="$AGENT_HOME/state/detached-ready" nonce="rsbx-detached-$$" out rc
  mkdir -p "$AGENT_HOME/state"
  rm -f "$ready"
  out=$(fixture spawn "$ready" "$nonce"); rc=$?
  [ $rc -eq 0 ] || { echo "spawn failed (rc=$rc): $out"; return 1; }
  [ -s "$ready" ] || { echo "detached child did not record itself"; return 1; }
  gone_after "$nonce" || { echo "detached child survived its session"; return 1; }
  return 0
}

# 7. A canceled session is cleaned up: the process the session started dies
#    with it, and a fresh session with the same configuration works.
check_canceled_session_cleanup(){
  local nonce="rsbx-hold-$$" out rc pid
  timeout -s INT 90 "$F" -config "$MNT/real.toml" -- "$FIXTURE" hold "$nonce" >/dev/null 2>&1 &
  pid=$!
  if ! alive_after "$nonce"; then
    kill -KILL "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    echo "hold session never started"
    return 1
  fi
  kill -INT "$pid"
  wait "$pid"; rc=$?
  [ $rc -ne 0 ] || { echo "canceled session exited 0"; return 1; }
  gone_after "$nonce" || { echo "hold process survived cancellation"; return 1; }
  out=$(run "echo fresh-session"); rc=$?
  [ $rc -eq 0 ] || { echo "fresh session failed (rc=$rc): $out"; return 1; }
  [ "$out" = "fresh-session" ] || { echo "fresh session after cancel: $out"; return 1; }
  return 0
}

prepare || { echo "FAIL prepare: environment could not be prepared"; exit 1; }

failed=0
for t in check_versions check_multica_config_io check_local_remote_split \
         check_placement check_git_flow check_detached_child_cleanup \
         check_canceled_session_cleanup; do
  if e=$($t 2>&1); then
    if [ "$t" = check_versions ]; then printf '%s\n' "$e"; fi
    ok "${t#check_}"
  else
    bad "${t#check_}" "${e:0:240}"
    failed=1
  fi
done
exit "$failed"
