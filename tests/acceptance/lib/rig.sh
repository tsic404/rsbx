#!/bin/bash
# Shared docker rig for the acceptance carriers.
#
# One rig is one daemon container serving a throwaway project volume and one
# long-lived client container that shares only the socket volume and its own
# scratch state. The client never mounts the project: its only view of the
# daemon's tree is the one rsbx serves. All assertions stay in the per-TC
# entries; this file only builds, addresses and tears down that layout.
#
# Everything is driven from the host with `docker exec`, so the entries are
# plain bash and can be read, run one at a time, and inspected afterwards.
# Every function prints nothing on success unless its name says otherwise.
set -u

ACC_PREFIX=${ACC_PREFIX:-acc-$$}
ACC_DAEMON_IMG=${ACC_DAEMON_IMG:-rsbx-daemon:full}
ACC_CLIENT_IMG=${ACC_CLIENT_IMG:-rsbx:ci}
ACC_BIN=${ACC_BIN:-/tmp/tcbuild}
ACC_SESSION_TIMEOUT=${ACC_SESSION_TIMEOUT:-180}

# Paths as each side sees them.
ACC_PROJ=/proj            # daemon-side project tree
ACC_SOCK=/run/rsbx/daemon.sock
ACC_STATE=/state          # client scratch: configs, mounts, caches
ACC_WORK=/work            # client-side local trees
ACC_EXEC_DIR=${ACC_EXEC_DIR:-/usr/local/tcbin} # writable exec directory
ACC_LOCAL_DIR=${ACC_LOCAL_DIR:-/opt/acc}       # carrier-staged local programs

ACC_DAEMON=$ACC_PREFIX-daemon
ACC_CLIENT=$ACC_PREFIX-client

# ---------------------------------------------------------------------------
# lifecycle

acc_rig_prereqs(){
  command -v docker >/dev/null 2>&1 || {
    acc_skip_all docker_cli "docker CLI not found"; return 1; }
  docker info >/dev/null 2>&1 || {
    acc_skip_all docker_daemon "docker daemon unreachable"; return 1; }
  local img
  for img in "$ACC_DAEMON_IMG" "$ACC_CLIENT_IMG"; do
    docker image inspect "$img" >/dev/null 2>&1 || {
      acc_skip_all "image:$img" "image not present; build it first"; return 1; }
  done
  docker run --rm --entrypoint rsbxd "$ACC_DAEMON_IMG" -version >/dev/null 2>&1 || {
    acc_skip_all daemon_binary "rsbxd not runnable in $ACC_DAEMON_IMG"; return 1; }
  return 0
}

acc_rig_create(){
  local v
  for v in proj run state work; do
    docker volume create "$ACC_PREFIX-$v" >/dev/null
  done
  docker network create "$ACC_PREFIX-net" >/dev/null
  docker run --rm --user 0 -v "$ACC_PREFIX-run:/run/rsbx" \
    --entrypoint /bin/sh "$ACC_DAEMON_IMG" \
    -c 'mkdir -p /run/rsbx && chown 1000:1000 /run/rsbx' >/dev/null 2>&1
  # A fresh named volume is root-owned. The daemon runs as the image's own
  # unprivileged user, so the project tree has to belong to that user before
  # any session can write into it. This is the same preparation the socket
  # directory gets, for the same reason.
  docker run --rm --user 0 -v "$ACC_PREFIX-proj:$ACC_PROJ" \
    --entrypoint /bin/sh "$ACC_DAEMON_IMG" \
    -c "chown 1000:1000 $ACC_PROJ" >/dev/null 2>&1
  docker run -d --rm --name "$ACC_DAEMON" --network "$ACC_PREFIX-net" \
    -v "$ACC_PREFIX-proj:$ACC_PROJ" -v "$ACC_PREFIX-run:/run/rsbx" \
    --entrypoint rsbxd "$ACC_DAEMON_IMG" -socket "$ACC_SOCK" >/dev/null
  docker run --rm --network "$ACC_PREFIX-net" -v "$ACC_PREFIX-run:/run/rsbx" \
    --entrypoint /bin/bash "$ACC_DAEMON_IMG" \
    -c 'for i in $(seq 1 100); do [ -S /run/rsbx/daemon.sock ] && exit 0; sleep 0.2; done; exit 1' \
    >/dev/null 2>&1
  # The client is the container that never sees the project volume.
  docker run -d --name "$ACC_CLIENT" --privileged --user 0 \
    --network "$ACC_PREFIX-net" \
    -v "$ACC_PREFIX-run:/run/rsbx" -v "$ACC_PREFIX-state:$ACC_STATE" \
    -v "$ACC_PREFIX-work:$ACC_WORK" \
    --entrypoint /bin/bash "$ACC_CLIENT_IMG" \
    -c 'while :; do sleep 5; done' >/dev/null
  local i
  for i in $(seq 1 100); do
    acc_exec "mkdir -p $ACC_STATE/sb $ACC_STATE/cache $ACC_WORK $ACC_LOCAL_DIR && chmod 777 $ACC_STATE $ACC_WORK $ACC_LOCAL_DIR" \
      >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  return 1
}

# acc_exec_dir_prepare: make the exec directory writable on both sides. A
# carrier that studies directory snapshots needs a directory that exists on
# this machine (for the local copy) and on the daemon (for the remote copy);
# they are two different trees that happen to share a name.
#
# Only the directory's own creation is privileged, and only on the daemon
# side: the image ends as an unprivileged user, and a path under /usr/local is
# root-owned, so the unprivileged daemon cannot create it. Everything the
# carriers assert still runs as the image's own user — this prepares a place
# to put a program, it does not change who runs the daemon.
#
# Which side failed goes to ACC_EXEC_DIR_SIDE so the caller's SKIP reason can
# name it: the two sides are independent, and "not writable on both sides"
# hid a daemon-only failure once.
ACC_EXEC_DIR_SIDE=
acc_exec_dir_prepare(){
  if ! acc_exec "mkdir -p $ACC_EXEC_DIR && chmod 777 $ACC_EXEC_DIR"; then
    ACC_EXEC_DIR_SIDE=client; return 1
  fi
  if ! docker exec --user 0 "$ACC_DAEMON" /bin/bash -c \
      "mkdir -p $ACC_EXEC_DIR && chmod 777 $ACC_EXEC_DIR"; then
    ACC_EXEC_DIR_SIDE=daemon; return 1
  fi
  ACC_EXEC_DIR_SIDE=
  return 0
}

acc_rig_cleanup(){
  docker rm -f "$ACC_CLIENT" "$ACC_DAEMON" >/dev/null 2>&1 || true
  docker network rm "$ACC_PREFIX-net" >/dev/null 2>&1 || true
  local v
  for v in proj run state work; do
    docker volume rm "$ACC_PREFIX-$v" >/dev/null 2>&1 || true
  done
}

# ---------------------------------------------------------------------------
# addressing

# acc_exec CMD...  — run a shell command in the client container.
acc_exec(){ docker exec "$ACC_CLIENT" /bin/bash -c "$1"; return $?; }

# acc_exec_out CMD... — same, capturing combined output in ACC_OUT.
acc_exec_out(){ ACC_OUT=$(docker exec "$ACC_CLIENT" /bin/bash -c "$1" 2>&1); return $?; }

acc_daemon(){ docker exec "$ACC_DAEMON" /bin/bash -c "$1"; }

acc_daemon_kill(){ docker kill "$ACC_DAEMON" >/dev/null 2>&1 || true; }

# acc_proc_match client|daemon PATTERN — print the command line of every
# process on that side whose argv contains PATTERN, and succeed only when at
# least one was found.
#
# This reads /proc/*/cmdline instead of running ps: the slim images carry no
# procps, and a missing ps would make "no process was left behind" pass
# without anyone looking. The pattern travels in the environment, never in the
# scanner's own command line, so the scanner cannot match itself.
acc_proc_match(){
  local where=$1 pattern=$2 container
  case $where in
    client) container=$ACC_CLIENT ;;
    daemon) container=$ACC_DAEMON ;;
    *) return 2 ;;
  esac
  docker exec -e ACC_PAT="$pattern" "$container" /bin/bash -c '
    rc=1
    for d in /proc/[0-9]*; do
      [ -r "$d/cmdline" ] || continue
      args=$(tr "\0" " " < "$d/cmdline" 2>/dev/null) || continue
      case $args in
        *"$ACC_PAT"*) printf "%s\n" "$args"; rc=0 ;;
      esac
    done
    exit $rc
  '
}

# acc_put_name PATH BODY [MODE] — write a client-side file with an exact body.
# The body goes through stdin, so quoting and newlines survive.
acc_put(){
  local path=$1 mode=${3:-644}
  local dir=${path%/*}
  printf '%s' "$2" | docker exec -i "$ACC_CLIENT" /bin/bash -c \
    "mkdir -p $(printf '%q' "$dir") && cat > $(printf '%q' "$path") && chmod $mode $(printf '%q' "$path")"
}

acc_get(){ acc_exec "cat $(printf '%q' "$1") 2>/dev/null"; }
acc_exists(){ acc_exec "test -e $(printf '%q' "$1")"; }
acc_rm(){ acc_exec "rm -rf $(printf '%q' "$1")"; }

# acc_config NAME ALLOW_ARRAY PATHS_ARRAY [ENTRY] [EXTRA_TOML]
# Writes $ACC_STATE/NAME.toml with the rig's socket and its own mount/cache
# pair, so several configs can be live at once in one carrier.
acc_config(){
  local name=$1 allow=$2 paths=$3 entry=${4:-/bin/sh} extra=${5:-}
  local mount=$ACC_STATE/sb-$name cache=$ACC_STATE/cache-$name
  acc_exec "mkdir -p $mount $cache"
  printf '%s' "[daemon]
transport = \"unix\"
socket = \"$ACC_SOCK\"

[local]
allow = $allow
entry = \"$entry\"
paths = $paths
read_only_paths = ${READ_ONLY:-[]}
$extra
[sandbox]
mount = \"$mount\"
cache = \"$cache\"
unshare_user = false
" | docker exec -i "$ACC_CLIENT" /bin/bash -c "cat > $ACC_STATE/$name.toml"
  printf '%s' "$ACC_STATE/$name.toml"
}

# acc_run CMD — run a shell command in the client. The combined output lands
# in the global ACC_OUT and the command's own status is the return value.
#
# Both facts are carried through files inside the client: command
# substitution would run this function in a subshell, and an assignment there
# never reaches the caller's ACC_OUT.
acc_run(){
  local stamp=$RANDOM$RANDOM
  local outfile=/tmp/.acc-out-$stamp rcfile=/tmp/.acc-rc-$stamp
  docker exec "$ACC_CLIENT" /bin/bash -c "$1 > $outfile 2>&1; echo \$? > $rcfile" >/dev/null 2>&1
  ACC_OUT=$(docker exec "$ACC_CLIENT" /bin/bash -c "cat $outfile 2>/dev/null")
  local rc
  rc=$(docker exec "$ACC_CLIENT" /bin/bash -c "cat $rcfile 2>/dev/null")
  docker exec "$ACC_CLIENT" /bin/bash -c "rm -f $outfile $rcfile" >/dev/null 2>&1
  [ -n "$rc" ] || { ACC_RC=255; return 255; }
  ACC_RC=$rc
  return "$rc"
}

# acc_session CFG ARGS... — one session. Output in ACC_OUT, status returned.
# ACC_SESSION_FLAGS, when set, is inserted before the `--` separator; that is
# where -workspace and -workspace-seed belong.
acc_session(){
  local cfg=$1; shift
  acc_run "timeout $ACC_SESSION_TIMEOUT /usr/local/bin/rsbx -config $cfg ${ACC_SESSION_FLAGS:-} -- $(printf '%q ' "$@")"
}

# acc_session_log CFG LOG ARGS... — same, but the combined output is written
# inside the client at LOG (needed when a session must outlive the call).
acc_session_log(){
  local cfg=$1 log=$2; shift 2
  acc_exec "timeout $ACC_SESSION_TIMEOUT /usr/local/bin/rsbx -config $cfg -- $(printf '%q ' "$@") > $log 2>&1"
}

# acc_boot REMOTE_SH — a session with an empty allowlist, used to seed the
# daemon's own tree. Nothing it runs is local content. The output goes to
# stdout as well as to ACC_OUT, so both `acc_boot ...` and
# `x=$(acc_boot ...)` see it.
acc_boot(){
  local cfg; cfg=$(acc_config boot '[]' '[]')
  acc_session "$cfg" /bin/sh -c "$1"
  local rc=$?
  printf '%s\n' "$ACC_OUT"
  return $rc
}

# acc_bg_session CFG LOGFILE ARGS... — start a session in the background,
# leaving its output in LOGFILE inside the client.
acc_bg_session(){
  local cfg=$1 log=$2; shift 2
  docker exec -d "$ACC_CLIENT" /bin/bash -c \
    "exec timeout $ACC_SESSION_TIMEOUT /usr/local/bin/rsbx -config $cfg -- $(printf '%q ' "$@") > $log 2>&1"
}

# acc_wait_file PATH [TICKS] — wait for a file to appear and be non-empty.
acc_wait_file(){
  local path=$1 ticks=${2:-150} i
  for i in $(seq 1 "$ticks"); do
    acc_exec "test -s $(printf '%q' "$path")" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

# ---------------------------------------------------------------------------
# environment facts

# acc_env_report prints what this deployment has. Each line is evidence for
# the carrier's own SKIP decisions; none of it is a verdict.
acc_env_report(){
  printf 'INFO client_init=%s daemon_init=%s\n' "$ACC_CLIENT_INIT" "$ACC_DAEMON_INIT"
  printf 'INFO daemon_git=%s\n' "$(acc_daemon 'command -v git >/dev/null 2>&1 && echo present || echo absent')"
  printf 'INFO daemon_python3=%s\n' "$(acc_daemon 'command -v python3 >/dev/null 2>&1 && echo present || echo absent')"
  printf 'INFO client_python3=%s\n' "$(acc_exec 'command -v python3 >/dev/null 2>&1 && echo present || echo absent')"
  printf 'INFO dev_fuse=%s\n' "$(acc_exec 'test -c /dev/fuse && test -w /dev/fuse && echo present || echo absent')"
  printf 'INFO cap_sys_admin=%s\n' "$(acc_exec 'c=$(sed -n "s/^CapEff:[[:space:]]*//p" /proc/self/status); [ -n "$c" ] && [ $(( 0x$c >> 21 & 1 )) -eq 1 ] && echo present || echo absent')"
  # Both sides separately: the directory exists in two trees, and one of them
  # being writable says nothing about the other.
  local probe="touch $ACC_EXEC_DIR/.acc-probe-\$\$ && rm -f $ACC_EXEC_DIR/.acc-probe-\$\$ && echo writable || echo read-only"
  printf 'INFO exec_dir=%s client=%s daemon=%s\n' "$ACC_EXEC_DIR" \
    "$(acc_exec "$probe")" "$(acc_daemon "$probe")"
}

# acc_need_fuse: the mount is the sandbox; without it nothing can be judged.
acc_need_fuse(){
  local fuse
  fuse=$(acc_exec 'test -c /dev/fuse && test -w /dev/fuse && echo present || echo absent')
  [ "$fuse" = present ] || { acc_skip_all dev_fuse "/dev/fuse absent or not writable in the client container"; return 1; }
  local cap
  cap=$(acc_exec 'c=$(sed -n "s/^CapEff:[[:space:]]*//p" /proc/self/status); [ -n "$c" ] && [ $(( 0x$c >> 21 & 1 )) -eq 1 ] && echo present || echo absent')
  [ "$cap" = present ] || { acc_skip_all cap_sys_admin "client container lacks CAP_SYS_ADMIN (--privileged)"; return 1; }
  return 0
}

# acc_init_names: read the init each side really has, once, from the kernel.
#
# A local program's /proc/1 is the session's own init, not the container's:
# the sandbox puts each session in its own pid namespace, so that is the
# identity a placement check must compare against. Both names are measured,
# never assumed, and CLIENT_INIT/DAEMON_INIT override them when a deployment
# names its binaries differently.
#
# The client name is read with the entry shell's own `read` builtin: `cat`
# would be an unlisted program, run on the daemon, and measure the wrong side.
acc_init_names(){
  ACC_DAEMON_INIT=${DAEMON_INIT:-$(acc_daemon 'cat /proc/1/comm')}
  if [ -n "${CLIENT_INIT:-}" ]; then
    ACC_CLIENT_INIT=$CLIENT_INIT
  else
    local cfg
    cfg=$(acc_config initprobe '[]' '[]')
    acc_session "$cfg" /bin/sh -c 'IFS= read -r p < /proc/1/comm; echo "$p"'
    ACC_CLIENT_INIT=$(printf '%s' "$ACC_OUT" | tail -1)
  fi
}

# acc_install_binaries: put the binaries under test on both sides. ACC_BIN is
# the directory the build produced (default /tmp/tcbuild); without it the
# images' own binaries are what runs, and the report says so.
acc_install_binaries(){
  local b installed=
  for b in rsbx rsbxd rsbx-tramp rsbx-guard; do
    [ -f "$ACC_BIN/$b" ] || continue
    docker cp "$ACC_BIN/$b" "$ACC_CLIENT:/usr/local/bin/$b" >/dev/null 2>&1 || return 1
    docker cp "$ACC_BIN/$b" "$ACC_DAEMON:/usr/local/bin/$b" >/dev/null 2>&1 || return 1
    installed=$ACC_BIN
  done
  if [ -n "$installed" ]; then
    acc_exec 'chmod 755 /usr/local/bin/rsbx /usr/local/bin/rsbx-tramp /usr/local/bin/rsbx-guard'
    # The daemon is already running the image's binary; restart it so the
    # binary under test is the one serving.
    docker restart "$ACC_DAEMON" >/dev/null
    docker run --rm --network "$ACC_PREFIX-net" -v "$ACC_PREFIX-run:/run/rsbx" \
      --entrypoint /bin/bash "$ACC_DAEMON_IMG" \
      -c 'for i in $(seq 1 100); do [ -S /run/rsbx/daemon.sock ] && exit 0; sleep 0.2; done; exit 1' \
      >/dev/null 2>&1
  fi
  printf 'INFO binaries=%s\n' "${installed:-image-default}"
}

# acc_ready: the standard preamble every carrier runs after creating its rig.
acc_ready(){
  acc_install_binaries || { acc_skip_all install_binaries "could not install $ACC_BIN into the rig"; return 1; }
  acc_exec_dir_prepare || {
    acc_skip_all exec_dir "$ACC_EXEC_DIR is not writable on the ${ACC_EXEC_DIR_SIDE:-unknown} side"
    return 1
  }
  acc_init_names
  acc_env_report
  acc_need_fuse || return 1
  acc_exec 'test -x /usr/local/bin/rsbx || exit 1' || {
    acc_skip_all client_binary "rsbx client binary absent in $ACC_CLIENT_IMG"; return 1; }
  return 0
}
