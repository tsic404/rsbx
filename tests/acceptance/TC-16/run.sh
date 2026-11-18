#!/bin/bash
# TC-16: the task workspace belongs to the daemon's tree. The client
# establishes it there from its own initial material before the session
# starts; the agent's starting directory is that remote path; remote commands
# read and write it; material declared local on this machine never enters it.
#
# Environment:
#   MNT         client scratch (config, mount and cache live here)
#   F           rsbx binary
#   SOCK        daemon socket
#   AGENT_HOME  local private tree, declared through local.paths
#   SEED        local directory holding the workspace's own initial material
#   WS          workspace path in the daemon's tree
#   UNSHARE_USER  sandbox user namespace (false inside a privileged container)
# runner: external-rig
set -u
MNT=${MNT:?}; F=${F:?}; SOCK=${SOCK:?}
AGENT_HOME=${AGENT_HOME:?}; SEED=${SEED:?}; WS=${WS:?}
UNSHARE_USER=${UNSHARE_USER:-true}
PRIVATE_MARKER=PRIVATE-TC16-MARKER

ok(){ echo "OK $1"; }
bad(){ failed=$(( ${failed:-0} + 1 )); echo "FAIL $1: $2"; }

run(){ timeout 120 "$F" -config "$MNT/tc16.toml" "$@" 2>&1; }

mkcfg(){
  cat > "$MNT/tc16.toml" <<CFG
[daemon]
transport = "unix"
socket = "$SOCK"

[local]
allow = []
entry = "/bin/sh"
# Agent configuration and state stay on this machine.
paths = ["$AGENT_HOME"]

[sandbox]
mount = "$MNT/sb"
cache = "$MNT/cache"
unshare_user = $UNSHARE_USER
CFG
}

setup(){
  mkdir -p "$MNT/sb" "$MNT/cache" "$AGENT_HOME" "$SEED/.multica" "$SEED/src"
  printf 'task instructions for tc16\n' > "$SEED/AGENTS.md"
  printf '{"task":"tc16"}\n' > "$SEED/.multica/state.json"
  printf 'package task\n' > "$SEED/src/main.go"
  printf '#!/bin/sh\necho seeded-run\n' > "$SEED/run.sh"
  chmod 0755 "$SEED/run.sh"
  printf '%s\n' "$PRIVATE_MARKER" > "$AGENT_HOME/private.txt"
  mkcfg
  # Reruns reuse a daemon tree: start from an absent workspace.
  ( cd /tmp && run -- /bin/sh -c "/bin/rm -rf '$WS' '$WS-private' '$WS-missing'" >/dev/null 2>&1 ) || true
}

# The agent starts in the remote workspace, and the daemon wrote the seed's
# content there, including the executable bit.
check_start_and_seed(){
  local out
  out=$(run -workspace "$WS" -workspace-seed "$SEED" -- /bin/sh -c '
    pwd
    /bin/cat AGENTS.md
    /bin/cat .multica/state.json
    /bin/cat src/main.go
    if [ -x run.sh ]; then echo SEED-EXEC; fi
  ')
  printf '%s\n' "$out" | grep -qx "$WS" || { echo "start dir: [$out]"; return 1; }
  printf '%s\n' "$out" | grep -qx 'task instructions for tc16' || { echo "seed AGENTS.md: [$out]"; return 1; }
  printf '%s\n' "$out" | grep -qx '{"task":"tc16"}' || { echo "seed state: [$out]"; return 1; }
  printf '%s\n' "$out" | grep -qx 'package task' || { echo "seed src: [$out]"; return 1; }
  printf '%s\n' "$out" | grep -qx 'SEED-EXEC' || { echo "seed mode: [$out]"; return 1; }
}

# A remote command writes in the workspace; the local view of the same path
# reads the same bytes.
check_remote_write_local_view(){
  local out
  out=$(run -workspace "$WS" -- /bin/sh -c '
    printf "remote-made\n" | /usr/bin/tee remote-made.txt >/dev/null || exit 1
    IFS= read -r v < remote-made.txt
    echo "LOCALVIEW=$v"
    if [ -f remote-made.txt ]; then echo LOCALSTAT=yes; fi
  ')
  printf '%s\n' "$out" | grep -qx 'LOCALVIEW=remote-made' || { echo "local view: [$out]"; return 1; }
  printf '%s\n' "$out" | grep -qx 'LOCALSTAT=yes' || { echo "local stat: [$out]"; return 1; }
}

# The local view writes; a remote command in the same workspace reads it.
check_local_write_remote_read(){
  local out
  out=$(run -workspace "$WS" -- /bin/sh -c '
    printf "local-made\n" > local-made.txt
    /bin/cat local-made.txt
  ')
  printf '%s\n' "$out" | grep -qx 'local-made' || { echo "remote read: [$out]"; return 1; }
}

# Private material stays on this machine: it is neither copied into the
# workspace nor readable from it.
check_private_material_absent(){
  local out
  out=$(run -workspace "$WS" -- /bin/sh -c "
    /bin/cat '$AGENT_HOME/private.txt' 2>&1; echo cat-rc=\$?
    /bin/grep -r '$PRIVATE_MARKER' . 2>&1; echo grep-rc=\$?
  ")
  if printf '%s' "$out" | grep -q "$PRIVATE_MARKER"; then
    echo "private marker reached the remote: [$out]"; return 1
  fi
  printf '%s\n' "$out" | grep -q 'cat-rc=[1-9]' || { echo "remote read of a local-only path: [$out]"; return 1; }
  printf '%s\n' "$out" | grep -q 'grep-rc=1' || { echo "workspace content scan: [$out]"; return 1; }
}

# A seed that is declared local is refused before anything is written: it is
# the agent's private material, not workspace content.
check_private_seed_refused(){
  local out rc
  out=$(run -workspace "$WS-private" -workspace-seed "$AGENT_HOME" -- /bin/sh -c 'echo RAN')
  rc=$?
  [ $rc -ne 0 ] || { echo "private seed accepted: [$out]"; return 1; }
  printf '%s' "$out" | grep -qi 'local' || { echo "refusal does not name the boundary: [$out]"; return 1; }
  out=$(run -workspace "$WS" -- /bin/sh -c "/bin/ls -d '$WS-private' 2>&1")
  printf '%s' "$out" | grep -q 'No such file' || { echo "refused seed wrote a workspace: [$out]"; return 1; }
}

# A workspace declared inside a local tree would be local content, not a
# remote workspace.
check_local_workspace_refused(){
  local out rc
  out=$(run -workspace "$AGENT_HOME/ws" -workspace-seed "$SEED" -- /bin/sh -c 'echo RAN')
  rc=$?
  [ $rc -ne 0 ] || { echo "local workspace accepted: [$out]"; return 1; }
  printf '%s' "$out" | grep -qi 'local' || { echo "refusal does not name the boundary: [$out]"; return 1; }
}

# A start directory that does not exist remotely fails explicitly; the entry
# never runs and nothing is created. There is no fallback directory.
check_missing_workspace_fails(){
  local out rc
  out=$(run -workspace "$WS-missing" -- /bin/sh -c 'echo RAN > marker')
  rc=$?
  [ $rc -ne 0 ] || { echo "missing workspace accepted: [$out]"; return 1; }
  printf '%s' "$out" | grep -qi 'no such' || { echo "failure does not name the directory: [$out]"; return 1; }
  printf '%s' "$out" | grep -q 'RAN' && { echo "entry ran anyway: [$out]"; return 1; }
  out=$(run -workspace "$WS" -- /bin/sh -c "/bin/ls -d '$WS-missing' 2>&1")
  printf '%s' "$out" | grep -q 'No such file' || { echo "failed session created the directory: [$out]"; return 1; }
}

# Re-initialization restores the seed's content and keeps products the agent
# already wrote in the workspace.
check_reinit_keeps_products(){
  local out
  out=$(run -workspace "$WS" -workspace-seed "$SEED" -- /bin/sh -c '
    /bin/cat AGENTS.md
    if [ -f remote-made.txt ]; then echo PRODUCT-KEPT; fi
  ')
  printf '%s\n' "$out" | grep -qx 'task instructions for tc16' || { echo "seed after reinit: [$out]"; return 1; }
  printf '%s\n' "$out" | grep -qx 'PRODUCT-KEPT' || { echo "agent product removed: [$out]"; return 1; }
}

check(){
  local name=$1
  shift
  if "$@"; then ok "$name"; else bad "$name" "$(printf '%s' "${out:-}" | tail -3 | tr '\n' ' ')"; fi
}

setup
check workspace-start-and-seed check_start_and_seed
check remote-write-local-view check_remote_write_local_view
check local-write-remote-read check_local_write_remote_read
check private-material-absent check_private_material_absent
check private-seed-refused check_private_seed_refused
check local-workspace-refused check_local_workspace_refused
check missing-workspace-fails check_missing_workspace_fails
check reinit-keeps-products check_reinit_keeps_products

if [ "${failed:-0}" -ne 0 ]; then exit 1; fi
