#!/bin/bash
# Verifies the mixed-execution model with the fixture programs installed in
# the two purpose-built images:
#   * the stand-in CLIs are host programs (they run here),
#   * everything they see is the daemon's tree,
#   * a program that is not allowlisted (git) runs on the daemon,
#   * the agent's configuration tree is local content.
#
# These programs are shell stand-ins for the real CLIs; this script proves
# placement and file-source policy, not agent compatibility. The real
# installed binaries are checked separately by real.sh.
#
# Placement is measured, never assumed: /proc/1/comm is the init of the
# machine the process really runs on. A local program sees this session's
# rsbx PID 1; a program the daemon started sees the daemon's own init. Both
# names come from the deployment (CLIENT_INIT/DAEMON_INIT), so a different
# PID 1 name is a visibly different fact, not silently accepted.
set -u
MNT=${MNT:?}; F=${F:?}; SOCK=${SOCK:?}
DAEMON_TREE=${DAEMON_TREE:-/proj}
AGENT_HOME=${AGENT_HOME:?}
CLIENT_INIT=${CLIENT_INIT:-rsbx}
DAEMON_INIT=${DAEMON_INIT:-rsbxd}

ok(){ echo "OK $1"; }
bad(){ echo "FAIL $1: $2"; }

run(){ timeout 120 "$F" -config "$MNT/lab.toml" -- /bin/sh -c "$1" 2>&1; }

# The session has its own PID namespace and rsbx init. A native daemon command
# sees the daemon's init; nonempty alone does not prove placement.
is_local_init(){
  [ "$1" = "$CLIENT_INIT" ]
}

is_daemon_init(){
  [ "$1" = "$DAEMON_INIT" ]
}


mkcfg(){
  cat > "$MNT/lab.toml" <<CFG
[daemon]
transport = "unix"
socket = "$SOCK"

[local]
# Only the listed programs and explicit entry run locally. Every other exec
# from the sandbox is routed independently of its PATH directory.
allow = ["/usr/local/bin/multica", "/usr/local/bin/omp", "/usr/local/bin/codex", "/usr/local/bin/claude", "/bin/sh"]
entry = "/bin/sh"
# The agent's configuration tree is local: the program must read and write it
# as this user, and it must never land on the daemon.
paths = ["$AGENT_HOME"]
read_only_paths = []

[sandbox]
mount = "$MNT/sb"
cache = "$MNT/cache"
share_network = true
unshare_user = false
CFG
}

# 1. multica runs here.
check_multica_local(){
  local out p
  out=$(run 'multica sees')
  p=$(printf '%s\n' "$out" | sed -n 's/^MULTICA-INIT=//p')
  is_local_init "$p" || { echo "multica ran on the daemon (no init): $out"; return 1; }
}

# 2. the tree multica sees is the daemon's.
check_multica_sees_remote(){
  local out
  out=$(run 'multica sees')
  printf '%s\n' "$out" | grep -q "MULTICA-SEES=daemon-marker" || { echo "got [$out]"; return 1; }
  [ -e "$DAEMON_TREE/marker" ] && { echo "this container also has /proj/marker, so the check proves nothing"; return 1; }
  return 0
}

# 3. git is not on this machine at all.
check_git_absent_here(){
  local p
  p=$(command -v git 2>/dev/null || true)
  [ -z "$p" ] || { echo "git is installed here at $p, the placement checks cannot prove anything"; return 1; }
  return 0
}

# 4. git still runs, because the daemon has it.
check_git_runs(){
  local out
  out=$(run 'git --version')
  printf '%s\n' "$out" | grep -q "^git version " || { echo "got [$out]"; return 1; }
}

# 5. and it runs on the daemon, not here. A git alias reads the init of the
#    machine it really runs on.
check_git_remote(){
  local out rc
  # The alias body must reach the daemon's git unchanged: it is single-quoted
  # at the local shell, so nothing here expands it. `cat /proc/1/comm` is the
  # daemon's own native procfs, which is what makes the placement observable.
  # stderr is kept: a missing alias or a failed remote exec has to be visible
  # in the failure message instead of becoming an empty string.
  out=$(run "git -c 'alias.w=!cat /proc/1/comm' w")
  rc=$?
  [ $rc -eq 0 ] || { echo "git alias probe failed (rc=$rc): $out"; return 1; }
  is_daemon_init "$out" || { echo "git init [$out] is not the daemon init $DAEMON_INIT"; return 1; }
  return 0
}

# 6. git's work lands on the daemon's tree and survives to the next session.
check_git_writes_remote(){
  local out
  out=$(run 'rm -rf /proj/repo; mkdir -p /proj/repo; cd /proj/repo || exit 1
    git init -q . || { echo INIT_FAILED; exit 1; }
    printf "remote-code\n" > a.txt || { echo WRITE_FAILED; exit 1; }
    git add a.txt || { echo ADD_FAILED; exit 1; }
    git -c user.email=l@x -c user.name=l commit -qm one || { echo COMMIT_FAILED; exit 1; }
    git rev-list --count HEAD')
  printf '%s\n' "$out" | grep -qx 1 || { echo "got [$out]"; return 1; }
  out=$(run 'cat /proj/repo/a.txt')
  printf '%s\n' "$out" | grep -q "remote-code" || { echo "read back [$out]"; return 1; }
  [ -e "$DAEMON_TREE/repo/a.txt" ] && { echo "this container also holds the repo"; return 1; }
  return 0
}

# 7. the agent's config tree is local: written by the agent, visible to this
#    container's own filesystem, and absent from the daemon's tree.
check_agent_config_local(){
  local out
  out=$(run 'omp config-write; omp config-read')
  printf '%s\n' "$out" | grep -q "OMP-CONFIG=\[model=local-config\]" || { echo "got [$out]"; return 1; }
  [ -f "$AGENT_HOME/omp/config.toml" ] || { echo "config not in this filesystem"; return 1; }
  [ -e "$DAEMON_TREE/omp/config.toml" ] && { echo "config also landed on the daemon"; return 1; }
  return 0
}

# 8. the agent's work product is remote.
check_agent_io_remote(){
  local out
  out=$(run 'mkdir -p /proj/agentwork && omp work /proj/agentwork')
  printf '%s\n' "$out" | grep -q "OMP-WORK=/proj/agentwork/out.txt" || { echo "got [$out]"; return 1; }
  out=$(run 'cat /proj/agentwork/out.txt')
  printf '%s\n' "$out" | grep -q "artifact from omp" || { echo "read back [$out]"; return 1; }
  [ -e "$DAEMON_TREE/agentwork" ] && { echo "this container also holds the work product"; return 1; }
  return 0
}

# 9. every agent CLI runs here.
check_all_agents_local(){
  local a out p
  for a in omp codex claude; do
    out=$(run "$a config-read")
    p=$(printf '%s\n' "$out" | sed -n 's/^[A-Z]*-INIT=//p')
    is_local_init "$p" || { echo "$a ran on the daemon (no init): $out"; return 1; }
  done
}

# A host CLI that shells out to git gets the daemon's git, and the code it
# fetches is code the CLI itself can then read: one tree, two sides.
check_cli_drives_git(){
  local out
  out=$(run 'multica run "git clone -q /proj/origin.git /proj/work && echo CLONED"')
  printf '%s\n' "$out" | grep -q CLONED || { echo "clone: [$out]"; return 1; }
  out=$(run 'multica run "cat /proj/work/lib.c"')
  printf '%s\n' "$out" | grep -q "lib code" || { echo "multica cannot see the fetched file: [$out]"; return 1; }
  # The clone must not exist on this machine: it was written on the daemon.
  [ -e "$DAEMON_TREE/work" ] && { echo "the client root also holds the clone"; return 1; }
  return 0
}

# 10. multica and git see one tree, not two.
check_one_tree(){
  local a b
  a=$(run 'multica run "ls /proj/repo | tr \"\n\" \" \""')
  b=$(run 'cd /proj/repo && git rev-parse --is-inside-work-tree')
  printf '%s\n' "$b" | grep -q true || { echo "git sees no work tree: [$b]"; return 1; }
  printf '%s\n' "$a" | grep -q "a.txt" || { echo "multica listing [$a]"; return 1; }
  printf '%s\n' "$a" | grep -q "MULTICA-PID=" || true
}

mkcfg
echo "=== client=$(hostname) ==="
failed=0
for t in check_multica_local check_multica_sees_remote check_git_absent_here \
         check_git_runs check_git_remote check_git_writes_remote \
         check_agent_config_local check_agent_io_remote check_all_agents_local \
         check_cli_drives_git check_one_tree; do
  if e=$($t 2>&1); then
    ok "${t#check_}"
  else
    bad "${t#check_}" "${e:0:240}"
    failed=1
  fi
done
exit "$failed"
