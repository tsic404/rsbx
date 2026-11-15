#!/bin/bash
# Verifies the mixed-execution model:
#   * multica and the agent CLIs are host programs (they run here),
#   * everything they see is the daemon's tree,
#   * a program that is not allowlisted (git) runs on the daemon,
#   * the agent's configuration tree is local content.
#
# Placement is measured, never assumed. A program that runs here reports its
# pid from this container's pid namespace; a program the daemon started reports
# one from the daemon's own sequence.
set -u
MNT=${MNT:?}; F=${F:?}; SOCK=${SOCK:?}
DAEMON_TREE=${DAEMON_TREE:-/proj}
AGENT_HOME=${AGENT_HOME:?}

ok(){ echo "OK $1"; }
bad(){ echo "FAIL $1: $2"; }

run(){ timeout 120 "$F" -config "$MNT/lab.toml" -- /bin/sh -c "$1" 2>&1; }

# Placement is read from /proc/1: it is the init of the machine the process
# really runs on. A host program sees this container's init; a program the
# daemon started sees rsbxd. The string is passed in from the runner.
is_local_pid1(){
  case "$1" in
    *rsbxd*) return 1 ;;
    "") return 1 ;;
    *) return 0 ;;
  esac
}

mkcfg(){
  cat > "$MNT/lab.toml" <<CFG
[daemon]
transport = "unix"
socket = "$SOCK"

[local]
# multica and the agent CLIs are named one by one; /usr/bin is listed as a
# directory so the names inside it are arbitrated per program. A name in a
# listed directory that the policy does not allowlist runs on the daemon; a
# name in a directory never listed is ordinary host content and runs here.
allow = ["/usr/local/bin/multica", "/usr/local/bin/omp", "/usr/local/bin/codex", "/usr/local/bin/claude", "/bin/sh", "/usr/bin"]
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
  p=$(printf '%s\n' "$out" | sed -n 's/^MULTICA-PID1=//p')
  is_local_pid1 "$p" || { echo "multica ran on the daemon (pid1 [$p]): $out"; return 1; }
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

# 5. and it runs on the daemon, not here. A git alias reports its own pid.
check_git_remote(){
  out=$(run 'git -c alias.w="!tr \\0 \" \" < /proc/1/cmdline" w 2>/dev/null | head -c 40')
  [ -n "$out" ] || { echo "no evidence from git"; return 1; }
  case "$out" in
    *rsbxd*) return 0 ;;
  esac
  echo "git ran here (pid1 [$out]): the redirect did not happen"; return 1
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
  out=$(run 'omp work /proj/agentwork')
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
    p=$(printf '%s\n' "$out" | sed -n 's/^[A-Z]*-PID1=//p')
    is_local_pid1 "$p" || { echo "$a ran on the daemon (pid1 [$p]): $out"; return 1; }
  done
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
for t in check_multica_local check_multica_sees_remote check_git_absent_here \
         check_git_runs check_git_remote check_git_writes_remote \
         check_agent_config_local check_agent_io_remote check_all_agents_local check_one_tree; do
  e=$($t 2>&1)
  if [ $? -eq 0 ]; then ok "${t#check_}"; else bad "${t#check_}" "${e:0:240}"; fi
done
