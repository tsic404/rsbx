#!/bin/bash
# Stress the mixed model: many concurrent sessions, each running the host
# programs and the daemon programs on one shared tree.
set -u
MNT=${MNT:?}; F=${F:?}; SOCK=${SOCK:?}; AGENT_HOME=${AGENT_HOME:?}
N=${N:-8}
ok(){ echo "OK $1"; }
bad(){ echo "FAIL $1: $2"; }
run(){ timeout 180 "$F" -config "$MNT/lab.toml" -- /bin/sh -c "$1" 2>&1; }
# A config describes one sandbox: its own mount point, its own cache. Concurrent
# sessions therefore each need their own config file, or they contend for the
# same mount and the same broker socket.
runn(){
  local n=$1; shift
  timeout 180 "$F" -config "$MNT/cfg$n.toml" -- /bin/sh -c "$1" 2>&1
}
mkcfg_n(){
  local n=$1
  sed -e "s|mount = .*|mount = \"$MNT/sb$n\"|" \
      -e "s|cache = .*|cache = \"$MNT/c$n\"|" "$MNT/lab.toml" > "$MNT/cfg$n.toml"
  mkdir -p "$MNT/sb$n" "$MNT/c$n"
}
mkcfg(){
  cat > "$MNT/lab.toml" <<CFG
[daemon]
transport = "unix"
socket = "$SOCK"
[local]
allow = ["/usr/local/bin/multica", "/usr/local/bin/omp", "/usr/local/bin/codex", "/usr/local/bin/claude", "/bin/sh", "/usr/bin"]
entry = "/bin/sh"
paths = ["$AGENT_HOME"]
read_only_paths = []
[sandbox]
mount = "$MNT/sb"
cache = "$MNT/cache"
share_network = true
unshare_user = false
CFG
}
mkcfg
for i in $(seq 1 $N); do mkcfg_n $i; done

# 1. N concurrent sessions each committing to their own subtree on the daemon.
concurrent_commits(){
  local i pids=() pid rc=0
  for i in $(seq 1 $N); do
    ( runn $i "rm -rf /proj/c$i; mkdir -p /proj/c$i; cd /proj/c$i
        git init -q . && printf 'work-$i\n' > f.txt
        git add f.txt
        git -c user.email=a@b -c user.name=n commit -qm c$i 2>/dev/null
        git rev-list --count HEAD" ) &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
  [ $rc -eq 0 ] || { echo "a session failed"; return 1; }
  for i in $(seq 1 $N); do
    local n; n=$(run "cd /proj/c$i && git rev-list --count HEAD")
    [ "$n" = 1 ] || { echo "c$i count=$n"; return 1; }
  done
}

# 2. host program and daemon program interleaved in one session, many times.
interleaved(){
  local out
  out=$(run 'i=0; lok=0; rok=0
    while [ $i -lt 20 ]; do
      if multica ver 2>/dev/null | grep -qv rsbxd; then lok=$((lok+1)); fi
      if git --version >/dev/null 2>&1; then rok=$((rok+1)); fi
      i=$((i+1))
    done
    echo "local=$lok remote=$rok"')
  printf '%s\n' "$out" | grep -q "local=20 remote=20" || { echo "got [$out]"; return 1; }
}

# 3. agent config stays local while work product stays remote, concurrently.
agent_split(){
  local i pids=() pid rc=0
  for i in $(seq 1 $N); do
    ( runn $i "OMP_CONFIG=$AGENT_HOME/omp/cfg$i.toml omp config-write
        omp work /proj/w$i" ) >/dev/null 2>&1 &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
  [ $rc -eq 0 ] || { echo "a session failed"; return 1; }
  local i
  for i in $(seq 1 $N); do
    [ -f "$AGENT_HOME/omp/cfg$i.toml" ] || { echo "cfg$i not local"; return 1; }
    local got; got=$(run "cat /proj/w$i/out.txt")
    printf '%s\n' "$got" | grep -q "artifact from omp" || { echo "w$i remote product [$got]"; return 1; }
  done
  return 0
}

# 4. one shared remote file, written by a host program and read by a daemon
#    program, repeatedly: the two views must be one tree.
cross_view(){
  local i out
  for i in $(seq 1 10); do
    run "multica run \"printf 'round-$i' > /proj/shared\"" >/dev/null 2>&1
    out=$(run 'cat /proj/shared')
    printf '%s\n' "$out" | grep -qx "round-$i" || { echo "round$i read [$out]"; return 1; }
  done
}

echo "=== stress: N=$N ==="
for t in concurrent_commits interleaved agent_split cross_view; do
  e=$($t 2>&1)
  if [ $? -eq 0 ]; then ok "$t"; else bad "$t" "${e:0:240}"; fi
done
