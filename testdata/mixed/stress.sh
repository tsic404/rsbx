#!/bin/bash
# Stress the mixed model: many concurrent sessions, each running the host
# programs and the daemon programs on one shared tree.
#
# The programs are the shell stand-ins from the two purpose-built images, so
# this measures the sandbox's placement, file-source and lifecycle behavior
# under contention. It does not measure real agent compatibility; the real
# installed binaries are exercised separately by real.sh.
#
# Every session reads the same single configuration file. The sandbox, not the
# caller, allocates a unique mount/cache/broker per invocation, which is the
# property this script holds under load.
#
# Placement assertions are against the init names the deployment actually has
# (CLIENT_INIT/DAEMON_INIT), read from the kernel's /proc/1/comm.
set -u
MNT=${MNT:?}; F=${F:?}; SOCK=${SOCK:?}; AGENT_HOME=${AGENT_HOME:?}
N=${N:-8}
CLIENT_INIT=${CLIENT_INIT:-rsbx}
DAEMON_INIT=${DAEMON_INIT:-rsbxd}
ok(){ echo "OK $1"; }
bad(){ echo "FAIL $1: $2"; }
run(){ timeout 180 "$F" -config "$MNT/lab.toml" -- /bin/sh -c "$1" 2>&1; }
# All concurrent invocations deliberately share the same configuration file.
mkcfg(){
  cat > "$MNT/lab.toml" <<CFG
[daemon]
transport = "unix"
socket = "$SOCK"
[local]
allow = ["/usr/local/bin/multica", "/usr/local/bin/omp", "/usr/local/bin/codex", "/usr/local/bin/claude", "/bin/sh"]
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

# 1. N concurrent sessions each committing to their own subtree on the daemon.
concurrent_commits(){
  local i pids=() pid rc=0
  for i in $(seq 1 $N); do
    ( run "rm -rf /proj/c$i; mkdir -p /proj/c$i; cd /proj/c$i && \
        git init -q . && printf 'work-$i\n' > f.txt && \
        git add f.txt && \
        git -c user.email=a@b -c user.name=n commit -qm c$i && \
        git rev-list --count HEAD" > "$MNT/commit.$i" 2>&1 ) &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
  [ $rc -eq 0 ] || {
    # Keep each session's own output. Reading it from split.* reported an
    # empty message, because those files belong to a different check: a
    # failure with no reason is worse than no failure reported at all.
    local i
    for i in $(seq 1 $N); do
      local got; got=$(cat "$MNT/commit.$i" 2>/dev/null)
      case "$got" in
        1) ;;
        *) echo "c$i: [${got:0:160}]"; return 1 ;;
      esac
    done
    echo "a session failed with no output"
    return 1
  }
  for i in $(seq 1 $N); do
    local n; n=$(run "cd /proj/c$i && git rev-list --count HEAD")
    [ "$n" = 1 ] || { echo "c$i count=$n"; return 1; }
  done
}

# 2. host program and daemon program interleaved in one session, many times.
#    Each round reads /proc/1/comm from the machine the command really ran on,
#    so both sides of the routing decision are measured rather than inferred
#    from a command merely succeeding.
#
#    The alias body is quote-free and the whole probe is single-quoted at the
#    local shell, so no `$` in it can be expanded here before the daemon's git
#    sees it. stderr is kept and each side's exit status is checked: a failed
#    probe must not be counted as a successful round.
interleaved(){
  local out
  # The stand-in has no subcommands: invoked with no arguments it prints its
  # own MULTICA-INIT marker (read from the kernel's /proc/1/comm) and exits 0.
  # Asking it for a name it does not implement would make /bin/sh report
  # "not found" and turn a placement probe into a fixture-capability probe.
  out=$(run "i=0; lok=0; rok=0; bad=0
    while [ \$i -lt 20 ]; do
      m=\$(multica)
      if [ \$? -eq 0 ] && printf '%s' \"\$m\" | grep -q 'MULTICA-INIT=$CLIENT_INIT'; then
        lok=\$((lok+1))
      else
        bad=\$((bad+1)); printf 'round %d local probe: [%s]\\n' \"\$i\" \"\$m\" >&2
      fi
      g=\$(git -c 'alias.w=!cat /proc/1/comm' w)
      if [ \$? -eq 0 ] && [ \"\$g\" = '$DAEMON_INIT' ]; then
        rok=\$((rok+1))
      else
        bad=\$((bad+1)); printf 'round %d remote probe: [%s]\\n' \"\$i\" \"\$g\" >&2
      fi
      i=\$((i+1))
    done
    echo \"local=\$lok remote=\$rok bad=\$bad\"")
  printf '%s\n' "$out" | grep -qx "local=20 remote=20 bad=0" || { echo "got [$out]"; return 1; }
}

# 3. agent config stays local while work product stays remote, concurrently.
agent_split(){
  local i pids=() pid rc=0
  for i in $(seq 1 $N); do
    ( run "OMP_CONFIG=$AGENT_HOME/omp/cfg$i.toml omp config-write
        mkdir -p /proj/w$i && omp work /proj/w$i" > "$MNT/split.$i" 2>&1 ) &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
  [ $rc -eq 0 ] || {
    local i
    for i in $(seq 1 $N); do
      local got; got=$(cat "$MNT/split.$i" 2>/dev/null)
      case "$got" in
        *OMP-WROTE*OMP-WORK*) ;;
        *) echo "w$i: [${got:0:160}]"; return 1 ;;
      esac
    done
    echo "a session failed with no output"
    return 1
  }
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
failed=0
for t in concurrent_commits interleaved agent_split cross_view; do
  if e=$($t 2>&1); then
    ok "$t"
  else
    bad "$t" "${e:0:240}"
    failed=1
  fi
done
exit "$failed"
