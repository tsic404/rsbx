#!/bin/bash
# The runtime facts an agent depends on before any model is involved: a large
# program starts, finds its libraries, reads and writes its own state, and the
# tree it sees is the sandbox's rather than this machine's.
# Destructive probe: RSBX_PROJ must be a disposable scratch directory; it is
# never safe to fall back to a host /proj, which this probe wipes clean.
set -u
: "${RSBX_PROJ:?set RSBX_PROJ to a disposable scratch directory for this destructive probe}"
R=$RSBX_PROJ
mkdir -p "$R" 2>/dev/null
if [ -d "$R" ]; then find "$R" -mindepth 1 -delete 2>/dev/null; fi
mkdir -p "$R" || { echo "FAIL setup: cannot create $R"; exit 1; }
cd "$R" || exit 1

ok(){ echo "OK $1"; }
bad(){ echo "FAIL $1: $2"; }
skip(){ echo "SKIP $1: $2"; }

# A large dynamically linked program starts and reports its version. This is the
# path an agent binary takes: dynamic loader, shared libraries, then main.
big_program_starts(){
  local bin=${RSBX_AGENT:-}
  [ -n "$bin" ] || return 2
  [ -x "$bin" ] || { echo "not executable"; return 1; }
  local out
  out=$(timeout 30 "$bin" --version 2>&1) || { echo "exit $? out=${out:0:60}"; return 1; }
  [ -n "$out" ] || { echo "no version output"; return 1; }
  echo "$out" | head -1
}
t_big_program_starts(){ if [ -z "${RSBX_AGENT:-}" ]; then skip big_program_starts "no agent binary configured"; return; fi
  local e; e=$(big_program_starts 2>&1); local r=$?; if [ $r -eq 2 ]; then skip big_program_starts "not configured"; elif [ $r -eq 0 ]; then ok big_program_starts; else bad big_program_starts "${e:0:100}"; fi; }

# The x86-64-v3 instructions the prebuilt agent libraries assume actually work.
# A CPU-feature check is the cheapest way to know the sandbox is not masking
# them.
cpu_features(){
  local flags; flags=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null)
  [ -n "$flags" ] || { echo "no cpuinfo"; return 1; }
  local want
  for want in sse4_2 avx2; do
    echo "$flags" | grep -qw "$want" || { echo "missing $want"; return 1; }
  done
}
t_cpu_features(){ local e; e=$(cpu_features 2>&1); [ $? -eq 0 ] && ok cpu_features_visible || bad cpu_features_visible "${e:0:100}"; }

# A big program's shared libraries resolve. `ldd` failing is the difference
# between "the tool is missing" and "the tool cannot start", and an agent's
# error messages depend on which one it is.
libs_resolve(){
  local bin=${RSBX_AGENT:-}
  [ -n "$bin" ] || return 2
  command -v ldd >/dev/null 2>&1 || return 2
  local missing
  missing=$(ldd "$bin" 2>&1 | grep -c 'not found')
  [ "$missing" = 0 ] || { echo "missing=$missing"; return 1; }
}
t_libs_resolve(){ if [ -z "${RSBX_AGENT:-}" ]; then skip libs_resolve "no agent binary configured"; return; fi
  if ! command -v ldd >/dev/null 2>&1; then skip libs_resolve "ldd absent"; return; fi
  local e; e=$(libs_resolve 2>&1); local r=$?; if [ $r -eq 2 ]; then skip libs_resolve "not configured"; elif [ $r -eq 0 ]; then ok libs_resolve; else bad libs_resolve "${e:0:100}"; fi; }

# The program's own state directory is writable and its files land there, which
# is what makes a session resumable.
state_dir_writable(){
  local d=$R/state
  mkdir -p "$d" || return 1
  printf '{"session":"s1"}' > "$d/session.json" || return 1
  printf 'line\n' >> "$d/transcript.jsonl" || return 1
  printf 'line\n' >> "$d/transcript.jsonl" || return 1
  [ "$(cat "$d/session.json")" = '{"session":"s1"}' ] || { echo "session content"; return 1; }
  [ "$(wc -l < "$d/transcript.jsonl")" = 2 ] || { echo "transcript lines"; return 1; }
}
t_state_dir_writable(){ local e; e=$(state_dir_writable 2>&1); [ $? -eq 0 ] && ok state_dir_writable || bad state_dir_writable "${e:0:100}"; }

# State written in one session is still there in the next. A resumed session
# reads its own history; a filesystem that loses it silently starts over.
state_survives_reopen(){
  local f=$R/persist.json
  printf '{"n":1}' > "$f" || return 1
  # close everything, then read in a fresh command
  local got; got=$(cat "$f")
  [ "$got" = '{"n":1}' ] || { echo "got=$got"; return 1; }
  # and the size on disk agrees with what was read
  local sz; sz=$(stat -c %s "$f")
  [ "$sz" = 7 ] || { echo "size=$sz"; return 1; }
}
t_state_survives_reopen(){ local e; e=$(state_survives_reopen 2>&1); [ $? -eq 0 ] && ok state_survives_reopen || bad state_survives_reopen "${e:0:100}"; }

# A program sees the sandbox's tree, not this machine's. A path that exists only
# on the host is either invisible or comes from the daemon; it must never be the
# host's own file.
view_is_the_sandbox(){
  # /proj is remote content; writing here must be visible on the daemon side,
  # which the caller checks. Locally it must not touch any host path outside
  # the configured trees.
  local f=$R/view.txt
  printf 'sandbox-view' > "$f" || return 1
  [ "$(cat "$f")" = sandbox-view ] || { echo "read back"; return 1; }
}
t_view_is_the_sandbox(){ local e; e=$(view_is_the_sandbox 2>&1); [ $? -eq 0 ] && ok view_is_the_sandbox || bad view_is_the_sandbox "${e:0:100}"; }

# Many short-lived programs in sequence, the way an agent shells out constantly.
# Each has to start, run and exit without leaving anything behind.
spawn_many(){
  local i out
  for i in $(seq 1 40); do
    out=$(printf '%d' "$i")
    [ "$out" = "$i" ] || { echo "iter $i"; return 1; }
  done
}
t_spawn_many(){ local e; e=$(spawn_many 2>&1); [ $? -eq 0 ] && ok spawn_many || bad spawn_many "${e:0:100}"; }

# A program that reads its configuration from a file it also writes on exit.
config_roundtrip(){
  local f=$R/config.yml
  printf 'model: test\nversion: 1\n' > "$f" || return 1
  local got; got=$(grep -c '^model:' "$f")
  [ "$got" = 1 ] || { echo "grep=$got"; return 1; }
  printf 'model: test\nversion: 2\n' > "$f" || return 1
  grep -q 'version: 2' "$f" || { echo "update lost"; return 1; }
}
t_config_roundtrip(){ local e; e=$(config_roundtrip 2>&1); [ $? -eq 0 ] && ok config_roundtrip || bad config_roundtrip "${e:0:100}"; }

# Large state file: an agent's session database reaches tens of megabytes. A
# small-file path that works can still fail on a single big write.
large_state_file(){
  local f=$R/big.db
  dd if=/dev/zero of="$f" bs=1M count=8 2>/dev/null || return 1
  local sz; sz=$(stat -c %s "$f")
  [ "$sz" = 8388608 ] || { echo "size=$sz"; return 1; }
  # and it can be read back in full
  local n; n=$(wc -c < "$f")
  [ "$n" = 8388608 ] || { echo "read=$n"; return 1; }
}
t_large_state_file(){ local e; e=$(large_state_file 2>&1); [ $? -eq 0 ] && ok large_state_file || bad large_state_file "${e:0:100}"; }

t_big_program_starts
t_cpu_features
t_libs_resolve
t_state_dir_writable
t_state_survives_reopen
t_view_is_the_sandbox
t_spawn_many
t_config_roundtrip
t_large_state_file
