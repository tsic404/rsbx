#!/bin/bash
# Process semantics: exit status, signals, stdio, environment, working directory.
#
# These are about what the sandbox does around a program, not the filesystem: a
# session's status must reach the caller unchanged, output must not be merged,
# and binary data must survive the bridge.
set -u
R=${RSBX_PROJ:-/proj/proc}
mkdir -p "$R" 2>/dev/null
if [ -d "$R" ]; then find "$R" -mindepth 1 -delete 2>/dev/null; fi
mkdir -p "$R" || { echo "FAIL setup: cannot create $R"; exit 1; }
cd "$R" || exit 1

ok(){ echo "OK $1"; }
bad(){ echo "FAIL $1: $2"; }
skip(){ echo "SKIP $1: $2"; }

# Exit status must arrive intact. A shell that reports 0 for everything makes
# every build script pass.
status(){
  local want got
  for want in 0 1 42 255; do
    ( exit "$want" )
    got=$?
    [ "$got" = "$want" ] || { echo "exit $want became $got"; return 1; }
  done
  bash -c 'kill -TERM $$' 2>/dev/null
  got=$?
  [ "$got" != 0 ] || { echo "signalled process reported success"; return 1; }
}
t_status(){ local e; e=$(status 2>&1); [ $? -eq 0 ] && ok exit_status || bad exit_status "${e:0:100}"; }

# stdout and stderr are different streams.
streams(){
  local o e
  o=$( { printf 'out-line'; printf 'err-line' >&2; } 2>"$R/err.txt" ) || return 1
  e=$(cat "$R/err.txt")
  [ "$o" = out-line ] || { echo "stdout=$o"; return 1; }
  [ "$e" = err-line ] || { echo "stderr=$e"; return 1; }
}
t_streams(){ local e; e=$(streams 2>&1); [ $? -eq 0 ] && ok stdio_separation || bad stdio_separation "${e:0:100}"; }

# stdin must reach the program and a pipe must end on EOF.
stdin_pipe(){
  local got
  got=$(printf 'a\nb\nc\n' | wc -l) || return 1
  [ "$got" = 3 ] || { echo "lines=$got"; return 1; }
  got=$(printf 'hello' | cat) || return 1
  [ "$got" = hello ] || { echo "content=$got"; return 1; }
}
t_stdin_pipe(){ local e; e=$(stdin_pipe 2>&1); [ $? -eq 0 ] && ok stdin_pipe || bad stdin_pipe "${e:0:100}"; }

# Binary through a pipe: NUL bytes and high bytes over several reads.
binary_pipe(){
  local f=$R/blob.bin
  python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256)) * 64)" > "$f" || return 2
  local n; n=$(wc -c < "$f")
  [ "$n" = 16384 ] || { echo "wrote=$n"; return 1; }
  local m; m=$(cat "$f" | wc -c)
  [ "$m" = 16384 ] || { echo "piped=$m"; return 1; }
  cmp -s "$f" <(cat "$f") || { echo "content differs"; return 1; }
}
t_binary_pipe(){ if ! command -v python3 >/dev/null 2>&1; then skip binary_pipe "python3 absent"; return; fi
  local e; e=$(binary_pipe 2>&1); local r=$?; if [ $r -eq 2 ]; then skip binary_pipe "python3 failed"; elif [ $r -eq 0 ]; then ok binary_pipe; else bad binary_pipe "${e:0:100}"; fi; }

# Large output must not be truncated or reordered.
large_output(){
  local n first last
  n=$(seq 1 20000 | wc -l) || return 1
  [ "$n" = 20000 ] || { echo "lines=$n"; return 1; }
  first=$(seq 1 20000 | head -1); last=$(seq 1 20000 | tail -1)
  [ "$first" = 1 ] || { echo "first=$first"; return 1; }
  [ "$last" = 20000 ] || { echo "last=$last"; return 1; }
}
t_large_output(){ local e; e=$(large_output 2>&1); [ $? -eq 0 ] && ok large_output || bad large_output "${e:0:100}"; }

# What the session exports is what the program sees.
env_passthrough(){
  RSBX_TEST_VAR=visible
  export RSBX_TEST_VAR
  local got; got=$(printenv RSBX_TEST_VAR) || { echo "not visible"; return 1; }
  [ "$got" = visible ] || { echo "got=$got"; return 1; }
}
t_env_passthrough(){ local e; e=$(env_passthrough 2>&1); [ $? -eq 0 ] && ok env_passthrough || bad env_passthrough "${e:0:100}"; }

# A session told to run in a directory starts there.
cwd_resolution(){
  mkdir -p "$R/work" || return 1
  printf 'marker' > "$R/work/f.txt" || return 1
  ( cd "$R/work" && [ "$(pwd)" = "$R/work" ] ) || { echo "pwd wrong"; return 1; }
  ( cd "$R/work" && [ "$(cat f.txt)" = marker ] ) || { echo "relative read failed"; return 1; }
}
t_cwd_resolution(){ local e; e=$(cwd_resolution 2>&1); [ $? -eq 0 ] && ok cwd_resolution || bad cwd_resolution "${e:0:100}"; }

# A program that fails after writing leaves what it wrote.
partial_on_failure(){
  local f=$R/partial.txt rc
  ( printf 'written-before-failure' > "$f"; exit 7 ) 2>/dev/null
  rc=$?
  [ "$rc" = 7 ] || { echo "rc=$rc"; return 1; }
  [ "$(cat "$f" 2>/dev/null)" = written-before-failure ] || { echo "output lost"; return 1; }
}
t_partial_on_failure(){ local e; e=$(partial_on_failure 2>&1); [ $? -eq 0 ] && ok partial_output_on_failure || bad partial_output_on_failure "${e:0:100}"; }

# Several sessions at once, each with its own output.
concurrent_sessions(){
  local i out
  for i in 1 2 3 4 5 6; do
    ( out=$(printf 'session-%d' "$i"); [ "$out" = "session-$i" ] || exit 1 ) &
  done
  wait
}
t_concurrent_sessions(){ local e; e=$(concurrent_sessions 2>&1); [ $? -eq 0 ] && ok concurrent_sessions || bad concurrent_sessions "${e:0:100}"; }

# An interrupted program must stop and report failure, not hang.
interrupt(){
  local pid rc
  ( sleep 30 ) &
  pid=$!
  sleep 0.2
  kill -TERM "$pid" 2>/dev/null || return 1
  wait "$pid" 2>/dev/null
  rc=$?
  [ "$rc" != 0 ] || { echo "interrupted job reported success"; return 1; }
  kill -0 "$pid" 2>/dev/null && { echo "process survived SIGTERM"; return 1; }
  return 0
}
t_interrupt(){ local e; e=$(interrupt 2>&1); [ $? -eq 0 ] && ok interrupt_stops_process || bad interrupt_stops_process "${e:0:100}"; }

t_status
t_streams
t_stdin_pipe
t_binary_pipe
t_large_output
t_env_passthrough
t_cwd_resolution
t_partial_on_failure
t_concurrent_sessions
t_interrupt
