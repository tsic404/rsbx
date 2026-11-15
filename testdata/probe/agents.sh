#!/bin/bash
# Several agents working at once in one project, which is what a shared sandbox
# actually sees. Asserts that concurrent sessions do not corrupt each other's
# state and that each one's own view stays consistent.
# Destructive probe: RSBX_PROJ must be a disposable scratch directory; it is
# never safe to fall back to a host /proj, which this probe wipes clean.
set -u
: "${RSBX_PROJ:?set RSBX_PROJ to a disposable scratch directory for this destructive probe}"
R=$RSBX_PROJ
mkdir -p "$R" 2>/dev/null
if [ -d "$R" ]; then
  find "$R" -mindepth 1 -delete 2>/dev/null || rm -rf "${R:?}"/* 2>/dev/null
fi
mkdir -p "$R" || { echo "FAIL setup: cannot create $R"; exit 1; }
cd "$R" || exit 1

ok(){ echo "OK $1"; }
bad(){ echo "FAIL $1: $2"; }
skip(){ echo "SKIP $1: $2"; }

# Four sessions each keep a transcript, a lock file and a work product. They
# never share a name, which is how agents in one repo stay out of each other's
# way; the filesystem must not introduce interference of its own.
sessions(){
  local pids=() pid rc=0
  local i
  for i in 1 2 3 4; do
    (
      local d=$R/agent-$i
      mkdir -p "$d" || exit 1
      : > "$d/session.lock" || exit 1
      local j
      for j in $(seq 1 30); do
        printf 'step %d\n' "$j" >> "$d/transcript.jsonl" || exit 1
        printf 'result %d' "$j" > "$d/out.tmp" || exit 1
        mv -f "$d/out.tmp" "$d/out.txt" || exit 1
      done
      rm -f "$d/session.lock" || exit 1
    ) &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
  [ $rc -eq 0 ] || { echo "a worker exited nonzero"; return 1; }
  for i in 1 2 3 4; do
    local d=$R/agent-$i
    [ "$(wc -l < "$d/transcript.jsonl" 2>/dev/null)" = 30 ] || { echo "agent $i lines=$(wc -l < "$d/transcript.jsonl" 2>/dev/null)"; return 1; }
    [ "$(cat "$d/out.txt" 2>/dev/null)" = "result 30" ] || { echo "agent $i out=$(cat "$d/out.txt" 2>/dev/null)"; return 1; }
    [ ! -e "$d/session.lock" ] || { echo "agent $i lock left"; return 1; }
    [ ! -e "$d/out.tmp" ] || { echo "agent $i temp left"; return 1; }
  done
}
t_sessions(){ local e; e=$(sessions 2>&1); [ $? -eq 0 ] && ok concurrent_sessions || bad concurrent_sessions "${e:0:100}"; }

# Two sessions writing one shared file under a lock, the way a build cache does.
# The winner's content must be one of the two whole writes, never a mixture.
sharedlock(){
  local pids=() pid rc=0
  printf 'init' > "$R/shared.cache" || return 1
  local i
  for i in 1 2; do
    (
      local t
      for t in $(seq 1 20); do
        ( set -C; printf 'writer-%d-%d' "$i" "$t" > "$R/shared.lock" ) 2>/dev/null || { sleep 0.01; continue; }
        printf 'writer-%d-%d' "$i" "$t" > "$R/shared.cache" || true
        rm -f "$R/shared.lock"
      done
    ) &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
  [ $rc -eq 0 ] || { echo "a writer exited nonzero"; return 1; }
  local v; v=$(cat "$R/shared.cache")
  case "$v" in
    writer-[12]-[0-9]*) return 0 ;;
    *) echo "torn content=${v:0:40}"; return 1 ;;
  esac
}
t_sharedlock(){ local e; e=$(sharedlock 2>&1); [ $? -eq 0 ] && ok shared_file_under_lock || bad shared_file_under_lock "${e:0:100}"; }

# A long-lived process holding files open while another session rearranges the
# tree: the holder's descriptors must keep working.
holder(){
  local d=$R/live
  mkdir -p "$d" || return 1
  printf 'original' > "$d/data.txt" || return 1
  exec 5<"$d/data.txt" || return 1
  # Replace the name with a new file, the way editors and state writers save.
  # A descriptor keeps the inode it opened, so it still reads the old bytes;
  # only an in-place rewrite is visible to a holder, and that is not this.
  printf 'replacement' > "$d/.data.tmp" || return 1
  mv "$d/.data.tmp" "$d/data.txt" || return 1
  local fromfd; fromfd=$(dd bs=64 count=1 <&5 2>/dev/null)
  exec 5<&-
  [ "$fromfd" = original ] || { echo "fd saw=${fromfd:0:30}"; return 1; }
  [ "$(cat "$d/data.txt")" = replacement ] || { echo "new content wrong"; return 1; }
}
t_holder(){ local e; e=$(holder 2>&1); [ $? -eq 0 ] && ok open_fd_survives_rewrite || bad open_fd_survives_rewrite "${e:0:100}"; }

# Many files created in a loop the way a tool writes a cache directory: the
# listing afterwards must be exactly what was written, no duplicates or ghosts.
cachedir(){
  local d=$R/cache
  mkdir -p "$d" || return 1
  local i
  for i in $(seq 1 200); do
    printf 'x' > "$d/entry-$i" || { echo "write $i"; return 1; }
  done
  local n; n=$(ls -1 "$d" | wc -l)
  [ "$n" = 200 ] || { echo "listed=$n want 200"; return 1; }
  ls -1 "$d" | sort -u | wc -l | grep -qx 200 || { echo "duplicate names listed"; return 1; }
}
t_cachedir(){ local e; e=$(cachedir 2>&1); [ $? -eq 0 ] && ok cache_directory || bad cache_directory "${e:0:100}"; }

# Removing an entire cache while another session is reading it: the reader may
# fail, but must fail cleanly and leave nothing behind.
rmwhile(){
  local d=$R/victim
  mkdir -p "$d" || return 1
  local i
  for i in $(seq 1 100); do printf 'v' > "$d/f$i"; done
  ( sleep 0.02; rm -rf "$d" ) &
  local j pid=$!
  for j in $(seq 1 100); do cat "$d/f$j" >/dev/null 2>&1 || true; done
  wait "$pid" || { echo "remover failed"; return 1; }
  [ ! -e "$d" ] || { echo "tree survived removal"; return 1; }
}
t_rmwhile(){ local e; e=$(rmwhile 2>&1); [ $? -eq 0 ] && ok remove_while_reading || bad remove_while_reading "${e:0:100}"; }

# A tool that writes a file, syncs, then renames it into place — the durable
# pattern a state file uses. After the rename the destination must be readable
# and the source gone.
durable_rename(){
  local dst=$R/state.json src=$R/state.json.new
  printf '{"gen":1}' > "$src" || return 1
  sync
  mv "$src" "$dst" || return 1
  [ "$(cat "$dst")" = '{"gen":1}' ] || { echo "dst=$(cat "$dst" 2>&1)"; return 1; }
  [ ! -e "$src" ] || { echo "source left behind"; return 1; }
  # and a second generation replaces it the same way
  printf '{"gen":2}' > "$src" || return 1
  sync
  mv "$src" "$dst" || return 1
  [ "$(cat "$dst")" = '{"gen":2}' ] || { echo "gen2=$(cat "$dst" 2>&1)"; return 1; }
}
t_durable_rename(){ local e; e=$(durable_rename 2>&1); [ $? -eq 0 ] && ok durable_state_file || bad durable_state_file "${e:0:100}"; }

# Interleaved read and write on one descriptor, which is how a log tailer and a
# writer share a file.
readwrite_mix(){
  local f=$R/mix.log
  : > "$f" || return 1
  local i
  for i in $(seq 1 20); do printf 'line %d\n' "$i" >> "$f" || return 1; done
  local first; first=$(head -1 "$f") || return 1
  [ "$first" = "line 1" ] || { echo "first=$first"; return 1; }
  local last; last=$(tail -1 "$f") || return 1
  [ "$last" = "line 20" ] || { echo "last=$last"; return 1; }
  local n; n=$(wc -l < "$f")
  [ "$n" = 20 ] || { echo "lines=$n"; return 1; }
}
t_readwrite_mix(){ local e; e=$(readwrite_mix 2>&1); [ $? -eq 0 ] && ok sequential_read_write || bad sequential_read_write "${e:0:100}"; }

# A process that exits leaves no descriptor-based leftovers: every file it
# created is either complete or absent, never truncated.
process_exit(){
  local d=$R/exit
  mkdir -p "$d" || return 1
  ( for i in $(seq 1 50); do printf 'complete-%d' "$i" > "$d/f$i"; done; exit 0 ) || return 1
  local bad_count=0 i v
  for i in $(seq 1 50); do
    v=$(cat "$d/f$i" 2>/dev/null)
    [ "$v" = "complete-$i" ] || bad_count=$((bad_count+1))
  done
  [ "$bad_count" = 0 ] || { echo "incomplete=$bad_count"; return 1; }
}
t_process_exit(){ local e; e=$(process_exit 2>&1); [ $? -eq 0 ] && ok clean_process_exit || bad clean_process_exit "${e:0:100}"; }

t_sessions
t_sharedlock
t_holder
t_cachedir
t_rmwhile
t_durable_rename
t_readwrite_mix
t_process_exit
