#!/bin/bash
# The read cache: several sessions reading the same remote file at once, and a
# file that changes underneath them.
#
# A cache entry is a path hash plus a stamp of the daemon's metadata. Two
# sessions fetching at once must not see a half-written entry, and a changed
# file must not be served from a stale one.
set -u
R=${RSBX_PROJ:-/proj/cache}
mkdir -p "$R" 2>/dev/null
if [ -d "$R" ]; then find "$R" -mindepth 1 -delete 2>/dev/null; fi
mkdir -p "$R" || { echo "FAIL setup: cannot create $R"; exit 1; }
cd "$R" || exit 1

ok(){ echo "OK $1"; }
bad(){ echo "FAIL $1: $2"; }
skip(){ echo "SKIP $1: $2"; }

# Concurrent readers of one file must all see the same complete content.
concurrent_read(){
  local f=$R/big.txt
  seq 1 5000 > "$f" || return 1
  local want; want=$(wc -l < "$f")
  [ "$want" = 5000 ] || { echo "seed=$want"; return 1; }
  local i bad=0
  for i in $(seq 1 8); do
    ( local n; n=$(wc -l < "$f"); [ "$n" = 5000 ] || exit 1 ) &
  done
  wait
}
t_concurrent_read(){ local e; e=$(concurrent_read 2>&1); [ $? -eq 0 ] && ok concurrent_read || bad concurrent_read "${e:0:100}"; }

# A file rewritten between reads must never be served from the old copy. The
# reader may see the old or the new content, but the size must match what it
# reads.
rewrite_consistency(){
  local f=$R/state.txt
  printf 'version-1-aaaaaaaaaa' > "$f" || return 1
  local i
  for i in 1 2 3 4 5; do
    printf 'version-%d-%s' "$i" "$(printf 'b%.0s' $(seq 1 $((i * 5))))" > "$f" || return 1
    local size got
    size=$(stat -c %s "$f")
    got=$(cat "$f")
    [ "${#got}" = "$size" ] || { echo "read ${#got} stat $size"; return 1; }
  done
}
t_rewrite_consistency(){ local e; e=$(rewrite_consistency 2>&1); [ $? -eq 0 ] && ok rewrite_consistency || bad rewrite_consistency "${e:0:100}"; }

# A read-only open of a remote file, then the file is deleted: the holder keeps
# the content it opened on.
deleted_after_open(){
  local f=$R/gone.txt
  printf 'keep-me' > "$f" || return 1
  exec 6<"$f" || return 1
  rm -f "$f" || return 1
  local got; got=$(cat <&6)
  exec 6<&-
  [ "$got" = keep-me ] || { echo "got=$got"; return 1; }
  [ ! -e "$f" ] || { echo "name returned"; return 1; }
}
t_deleted_after_open(){ local e; e=$(deleted_after_open 2>&1); [ $? -eq 0 ] && ok deleted_after_open || bad deleted_after_open "${e:0:100}"; }

# Same-size rewrite with the same second timestamp: the stamp cannot tell them
# apart, so the content must still be correct. This is the case a cache keyed on
# size and mtime gets wrong.
same_size_same_mtime(){
  local f=$R/same.txt
  printf 'AAAAAAAAAA' > "$f" || return 1
  local t; t=$(stat -c %Y "$f")
  printf 'BBBBBBBBBB' > "$f" || return 1
  touch -d "@$t" "$f" 2>/dev/null || true
  local got; got=$(cat "$f")
  [ "$got" = BBBBBBBBBB ] || { echo "got=$got"; return 1; }
}
t_same_size_same_mtime(){ local e; e=$(same_size_same_mtime 2>&1); [ $? -eq 0 ] && ok same_size_same_mtime || bad same_size_same_mtime "${e:0:100}"; }

# Reading a large file in pieces must give the same bytes as reading it whole.
partial_reads(){
  local f=$R/chunks.bin
  python3 -c "
import sys
sys.stdout.buffer.write(bytes((i % 251) for i in range(200000)))
" > "$f" || return 2
  local whole sum1 sum2
  whole=$(sha256sum < "$f" | cut -d' ' -f1)
  sum2=$(cat "$f" | sha256sum | cut -d' ' -f1)
  [ "$whole" = "$sum2" ] || { echo "pipe differs"; return 1; }
  # head/tail boundary consistency
  local a b
  a=$(head -c 100000 "$f" | sha256sum | cut -d' ' -f1)
  b=$(tail -c 100000 "$f" | sha256sum | cut -d' ' -f1)
  [ "$a" != "$b" ] || true
  local total; total=$( (head -c 100000 "$f"; tail -c 100000 "$f") | wc -c )
  [ "$total" = 200000 ] || { echo "split total=$total"; return 1; }
}
t_partial_reads(){ if ! command -v python3 >/dev/null 2>&1; then skip partial_reads "python3 absent"; return; fi
  local e; e=$(partial_reads 2>&1); local r=$?; if [ $r -eq 2 ]; then skip partial_reads "python3 failed"; elif [ $r -eq 0 ]; then ok partial_reads; else bad partial_reads "${e:0:100}"; fi; }

# A write followed immediately by a read of the same path must see the write,
# even though the cache may still hold the pre-write copy.
write_then_read(){
  local f=$R/wr.txt
  local i
  for i in $(seq 1 20); do
    printf 'gen-%d' "$i" > "$f" || return 1
    local got; got=$(cat "$f")
    [ "$got" = "gen-$i" ] || { echo "iter $i got=$got"; return 1; }
  done
}
t_write_then_read(){ local e; e=$(write_then_read 2>&1); [ $? -eq 0 ] && ok write_then_read || bad write_then_read "${e:0:100}"; }

t_concurrent_read
t_rewrite_consistency
t_deleted_after_open
t_same_size_same_mtime
t_partial_reads
t_write_then_read
