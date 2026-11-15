#!/bin/bash
# One round of realistic agent work, run inside the sandbox.
#
# Prints "OK <name>" or "FAIL <name>: <why>" for each check and nothing else, so
# a caller can count passes and diff failures. RSBX_PROJ names the directory to
# work in; it must be on the remote tree, since everything here stands in for
# what an agent does to its project.
#
# Every check exists because it once failed:
#
#   atomic_write     rename left the inode pointing at the old path
#   append           O_APPEND writes went through WriteAt
#   ftruncate        Setattr ignored everything but size
#   symlink/hardlink Link and Symlink were unimplemented
#   chmod/utimes     Setattr reported success without changing anything
#   rmdir_tree       Rmdir was unimplemented, so rm -rf of a dir silently failed
#   rename_dir       renaming a directory left every child's path stale
#   sqlite           create truncated the file, and reads of a write handle
#                    returned empty
#   tar              the stat before and after reading disagreed on mtime
#   git_commit       link(2) produced an invisible entry; dentry caching then
#                    hid a directory created microseconds earlier
set -u
R=${RSBX_PROJ:-/proj/run}
# Start from a clean directory. Every check asserts on an exact result, so state
# left by an earlier run turns into a false failure — a leftover file makes
# "ln" fail with EEXIST and a leftover directory makes "mkdir" fail the same way.
#
# The directory itself is emptied rather than removed: $R may be the root of the
# tree under test, whose parent is not writable.
mkdir -p "$R" 2>/dev/null
if [ -d "$R" ]; then
  find "$R" -mindepth 1 -delete 2>/dev/null || rm -rf "${R:?}"/* 2>/dev/null
fi
mkdir -p "$R" || { echo "FAIL setup: cannot create $R"; exit 1; }
ok(){ echo "OK $1"; }
bad(){ echo "FAIL $1: $2"; }
# A check whose program is not installed is not a filesystem failure. Reported
# separately so a slim image can still run the rest of the suite honestly.
skip(){ echo "SKIP $1: $2"; }
t(){ local n=$1; shift; local e; e=$("$@" 2>&1); [ $? -eq 0 ] && ok "$n" || bad "$n" "${e:0:120}"; }

mkdir -p "$R/sub/deep" || bad mkdir "mkdir"
[ -d "$R/sub/deep" ] && ok mkdir_p || bad mkdir_p "missing"

# atomic write
( printf 'payload' > "$R/a.tmp" && mv "$R/a.tmp" "$R/a.txt" ) 2>/dev/null && ok atomic_write || bad atomic_write "rename"
[ "$(cat "$R/a.txt" 2>/dev/null)" = payload ] && ok atomic_read || bad atomic_read "content"

# append
( printf 'l1\n' >> "$R/log.txt"; printf 'l2\n' >> "$R/log.txt" ) 2>/dev/null && ok append || bad append "write"
[ "$(wc -l < "$R/log.txt" 2>/dev/null)" = 2 ] && ok append_lines || bad append_lines "count"

# truncate via shell redirect
( : > "$R/trunc.txt"; printf 'abc' > "$R/trunc.txt" ) 2>/dev/null && [ "$(cat "$R/trunc.txt")" = abc ] && ok truncate_redirect || bad truncate_redirect "content"
# truncate command (ftruncate)
( printf 'abcdefg' > "$R/ft.txt"; truncate -s 3 "$R/ft.txt" ) 2>/dev/null && [ "$(cat "$R/ft.txt")" = abc ] && ok ftruncate || bad ftruncate "size=$(stat -c %s "$R/ft.txt" 2>/dev/null)"

# symlink
( ln -sf "$R/a.txt" "$R/link.txt" ) 2>/dev/null && [ "$(cat "$R/link.txt" 2>/dev/null)" = payload ] && ok symlink || bad symlink "read through link"

# hard link
( ln "$R/a.txt" "$R/hard.txt" ) 2>/dev/null && ok hardlink || bad hardlink "ln"
[ "$(stat -c %h "$R/a.txt" 2>/dev/null)" = 2 ] && ok hardlink_nlink || bad hardlink_nlink "nlink=$(stat -c %h "$R/a.txt" 2>/dev/null)"

# chmod
( chmod 600 "$R/a.txt" ) 2>/dev/null && [ "$(stat -c %a "$R/a.txt" 2>/dev/null)" = 600 ] && ok chmod || bad chmod "mode=$(stat -c %a "$R/a.txt" 2>/dev/null)"

# touch -d (mtime set)
( touch -d '2020-01-01 00:00:00' "$R/a.txt" ) 2>/dev/null && [ "$(stat -c %Y "$R/a.txt" 2>/dev/null)" = 1577836800 ] && ok utimes || bad utimes "mtime=$(stat -c %Y "$R/a.txt" 2>/dev/null)"

# rm -rf dir then rmdir
mkdir -p "$R/rmme/x" 2>/dev/null; printf 'q' > "$R/rmme/x/f" 2>/dev/null
( rm -rf "$R/rmme" ) 2>/dev/null && [ ! -e "$R/rmme" ] && ok rmdir_tree || bad rmdir_tree "still exists"

# rename dir
( mkdir -p "$R/d1" && printf 'z' > "$R/d1/f" && mv "$R/d1" "$R/d2" ) 2>/dev/null && [ "$(cat "$R/d2/f" 2>/dev/null)" = z ] && ok rename_dir || bad rename_dir "content"

# sqlite (skipped where python3 is absent, as in the slim runtime image)
if command -v python3 >/dev/null 2>&1; then
  ( python3 - "$R/db.sqlite" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]); c.execute("create table t(a)"); c.executemany("insert into t values(?)",[(i,) for i in range(50)]); c.commit(); c.close()
PY
  ) >/dev/null 2>&1 && ok sqlite || bad sqlite "python sqlite"
  [ "$(python3 -c "import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute('select count(*) from t').fetchone()[0])" "$R/db.sqlite" 2>&1)" = 50 ] && ok sqlite_rows || bad sqlite_rows "count"
else
  skip sqlite "python3 absent"
  skip sqlite_rows "python3 absent"
fi

# large file + checksum
( dd if=/dev/zero of="$R/big.bin" bs=1M count=8 2>/dev/null ) && [ "$(stat -c %s "$R/big.bin")" = 8388608 ] && ok large_file || bad large_file "size"
( printf 'x' | dd of="$R/big.bin" bs=1 seek=4194304 conv=notrunc 2>/dev/null ) && ok seek_write || bad seek_write "dd seek"

# many small files
( for i in $(seq 1 100); do printf '%s' "$i" > "$R/many/$i"; done ) 2>/dev/null || mkdir -p "$R/many" 2>/dev/null
mkdir -p "$R/many" 2>/dev/null
( for i in $(seq 1 100); do printf '%s' "$i" > "$R/many/$i"; done ) 2>/dev/null
[ "$(ls "$R/many" 2>/dev/null | wc -l)" = 100 ] && ok many_files || bad many_files "count=$(ls "$R/many" 2>/dev/null|wc -l)"

# tar roundtrip
( tar -cf "$R/a.tar" -C "$R" a.txt 2>/dev/null && mkdir -p "$R/untar" && tar -xf "$R/a.tar" -C "$R/untar" ) 2>/dev/null && [ "$(cat "$R/untar/a.txt" 2>/dev/null)" = payload ] && ok tar || bad tar "roundtrip"

# git (skipped where git is absent, as in the slim runtime image)
if command -v git >/dev/null 2>&1; then
  ( cd "$R" && git init -q . && git add -A >/dev/null 2>&1 && git -c user.name=a -c user.email=a@b commit -qm m >/dev/null 2>&1 ) && ok git_commit || bad git_commit "git"
else
  skip git_commit "git absent"
fi

# readdir count vs stat
N1=$(ls -la "$R" 2>/dev/null | wc -l); N2=$(find "$R" -maxdepth 1 2>/dev/null | wc -l)
[ "$N2" -ge 5 ] && ok readdir || bad readdir "entries=$N2"

# concurrent writers, separate files
for i in 1 2 3 4; do ( for j in $(seq 1 40); do printf 'w%d-%d\n' $i $j >> "$R/conc.$i"; done ) & done; wait
[ "$(cat "$R"/conc.* 2>/dev/null | wc -l)" = 160 ] && ok concurrent || bad concurrent "lines=$(cat "$R"/conc.* 2>/dev/null|wc -l)"
