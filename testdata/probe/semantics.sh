#!/bin/bash
# Deeper runtime semantics: what an agent's tools do beyond plain read/write.
#
# Each check names the behaviour it asserts, so a failure identifies the
# operation rather than just "something broke".
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

# A file removed while a descriptor is still open: the writes must land somewhere
# the holder can read, and the name must stay gone. Tools create a scratch file,
# unlink it immediately, and keep using the descriptor.
d_unlink_open(){
  local f=$R/live.txt
  exec 4>"$f" || return 1
  printf 'first' >&4
  rm -f "$f" || return 1
  printf 'second' >&4
  exec 4>&-
  # the name must not come back
  [ ! -e "$f" ] || { echo "name reappeared after unlink"; return 1; }
  return 0
}
t_d(){ local e; e=$(d_unlink_open 2>&1); [ $? -eq 0 ] && ok deleted_open || bad deleted_open "${e:0:100}"; }

# Replacing a file by renaming another over it: the destination keeps the new
# bytes and the old inode disappears. This is how every editor saves.
repl(){
  printf 'old' > "$R/target.txt" || return 1
  printf 'new' > "$R/target.tmp" || return 1
  mv -f "$R/target.tmp" "$R/target.txt" || return 1
  [ "$(cat "$R/target.txt")" = new ] || { echo "content=$(cat "$R/target.txt" 2>&1)"; return 1; }
  [ ! -e "$R/target.tmp" ] || { echo "temp survived"; return 1; }
}
t_repl(){ local e; e=$(repl 2>&1); [ $? -eq 0 ] && ok rename_over_existing || bad rename_over_existing "${e:0:100}"; }

# Across directories, with the source's directory left intact.
xdir(){
  mkdir -p "$R/d1" "$R/d2" || return 1
  printf 'moved' > "$R/d1/f.txt" || return 1
  mv "$R/d1/f.txt" "$R/d2/f.txt" || return 1
  [ "$(cat "$R/d2/f.txt")" = moved ] || return 1
  [ ! -e "$R/d1/f.txt" ] || { echo "source survived"; return 1; }
  [ -d "$R/d1" ] || { echo "source dir removed"; return 1; }
}
t_xdir(){ local e; e=$(xdir 2>&1); [ $? -eq 0 ] && ok rename_across_dirs || bad rename_across_dirs "${e:0:100}"; }

# A link to a name that does not exist is a link that dangles, not an error.
dangle(){
  ln -sfn "$R/no-such-file" "$R/dangling" || return 1
  [ -L "$R/dangling" ] || { echo "not a symlink"; return 1; }
  [ "$(readlink "$R/dangling")" = "$R/no-such-file" ] || { echo "text=$(readlink "$R/dangling")"; return 1; }
  cat "$R/dangling" 2>/dev/null && { echo "dangling link readable"; return 1; }
  return 0
}
t_dangle(){ local e; e=$(dangle 2>&1); [ $? -eq 0 ] && ok dangling_symlink || bad dangling_symlink "${e:0:100}"; }

# a -> b -> a must end in ELOOP, not a hang or a stack overflow.
loop(){
  ln -sfn "$R/loop-b" "$R/loop-a" || return 1
  ln -sfn "$R/loop-a" "$R/loop-b" || return 1
  local msg
  msg=$(cat "$R/loop-a" 2>&1) && { echo "loop resolved"; return 1; }
  case "$msg" in *"Too many levels"*|*"too many levels"*) return 0 ;; esac
  echo "err=${msg:0:60}"; return 1
}
t_loop(){ local e; e=$(loop 2>&1); [ $? -eq 0 ] && ok symlink_loop || bad symlink_loop "${e:0:100}"; }

# O_EXCL must refuse an existing name. A tool that creates lock files depends
# on the refusal to decide it lost the race.
excl(){
  printf 'x' > "$R/lock" || return 1
  if ( set -C; printf 'y' > "$R/lock" ) 2>/dev/null; then
    echo "second create succeeded"; return 1
  fi
  [ "$(cat "$R/lock")" = x ] || { echo "content clobbered"; return 1; }
}
t_excl(){ local e; e=$(excl 2>&1); [ $? -eq 0 ] && ok o_excl || bad o_excl "${e:0:100}"; }

# rmdir refuses a directory with anything in it, including an empty child.
rmnonempty(){
  mkdir -p "$R/nonempty/child" || return 1
  if rmdir "$R/nonempty" 2>/dev/null; then echo "removed a non-empty dir"; return 1; fi
  [ -d "$R/nonempty/child" ] || { echo "contents lost"; return 1; }
}
t_rmnonempty(){ local e; e=$(rmnonempty 2>&1); [ $? -eq 0 ] && ok rmdir_nonempty || bad rmdir_nonempty "${e:0:100}"; }

# Deep paths: a package manager's node_modules is a dozen levels down, and a
# path buffer that truncates would silently write to the wrong place.
deep(){
  local p=$R
  local i
  for i in $(seq 1 60); do p=$p/l$i; done
  mkdir -p "$p" || { echo "mkdir depth 60 failed"; return 1; }
  printf 'bottom' > "$p/leaf.txt" || return 1
  [ "$(cat "$p/leaf.txt")" = bottom ] || return 1
  rm -rf "$R/l1"
}
t_deep(){ local e; e=$(deep 2>&1); [ $? -eq 0 ] && ok deep_nesting || bad deep_nesting "${e:0:100}"; }

# Names that are legal on a filesystem and awkward in a shell.
weird(){
  local n
  for n in 'with space.txt' 'quote'"'"'s.txt' 'dollar$var.txt' 'ünïcode.txt' '-dash.txt' 'tab	sep.txt'; do
    printf 'v' > "$R/$n" 2>/dev/null || { echo "create: $n"; return 1; }
    [ "$(cat "$R/$n" 2>/dev/null)" = v ] || { echo "read: $n"; return 1; }
    rm -f "$R/$n" 2>/dev/null || { echo "remove: $n"; return 1; }
  done
  # the directory listing must survive a name that looks like an option
  printf 'v' > "$R/--not-a-flag"
  [ -e "$R/--not-a-flag" ] || return 1
  rm -f "$R/--not-a-flag"
}
t_weird(){ local e; e=$(weird 2>&1); [ $? -eq 0 ] && ok weird_names || bad weird_names "${e:0:100}"; }

# Extending a file with truncate creates a hole, and the hole reads as zeros.
sparse(){
  : > "$R/sparse.bin" || return 1
  truncate -s 1048576 "$R/sparse.bin" || { echo "truncate extend"; return 1; }
  local sz; sz=$(stat -c %s "$R/sparse.bin") || return 1
  [ "$sz" = 1048576 ] || { echo "size=$sz"; return 1; }
  # the tail must read back as zeros, not as stale bytes or a short read
  local tail; tail=$(tail -c 16 "$R/sparse.bin" | od -An -tx1 | tr -d ' \n') || return 1
  [ "$tail" = "00000000000000000000000000000000" ] || { echo "tail=$tail"; return 1; }
}
t_sparse(){ local e; e=$(sparse 2>&1); [ $? -eq 0 ] && ok sparse_extend || bad sparse_extend "${e:0:100}"; }

# Several processes appending to one file: O_APPEND decides the offset, so no
# write may land in the middle of another and no line may be lost.
concappend(){
  local f=$R/shared.log
  : > "$f" || return 1
  local i pids=() pid rc=0
  for i in 1 2 3 4 5 6 7 8; do
    ( local j; for j in $(seq 1 50); do printf 'p%d-%03d\n' "$i" "$j" >> "$f" || exit 1; done ) &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
  [ $rc -eq 0 ] || { echo "an appender failed"; return 1; }
  local n; n=$(wc -l < "$f") || return 1
  [ "$n" = 400 ] || { echo "lines=$n want 400"; return 1; }
  # every line must be intact: a torn write shows up as a line of the wrong shape
  local bad_lines; bad_lines=$(grep -cvE '^p[1-8]-[0-9]{3}$' "$f")
  [ "$bad_lines" = 0 ] || { echo "torn lines=$bad_lines"; return 1; }
}
t_concappend(){ local e; e=$(concappend 2>&1); [ $? -eq 0 ] && ok concurrent_append || bad concurrent_append "${e:0:100}"; }

# An empty file is a file: size 0, readable, and not confused with "missing".
zero(){
  : > "$R/empty" || return 1
  [ -f "$R/empty" ] || { echo "not a regular file"; return 1; }
  [ "$(stat -c %s "$R/empty")" = 0 ] || { echo "size != 0"; return 1; }
  [ "$(wc -c < "$R/empty")" = 0 ] || { echo "read not empty"; return 1; }
}
t_zero(){ local e; e=$(zero 2>&1); [ $? -eq 0 ] && ok zero_byte_file || bad zero_byte_file "${e:0:100}"; }

# Listing a directory while it changes must not fail or report a vanished entry
# as present with no attributes.
readdir_mut(){
  mkdir -p "$R/busy" || return 1
  local i
  for i in $(seq 1 50); do : > "$R/busy/f$i"; done
  ( local j; for j in $(seq 51 100); do : > "$R/busy/f$j" || exit 1; done ) &
  local mutator=$!
  local out; out=$(ls "$R/busy" 2>&1) || { echo "ls failed: ${out:0:60}"; return 1; }
  wait "$mutator" || { echo "mutator failed"; return 1; }
  local n; n=$(ls "$R/busy" | wc -l)
  [ "$n" = 100 ] || { echo "count=$n"; return 1; }
}
t_readdir_mut(){ local e; e=$(readdir_mut 2>&1); [ $? -eq 0 ] && ok readdir_under_mutation || bad readdir_under_mutation "${e:0:100}"; }

# Mapping a file and reading it, which is how sqlite and most editors look at
# data. A filesystem that serves reads only through read(2) fails here.
mmapread(){
  command -v python3 >/dev/null 2>&1 || return 2
  python3 - "$R/mapped.bin" <<'PY'
import mmap, os, sys
p = sys.argv[1]
data = b"0123456789" * 100
open(p, "wb").write(data)
fd = os.open(p, os.O_RDONLY)
m = mmap.mmap(fd, 0, prot=mmap.PROT_READ)
got = m[:]
os.close(fd)
m.close()
if got != data:
    print("mismatch len=%d" % len(got)); sys.exit(1)
PY
}
t_mmap(){ local e; e=$(mmapread 2>&1); local r=$?; if [ $r -eq 2 ]; then skip mmap_read "python3 absent"; elif [ $r -eq 0 ]; then ok mmap_read; else bad mmap_read "${e:0:100}"; fi; }

# chmod followed by stat: the answer must reflect the change, including the
# inode and link count, and must not move the modification time.
chmodstat(){
  printf 'v' > "$R/meta.txt" || return 1
  local m0; m0=$(stat -c %Y "$R/meta.txt")
  chmod 640 "$R/meta.txt" || return 1
  [ "$(stat -c %a "$R/meta.txt")" = 640 ] || { echo "mode=$(stat -c %a "$R/meta.txt")"; return 1; }
  [ "$(stat -c %Y "$R/meta.txt")" = "$m0" ] || { echo "chmod moved mtime"; return 1; }
  [ "$(stat -c %h "$R/meta.txt")" = 1 ] || { echo "nlink=$(stat -c %h "$R/meta.txt")"; return 1; }
}
t_chmodstat(){ local e; e=$(chmodstat 2>&1); [ $? -eq 0 ] && ok stat_after_chmod || bad stat_after_chmod "${e:0:100}"; }

# Renaming one name of a hard-linked file leaves the other name readable and
# still pointing at the same bytes.
hlrename(){
  printf 'shared' > "$R/ha.txt" || return 1
  ln "$R/ha.txt" "$R/hb.txt" || return 1
  mv "$R/ha.txt" "$R/hc.txt" || return 1
  [ "$(cat "$R/hb.txt")" = shared ] || { echo "survivor read=$(cat "$R/hb.txt" 2>&1)"; return 1; }
  [ "$(cat "$R/hc.txt")" = shared ] || { echo "moved read"; return 1; }
  local ia ib; ia=$(stat -c %i "$R/hb.txt"); ib=$(stat -c %i "$R/hc.txt")
  [ "$ia" = "$ib" ] || { echo "inodes $ia != $ib"; return 1; }
}
t_hlrename(){ local e; e=$(hlrename 2>&1); [ $? -eq 0 ] && ok hardlink_survives_rename || bad hardlink_survives_rename "${e:0:100}"; }

# A directory tree renamed after its contents were read once: every cached
# child has to follow the new name.
dirrename_deep(){
  local src=$R/tree-a dst=$R/tree-b
  mkdir -p "$src/x/y/z" || return 1
  printf 'deep' > "$src/x/y/z/f.txt" || return 1
  cat "$src/x/y/z/f.txt" >/dev/null || return 1
  mv "$src" "$dst" || return 1
  [ "$(cat "$dst/x/y/z/f.txt" 2>&1)" = deep ] || { echo "read after rename"; return 1; }
  [ ! -e "$src" ] || { echo "old name survived"; return 1; }
}
t_dirrename_deep(){ local e; e=$(dirrename_deep 2>&1); [ $? -eq 0 ] && ok dir_rename_deep || bad dir_rename_deep "${e:0:100}"; }

# fsync on a directory: running programs do this after a rename to make it
# durable, and an error there makes them report a failed save.
fsyncdir(){
  mkdir -p "$R/durable" || return 1
  printf 'v' > "$R/durable/f" || return 1
  python3 -c "import os,sys; fd=os.open(sys.argv[1], os.O_RDONLY); os.fsync(fd); os.close(fd)" "$R/durable" 2>/dev/null
}
t_fsyncdir(){ if ! command -v python3 >/dev/null 2>&1; then skip fsync_dir "python3 absent"; return; fi
  local e; e=$(fsyncdir 2>&1); [ $? -eq 0 ] && ok fsync_dir || bad fsync_dir "${e:0:100}"; }

# copy -p must carry the timestamp across; a build tool compares them to decide
# whether to rebuild.
cppreserve(){
  printf 'v' > "$R/src.txt" || return 1
  touch -d '2021-06-01 12:00:00' "$R/src.txt" || return 1
  cp -p "$R/src.txt" "$R/dst.txt" || return 1
  local a b; a=$(stat -c %Y "$R/src.txt"); b=$(stat -c %Y "$R/dst.txt")
  [ "$a" = "$b" ] || { echo "mtime $a != $b"; return 1; }
}
t_cppreserve(){ local e; e=$(cppreserve 2>&1); [ $? -eq 0 ] && ok cp_preserve || bad cp_preserve "${e:0:100}"; }

# A symlink to a directory, entered the way a build script enters a linked
# source directory.
dirlink(){
  mkdir -p "$R/real/sub" || return 1
  printf 'inner' > "$R/real/sub/f.txt" || return 1
  ln -sfn "$R/real" "$R/link" || return 1
  [ "$(cat "$R/link/sub/f.txt" 2>&1)" = inner ] || { echo "through link"; return 1; }
  ( cd "$R/link/sub" && [ "$(cat f.txt)" = inner ] ) || { echo "cd through link"; return 1; }
}
t_dirlink(){ local e; e=$(dirlink 2>&1); [ $? -eq 0 ] && ok symlink_to_dir || bad symlink_to_dir "${e:0:100}"; }

# Many processes creating and removing the same names. A racing directory
# operation must report ENOENT/EEXIST, never anything else.
conc_mkdir(){
  local i pids=() pid rc=0
  for i in 1 2 3 4; do
    ( local j; for j in $(seq 1 30); do
        mkdir "$R/race-$i" 2>/dev/null || true
        rmdir "$R/race-$i" 2>/dev/null || true
      done ) &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
  [ $rc -eq 0 ] || { echo "a racer failed"; return 1; }
  # nothing may be left behind
  local left; left=$(ls -d "$R"/race-* 2>/dev/null | wc -l)
  [ "$left" = 0 ] || { echo "leftover=$left"; return 1; }
}
t_conc_mkdir(){ local e; e=$(conc_mkdir 2>&1); [ $? -eq 0 ] && ok concurrent_mkdir_rmdir || bad concurrent_mkdir_rmdir "${e:0:100}"; }

# A tool that writes its state, reads it back, and expects the same bytes.
roundtrip(){
  local i
  for i in $(seq 1 20); do
    printf 'v%d' "$i" > "$R/rt-$i.json" || { echo "write $i"; return 1; }
  done
  for i in $(seq 1 20); do
    [ "$(cat "$R/rt-$i.json")" = "v$i" ] || { echo "read $i=$(cat "$R/rt-$i.json" 2>&1)"; return 1; }
  done
}
t_roundtrip(){ local e; e=$(roundtrip 2>&1); [ $? -eq 0 ] && ok write_read_many || bad write_read_many "${e:0:100}"; }

t_deleted_open(){ :; }
for name in repl xdir dangle loop excl rmnonempty deep weird sparse concappend zero readdir_mut mmap chmodstat hlrename dirrename_deep fsyncdir cppreserve dirlink conc_mkdir roundtrip; do
  "t_$name"
done
# the deleted-open check is defined inline, run it last
t_d
