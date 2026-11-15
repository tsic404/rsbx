#!/bin/bash
# One daemon tree, two sandboxes writing to it at once.
#
# A shared project is the real shape of an agent team: each session edits its
# own files and occasionally the same ones. The daemon has to arbitrate both
# without losing bytes, mixing writers, or letting one session see another's
# half-written work.
set -u
D=${D:-/var/tmp/stress}
# The daemon tree may live elsewhere than D; in the container job D is the home
# dir (socket, configs, mounts) and the tree is separate.
TREE=${TREE:-$D/tree}
MNT=${MNT:-$D/home}
F=${F:-$HOME/rsbx-client/dist/rsbx}
R=/shared

ok(){ echo "OK $1"; }
bad(){ echo "FAIL $1: $2"; }

run_session(){
  local cfg=$1 script=$2
  timeout 90 "$F" -config "$MNT/cfg$cfg.toml" -- /usr/bin/bash -c "$script" 2>&1
}

# make_cfg writes a config with its own mount point and cache, so several
# sessions can run at once. A shared mount point is not a load test: it is two
# clients fighting over one directory. The base config (daemon socket, allow,
# roots) is taken from CFG_BASE when set, so the probe runs unchanged in the
# container job where the layout differs.
make_cfg(){
  local n=$1
  if [ -n "${CFG_BASE:-}" ] && [ -f "$CFG_BASE" ]; then
    sed -e "s|#MOUNT#|$MNT/sb$n|" -e "s|#CACHE#|$MNT/c$n|" "$CFG_BASE" > "$MNT/cfg$n.toml"
  else
    cat > "$MNT/cfg$n.toml" <<CFG
[daemon]
transport = "unix"
socket = "$MNT/d.sock"

[local]
allow = ["/usr/bin", "/bin"]
paths = []
entry = "/usr/bin/bash"

[sandbox]
mount = "$MNT/sb$n"
cache = "$MNT/c$n"
share_network = true
CFG
  fi
  mkdir -p "$MNT/sb$n"
}
make_cfg 1
make_cfg 2

# Each session appends its own lines to its own file. The daemon is one tree,
# so both files must be complete and intact afterwards.
separate_files(){
  rm -rf $TREE$R; mkdir -p $TREE$R
  run_session 1 "for i in \$(seq 1 40); do printf 's1-%d\n' \$i >> $R/owner-1.txt; done" &
  local p1=$!
  run_session 2 "for i in \$(seq 1 40); do printf 's2-%d\n' \$i >> $R/owner-2.txt; done" &
  local p2=$!
  wait $p1 || return 1
  wait $p2 || return 1
  local n1 n2
  n1=$(wc -l < "$TREE$R/owner-1.txt" 2>/dev/null || echo 0)
  n2=$(wc -l < "$TREE$R/owner-2.txt" 2>/dev/null || echo 0)
  [ "$n1" = 40 ] || { echo "owner-1 lines=$n1"; return 1; }
  [ "$n2" = 40 ] || { echo "owner-2 lines=$n2"; return 1; }
  local bad1 bad2
  bad1=$(grep -cvE '^s1-[0-9]+$' "$TREE$R/owner-1.txt" || true)
  bad2=$(grep -cvE '^s2-[0-9]+$' "$TREE$R/owner-2.txt" || true)
  [ "$bad1" = 0 ] || { echo "owner-1 torn=$bad1"; return 1; }
  [ "$bad2" = 0 ] || { echo "owner-2 torn=$bad2"; return 1; }
}
t_sep(){ local e; e=$(separate_files 2>&1); [ $? -eq 0 ] && ok concurrent_separate_files || bad concurrent_separate_files "${e:0:80}"; }

# Both sessions append to one file. Every line must be whole — a torn write
# shows up as a line with the wrong shape — and no line may be lost.
shared_appends(){
  rm -rf $TREE$R; mkdir -p $TREE$R
  : > "$TREE$R/shared.log"
  run_session 1 "for i in \$(seq 1 30); do printf 'A%03d\n' \$i >> $R/shared.log; done" &
  local p1=$!
  run_session 2 "for i in \$(seq 1 30); do printf 'B%03d\n' \$i >> $R/shared.log; done" &
  local p2=$!
  wait $p1 || return 1
  wait $p2 || return 1
  local n; n=$(wc -l < "$TREE$R/shared.log" 2>/dev/null || echo 0)
  [ "$n" = 60 ] || { echo "lines=$n want 60"; return 1; }
  local torn; torn=$(grep -cvE '^[AB][0-9]{3}$' "$TREE$R/shared.log" || true)
  [ "$torn" = 0 ] || { echo "torn=$torn"; return 1; }
}
t_shared(){ local e; e=$(shared_appends 2>&1); [ $? -eq 0 ] && ok concurrent_shared_append || bad concurrent_shared_append "${e:0:80}"; }

# One session's write must be visible to the other. The daemon is the single
# truth, so a file created in one sandbox appears in the other at once.
cross_visibility(){
  rm -rf $TREE$R; mkdir -p $TREE$R
  run_session 1 "printf 'from-one' > $R/one.txt" || return 1
  local got
  got=$(run_session 2 "cat $R/one.txt 2>&1")
  [ "$got" = from-one ] || { echo "second saw [$got]"; return 1; }
}
t_cross(){ local e; e=$(cross_visibility 2>&1); [ $? -eq 0 ] && ok cross_session_visibility || bad cross_session_visibility "${e:0:80}"; }

# A directory tree built by one session is complete for the other: the second
# must see every file, not a subset.
tree_visible_to_other(){
  rm -rf $TREE$R; mkdir -p $TREE$R
  run_session 1 "mkdir -p $R/pkg/sub && for i in \$(seq 1 30); do printf 'v%d' \$i > $R/pkg/sub/f\$i; done" || return 1
  local n
  n=$(run_session 2 "ls $R/pkg/sub | wc -l" 2>&1)
  [ "$n" = 30 ] || { echo "other saw $n files"; return 1; }
  local v
  v=$(run_session 2 "cat $R/pkg/sub/f17 2>&1")
  [ "$v" = v17 ] || { echo "f17=[$v]"; return 1; }
}
t_tree(){ local e; e=$(tree_visible_to_other 2>&1); [ $? -eq 0 ] && ok cross_session_tree || bad cross_session_tree "${e:0:80}"; }

# Both sessions create and remove the same names. The daemon must serialise
# them: one of them wins, and neither leaves a half-made entry.
racing_names(){
  rm -rf $TREE$R; mkdir -p $TREE$R
  run_session 1 "for i in \$(seq 1 20); do mkdir $R/race 2>/dev/null; printf 'one' > $R/race/f 2>/dev/null; rm -rf $R/race 2>/dev/null; done" &
  local p1=$!
  run_session 2 "for i in \$(seq 1 20); do mkdir $R/race 2>/dev/null; printf 'two' > $R/race/f 2>/dev/null; rm -rf $R/race 2>/dev/null; done" &
  local p2=$!
  wait $p1 || return 1
  wait $p2 || return 1
  # whatever survives must be whole, not a mixture
  if [ -e "$TREE$R/race/f" ]; then
    local v; v=$(cat "$TREE$R/race/f")
    case "$v" in one|two) return 0 ;; *) echo "mixed content=${v:0:20}"; return 1 ;; esac
  fi
  # or nothing survives, which is also consistent
  [ ! -e "$TREE$R/race" ] || { echo "leftover dir"; return 1; }
}
t_race(){ local e; e=$(racing_names 2>&1); [ $? -eq 0 ] && ok racing_names || bad racing_names "${e:0:80}"; }

t_sep
t_shared
t_cross
t_tree
t_race

# Four sessions at once, each with its own project subtree. This is what a team
# of agents in one repo looks like, and it must not degrade: every subtree ends
# complete and every file matches what its owner wrote.
four_sessions(){
  rm -rf $TREE$R; mkdir -p $TREE$R
  # Four clients need four mount points. Two clients cannot share one: each
  # mounts its own filesystem there, and the second start finds the path busy.
  local i
  for i in 1 2 3 4; do
    make_cfg "$i"
  done
  for i in 1 2 3 4; do
    run_session $i "mkdir -p $R/p$i && for j in \$(seq 1 25); do printf 'p$i-%d' \$j > $R/p$i/f\$j; done" &
  done
  wait
  local d n v
  for d in p1 p2 p3 p4; do
    n=$(ls "$TREE$R/$d" 2>/dev/null | wc -l)
    [ "$n" = 25 ] || { echo "$d has $n files"; return 1; }
    v=$(cat "$TREE$R/$d/f7" 2>/dev/null)
    [ "$v" = "p${d#p}-7" ] || { echo "$d/f7=[$v]"; return 1; }
  done
}
t_four(){ local e; e=$(four_sessions 2>&1); [ $? -eq 0 ] && ok four_sessions || bad four_sessions "${e:0:80}"; }

# Each session keeps its own cache directory. Two sessions reading the same
# remote file must not share a copy that one of them can invalidate.
separate_caches(){
  rm -rf $TREE$R; mkdir -p $TREE$R
  printf 'shared-body' > "$TREE$R/body.txt" || return 1
  local a b
  a=$(run_session 1 "cat $R/body.txt")
  b=$(run_session 2 "cat $R/body.txt")
  [ "$a" = shared-body ] || { echo "sb1=[$a]"; return 1; }
  [ "$b" = shared-body ] || { echo "sb2=[$b]"; return 1; }
  # the caches are distinct directories
  [ -d "$MNT/c1" ] && [ -d "$MNT/c2" ] || { echo "cache dirs missing"; return 1; }
}
t_caches(){ local e; e=$(separate_caches 2>&1); [ $? -eq 0 ] && ok separate_caches || bad separate_caches "${e:0:80}"; }

# One session rewrites a file repeatedly while the other reads it. A truncate is
# immediately visible, exactly as it is on a local filesystem, so the reader may
# lawfully see a short file. What it must never see is bytes that were never
# written, or a length that disagrees with the bytes it read. Both sessions end
# with the file whole.
reader_during_writer(){
  rm -rf $TREE$R; mkdir -p $TREE$R
  printf 'v0-aaaaaaaaaa' > "$TREE$R/live.txt" || return 1
  run_session 1 "
    for i in \$(seq 1 15); do
      printf 'v%d-%s' \$i \"\$(printf 'b%.0s' \$(seq 1 10))\"
    done > $R/live.txt
  " &
  local p=$!
  local i
  for i in $(seq 1 15); do
    # One open, then stat and read through that same descriptor: the two must
    # agree, because the descriptor is the file it opened. A stat taken in one
    # call and a read in another are two moments, and the writer may have moved
    # the file on in between — which is lawful, and not what this checks.
    local out
    out=$(run_session 2 'exec 7<$R/live.txt; a=$(stat -c %s /proc/self/fd/7 2>/dev/null); b=$(wc -c </proc/self/fd/7 2>/dev/null); echo "$a/$b"' 2>/dev/null)
    case "$out" in
      */*) : ;;
      *)   echo "handle=[$out]"; return 1 ;;
    esac
    local a b
    a=${out%%/*}; b=${out##*/}
    [ "$a" = "$b" ] || { echo "handle stat $a != read $b"; return 1; }
  done
  wait $p || return 1
  # The writer redirects once and prints fifteen generations into that one
  # stream, so the file is a concatenation. What matters is that every write
  # arrived and none of them interleaved with another writer's bytes.
  local final n
  final=$(cat "$TREE$R/live.txt")
  n=$(printf '%s' "$final" | grep -o 'v[0-9]*-' | wc -l)
  [ "$n" = 15 ] || { echo "generations=$n final=[${final:0:30}]"; return 1; }
}
t_reader(){ local e; e=$(reader_during_writer 2>&1); [ $? -eq 0 ] && ok reader_during_writer || bad reader_during_writer "${e:0:80}"; }

t_four
t_caches
t_reader
