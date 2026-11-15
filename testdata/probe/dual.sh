#!/bin/bash
# One daemon tree, two sandboxes writing to it at once.
#
# A shared project is the real shape of an agent team: each session edits its
# own files and occasionally the same ones. The daemon has to arbitrate both
# without losing bytes, mixing writers, or letting one session see another's
# half-written work.
#
# This is a DESTRUCTIVE probe: every check wipes $TREE/shared clean. Run it
# only against a disposable daemon project tree (a throwaway volume mounted at
# TREE in the daemon's own container). It refuses to fall back to a host /proj
# and never touches a path outside $TREE.
set -u
: "${TREE:?set TREE to the sandbox path of a disposable daemon project tree, e.g. /proj}"
: "${MNT:?set MNT to a disposable client scratch home for this destructive probe}"
: "${F:?set F to the rsbx client binary to test}"
# TREE is a native daemon path: the sandbox shows the daemon's / verbatim, so
# the same string addresses the daemon's files. Refuse the roots that are
# never a project directory.
TREE=${TREE%/}
case "$TREE" in
  /|/proc|/sys|/dev|/etc|/usr|/var|/home|/root|/bin|/lib|/boot)
    echo "refusing TREE=$TREE: not a disposable project tree" >&2; exit 1 ;;
  /*) ;;
  *) echo "TREE must be an absolute daemon path: $TREE" >&2; exit 1 ;;
esac
D=${D:-$MNT}
SOCK=${SOCK:-$MNT/d.sock}
R="$TREE/shared"

ok(){ echo "OK $1"; }
bad(){ echo "FAIL $1: $2"; }

# Every launched session's status is checked: a session that dies early or is
# killed by timeout must fail the check that started it, not pass silently.
run_session(){
  local cfg=$1 script=$2
  timeout 90 "$F" -config "$MNT/cfg$cfg.toml" -- /usr/bin/bash -c "$script" 2>&1
}

# Verification goes through a session too. The client container has no bind of
# the project tree, so the only honest view of it is the one rsbx serves; a
# host path here would be the wrong filesystem entirely.
sread(){ run_session 1 "cat $1" 2>/dev/null; }
slines(){ run_session 1 "wc -l < $1" 2>/dev/null | tr -d '[:space:]'; }
reset(){ run_session 1 "rm -rf '$R' && mkdir -p '$R'"; }

# make_cfg writes a config with its own mount point and cache, so several
# sessions can run at once. A shared mount point is not a load test: it is two
# clients fighting over one directory. The base config (daemon socket, allow,
# paths) is taken from CFG_BASE when set, so the probe runs unchanged in the
# container job where the layout differs.
make_cfg(){
  local n=$1
  if [ -n "${CFG_BASE:-}" ] && [ -f "$CFG_BASE" ]; then
    sed -e "s|#MOUNT#|$MNT/sb$n|" -e "s|#CACHE#|$MNT/c$n|" -e "s|#SOCK#|$SOCK|" "$CFG_BASE" > "$MNT/cfg$n.toml"
  else
    cat > "$MNT/cfg$n.toml" <<CFG
[daemon]
transport = "unix"
socket = "$SOCK"

[local]
allow = ["/usr/bin/bash"]
paths = []
entry = "/bin/sh"

[sandbox]
mount = "$MNT/sb$n"
cache = "$MNT/c$n"
share_network = true
unshare_user = false
CFG
  fi
  mkdir -p "$MNT/sb$n"
}
make_cfg 1
make_cfg 2

# Each session appends its own lines to its own file. The daemon is one tree,
# so both files must be complete and intact afterwards.
separate_files(){
  reset || return 1
  run_session 1 "for i in \$(seq 1 40); do printf 's1-%d\n' \$i >> $R/owner-1.txt; done" &
  local p1=$!
  run_session 2 "for i in \$(seq 1 40); do printf 's2-%d\n' \$i >> $R/owner-2.txt; done" &
  local p2=$!
  local rc=0
  wait "$p1" || rc=1
  wait "$p2" || rc=1
  [ $rc -eq 0 ] || { echo "a session exited nonzero or was killed"; return 1; }
  local n1 n2 bad1 bad2
  n1=$(slines "$R/owner-1.txt")
  n2=$(slines "$R/owner-2.txt")
  [ "$n1" = 40 ] || { echo "owner-1 lines=$n1"; return 1; }
  [ "$n2" = 40 ] || { echo "owner-2 lines=$n2"; return 1; }
  bad1=$(run_session 1 "grep -cvE '^s1-[0-9]+\$' $R/owner-1.txt" 2>/dev/null)
  bad2=$(run_session 1 "grep -cvE '^s2-[0-9]+\$' $R/owner-2.txt" 2>/dev/null)
  [ "$bad1" = 0 ] || { echo "owner-1 torn=$bad1"; return 1; }
  [ "$bad2" = 0 ] || { echo "owner-2 torn=$bad2"; return 1; }
}
t_sep(){ local e; e=$(separate_files 2>&1); [ $? -eq 0 ] && ok concurrent_separate_files || bad concurrent_separate_files "${e:0:80}"; }

# Both sessions append to one file. Every line must be whole — a torn write
# shows up as a line with the wrong shape — and no line may be lost.
shared_appends(){
  reset || return 1
  run_session 1 ": > $R/shared.log" || return 1
  run_session 1 "for i in \$(seq 1 30); do printf 'A%03d\n' \$i >> $R/shared.log; done" &
  local p1=$!
  run_session 2 "for i in \$(seq 1 30); do printf 'B%03d\n' \$i >> $R/shared.log; done" &
  local p2=$!
  local rc=0
  wait "$p1" || rc=1
  wait "$p2" || rc=1
  [ $rc -eq 0 ] || { echo "a session exited nonzero or was killed"; return 1; }
  local n torn
  n=$(slines "$R/shared.log")
  [ "$n" = 60 ] || { echo "lines=$n want 60"; return 1; }
  torn=$(run_session 1 "grep -cvE '^[AB][0-9]{3}\$' $R/shared.log" 2>/dev/null)
  [ "$torn" = 0 ] || { echo "torn=$torn"; return 1; }
}
t_shared(){ local e; e=$(shared_appends 2>&1); [ $? -eq 0 ] && ok concurrent_shared_append || bad concurrent_shared_append "${e:0:80}"; }

# One session's write must be visible to the other. The daemon is the single
# truth, so a file created in one sandbox appears in the other at once.
cross_visibility(){
  reset || return 1
  run_session 1 "printf 'from-one' > $R/one.txt" || return 1
  local got
  got=$(run_session 2 "cat $R/one.txt" 2>&1)
  [ "$got" = from-one ] || { echo "second saw [$got]"; return 1; }
}
t_cross(){ local e; e=$(cross_visibility 2>&1); [ $? -eq 0 ] && ok cross_session_visibility || bad cross_session_visibility "${e:0:80}"; }

# A directory tree built by one session is complete for the other: the second
# must see every file, not a subset.
tree_visible_to_other(){
  reset || return 1
  run_session 1 "mkdir -p $R/pkg/sub && for i in \$(seq 1 30); do printf 'v%d' \$i > $R/pkg/sub/f\$i; done" || return 1
  local n
  n=$(run_session 2 "ls $R/pkg/sub | wc -l" 2>&1)
  [ "$n" = 30 ] || { echo "other saw $n files"; return 1; }
  local v
  v=$(run_session 2 "cat $R/pkg/sub/f17" 2>&1)
  [ "$v" = v17 ] || { echo "f17=[$v]"; return 1; }
}
t_tree(){ local e; e=$(tree_visible_to_other 2>&1); [ $? -eq 0 ] && ok cross_session_tree || bad cross_session_tree "${e:0:80}"; }

# Both sessions create and remove the same names. The daemon must serialise
# them: one of them wins, and neither leaves a half-made entry.
racing_names(){
  reset || return 1
  run_session 1 "for i in \$(seq 1 20); do mkdir $R/race 2>/dev/null; printf 'one' > $R/race/f 2>/dev/null; rm -rf $R/race 2>/dev/null; done" &
  local p1=$!
  run_session 2 "for i in \$(seq 1 20); do mkdir $R/race 2>/dev/null; printf 'two' > $R/race/f 2>/dev/null; rm -rf $R/race 2>/dev/null; done" &
  local p2=$!
  local rc=0
  wait "$p1" || rc=1
  wait "$p2" || rc=1
  [ $rc -eq 0 ] || { echo "a session exited nonzero or was killed"; return 1; }
  # whatever survives must be whole, not a mixture
  local out
  out=$(run_session 1 "if [ -e $R/race/f ]; then cat $R/race/f; elif [ -e $R/race ]; then echo leftover-dir; else echo none; fi" 2>&1)
  case "$out" in
    one|two) return 0 ;;
    none) return 0 ;;
    *) echo "race ended as ${out:0:20}"; return 1 ;;
  esac
}
t_race(){ local e; e=$(racing_names 2>&1); [ $? -eq 0 ] && ok racing_names || bad racing_names "${e:0:80}"; }

# Four sessions at once, each with its own project subtree. This is what a team
# of agents in one repo looks like, and it must not degrade: every subtree ends
# complete and every file matches what its owner wrote.
four_sessions(){
  reset || return 1
  # Four clients need four mount points. Two clients cannot share one: each
  # mounts its own filesystem there, and the second start finds the path busy.
  local i
  for i in 1 2 3 4; do
    make_cfg "$i"
  done
  local pids=()
  for i in 1 2 3 4; do
    run_session $i "mkdir -p $R/p$i && for j in \$(seq 1 25); do printf 'p$i-%d' \$j > $R/p$i/f\$j; done" &
    pids+=($!)
  done
  local rc=0 pid
  for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
  [ $rc -eq 0 ] || { echo "a session exited nonzero or was killed"; return 1; }
  local out
  out=$(run_session 1 '
    rc=0
    for d in p1 p2 p3 p4; do
      n=$(ls "$R/$d" 2>/dev/null | wc -l)
      [ "$n" = 25 ] || { echo "$d has $n files"; rc=1; }
      v=$(cat "$R/$d/f7" 2>/dev/null)
      [ "$v" = "${d#p}-7" ] || { echo "$d/f7=[$v]"; rc=1; }
    done
    exit $rc
  ' 2>&1)
  rc=$?
  [ $rc -eq 0 ] || { echo "${out:0:80}"; return 1; }
}
t_four(){ local e; e=$(four_sessions 2>&1); [ $? -eq 0 ] && ok four_sessions || bad four_sessions "${e:0:80}"; }

# Each session keeps its own cache directory. Two sessions reading the same
# remote file must not share a copy that one of them can invalidate.
separate_caches(){
  reset || return 1
  run_session 1 "printf 'shared-body' > $R/body.txt" || return 1
  local a b
  a=$(sread "$R/body.txt")
  b=$(run_session 2 "cat $R/body.txt" 2>/dev/null)
  [ "$a" = shared-body ] || { echo "sb1=[$a]"; return 1; }
  [ "$b" = shared-body ] || { echo "sb2=[$b]"; return 1; }
  # the caches are distinct directories, on the client side
  [ -d "$MNT/c1" ] && [ -d "$MNT/c2" ] || { echo "cache dirs missing"; return 1; }
  [ "$MNT/c1" != "$MNT/c2" ] || { echo "caches share a directory"; return 1; }
}
t_caches(){ local e; e=$(separate_caches 2>&1); [ $? -eq 0 ] && ok separate_caches || bad separate_caches "${e:0:80}"; }

# A rename while another session holds the same file open. POSIX keeps the
# holder's descriptor pointing at the same inode: it keeps reading the OLD
# bytes even though the name now resolves to the new file. This is the proof
# that session 2's handle is a real fd on the inode it opened, not a path that
# is re-resolved (or re-served from a snapshot) at read time.
same_fd_rename_consumer(){
  reset || return 1
  run_session 1 "printf 'old' > $R/f.txt" || return 1
  local out rc rc2 pw
  # Session 1 replaces f.txt by create+rename once session 2 says it holds
  # the descriptor; session 2 then reads through the fd. If the fd followed
  # the name it would read 'new'; a dropped or reopened handle would error
  # or return empty. It must read 'old'.
  run_session 1 "
    for _ in \$(seq 1 100); do [ -s $R/.ready ] && break; sleep 0.05; done
    printf 'new' > $R/f.new && mv -f $R/f.new $R/f.txt
    sleep 0.3
  " &
  pw=$!
  out=$(run_session 2 "
    exec 7<$R/f.txt || exit 3
    : > $R/.ready
    sleep 0.6
    got=\$(cat <&7)
    exec 7<&-
    [ \"\$got\" = old ] || { echo \"fd read [\$got] after rename\"; exit 1; }
    # the name itself must now serve the new bytes: the rename happened
    [ \"\$(cat $R/f.txt)\" = new ] || { echo \"name stale\"; exit 1; }
    exit 0
  " 2>&1)
  rc2=$?
  if ! wait "$pw"; then echo "renamer failed"; return 1; fi
  [ $rc2 -eq 0 ] || { echo "$out"; return 1; }
  # and the tree is left with only the new name, verified through a session
  out=$(run_session 1 "[ \"\$(cat $R/f.txt)\" = new ] && [ ! -e $R/f.new ] && echo clean || echo dirty" 2>&1)
  rc=$?
  [ $rc -eq 0 ] && [ "$out" = clean ] || { echo "final tree [$out]"; return 1; }
  run_session 1 "rm -f $R/.ready" >/dev/null 2>&1 || true
}
t_reader(){ local e; e=$(same_fd_rename_consumer 2>&1); [ $? -eq 0 ] && ok same_fd_rename_consumer || bad same_fd_rename_consumer "${e:0:80}"; }

t_sep
t_shared
t_cross
t_tree
t_race
t_four
t_caches
t_reader
