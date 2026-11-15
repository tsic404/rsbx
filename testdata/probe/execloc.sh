#!/bin/bash
# A directory the policy uses to decide where programs run also holds ordinary
# files. This checks the two are told apart: a program is redirected or run
# here, and everything else is data.
set -u
D=${RSBX_EXEC_DIR:-/opt/tools}
R=${RSBX_PROJ:-/proj/execloc}
# The working directory doubles as the exec directory under test, so it is never
# cleaned wholesale: the probes themselves may live there, and deleting the
# directory's contents deletes the script that is running. Each check removes
# only the names it created instead.
mkdir -p "$R" || { echo "FAIL setup: cannot create $R"; exit 1; }
cd "$R" || exit 1

ok(){ echo "OK $1"; }
bad(){ echo "FAIL $1: $2"; }
skip(){ echo "SKIP $1: $2"; }

[ -d "$D" ] || { skip exec_dir_checks "$D absent in this configuration"; exit 0; }
# The directory has to be writable for these checks; a read-only exec directory
# such as /usr/bin is covered by the larger workloads.
if ! : > "$D/.probe-writable" 2>/dev/null; then
  skip exec_dir_checks "$D is not writable here"
  exit 0
fi
rm -f "$D/.probe-writable"

# A file created in an exec directory is data, with its own size and content.
# Serving it as the trampoline would report a 3 MB file and hand back ELF.
new_file_is_data(){
  local f=$D/new-note.txt
  : > "$f" || return 1
  local sz; sz=$(stat -c %s "$f") || return 1
  [ "$sz" = 0 ] || { echo "size=$sz"; return 1; }
  printf 'hello' > "$f" || return 1
  sz=$(stat -c %s "$f")
  [ "$sz" = 5 ] || { echo "size after write=$sz"; return 1; }
  [ "$(cat "$f")" = hello ] || { echo "content=$(cat "$f" 2>&1)"; return 1; }
  rm -f "$f"
}
t_new_file_is_data(){ local e; e=$(new_file_is_data 2>&1); [ $? -eq 0 ] && ok exec_dir_new_file_is_data || bad exec_dir_new_file_is_data "${e:0:100}"; }

# A data file that is not executable stays data even if it is large.
data_file_stays_data(){
  local f=$D/blob.dat
  head -c 4096 /dev/zero > "$f" || return 1
  local sz; sz=$(stat -c %s "$f")
  [ "$sz" = 4096 ] || { echo "size=$sz"; return 1; }
  rm -f "$f"
}
t_data_file_stays_data(){ local e; e=$(data_file_stays_data 2>&1); [ $? -eq 0 ] && ok exec_dir_data_file_stays_data || bad exec_dir_data_file_stays_data "${e:0:100}"; }

# A script written into the exec directory can be read back byte for byte. A
# tool that installs a helper script here must not receive a binary instead.
script_roundtrip(){
  local f=$D/helper.sh
  printf '#!/bin/sh\necho helper-ran\n' > "$f" || return 1
  chmod +x "$f" 2>/dev/null || true
  local got; got=$(cat "$f")
  case "$got" in
    '#!/bin/sh'*) return 0 ;;
  esac
  echo "content=$(printf '%.20s' "$got")"; return 1
}
t_script_roundtrip(){ local e; e=$(script_roundtrip 2>&1); [ $? -eq 0 ] && ok exec_dir_script_roundtrip || bad exec_dir_script_roundtrip "${e:0:100}"; }

# A subdirectory of the exec directory is a directory, not a trampoline.
subdir_is_directory(){
  local d=$D/subdir
  mkdir -p "$d" || return 1
  [ -d "$d" ] || { echo "not a directory"; return 1; }
  printf 'x' > "$d/f.txt" || return 1
  [ "$(cat "$d/f.txt")" = x ] || { echo "child read failed"; return 1; }
  rm -rf "$d"
}
t_subdir_is_directory(){ local e; e=$(subdir_is_directory 2>&1); [ $? -eq 0 ] && ok exec_dir_subdir_is_directory || bad exec_dir_subdir_is_directory "${e:0:100}"; }

# Many files created in quick succession, each with its own content.
many_files_distinct(){
  local i
  for i in $(seq 1 20); do printf 'n%d' "$i" > "$D/m$i.txt" || return 1; done
  for i in $(seq 1 20); do
    [ "$(cat "$D/m$i.txt")" = "n$i" ] || { echo "m$i=$(cat "$D/m$i.txt" 2>&1)"; break; }
  done
  local rc=$?
  rm -f "$D"/m*.txt
  return $rc
}
t_many_files_distinct(){ local e; e=$(many_files_distinct 2>&1); [ $? -eq 0 ] && ok exec_dir_many_files || bad exec_dir_many_files "${e:0:100}"; }

# Editing a file in place, the way a config file is edited.
in_place_edit(){
  local f=$D/conf.txt
  printf 'a=1\nb=2\n' > "$f" || return 1
  sed -i 's/b=2/b=3/' "$f" 2>/dev/null || { echo "sed failed"; return 1; }
  grep -q 'b=3' "$f" || { echo "edit lost: $(cat "$f" | tr '\n' ' ')"; return 1; }
  rm -f "$f"
}
t_in_place_edit(){ local e; e=$(in_place_edit 2>&1); [ $? -eq 0 ] && ok exec_dir_in_place_edit || bad exec_dir_in_place_edit "${e:0:100}"; }

t_new_file_is_data
t_data_file_stays_data
t_script_roundtrip
t_subdir_is_directory
t_many_files_distinct
t_in_place_edit
