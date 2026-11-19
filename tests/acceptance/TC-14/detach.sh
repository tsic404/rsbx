#!/bin/bash
# The local descendant TC-14 needs: it runs on this machine and has left the
# entry's session and process group (setsid(1) did that before this script
# started), so a kill aimed at the entry's process group misses it.
#
# It records what the kernel says about it and then heartbeats until the
# session tears it down. Only shell builtins and the allowlisted sleep are
# used: any other program would become an execution subject of its own, and
# this process has to stay on this machine.
#
# Arguments: --child MARK WORK
set -u
set -f
[ "${1:-}" = --child ] || {
  printf 'usage: %s --child MARK WORK\n' "$0" >&2
  exit 2
}
mark=$2
work=$3

read -r line < /proc/self/stat
line=${line##*) }
set -- $line
pgrp=$3
sid=$4
IFS= read -r init < /proc/1/comm
printf 'MARK=%s\nINIT=%s\nPID=%s\nPGRP=%s\nSID=%s\n' \
  "$mark" "$init" "$$" "$pgrp" "$sid" > "$work/detached.record"

while :; do
  printf 'tick\n' >> "$work/detached.beat"
  sleep 0.2
done
