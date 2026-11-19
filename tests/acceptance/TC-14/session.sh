#!/bin/bash
# The local entry of one TC-14 scene.
#
# It starts exactly the two processes the design names and then stays alive
# until the session is ended from outside:
#
#   * a long command that runs on the daemon. /bin/sh is not in local.allow,
#     so that exec is routed there; the loop reports the init it really sees
#     and heartbeats into the daemon's own tree.
#   * a local descendant started through setsid(1), so it holds its own
#     session and process group. A kill aimed at this shell's process group
#     would miss it; only reclamation scoped to the whole session reaches it.
#
# Nothing here asserts placement: each process records the init the kernel
# shows it, and the carrier compares that with the init measured on each side.
#
# Arguments: MARK WORK REMOTE DETACH SETSID.
set -u
set -f
mark=$1
work=$2
remote=$3
detach=$4
setsid=$5

# The kernel's own record of this shell: field 5 is the process group, field 6
# the session. `comm` is "(bash)" here, so stripping through ") " is exact.
read -r line < /proc/self/stat
line=${line##*) }
set -- $line
entry_pgrp=$3
entry_sid=$4
IFS= read -r init < /proc/1/comm
printf 'MARK=%s\nINIT=%s\nPID=%s\nPGRP=%s\nSID=%s\n' \
  "$mark" "$init" "$$" "$entry_pgrp" "$entry_sid" > "$work/entry.record"

# The remote long command. argv[0] carries the marker, so the daemon-side
# process is named from its own command line rather than from a container.
( exec -a "$mark-remote" /bin/sh -c '
    IFS= read -r i < /proc/1/comm
    printf "INIT=%s\n" "$i" > "$0"
    while :; do
      printf "tick\n" >> "$1"
      sleep 0.2
    done
  ' "$remote/remote.record" "$remote/remote.beat" ) &

"$setsid" "$detach" --child "$mark-local" "$work" &

wait
