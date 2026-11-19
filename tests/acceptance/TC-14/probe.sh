#!/bin/bash
# Measures the state one TC-14 session left behind, from outside the sandbox.
#
#   probe.sh procs    count processes whose command line carries $PROBE_PAT
#   probe.sh client   count processes carrying $PROBE_PREFIX and $PROBE_LOCAL,
#                     processes whose mount table names $PROBE_MOUNT, and
#                     session-* entries under $PROBE_MOUNT_BASE and
#                     $PROBE_CACHE_BASE
#
# /proc is read directly: the slim images carry no ps, and a missing ps would
# let "no process is left" pass without anyone looking. Every pattern arrives
# in the environment, never in this script's own command line, so the scan
# cannot match itself.
set -u

count_procs(){
  local d args n=0
  for d in /proc/[0-9]*; do
    [ -r "$d/cmdline" ] || continue
    args=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null) || continue
    case $args in
      *"$1"*) n=$((n + 1)) ;;
    esac
  done
  printf '%s' "$n"
}

count_mounts(){
  local d n=0
  for d in /proc/[0-9]*; do
    [ -r "$d/mountinfo" ] || continue
    grep -Fq -- "$1" "$d/mountinfo" 2>/dev/null && n=$((n + 1))
  done
  printf '%s' "$n"
}

count_dirs(){
  ls -A "$1" 2>/dev/null | grep -c '^session-'
}

case ${1:-} in
  procs)
    printf 'procs=%s\n' "$(count_procs "${PROBE_PAT:?}")"
    ;;
  client)
    printf 'procs=%s\n' "$(count_procs "${PROBE_PREFIX:?}")"
    printf 'local=%s\n' "$(count_procs "${PROBE_LOCAL:?}")"
    printf 'mounts=%s\n' "$(count_mounts "${PROBE_MOUNT:?}")"
    printf 'mountdirs=%s\n' "$(count_dirs "${PROBE_MOUNT_BASE:?}")"
    printf 'cachedirs=%s\n' "$(count_dirs "${PROBE_CACHE_BASE:?}")"
    ;;
  *)
    printf 'usage: %s procs|client\n' "$0" >&2
    exit 2
    ;;
esac
