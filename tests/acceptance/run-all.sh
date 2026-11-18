#!/bin/bash
# Run every acceptance carrier in this repository and summarize the outcome.
#
# Each `TC-*/run.sh` is an independent carrier: it builds its own docker rig,
# states its prerequisites, and reports `OK` / `SKIP` / `FAIL` lines followed
# by a `SUMMARY` line. This entry only runs them in order and totals the three
# outcomes, which are three different facts:
#
#   OK    the design criterion held
#   SKIP  this environment cannot express the check (missing /dev/fuse, no
#         client image, no python3 for a pty harness, ...)
#   FAIL  the design criterion did not hold
#
# Exit status: 0 when every carrier passed, 1 when any carrier failed, 77 when
# nothing failed but at least one carrier could not be judged. A SKIP is never
# counted as a pass, and a failing carrier is never rescued by a skipping one.
#
# Usage:
#   bash tests/acceptance/run-all.sh              # every carrier
#   bash tests/acceptance/run-all.sh TC-1 TC-13   # just these
#   ACC_BIN=dist bash tests/acceptance/run-all.sh # binaries under test
#
# Environment:
#   ACC_BIN        directory holding rsbx/rsbxd/rsbx-tramp/rsbx-guard
#                  (default /tmp/tcbuild; when absent the images' own binaries
#                  are used and every carrier says so)
#   ACC_CLIENT_IMG image for client containers   (default rsbx:ci)
#   ACC_DAEMON_IMG image for daemon containers   (default rsbx-daemon:full)
#   CLIENT_INIT / DAEMON_INIT  expected init names (measured when unset)
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE" || exit 1

if [ $# -gt 0 ]; then
  carriers=("$@")
else
  carriers=()
  for d in TC-*/run.sh; do
    [ -f "$d" ] && carriers+=("$(dirname "$d")")
  done
fi

if [ ${#carriers[@]} -eq 0 ]; then
  echo "no carriers found under $HERE" >&2
  exit 1
fi

total_ok=0
total_skip=0
total_fail=0
failed_names=()
skipped_names=()
passed_names=()
delegated_names=()

printf '=== %d carrier(s) under %s ===\n' "${#carriers[@]}" "$HERE"
for tc in "${carriers[@]}"; do
  script=$tc/run.sh
  if [ ! -f "$script" ]; then
    printf '\n--- %s: MISSING (%s)\n' "$tc" "$script"
    total_fail=$((total_fail + 1))
    failed_names+=("$tc (missing run.sh)")
    continue
  fi

  # A carrier marked `runner: external-rig` expects a rig from its caller
  # (the CI job builds one and passes MNT/F/SOCK). This runner owns no such
  # layout, so it reports the carrier as not run rather than inventing one.
  if grep -q '^# runner: external-rig' "$script" 2>/dev/null; then
    printf '\n--- %s: delegated (external rig)\n' "$tc"
    delegated_names+=("$tc")
    continue
  fi

  printf '\n--- %s\n' "$tc"
  log=$(mktemp)
  # Each carrier runs in its own process group; a carrier that wedges must not
  # wedge the whole run. The timeout is generous: TC-10a alone seeds a 256 MiB
  # remote file and drives a deliberate disconnect.
  timeout "${CARRIER_TIMEOUT:-1800}" bash "$script" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}

  # Count from the results the carrier actually printed. The exit status only
  # decides the classification when a carrier dies without a summary.
  ok=$(grep -c '^OK ' "$log" || true)
  skip=$(grep -c '^SKIP ' "$log" || true)
  fail=$(grep -c '^FAIL ' "$log" || true)
  total_ok=$((total_ok + ok))
  total_skip=$((total_skip + skip))
  total_fail=$((total_fail + fail))

  if [ "$fail" -gt 0 ] || [ "$rc" -eq 1 ]; then
    failed_names+=("$tc")
    printf '    => %s FAILED (ok=%d skip=%d fail=%d, exit=%d)\n' "$tc" "$ok" "$skip" "$fail" "$rc"
  elif [ "$rc" -eq 77 ] || [ "$skip" -gt 0 ]; then
    skipped_names+=("$tc")
    printf '    => %s SKIPPED (ok=%d skip=%d fail=%d, exit=%d)\n' "$tc" "$ok" "$skip" "$fail" "$rc"
  elif [ "$rc" -ne 0 ]; then
    # A carrier that exits nonzero without printing FAIL or a summary did not
    # judge anything; call it out instead of letting it pass silently.
    failed_names+=("$tc (exit $rc without a verdict)")
    total_fail=$((total_fail + 1))
    printf '    => %s ERRORED (exit=%d, no verdict)\n' "$tc" "$rc"
  else
    passed_names+=("$tc")
    printf '    => %s OK (ok=%d)\n' "$tc" "$ok"
  fi
  rm -f "$log"
done

printf '\n=== summary ===\n'
printf 'carriers passed: %d\n' "${#passed_names[@]}"
printf 'carriers skipped: %d\n' "${#skipped_names[@]}"
printf 'carriers failed: %d\n' "${#failed_names[@]}"
printf 'carriers delegated: %d\n' "${#delegated_names[@]}"
printf 'checks ok=%d skip=%d fail=%d\n' "$total_ok" "$total_skip" "$total_fail"
if [ ${#delegated_names[@]} -gt 0 ]; then
  printf 'delegated to a caller-provided rig:\n'
  printf '  %s\n' "${delegated_names[@]}"
fi
if [ ${#skipped_names[@]} -gt 0 ]; then
  printf 'skipped:\n'
  printf '  %s\n' "${skipped_names[@]}"
fi
if [ ${#failed_names[@]} -gt 0 ]; then
  printf 'failed:\n'
  printf '  %s\n' "${failed_names[@]}"
fi

if [ "$total_fail" -gt 0 ]; then
  exit 1
fi
if [ ${#skipped_names[@]} -gt 0 ]; then
  exit 77
fi
exit 0
