#!/bin/bash
# TC-7 (AC-5) — daemon unreachable and a missing directory.
#
# Design `docs/03-acceptance.md` §TC-7 judges three situations, and each has
# its own expected failure rather than a shared "it did not work":
#   a. the daemon is unreachable: session establishment fails and no process
#      is produced on either side;
#   b. a remote command asks for a working directory that does not exist in
#      the daemon's tree;
#   c. the daemon's own CheckStart refuses a missing start directory instead
#      of silently switching to another one.
#
# (b) is carried by `TestCwdValidationNoFallback` in internal/daemon: it drives
# the daemon's own resolveCwd over a pipe and asserts TErr plus status 127 for
# a missing directory, which is the same decision this carrier would exercise
# through a container. Keeping both would give one criterion two definitions
# that can drift apart.
#
# (c) is carried by `TestEnsureRefusesMissingStartDirectory` in
# internal/workspace and `TestWorkspaceBecomesSessionStartDir` in
# internal/sandbox: together they prove the session's start directory is the
# daemon path and that its absence is refused through the daemon's own channel.
# The remaining two checks here are the ones a unit test cannot express: a real
# daemon socket that is absent, and the resulting absence of any process.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
cd "$(dirname "$0")" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc7-$$
acc_init TC-7
trap acc_rig_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

MARKER=tc7-should-not-run-$$

# --- a. daemon unreachable ------------------------------------------------
# The socket is a path that cannot exist. The session must fail at
# establishment, and neither side may show a process for the command.
check_unreachable(){
  local cfg out
  cfg=$(acc_config unreach '["/bin/cat"]' '[]')
  acc_exec "sed -i 's|socket = \"$ACC_SOCK\"|socket = \"/run/rsbx/no-such-$$.sock\"|' $cfg"
  acc_session "$cfg" /bin/sh -c "echo $MARKER"
  local rc=$?; out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  [ $rc -ne 0 ] || { echo "    an unreachable daemon still produced a session (rc=0)"; return 1; }
  printf '%s\n' "$out" | grep -q "$MARKER" \
    && { echo "    the command ran anyway"; return 1; }
  printf '%s\n' "$out" | grep -qiE 'unreachable|connect|no such file' \
    || { echo "    the failure does not name the unreachable daemon: [$out]"; return 1; }
  # No process may be left behind carrying this run's marker on the daemon.
  # /proc is readable in the image; ps is not, and a missing ps would make this
  # pass without anyone looking.
  acc_proc_match daemon "$MARKER" >/dev/null 2>&1 \
    && { echo "    a process was left on the daemon"; return 1; }
  return 0
}

# --- c. a missing start directory with a local first program --------------
# This is the case where a fallback would be most tempting: the first program
# runs here, so the session could start it in any local directory. The design
# forbids exactly that.
check_missing_startdir(){
  local cfg out dir=$ACC_PROJ/no-such-start-$$
  acc_put "$ACC_LOCAL_DIR/tc7-local" "#!/bin/sh
echo $MARKER
" 755
  cfg=$(acc_config startdir '["'"$ACC_LOCAL_DIR"'/tc7-local","/bin/cat"]' '[]')
  ACC_SESSION_FLAGS="-workspace $dir" acc_session "$cfg" "$ACC_LOCAL_DIR/tc7-local"
  local rc=$?; out=$ACC_OUT
  printf '%s\n' "$out" | sed 's/^/    /'
  [ $rc -ne 0 ] || { echo "    the session started despite a missing start directory"; return 1; }
  printf '%s\n' "$out" | grep -q "$MARKER" \
    && { echo "    the local program ran anyway — a silent directory fallback"; return 1; }
  printf '%s\n' "$out" | grep -qiE 'no such|not exist|workspace' \
    || { echo "    the failure does not name the start directory: [$out]"; return 1; }
  return 0
}

check(){ local n=$1; shift; if "$@"; then acc_ok "$n"; else acc_fail "$n" "output above"; fi; }

check daemon-unreachable-no-process check_unreachable
check missing-startdir-no-fallback check_missing_startdir

acc_finish
