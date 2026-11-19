#!/bin/bash
# TC-18 (AC-12) — the network transport authenticates both ends.
#
# Design `docs/03-acceptance.md` §TC-18 judges four combinations against one
# mutual-TLS daemon: a trusted client certificate establishes a session and
# completes a remote execution; an untrusted client certificate, a missing
# client certificate and an untrusted server certificate each fail before the
# session is established, with a failure that names the certificate rather
# than the command, and neither side starts a command process.
#
# The negative cases write a marker into the daemon's tree. Its absence after
# the call is the evidence that no command was served; the process scan is
# the second half of the same claim. `tls_skip_verify` is deliberately not
# used for the untrusted-server case: the client is given a different CA, so
# the failure happens in certificate verification rather than in a bypass.
#
# Exit 0 all checks held; 1 a criterion failed; 77 nothing could be judged.
set -u
ACC_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$ACC_DIR" || exit 1
. ../lib/harness.sh
. ../lib/rig.sh

ACC_PREFIX=acc-tc18-$$
acc_init TC-18
trap acc_rig_cleanup EXIT

acc_rig_prereqs || exit 77
acc_rig_create || { acc_skip_all rig "could not create the docker rig"; exit 77; }
acc_ready || exit 77

acc_tls_prepare || { acc_skip_all tls_material "$ACC_TLS_WHY"; exit 77; }
acc_tls_client_install || { acc_skip_all tls_material "could not install client certificate material"; exit 77; }
if ! acc_tls_daemon_start; then
  acc_tls_daemon_diag
  acc_fail tls_daemon "the mutual-TLS daemon container could not be created"
  acc_finish
fi
if ! acc_tls_wait; then
  # A daemon that cannot serve here is a defect, not a missing prerequisite:
  # the images, /dev/fuse, git and python3 were all provisioned above.
  acc_tls_daemon_diag
  acc_fail tls_daemon "the mutual-TLS daemon never accepted a connection on :$ACC_TLS_PORT"
  acc_finish
fi

TC18=/proj/tc18
docker exec "$ACC_TLS_DAEMON" /bin/sh -c "mkdir -p $TC18 && chmod 777 $TC18" >/dev/null 2>&1
DAEMON_HOST=$(docker exec "$ACC_TLS_DAEMON" /bin/sh -c 'cat /proc/sys/kernel/hostname' 2>/dev/null)

MARKER=$TC18

# One session shape for every case: the entry shell writes a marker into the
# daemon's tree and then runs a program that only the daemon carries, so a
# session that really came up is observable twice.
run_case(){
  local cfg=$1 marker=$2
  acc_session_split "$cfg" /bin/sh -c \
    "printf ran > $MARKER/$marker; /bin/uname -n"
}

check(){
  local name=$1
  shift
  if "$@"; then acc_ok "$name"; else acc_fail "$name" "output above"; fi
}

check_trusted(){
  local cfg
  cfg=$(acc_tls_config trusted '["/bin/sh"]' /bin/sh ca.pem client.pem client.key)
  run_case "$cfg" trusted
  printf '%s\n' "$ACC_OUT" | sed 's/^/    /'
  [ "$ACC_RC" -eq 0 ] || { echo "    the trusted pair did not establish a session (rc=$ACC_RC)"; return 1; }
  docker exec "$ACC_TLS_DAEMON" test -e "$MARKER/trusted" \
    || { echo "    no command was served from the trusted session"; return 1; }
  # /bin/uname is not in local.allow, so its answer is the daemon's hostname.
  printf '%s\n' "$ACC_OUT" | grep -qx "$DAEMON_HOST" \
    || { echo "    the remote execution did not answer from the daemon (want host $DAEMON_HOST)"; return 1; }
  return 0
}

# Each negative names the certificate as the cause and leaves no process and
# no marker behind. The three differ in which end is untrusted, which is what
# makes them three checks instead of one.
check_rejected(){
  local name=$1 cfg=$2 marker=$3 what=$4
  run_case "$cfg" "$marker"
  printf '%s\n' "$ACC_OUT" | sed 's/^/    /'
  printf '%s\n' "$ACC_ERR" | sed 's/^/    /'
  [ "$ACC_RC" -ne 0 ] || { echo "    $what was accepted (rc=$ACC_RC)"; return 1; }
  # The cause must be named by the message itself. The endpoint carries the
  # daemon's name, so a bare "tls" would match the address rather than a
  # certificate verdict; only certificate wording counts.
  printf '%s\n' "$ACC_ERR$ACC_OUT" \
    | grep -qiE 'certificate|x509|unknown authority|bad certificate|tls: ' \
    || { echo "    the failure does not point at the certificate"; return 1; }
  docker exec "$ACC_TLS_DAEMON" test -e "$MARKER/$marker" \
    && { echo "    a command ran before the session was rejected"; return 1; }
  acc_proc_match client "$MARKER/$marker" >/dev/null 2>&1 \
    && { echo "    a command process was left on the client side"; return 1; }
  acc_proc_match daemon "$MARKER/$marker" "$ACC_TLS_DAEMON" >/dev/null 2>&1 \
    && { echo "    a command process was left on the daemon side"; return 1; }
  return 0
}

cfgs(){
  # Rejected client certificate: signed by a CA the daemon does not trust.
  ACC_TLS_BAD=$(acc_tls_config untrusted-client '["/bin/sh"]' /bin/sh \
    ca.pem client-other.pem client-other.key)
  # No client certificate at all: the daemon requires one.
  ACC_TLS_NONE=$(acc_tls_config no-client '["/bin/sh"]' /bin/sh ca.pem - -)
  # The client trusts a CA the server certificate was not issued by.
  ACC_TLS_SERVER=$(acc_tls_config untrusted-server '["/bin/sh"]' /bin/sh \
    other-ca.pem client.pem client.key)
}
cfgs

check trusted-pair-establishes-session-and-runs check_trusted
check untrusted-client-certificate-rejected check_rejected \
  untrusted-client "$ACC_TLS_BAD" badclient "an untrusted client certificate"
check missing-client-certificate-rejected check_rejected \
  no-client "$ACC_TLS_NONE" nocert "a client with no certificate"
check untrusted-server-certificate-rejected check_rejected \
  untrusted-server "$ACC_TLS_SERVER" badserver "an untrusted server certificate"

acc_finish
