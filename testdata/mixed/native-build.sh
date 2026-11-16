#!/bin/bash
# Builds the native substrate fixture used by real.sh.
#
# The fixture is NOT an agent CLI: it is a small static C program that makes
# the sandbox boundary observable from inside a session. It is compiled here,
# at invocation, from testdata/mixed/native-proof.c, so the harness never
# depends on a parent build artifact. A static binary needs no interpreter, so
# the only runtime assets involved are the ones the four real CLIs bring.
#
# FIXTURE_DIR must be set; the binary is written to $FIXTURE_DIR/native-proof.
# CC may name a compiler (default cc). The build is local to this host: it must
# run where the client runs, not on the daemon.
set -eu
: "${FIXTURE_DIR:?FIXTURE_DIR must name the directory that receives native-proof}"
here=$(cd "$(dirname "$0")" && pwd)
src="$here/native-proof.c"
[ -f "$src" ] || { echo "native-build: missing $src" >&2; exit 1; }
mkdir -p "$FIXTURE_DIR"
CC=${CC:-cc}
"$CC" -static -O1 -Wall -o "$FIXTURE_DIR/native-proof" "$src"
chmod 755 "$FIXTURE_DIR/native-proof"
printf 'built %s from %s\n' "$FIXTURE_DIR/native-proof" "$src"
