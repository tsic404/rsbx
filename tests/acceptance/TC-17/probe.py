#!/usr/bin/env python3
"""Send one crafted reverse-exec request to a session's stub socket.

The shipped rsbx-stub builds its request from its own argv, working
directory and environment, so it cannot express a terminal request, a
relative working directory or a loader-injection environment. This probe
writes the wire form directly, from the daemon side: the session capability
is the socket path it was handed, and every refusal comes back as protocol
frames.

It prints the frames it receives as `PROBE-*` lines and exits 0 when the
dialogue completed, so a carrier can judge the refusal instead of the probe.
"""

import argparse
import socket
import struct
import sys

TEXEC = 0x01
TEXIT = 0x03
TERR = 0x04
TSTDOUT = 0x11
TSTDERR = 0x12


def frame(typ, payload):
    return struct.pack(">IB", len(payload), typ) + payload


def string(value):
    data = value.encode()
    return struct.pack(">I", len(data)) + data


def exec_request(target, argv, env, cwd, tty):
    body = bytes([2, 1 if tty else 0]) + struct.pack(">HH", 0, 0)
    body += string(cwd) + string(target)
    body += struct.pack(">I", len(argv))
    for item in argv:
        body += string(item)
    body += struct.pack(">I", len(env))
    for item in env:
        body += string(item)
    return body


def read_frame(conn):
    header = b""
    while len(header) < 5:
        chunk = conn.recv(5 - len(header))
        if not chunk:
            return None
        header += chunk
    length = struct.unpack(">I", header[:4])[0]
    payload = b""
    while len(payload) < length:
        chunk = conn.recv(length - len(payload))
        if not chunk:
            return None
        payload += chunk
    return header[4], payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--cwd", default="")
    parser.add_argument("--tty", action="store_true")
    parser.add_argument("--env", action="append", default=[])
    parser.add_argument("--arg", action="append", default=[])
    parser.add_argument("--frame-only", action="store_true",
                        help="send the request without the 64-byte capability")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    argv = args.arg or [args.target.rsplit("/", 1)[-1]]
    request = exec_request(args.target, argv, args.env, args.cwd, args.tty)

    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(args.timeout)
    try:
        conn.connect(args.socket)
    except OSError as exc:
        print("PROBE-DIAL-ERROR:%s" % exc)
        return 0

    try:
        if not args.frame_only:
            # The stub socket's capability is the socket path itself; there is
            # no token on this hop. --frame-only exercises the other side of
            # the same protocol (a caller that sends frames with no preamble).
            pass
        conn.sendall(frame(TEXEC, request))
    except OSError as exc:
        print("PROBE-WRITE-ERROR:%s" % exc)
        return 0

    while True:
        try:
            item = read_frame(conn)
        except (socket.timeout, OSError) as exc:
            print("PROBE-READ-ERROR:%s" % exc)
            break
        if item is None:
            print("PROBE-EOF")
            break
        typ, payload = item
        if typ == TSTDOUT:
            sys.stdout.write(payload.decode(errors="replace"))
            sys.stdout.flush()
        elif typ == TSTDERR:
            sys.stderr.write(payload.decode(errors="replace"))
            sys.stderr.flush()
        elif typ == TERR:
            print("PROBE-TERR:%s" % payload.decode(errors="replace"))
        elif typ == TEXIT:
            print("PROBE-EXIT:%d" % struct.unpack(">i", payload[:4])[0])
            break
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
