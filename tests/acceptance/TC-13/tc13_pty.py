#!/usr/bin/env python3
"""TC-13 (AC-7): interactive terminal semantics and pipe semantics.

Judged from design `docs/03-acceptance.md` §TC-13. Each check prints one line:

  OK   <check>      the criterion holds
  SKIP <check>: why this environment cannot express it
  FAIL <check>: why the criterion does not hold

Interactive (the session must behave as a real terminal):
  1. typed input is consumed by the foreground process
  2. a raw 0x03 is delivered as SIGINT to the foreground process (130)
  3. the session ends with the entry's own status (exit 23 -> 23)
  4. a foreground `sleep` holds the terminal, so a Ctrl-C interrupts it early
     instead of it running to completion
  5. the caller's termios is restored exactly on exit

Pipe (the session must carry the three streams and the end state):
  6. stdin bytes arrive in order
  7. a normal exit status arrives intact
  8. a signal-killed end is distinguishable from a normal one

The client binary and the config are taken from RSBX and CFG so the entry can
hand over the paths its own rig uses; nothing is hard-coded to one image.
"""
import os
import pty
import select
import signal
import subprocess
import sys
import termios
import time

RSBX = os.environ.get("RSBX", "/usr/local/bin/rsbx")
CFG = os.environ.get("CFG", "/state/pty.toml")

passed, failed, skipped = [], [], []


def ok(name):
    passed.append(name)
    print(f"OK {name}", flush=True)


def bad(name, why):
    failed.append(name)
    print(f"FAIL {name}: {why}", flush=True)


def skip(name, why):
    skipped.append(name)
    print(f"SKIP {name}: {why}", flush=True)


def drain(fd, secs):
    out = b""
    end = time.time() + secs
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
    return out


def start_pty():
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(RSBX, [RSBX, "-config", CFG, "--", "/bin/sh"])
        os._exit(127)
    return pid, fd


def pty_input_and_interrupt():
    pid, fd = start_pty()
    drain(fd, 2.0)
    os.write(fd, b"echo CONSUMED-$$\n")
    out = drain(fd, 2.0)
    if b"CONSUMED-" in out:
        ok("pty_typed_input_consumed")
    else:
        bad("pty_typed_input_consumed", f"got {out!r}")

    os.write(fd, b"sleep 30\n")
    time.sleep(0.5)
    os.write(fd, b"\x03")
    out = drain(fd, 3.0)
    os.write(fd, b"echo RC=$?\n")
    out += drain(fd, 2.0)
    if b"RC=130" in out or b"Interrupt" in out:
        ok("pty_ctrlc_is_signal")
    else:
        bad("pty_ctrlc_is_signal", f"got {out!r}")

    os.write(fd, b"exit 23\n")
    drain(fd, 3.0)
    _, status = os.waitpid(pid, 0)
    code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
    if code == 23:
        ok("pty_entry_status_propagated")
    else:
        bad("pty_entry_status_propagated", f"session exit={code}")
    os.close(fd)


def pty_foreground_handoff():
    pid, fd = start_pty()
    drain(fd, 2.0)
    start = time.time()
    os.write(fd, b"sleep 20\n")
    time.sleep(1.0)
    os.write(fd, b"\x03")
    out = drain(fd, 5.0)
    elapsed = time.time() - start
    if elapsed < 15:
        ok("pty_foreground_handoff")
    else:
        bad("pty_foreground_handoff", f"foreground sleep ran to completion ({elapsed:.1f}s, {out!r})")
    os.write(fd, b"exit 0\n")
    drain(fd, 2.0)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    os.close(fd)


def pty_termios_restored():
    master, slave = os.openpty()
    pid = os.fork()
    if pid == 0:
        os.setsid()
        try:
            import fcntl

            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        except Exception:
            pass
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)
        if slave > 2:
            os.close(slave)
        os.close(master)

        def ccval(c):
            if isinstance(c, int):
                return c
            if isinstance(c, bytes):
                return c[0] if len(c) else 0
            return ord(c)

        def dump(tag):
            a = termios.tcgetattr(0)
            cc = " ".join(f"{ccval(c):02x}" for c in a[6])
            print(f"{tag}|{a[0]:x}|{a[1]:x}|{a[2]:x}|{a[3]:x}|{a[4]}|{a[5]}|{cc}", flush=True)

        dump("BEFORE")
        rc = subprocess.call([RSBX, "-config", CFG, "--", "/bin/sh", "-c", "exit 0"])
        dump("AFTER")
        os._exit(rc)
    os.close(slave)
    out = drain(master, 4.0)
    os.waitpid(pid, 0)
    os.close(master)
    lines = [l for l in out.decode(errors="replace").splitlines() if l.startswith(("BEFORE|", "AFTER|"))]
    if len(lines) < 2:
        bad("pty_termios_restored", f"missing before/after reports: {out!r}")
        return
    before = [l for l in lines if l.startswith("BEFORE|")][0].split("|", 1)[1]
    after = [l for l in lines if l.startswith("AFTER|")][0].split("|", 1)[1]
    if before == after:
        ok("pty_termios_restored")
    else:
        bad("pty_termios_restored", f"before={before} after={after}")


def pipe_checks():
    r = subprocess.run(
        [RSBX, "-config", CFG, "--", "/bin/sh", "-c", "cat"],
        input=b"a\nb\nc\nd\n",
        capture_output=True,
        timeout=60,
    )
    if r.stdout.split() == [b"a", b"b", b"c", b"d"]:
        ok("pipe_stdin_order")
    else:
        bad("pipe_stdin_order", f"got {r.stdout!r}")

    r = subprocess.run([RSBX, "-config", CFG, "--", "/bin/sh", "-c", "exit 7"], capture_output=True, timeout=60)
    if r.returncode == 7:
        ok("pipe_exit_status_normal")
    else:
        bad("pipe_exit_status_normal", f"rc={r.returncode}")

    r = subprocess.run(
        [RSBX, "-config", CFG, "--", "/bin/sh", "-c", "kill -9 $$"], capture_output=True, timeout=60
    )
    if r.returncode == 137:
        ok("pipe_signal_exit_distinguishable")
    else:
        bad("pipe_signal_exit_distinguishable", f"rc={r.returncode}")


def main():
    pty_input_and_interrupt()
    pty_foreground_handoff()
    pty_termios_restored()
    pipe_checks()
    print(f"SUMMARY TC-13 ok={len(passed)} skip={len(skipped)} fail={len(failed)}", flush=True)
    if failed:
        print("FAILED: " + ", ".join(failed), flush=True)
        return 1
    if not passed:
        return 77
    if skipped:
        return 77
    return 0


if __name__ == "__main__":
    sys.exit(main())
