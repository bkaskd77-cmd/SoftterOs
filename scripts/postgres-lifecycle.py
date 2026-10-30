#!/usr/bin/env python3
"""Linux-only, private-cluster startup ownership and bounded cleanup.

Not an application adapter. Uses the already installed Python standard library.
The launch gate closes on exec; sealing it prevents a late pg_ctl child from
starting PostgreSQL. A pidfd pins the recorded process before identity checks
and signalling, avoiding PID-reuse and pg_ctl stop's PID-file lookup race.
"""

import contextlib
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import stat
import sys
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def start_ticks(proc):
    # comm may contain spaces or parentheses; field 22 follows its final ')'.
    return (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]


@contextlib.contextmanager
def gate(state, exclusive):
    with (state / "startup.lock").open("r+") as lock:
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(lock, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < deadline, "startup gate did not settle in 5 seconds")
                time.sleep(0.02)
        yield lock


def launch(state, data, postgres, token, args):
    # os.open / Python file descriptors are close-on-exec. Keep the gate held
    # until exec succeeds or this process exits, not merely until the record is
    # written. A late wrapper can never pass a gate already sealed by cleanup.
    with gate(state, False):
        require((state / "startup.allowed").exists(), "startup was cancelled")
        proc = Path("/proc/self")
        record = {
            "pid": os.getpid(), "start_ticks": start_ticks(proc),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "uid": os.getuid(), "data": str(data), "postgres": str(postgres), "token": token,
        }
        # No second launcher may replace ownership evidence.
        with (state / "startup-process.json").open("x") as output:
            json.dump(record, output)
            output.write("\n")
        env = os.environ.copy()
        env["SOFTTEROS_START_TOKEN"] = token
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        os.execve(postgres, [str(postgres), *args], env)


def seal(state):
    with gate(state, True):
        (state / "startup.allowed").unlink(missing_ok=True)
        (state / "startup.sealed").touch()


def verify(state, data, postgres, token):
    record = json.loads((state / "startup-process.json").read_text())
    proc = Path("/proc") / str(record["pid"])
    require(record["data"] == str(data) and record["postgres"] == str(postgres) and
            record["token"] == token and record["start_ticks"] == start_ticks(proc) and
            (proc / "exe").resolve() == postgres and
            (data / "postmaster.pid").read_text().splitlines()[0] == str(record["pid"]),
            "ready server is not this run's recorded process")


def stop(state, data, postgres, token):
    seal(state)
    if (state / "startup.stopped").exists():
        return
    record_path = state / "startup-process.json"
    if not record_path.exists():
        # No launcher crossed the gate; all later launchers are now denied.
        print("No owned PostgreSQL process was launched", flush=True)
        return
    record = json.loads(record_path.read_text())
    require(all(record[k] == v for k, v in {
        "uid": os.getuid(), "data": str(data), "postgres": str(postgres), "token": token,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }.items()), "startup record identity mismatch; refusing stop")
    pid = record["pid"]
    require(isinstance(pid, int) and pid > 1, "invalid recorded PID")
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        (state / "startup.stopped").touch()
        print("Owned startup process already exited", flush=True)
        return
    try:
        if not select.select([fd], [], [], 0)[0]:
            proc = Path("/proc") / str(pid)
            require(start_ticks(proc) == record["start_ticks"], "PID reused; refusing stop")
            require(proc.stat().st_uid == os.getuid(), "process owner mismatch; refusing stop")
            require((proc / "exe").resolve() == postgres, "executable mismatch; refusing stop")
            args = (proc / "cmdline").read_bytes().split(b"\0")
            require(any(args[i:i + 2] == [b"-D", os.fsencode(data)] for i in range(len(args))),
                    "process data directory mismatch; refusing stop")
            require(os.fsencode("SOFTTEROS_START_TOKEN=" + token) in
                    (proc / "environ").read_bytes().split(b"\0"), "run token mismatch; refusing stop")
            # The pidfd still pins this exact process even if it exits now.
            try:
                signal.pidfd_send_signal(fd, signal.SIGINT)  # PostgreSQL fast shutdown
            except ProcessLookupError:
                pass
            require(bool(select.select([fd], [], [], 30)[0]),
                    "owned PostgreSQL process did not stop within 30 seconds")
        (state / "startup.stopped").touch()
        print(f"Stopped/settled owned PostgreSQL process {pid}", flush=True)
    finally:
        os.close(fd)


def main():
    action, directory, data_arg, postgres_arg, token, *args = sys.argv[1:]
    state, data, postgres = map(Path, (directory, data_arg, postgres_arg))
    info = state.lstat()
    require(os.getuid() != 0 and info.st_uid == os.getuid() and
            stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700,
            "unsafe lifecycle state directory")
    require(state.resolve() == state and data.resolve() == data and postgres.resolve() == postgres,
            "unresolved lifecycle paths")
    require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "Linux pidfd support required")
    if action == "launch":
        launch(state, data, postgres, token, args)
    elif action == "seal":
        seal(state)
    elif action == "verify":
        verify(state, data, postgres, token)
    elif action == "stop":
        stop(state, data, postgres, token)
    else:
        raise RuntimeError("unknown lifecycle action")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Lifecycle failure: {error}; inspect {sys.argv[2]}", file=sys.stderr, flush=True)
        sys.exit(1)
