#!/usr/bin/env python3
"""Deterministic lifecycle regressions against the real private PostgreSQL cluster.

Requires the cluster initially stopped. No dependencies beyond the existing
Python standard library. BASH_ENV wrappers (outside Git) pause actual pg_ctl or
psql calls at explicit barriers; no implementation is rewritten. --original
accepts a saved, unmodified pre-repair harness and proves its interruption leak.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid


REPO = Path(__file__).resolve().parent.parent
SELF = Path(__file__).resolve()
ROOT = Path.home() / ".local/share/softteros/pg18-dev"
DATA, SOCKET = ROOT / "data", ROOT / "socket"
BIN = Path("/usr/lib/postgresql/18/bin")
USER = os.environ.get("USER", "")


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def interrupt(signum, _frame):
    raise Interrupted(signum)


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def until(predicate, message, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)  # poll a condition, never use a sleep as the barrier
    raise RuntimeError("Deadline: " + message)


def ticks(proc):
    return (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]


def server_record():
    pid = int((DATA / "postmaster.pid").read_text().splitlines()[0])
    proc = Path("/proc") / str(pid)
    return {"pid": pid, "start_ticks": ticks(proc)}


def status():
    return subprocess.run([str(BIN / "pg_ctl"), "-D", str(DATA), "status"],
                          capture_output=True, timeout=10).returncode


def real(tool, args, **kwargs):
    return subprocess.run([str(BIN / tool), *args], timeout=45, **kwargs)


def barrier(name, **values):
    case = Path(os.environ["SOFTTEROS_LIFECYCLE_CASE"])
    (case / (name + ".json")).write_text(json.dumps({"pid": os.getpid(), **values}))
    until(lambda: (case / (name + ".release")).exists(), name + " release", 25)


def probe(kind, args):
    """Test-only wrappers. Real server/client binaries remain unchanged."""
    mode = os.environ["SOFTTEROS_LIFECYCLE_MODE"]
    if kind == "launcher":
        if mode == "late-timeout":
            barrier("launcher-blocked", launcher_pid=os.getppid())
        return 0
    if kind == "stop":
        if mode == "repeated-signals":
            barrier("cleanup-stop")
        return 0
    if kind == "pg_ctl" and "start" in args:
        if mode == "before-launch":
            print("INJECTED FAILURE BEFORE LAUNCH", flush=True)
            return 42
        if mode == "invalid-start":
            args += ["-o", "-c softteros_invalid_startup_option=on"]
        if mode == "late-timeout":
            args[args.index("-t") + 1] = "1"
        result = real(kind, args)
        if mode == "late-timeout":
            check(result.returncode == 1, "real pg_ctl must time out, not fail setup")
            check(status() == 3, "delayed launcher must not have started a server")
            barrier("startup-return", pg_ctl_exit=result.returncode)
        elif mode in ("window", "repeated-signals", "nonzero-ready", "ownership-failure"):
            check(result.returncode == 0 and status() == 0, "positive startup control failed")
            barrier("startup-return", pg_ctl_exit=0, server=server_record())
            if mode in ("nonzero-ready", "ownership-failure"):
                print("INJECTED NONZERO AFTER REAL SUCCESSFUL START", flush=True)
                return 42
        return result.returncode
    if kind == "psql" and any(a.endswith("/db/tests/integration.sql") for a in args):
        if mode == "running-interrupt":
            barrier("sql-return")
            return 0  # interruption is delivered before control returns to Bash
        if mode == "sql-failure":
            print("INJECTED SQL-PHASE FAILURE AFTER RESOURCES CREATED", flush=True)
            return 42
    return real(kind, args).returncode


def env_for(evidence):
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG") and k != "BASH_ENV"}
    env.update(LC_ALL="C", PGPASSFILE=str(evidence / "no-password-file"),
               PGSERVICEFILE=str(evidence / "no-service-file"), PGCONNECT_TIMEOUT="5",
               PGOPTIONS="-c statement_timeout=10000 -c lock_timeout=500 -c transaction_timeout=20000",
               SOFTTEROS_LIFECYCLE_TEST_TOKEN=evidence.name)
    return env


def sql(env, text):
    p = real("psql", ["-X", "--no-password", "-qAt", "-h", str(SOCKET), "-U", USER,
                     "-d", "postgres", "-v", "ON_ERROR_STOP=1"],
             input=text, env=env, capture_output=True, text=True)
    check(p.returncode == 0, "SQL failed: " + p.stderr)
    return p.stdout.strip()


def inventory(env):
    return sql(env, """
SELECT json_build_object(
 'databases',(SELECT json_agg(row_to_json(d) ORDER BY oid) FROM
   (SELECT oid,datname,datdba,encoding,datallowconn,datacl,
    shobj_description(oid,'pg_database') AS comment FROM pg_database) d),
 'roles',(SELECT json_agg(row_to_json(r) ORDER BY oid) FROM
   (SELECT oid,rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,
    rolreplication,rolbypassrls,rolconfig,shobj_description(oid,'pg_authid') AS comment FROM pg_roles) r),
 'memberships',(SELECT coalesce(json_agg(row_to_json(m) ORDER BY roleid,member),'[]') FROM pg_auth_members m));
""")


def stop_owned(record, token):
    """Test recovery only: exact live process, not a name or PID-file guess."""
    fd = os.pidfd_open(record["pid"])
    try:
        proc = Path("/proc") / str(record["pid"])
        check(ticks(proc) == record["start_ticks"] and proc.stat().st_uid == os.getuid(),
              "test recovery process identity mismatch")
        check((proc / "exe").resolve() == BIN / "postgres", "test recovery executable mismatch")
        check(os.fsencode("SOFTTEROS_LIFECYCLE_TEST_TOKEN=" + token) in
              (proc / "environ").read_bytes().split(b"\0"), "test recovery token mismatch")
        check(os.fsencode(DATA) in (proc / "cmdline").read_bytes().split(b"\0"), "test data mismatch")
        signal.pidfd_send_signal(fd, signal.SIGINT)
        check(bool(select.select([fd], [], [], 30)[0]), "owned test server stop timed out")
        check(status() == 3, "cluster did not stop; do not guess at another process")
    finally:
        os.close(fd)


class Suite:
    def __init__(self, evidence):
        self.evidence = evidence
        self.env = env_for(evidence)
        self.owned = None
        self.control = None
        self.results = []
        self.children = []
        # BASH_ENV is test-only injection: wrappers use real binaries and
        # explicit file barriers, including a real pg_ctl -t 1 timeout.
        self.hook = evidence / "barriers.bash"
        self.hook.write_text('''
function /usr/lib/postgresql/18/bin/pg_ctl() {
    command /usr/bin/python3 "$SOFTTEROS_LIFECYCLE_DRIVER" probe pg_ctl "$@"
}
function /usr/lib/postgresql/18/bin/psql() {
    command /usr/bin/python3 "$SOFTTEROS_LIFECYCLE_DRIVER" probe psql "$@"
}
function /usr/bin/python3() {
    if [[ "$1" == */scripts/postgres-lifecycle.py && "${2:-}" == stop ]]; then
        command /usr/bin/python3 "$SOFTTEROS_LIFECYCLE_DRIVER" probe stop || return
    fi
    command /usr/bin/python3 "$@"
}
if [[ "$0" == */postgres-launch ]]; then
    command /usr/bin/python3 "$SOFTTEROS_LIFECYCLE_DRIVER" probe launcher || exit
fi
''')

    def start(self):
        check(status() == 3 and self.owned is None, "test start requires stopped cluster")
        state = self.evidence / ("control-" + uuid.uuid4().hex)
        state.mkdir(mode=0o700)
        for name in ("startup.allowed", "startup.lock"):
            (state / name).touch(mode=0o600)
        token = uuid.uuid4().hex
        launcher = state / "postgres-launch"
        launch_args = ["/usr/bin/python3", str(SELF.parent / "postgres-lifecycle.py"), "launch",
                       str(state), str(DATA), str(BIN / "postgres"), token]
        launcher.write_text("#!/bin/sh\nexec " + shlex.join(launch_args) + ' "$@"\n')
        launcher.chmod(0o700)
        # Test-control starts need the same late-launch protection as the
        # harness. Record ownership before invoking pg_ctl, including failures.
        self.control = (state, token)
        p = real("pg_ctl", ["-D", str(DATA), "-p", str(launcher), "-l", str(ROOT / "postgresql.log"), "-w", "-t", "30", "start"],
                 env=self.env, capture_output=True, text=True)
        # Even a failed wait is reconciled using our inherited process token.
        if status() == 0:
            record = server_record()
            proc = Path("/proc") / str(record["pid"])
            check(os.fsencode("SOFTTEROS_LIFECYCLE_TEST_TOKEN=" + self.evidence.name) in
                  (proc / "environ").read_bytes().split(b"\0"), "test start is not owned")
            self.owned = record
        check(p.returncode == 0 and self.owned is not None, "test control start failed: " + p.stderr)
        self.instances.append(self.owned.copy())
        control = sql(self.env, "SELECT system_identifier FROM pg_control_system();")
        check(control == self.control_id, "live control ID mismatch")

    def stop(self):
        check(self.owned is not None, "no owned test instance")
        self.settle_control()
        check(status() == 3, "test control cluster did not stop")
        self.owned = None

    def settle_control(self):
        if self.control is not None:
            state, token = self.control
            p = subprocess.run(["/usr/bin/python3", str(SELF.parent / "postgres-lifecycle.py"), "stop",
                                str(state), str(DATA), str(BIN / "postgres"), token],
                               env=self.env, capture_output=True, text=True, timeout=40)
            (state / "cleanup.log").write_text(p.stdout + p.stderr)
            check(p.returncode == 0, "test control cleanup failed; inspect " + str(state))
            self.control = None

    def launch(self, harness, name, mode):
        case = self.evidence / name
        case.mkdir(mode=0o700)
        env = self.env | {"BASH_ENV": str(self.hook), "SOFTTEROS_LIFECYCLE_DRIVER": str(SELF),
                          "SOFTTEROS_LIFECYCLE_CASE": str(case), "SOFTTEROS_LIFECYCLE_MODE": mode}
        with (case / "harness.log").open("w") as output:
            child = subprocess.Popen(["/usr/bin/bash", str(harness)], env=env, cwd=REPO,
                                     stdout=output, stderr=output, start_new_session=True)
        self.children.append((child, case))
        return child, case

    def reached(self, child, case, name):
        def read():
            path = case / (name + ".json")
            if path.exists():
                try:
                    return json.loads(path.read_text())
                except json.JSONDecodeError:
                    return None
            check(child.poll() is None, "harness exited before " + name + ": " + (case / "harness.log").read_text())
        return until(read, name)

    def run_case(self, harness, name, mode, sig=None, running=False, original=False):
        if running:
            self.start()
            initial_instance = self.owned.copy()
        else:
            check(status() == 3, "stopped case requires stopped cluster")
        child, case = self.launch(harness, name, mode)
        leaked = False
        try:
            if mode in ("window", "repeated-signals", "nonzero-ready", "ownership-failure", "late-timeout"):
                reached = self.reached(child, case, "startup-return")
                if mode != "late-timeout":
                    self.instances.append(reached["server"])
                logs = (case / "harness.log").read_text()
                state = Path(re.search(r"^LOGS (.+)$", logs, re.M)[1])
                if mode == "ownership-failure":
                    record = state / "startup-process.json"
                    original_record = record.read_text()
                    (case / "original-startup-process.json").write_text(original_record)
                    invalid = json.loads(original_record)
                    invalid["token"] = "deliberately-wrong-test-token"
                    record.write_text(json.dumps(invalid))
                if mode == "late-timeout":
                    waiting = self.reached(child, case, "launcher-blocked")
                    launcher_fd = os.pidfd_open(waiting["launcher_pid"])
                if name == "serialized-start":
                    other, other_case = self.launch(harness, name + "-contender", "normal")
                    check(other.wait(timeout=10) == 75, "contending harness must fail at lifecycle lock")
                    check("Another harness owns" in (other_case / "harness.log").read_text(), "wrong lock failure")
                if sig:
                    child.send_signal(sig)
                (case / "startup-return.release").touch()
                if mode == "late-timeout":
                    until(lambda: (state / "startup.sealed").exists(), "cleanup must seal delayed launch")
                    (case / "launcher-blocked.release").touch()
                    try:
                        check(bool(select.select([launcher_fd], [], [], 10)[0]), "late launcher did not exit")
                    finally:
                        os.close(launcher_fd)
                    check(not (state / "startup-process.json").exists(), "sealed late launcher crossed gate")
                if mode == "repeated-signals":
                    self.reached(child, case, "cleanup-stop")
                    child.send_signal(signal.SIGINT)
                    child.send_signal(signal.SIGTERM)
                    (case / "cleanup-stop.release").touch()
            elif mode == "running-interrupt":
                self.reached(child, case, "sql-return")
                child.send_signal(sig)
                (case / "sql-return.release").touch()
            code = child.wait(timeout=90)
            expected = 128 + sig if sig else (42 if mode in ("before-launch", "nonzero-ready", "ownership-failure", "sql-failure") else
                                               1 if mode in ("late-timeout", "invalid-start") else 0)
            check(code == expected, f"{name}: expected exit {expected}, got {code}")
            output = (case / "harness.log").read_text()
            if original or mode == "ownership-failure":
                check(status() == 0, "expected independently recoverable running instance")
                leaked = True
                check(server_record() == reached["server"], "different instance: refuse test recovery")
                if not original:
                    check("CLEANUP FAILED" in output and "CLEANUP PASSED" not in output,
                          "cleanup identity failure must be visible")
                stop_owned(reached["server"], self.evidence.name)
            else:
                cleanup_output = output
                if mode == "running-interrupt":
                    # EXIT runs inside the redirected psql_admin call. Select
                    # only this invocation's first database log, never a glob.
                    run = re.search(r"^RUN ([0-9a-f]{32})$", output, re.M)
                    logs = re.search(r"^LOGS (.+)$", output, re.M)
                    check(run is not None and logs is not None, "missing cleanup invocation identity")
                    cleanup_output = (Path(logs[1]) / f"stpg_{run[1]}_a-tests.log").read_text()
                check("CLEANUP PASSED" in cleanup_output, "cleanup did not confirm success: " + cleanup_output)
                check("CLEANUP FAILED" not in output + cleanup_output, "hidden cleanup failure")
            if running:
                check(status() == 0 and server_record() == initial_instance, "pre-existing server changed")
            else:
                check(status() == 3, "newly started server leaked")
                self.start()
            check(inventory(self.env) == self.with_sentinels, "pre-existing database/role inventory changed")
            self.stop()
            result = {"case": name, "exit": code, "original_leak_detected": original and leaked,
                      "inventory_preserved": True, "initially_running": running}
            logs = (case / "harness.log").read_text()
            state_match = re.search(r"^LOGS (.+)$", logs, re.M)
            if state_match:
                state = Path(state_match[1])
                result["harness_logs"] = str(state)
                result["exact_objects"] = (state / "objects.txt").read_text() if (state / "objects.txt").exists() else "none created"
            self.results.append(result)
            print("PASS " + json.dumps(result), flush=True)
        finally:
            if sys.exc_info()[0] is not None:
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
            # Release only this test's barriers. Do not kill arbitrary descendants.
            for stem in ("startup-return", "launcher-blocked", "cleanup-stop", "sql-return"):
                (case / (stem + ".release")).touch()
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
                child.wait(timeout=45)
            if not running and status() == 0 and self.owned is None:
                # Recover only this suite's positively identified instance if
                # an assertion interrupted normal test teardown.
                stop_owned(server_record(), self.evidence.name)

    def execute(self, original):
        os.umask(0o077)
        self.instances = []
        for path in (ROOT, DATA, SOCKET):
            check(path.resolve() == path and path.stat().st_uid == os.getuid() and
                  stat.S_IMODE(path.stat().st_mode) == 0o700, "unsafe private cluster path")
        check(os.getuid() != 0 and USER == subprocess.check_output(["id", "-un"], text=True).strip(), "non-root cluster owner required")
        check(status() == 3, "regressions require initially stopped cluster; will not stop a pre-existing server")
        check(subprocess.check_output([str(BIN / "postgres"), "-D", str(DATA), "-C", "listen_addresses"], text=True).strip() == "", "TCP must stay disabled")
        check(subprocess.check_output([str(BIN / "postgres"), "-D", str(DATA), "-C", "unix_socket_directories"], text=True).strip() == str(SOCKET), "wrong socket")
        control = subprocess.check_output([str(BIN / "pg_controldata"), str(DATA)], text=True)
        self.control_id = re.search(r"Database system identifier:\s+(\d+)", control)[1]
        self.file_hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in DATA.iterdir()
                            if p.name.endswith(".conf")}
        self.start()
        self.baseline = inventory(self.env)
        tag = "slr_" + uuid.uuid4().hex
        self.sentinel_role, self.sentinel_db = tag + "_role", tag + "_db"
        self.marker = "SoftterOs lifecycle sentinel " + tag
        role_created, db_created = False, False
        try:
            sql(self.env, f'CREATE ROLE "{self.sentinel_role}" NOLOGIN; COMMENT ON ROLE "{self.sentinel_role}" IS \'{self.marker}\';')
            role_created = True
            self.role_oid = sql(self.env, f"SELECT oid FROM pg_roles WHERE rolname='{self.sentinel_role}';")
            sql(self.env, f'CREATE DATABASE "{self.sentinel_db}" TEMPLATE template0;')
            db_created = True
            self.db_oid = sql(self.env, f"SELECT oid FROM pg_database WHERE datname='{self.sentinel_db}';")
            sql(self.env, f'COMMENT ON DATABASE "{self.sentinel_db}" IS \'{self.marker}\';')
            self.with_sentinels = inventory(self.env)
            (self.evidence / "sentinels.json").write_text(json.dumps({"database": self.sentinel_db,
                "database_oid": self.db_oid, "role": self.sentinel_role, "role_oid": self.role_oid,
                "marker": self.marker, "control_id": self.control_id}, indent=2))
            self.stop()
            if original:
                # Preserve original bytes; only the external copy's relative db
                # directory is supplied via a symlink to the existing SQL files.
                tree = self.evidence / "original"
                (tree / "scripts").mkdir(parents=True)
                saved = tree / "scripts/test-postgres.sh"
                saved.write_bytes(original.read_bytes())
                (tree / "db").symlink_to(REPO / "db", target_is_directory=True)
                self.run_case(saved, "original-term-window", "window", signal.SIGTERM, original=True)
            harness = REPO / "scripts/test-postgres.sh"
            for name, mode, sig, running in [
                ("term-start-window", "window", signal.SIGTERM, False),
                ("int-start-window", "window", signal.SIGINT, False),
                ("repeated-cleanup-signals", "repeated-signals", signal.SIGTERM, False),
                ("real-timeout-delayed-launch", "late-timeout", None, False),
                ("nonzero-after-real-start", "nonzero-ready", None, False),
                ("failure-before-launch", "before-launch", None, False),
                ("postgres-startup-failure", "invalid-start", None, False),
                ("unproven-ownership-refused", "ownership-failure", None, False),
                ("serialized-start", "window", signal.SIGTERM, False),
                ("normal-initially-stopped", "normal", None, False),
                ("normal-initially-running", "normal", None, True),
                ("term-initially-running", "running-interrupt", signal.SIGTERM, True),
                ("int-initially-running", "running-interrupt", signal.SIGINT, True),
                ("sql-failure-initially-running", "sql-failure", None, True),
            ]:
                self.run_case(harness, name, mode, sig, running)
        finally:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            if self.owned is None and self.control is not None:
                self.settle_control()
            if self.owned is None:
                if status() == 3:
                    self.start()
                else:
                    raise RuntimeError("Unresolved running instance; refusing to guess at cleanup. Inspect " + str(self.evidence))
            try:
                # Exact OIDs, ownership, comments; never a prefix-based cleanup.
                if db_created:
                    check(sql(self.env, f"SELECT count(*) FROM pg_database WHERE oid={self.db_oid} AND datname='{self.sentinel_db}' AND datdba=(SELECT oid FROM pg_roles WHERE rolname='{USER}') AND shobj_description(oid,'pg_database')='{self.marker}';") == "1", "sentinel database identity changed")
                    sql(self.env, f'DROP DATABASE "{self.sentinel_db}";')
                if role_created:
                    check(sql(self.env, f"SELECT count(*) FROM pg_roles WHERE oid={self.role_oid} AND rolname='{self.sentinel_role}' AND shobj_description(oid,'pg_authid')='{self.marker}';") == "1", "sentinel role identity changed")
                    sql(self.env, f'DROP ROLE "{self.sentinel_role}";')
                check(inventory(self.env) == self.baseline, "original database/role inventory changed")
            finally:
                self.stop()
            check(all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == h for p, h in self.file_hashes.items()), "cluster configuration changed")
            (self.evidence / "results.json").write_text(json.dumps({"cases": self.results,
                "instances": self.instances, "initial_state": "stopped", "final_state": "stopped",
                "original_inventory_preserved": True, "configuration_unchanged": True}, indent=2))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "probe":
        return probe(sys.argv[2], sys.argv[3:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", type=Path, help="external unmodified pre-repair harness")
    parser.add_argument("--evidence", type=Path, help="new directory outside the repository")
    options = parser.parse_args()
    os.umask(0o077)
    evidence = options.evidence or Path(tempfile.mkdtemp(prefix="softteros-lifecycle-tests-", dir=Path.home() / ".cache"))
    if options.evidence:
        check(not evidence.exists(), "evidence directory must be new")
        evidence.mkdir(mode=0o700)
    check(not evidence.resolve().is_relative_to(REPO), "evidence must be outside the repository")
    print("EVIDENCE " + str(evidence), flush=True)
    with (ROOT / "sql-lifecycle-regression.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        suite = Suite(evidence)
        signal.signal(signal.SIGINT, interrupt)
        signal.signal(signal.SIGTERM, interrupt)
        try:
            suite.execute(options.original)
        finally:
            # Includes a timeout or interruption in the first control start.
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            suite.settle_control()
    print("ALL LIFECYCLE REGRESSIONS PASSED; initial stopped state restored", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Interrupted as error:
        print(f"LIFECYCLE REGRESSIONS INTERRUPTED: signal {error.signum}", file=sys.stderr, flush=True)
        sys.exit(128 + error.signum)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print("LIFECYCLE REGRESSION FAILURE: " + str(error), file=sys.stderr, flush=True)
        sys.exit(1)
