#!/usr/bin/env python3
"""Deterministic Step 2A runner regressions using real PostgreSQL.

Requires the private cluster initially stopped; preserves the complete catalog.
Test-only wrappers inject real signals after completed commands or a write error.
No production hook or reviewed lifecycle implementation is changed.
"""
import argparse
import copy
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("runner", REPO / "scripts/test-postgres-go.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
life = runner.life


def worker(case, point, signum):
    fired = False
    real_start = life.Suite.start
    real_run = subprocess.run
    real_write = Path.write_text
    real_cleanup = runner.Resources.cleanup

    def trigger():
        nonlocal fired
        if fired:
            return
        fired = True
        print("INJECT " + point, flush=True)
        if point in ("evidence", "intent", "metadata"):
            raise OSError("injected " + point + " write failure")
        os.kill(os.getpid(), signum)

    def start(suite):
        result = real_start(suite)
        if point == "startup":
            trigger()
        return result

    def command(args, *a, **kw):
        result = real_run(args, *a, **kw)
        if result.returncode == 0:
            at_roles = point == "roles" and "-f" in args and str(args[-1]) == str(REPO / "db/bootstrap.sql")
            at_database = point == "database" and kw.get("input", "").startswith("CREATE DATABASE ")
            if at_roles or at_database:
                intent = json.loads((case / "creation-intent.json").read_text())
                catalog = json.loads(life.inventory(life.env_for(case)))
                created = [r for r in catalog["roles"] if r["rolname"] in intent["roles"].values()]
                life.check(len(created) == 4 and all(r["comment"] == intent["marker"] for r in created),
                           "positive role-creation control failed")
                if at_database:
                    db = next(d for d in catalog["databases"] if d["datname"] == intent["database"])
                    owner = next(r for r in created if r["rolname"] == intent["roles"]["owner"])
                    life.check(db["datdba"] == owner["oid"] and db["comment"] is None,
                               "positive pre-metadata database control failed")
                (case / "boundary-catalog.json").write_text(json.dumps(catalog, indent=2))
                trigger()
        return result

    def write(path, *a, **kw):
        if path == case / "inventory-before.json":
            if point in ("startup", "evidence"):
                trigger()  # Running case has no startup call of its own.
        if point == "intent" and path == case / "creation-intent.json":
            trigger()
        if point == "metadata" and path == case / "objects.json":
            trigger()
        return real_write(path, *a, **kw)

    def cleanup(resources):
        # The runner must ignore repeated signals during bounded cleanup.
        life.check(signal.getsignal(signal.SIGTERM) == signal.SIG_IGN, "cleanup signals not masked")
        os.kill(os.getpid(), signal.SIGTERM)
        os.kill(os.getpid(), signal.SIGINT)
        real_cleanup(resources)
        real_cleanup(resources)  # Repeat-safe with all owned objects already gone.

    with patch.object(life.Suite, "start", start), patch.object(subprocess, "run", command), \
         patch.object(Path, "write_text", write), patch.object(runner.Resources, "cleanup", cleanup), \
         patch.object(tempfile, "mkdtemp", return_value=str(case)):
        code = runner.main([])
    life.check(fired, "injection boundary never reached")
    return code


def ownership_checks():
    """Negative controls: no destructive SQL for pre-existing/ambiguous objects."""
    base = runner.Resources.__new__(runner.Resources)
    base.instance = {"pid": 123, "start_ticks": "456"}
    base.suite = type("Fixture", (), {"control_id": "fixture", "env": {}})()
    base.tag, base.database, base.marker = "fixture", "owned_db", "owned_marker"
    base.roles = {"owner": "owned_role"}
    base.role_oids, base.db_oid = {"owned_role": 101}, "102"
    base.roles_attempted = base.database_attempted = True
    base.baseline = {"roles": [{"oid": 1, "rolname": "pre_existing"}],
                     "databases": [{"oid": 2, "datname": "pre_existing_db"}]}
    roles = [{"oid": 101, "name": "owned_role", "marker": "owned_marker"}]
    dbs = [{"oid": 102, "owner": 101, "marker": "owned_marker"}]
    variants = [
        ("role marker", lambda r, d, s: r[0].update(marker="foreign")),
        ("pre-existing role OID", lambda r, d, s: r[0].update(oid=1)),
        ("pre-existing role name", lambda r, d, s: r[0].update(name="pre_existing")),
        ("recorded role OID", lambda r, d, s: s.role_oids.update(owned_role=999)),
        ("database owner", lambda r, d, s: d[0].update(owner=999)),
        ("pre-existing database OID", lambda r, d, s: d[0].update(oid=2)),
        ("database marker", lambda r, d, s: d[0].update(marker="foreign")),
        ("recorded database OID", lambda r, d, s: setattr(s, "db_oid", "999")),
    ]
    for name, corrupt in variants:
        subject, rr, dd = copy.copy(base), copy.deepcopy(roles), copy.deepcopy(dbs)
        subject.role_oids = base.role_oids.copy()
        corrupt(rr, dd, subject)
        def sql(query, **_kw):
            if "system_identifier" in query: return "fixture"
            if "pg_stat_activity" in query: return "0"
            if "FROM pg_database" in query: return json.dumps(dd)
            raise AssertionError("destructive/unexpected SQL reached: " + name)
        with patch.object(life, "status", return_value=0), \
             patch.object(life, "server_record", return_value=base.instance), \
             patch.object(subject, "roles_now", return_value=rr), patch.object(subject, "sql", sql):
            try:
                subject.cleanup()
            except RuntimeError as error:
                life.check("unresolved" in str(error), "unrelated ownership failure")
            else:
                raise AssertionError("ambiguous ownership accepted: " + name)
        print("PASS refusal: " + name, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", nargs=3, metavar=("DIRECTORY", "POINT", "SIGNAL"))
    args = parser.parse_args()
    if args.worker:
        return worker(Path(args.worker[0]), args.worker[1], int(args.worker[2]))
    ownership_checks()
    os.umask(0o077)
    evidence = Path(tempfile.mkdtemp(prefix="softteros-step2a-runner-", dir=Path.home() / ".cache"))
    print("EVIDENCE " + str(evidence), flush=True)
    with (life.ROOT / "sql-lifecycle-regression.lock").open("a") as regression_lock:
        fcntl.flock(regression_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        life.check(life.status() == 3, "runner regressions require initially stopped cluster")
        suite = life.Suite(evidence)
        suite.instances = []
        suite.control_id = re.search(r"Database system identifier:\s+(\d+)",
            subprocess.check_output([str(life.BIN / "pg_controldata"), str(life.DATA)], text=True, timeout=10))[1]
        life.check(suite.control_id == "7701995125204757390", "unexpected private cluster")
        baseline = None
        results = []

        def locked():
            lock = (life.ROOT / "sql-test-lifecycle.lock").open("r+")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock

        def inventory():
            was_stopped = life.status() == 3
            with locked():
                try:
                    if was_stopped:
                        suite.start()
                    return life.inventory(suite.env)
                finally:
                    if was_stopped:
                        suite.settle_control()
                        suite.owned = None

        try:
            baseline = inventory()
            (evidence / "catalog-before.json").write_text(baseline + "\n")
            for running in (False, True):
                if running:
                    with locked():
                        suite.start()
                    original = life.server_record()
                try:
                    for point in ("startup", "roles", "database", "evidence", "intent", "metadata"):
                        signals = (signal.SIGTERM, signal.SIGINT) if point in ("startup", "roles", "database") else (0,)
                        for sig in signals:
                            name = ("running-" if running else "stopped-") + point + "-" + str(int(sig))
                            case = evidence / name
                            case.mkdir(mode=0o700)
                            with (case / "worker.log").open("w") as output:
                                child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--worker",
                                    str(case), point, str(int(sig))], cwd=REPO, env=suite.env,
                                    stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
                                try:
                                    child.wait(timeout=180)
                                except subprocess.TimeoutExpired:
                                    child.send_signal(signal.SIGTERM)
                                    # Allow bounded cleanup rather than SIGKILLing a runner.
                                    child.wait(timeout=360)
                                    raise RuntimeError("worker deadline exceeded: " + str(case))
                            log = (case / "worker.log").read_text()
                            life.check("INJECT " + point in log, "wrong setup failure: " + name)
                            life.check(child.returncode == (128 + sig if sig else 1),
                                       "interruption/failure status lost: " + name + "; inspect " + str(case))
                            life.check("CLEANUP: exact disposable objects removed" in log and "CLEANUP FAILED" not in log,
                                       "cleanup failed: " + name + "; inspect " + str(case))
                            if running:
                                life.check(life.status() == 0 and life.server_record() == original,
                                           "pre-existing instance replaced/stopped")
                            else:
                                life.check(life.status() == 3, "started instance leaked")
                            life.check(inventory() == baseline, "pre-existing catalog changed: " + name)
                            results.append({"case": name, "exit": child.returncode, "passed": True})
                            print("PASS " + name, flush=True)
                finally:
                    if running:
                        with locked():
                            suite.settle_control()
                            suite.owned = None
        finally:
            with locked():
                suite.settle_control()
            life.check(life.status() == 3, "initial stopped state not restored")
            if baseline is not None:
                life.check(inventory() == baseline, "final catalog changed")
            (evidence / "results.json").write_text(json.dumps({
                "cases": results, "initial_state": "stopped", "final_state": "stopped",
                "catalog_preserved": True}, indent=2))
        print("ALL 18 STEP 2A RUNNER REGRESSIONS PASSED; stopped state and catalogs preserved", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
