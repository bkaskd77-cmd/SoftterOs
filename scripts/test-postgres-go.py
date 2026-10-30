#!/usr/bin/env python3
"""Step 2A synthetic integration tests; reuse the reviewed private lifecycle helper.

No installations, credential changes, default cluster or migration modifications.
Requires exclusive use of the private cluster. Leaves an initially running server
running; stops only the positively identified control instance this run started.
"""
import argparse
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
import time
import uuid

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("lifecycle", REPO / "scripts/test-postgres-lifecycle.py")
life = importlib.util.module_from_spec(spec)
spec.loader.exec_module(life)



class Resources:
    """Run intentions plus catalog evidence; a UUID/name alone never owns DDL."""
    def __init__(self, evidence, suite, baseline, instance):
        self.evidence, self.suite, self.baseline = evidence, suite, json.loads(baseline)
        self.instance = instance
        tag = "s2a_" + uuid.uuid4().hex
        self.roles = {k: tag + "_" + k for k in ("owner", "runtime", "writer", "lock")}
        self.database = tag + "_db"
        self.marker = "SoftterOs Step 2A disposable " + tag
        self.command_env = suite.env | {"PGAPPNAME": tag}
        self.tag = tag
        self.role_oids = {}
        self.db_oid = None
        self.roles_attempted = self.database_attempted = False
        old_names = {r["rolname"] for r in self.baseline["roles"]}
        old_dbs = {d["datname"] for d in self.baseline["databases"]}
        life.check(not old_names.intersection(self.roles.values()) and self.database not in old_dbs,
                   "creation intent collides with pre-existing resources")
        self.record()

    def record(self):
        (self.evidence / "creation-intent.json").write_text(json.dumps({
            "system_identifier": self.suite.control_id, "instance": self.instance,
            "roles": self.roles, "database": self.database, "marker": self.marker,
            "roles_attempted": self.roles_attempted, "database_attempted": self.database_attempted,
            "role_oids": self.role_oids, "database_oid": self.db_oid,
        }, indent=2) + "\n")

    def sql(self, text, db="postgres", cleanup=False):
        p = subprocess.run([str(life.BIN / "psql"), "-X", "--no-password", "-qAt",
            "-h", str(life.SOCKET), "-U", life.USER, "-d", db, "-v", "ON_ERROR_STOP=1"],
            input=text, capture_output=True, text=True,
            env=self.suite.env if cleanup else self.command_env, timeout=30)
        life.check(p.returncode == 0, "synthetic SQL fixture/cleanup failed; inspect " + str(self.evidence))
        return p.stdout.strip()

    def bootstrap(self, file):
        self.roles_attempted = True
        self.record()  # Persist intent before DDL, including uncertain acknowledgements.
        file(REPO / "db/bootstrap.sql", "postgres")
        rows = self.roles_now()
        self.role_oids = {r["name"]: r["oid"] for r in rows}
        life.check(len(rows) == 4, "bootstrap did not create four roles")
        self.record()

    def create_database(self):
        self.database_attempted = True
        self.record()
        self.sql('CREATE DATABASE "' + self.database + '" TEMPLATE template0 OWNER "' + self.roles["owner"] + '"')
        self.db_oid = self.sql("SELECT oid FROM pg_database WHERE datname='" + self.database + "'")
        self.sql('COMMENT ON DATABASE "' + self.database + '" IS \'' + self.marker + "'")
        self.record()
        (self.evidence / "objects.json").write_text(json.dumps({
            "database": self.database, "database_oid": self.db_oid, "roles": self.role_oids,
            "marker": self.marker, "system_identifier": self.suite.control_id}, indent=2))

    def roles_now(self):
        return json.loads(self.sql("SELECT coalesce(json_agg(json_build_object('oid',oid,'name',rolname,"
            "'marker',shobj_description(oid,'pg_authid'))),'[]') FROM pg_roles WHERE rolname IN (" +
            ",".join("'" + n + "'" for n in self.roles.values()) + ")", cleanup=True))

    def cleanup(self):
        life.check(life.status() == 0 and life.server_record() == self.instance,
                   "unresolved ownership: cluster instance changed")
        life.check(self.sql("SELECT system_identifier::text FROM pg_control_system()", cleanup=True) ==
                   self.suite.control_id, "unresolved ownership: cluster identifier changed")
        # subprocess.run reaps its client on interruption/timeout. Wait for any
        # server-side command to finish too, so an uncertain DDL cannot commit later.
        deadline = time.monotonic() + 30
        while self.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='" + self.tag +
                       "' AND usename='" + life.USER + "'", cleanup=True) != "0":
            life.check(time.monotonic() < deadline, "unresolved run SQL sessions: " + self.tag)
            time.sleep(0.05)
        rows = self.roles_now()
        old_roles = self.baseline["roles"]
        for r in rows:
            life.check(self.roles_attempted and r["marker"] == self.marker and
                       all(r["oid"] != p["oid"] and r["name"] != p["rolname"] for p in old_roles) and
                       (r["name"] not in self.role_oids or self.role_oids[r["name"]] == r["oid"]),
                       "unresolved role ownership: " + r["name"])
        dbs = json.loads(self.sql("SELECT coalesce(json_agg(json_build_object('oid',oid,'owner',datdba,"
            "'marker',shobj_description(oid,'pg_database'))),'[]') FROM pg_database WHERE datname='" +
            self.database + "'", cleanup=True))
        for d in dbs:
            owner = next((r for r in rows if r["name"] == self.roles["owner"]), None)
            # CREATE DATABASE and COMMENT cannot be one transaction. Before the
            # comment exists, require its verified newly-created owner OID,
            # persisted creation intent and absence from the full baseline.
            life.check(self.database_attempted and owner is not None and d["owner"] == owner["oid"] and
                       d["marker"] in (None, self.marker) and
                       all(d["oid"] != p["oid"] and self.database != p["datname"]
                           for p in self.baseline["databases"]) and
                       (self.db_oid is None or str(d["oid"]) == str(self.db_oid)),
                       "unresolved database ownership: " + self.database)
        # All identities are validated before any deletion. Exclusive harness
        # locking and the private owner account exclude cooperating DDL races.
        for d in dbs:
            self.sql('DROP DATABASE "' + self.database + '"', cleanup=True)
        for r in rows:
            self.sql('DROP ROLE "' + r["name"] + '"', cleanup=True)
        life.check(json.loads(life.inventory(self.suite.env)) == self.baseline,
                   "pre-existing catalog inventory changed")


def run(evidence, race, go):
    suite = resources = baseline = initial = original_instance = None
    failure = None
    cleanup_errors = []
    handlers = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    for s in handlers:
        signal.signal(s, life.interrupt)
    try:
        suite = life.Suite(evidence)
        suite.instances = []
        initial = life.status()
        life.check(initial in (0, 3), "unexpected private cluster state")
        control = subprocess.check_output([str(life.BIN / "pg_controldata"), str(life.DATA)], text=True, timeout=10)
        suite.control_id = re.search(r"Database system identifier:\s+(\d+)", control)[1]
        life.check(suite.control_id == "7701995125204757390", "unexpected private cluster identifier")
        for path in (life.ROOT, life.DATA, life.SOCKET):
            life.check(path.resolve() == path and path.stat().st_uid == os.getuid() and
                       path.stat().st_mode & 0o777 == 0o700, "unsafe private cluster path")
        if initial == 3:
            suite.start()
        else:
            original_instance = life.server_record()
        instance = life.server_record()
        life.check(life.sql(suite.env, "SELECT current_setting('data_directory')='" + str(life.DATA) +
            "' AND current_setting('listen_addresses')='' AND current_setting('unix_socket_directories')='" +
            str(life.SOCKET) + "' AND inet_server_addr() IS NULL AND "
            "(SELECT system_identifier::text FROM pg_control_system())='" + suite.control_id +
            "' AND NOT EXISTS(SELECT 1 FROM pg_hba_file_rules WHERE error IS NOT NULL OR auth_method='trust')") == "t",
            "private cluster identity/authentication mismatch")
        baseline = life.inventory(suite.env)
        (evidence / "inventory-before.json").write_text(baseline + "\n")
        resources = Resources(evidence, suite, baseline, instance)
        variables = [item for k, v in resources.roles.items() for item in ("-v", k + "_role=" + v)] + ["-v", "marker=" + resources.marker]
        def file(path, db):
            p = subprocess.run([str(life.BIN / "psql"), "-X", "--no-password", "-h", str(life.SOCKET),
                "-U", life.USER, "-d", db, "-v", "ON_ERROR_STOP=1", *variables, "-f", str(path)],
                env=resources.command_env, capture_output=True, text=True, timeout=30)
            (evidence / (path.name + ".log")).write_text(p.stdout + p.stderr)
            life.check(p.returncode == 0, "fixture file failed; inspect " + str(evidence))
        resources.bootstrap(file)
        resources.create_database()
        resources.sql('REVOKE ALL ON DATABASE "' + resources.database + '" FROM PUBLIC; REVOKE ALL ON SCHEMA public FROM PUBLIC;', resources.database)
        for path in sorted((REPO / "db/migrations").glob("*.sql")):
            file(path, resources.database)
        # Only administrative fixture plumbing: no enquiry business command.
        resources.sql("""
INSERT INTO softteros_access.actors VALUES('actor-1'),('actor-2');
INSERT INTO softteros_access.organizations VALUES('org-1'),('org-2');
INSERT INTO softteros_access.memberships VALUES
 ('org-1','member-1','actor-1',true,false,'2000-01-01+00','9999-01-01+00'),
 ('org-2','member-2','actor-1',true,false,'2000-01-01+00','9999-01-01+00'),
 ('org-1','member-3','actor-2',true,false,'2000-01-01+00','9999-01-01+00'),
 ('org-2','member-4','actor-2',true,false,'2000-01-01+00','9999-01-01+00');
CREATE SCHEMA step2_fixture;
REVOKE ALL ON SCHEMA step2_fixture FROM PUBLIC;
CREATE TABLE step2_fixture.probe(organization_id text NOT NULL, value integer NOT NULL,
 UNIQUE(organization_id,value) DEFERRABLE INITIALLY DEFERRED);
ALTER TABLE step2_fixture.probe ENABLE ROW LEVEL SECURITY;
ALTER TABLE step2_fixture.probe FORCE ROW LEVEL SECURITY;
""" + 'CREATE POLICY tenant ON step2_fixture.probe TO "' + resources.roles["runtime"] + '" USING (organization_id=softteros_access.context_organization()) WITH CHECK (organization_id=softteros_access.context_organization());' +
            'GRANT USAGE ON SCHEMA step2_fixture TO "' + resources.roles["runtime"] + '"; GRANT SELECT,INSERT ON step2_fixture.probe TO "' + resources.roles["runtime"] + '";', resources.database)
        env = suite.env | {"SOFTTEROS_PG_INTEGRATION": "1", "SOFTTEROS_TEST_SOCKET": str(life.SOCKET),
            "SOFTTEROS_TEST_DATABASE": resources.database, "SOFTTEROS_TEST_RUNTIME": resources.roles["runtime"], "GOTOOLCHAIN": "local", "GOENV": "off"}
        # Reuse this task's external caches when explicitly supplied by its caller.
        for key in ("GOCACHE", "GOMODCACHE", "GOTMPDIR"):
            if key in os.environ: env[key] = os.environ[key]
        args = [str(go), "test", "-v", "-count=1", "-timeout=90s"] + (["-race"] if race else []) + ["./..."]
        print("RUN " + " ".join(args), flush=True)
        with (evidence / "go-tests.log").open("w") as output:
            p = subprocess.run(args, cwd=REPO, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=180)
        for line in (evidence / "go-tests.log").read_text().splitlines():
            if line.startswith(("ok ", "FAIL", "--- FAIL", "--- PASS: TestIntegration")) or ".go:" in line:
                print(line, flush=True)
        life.check(p.returncode == 0, "Go integration suite failed")
    except BaseException as error:
        failure = error
    finally:
        for s in handlers:
            signal.signal(s, signal.SIG_IGN)
        try:
            if resources is not None:
                try:
                    resources.cleanup()
                except BaseException as error:
                    cleanup_errors.append(str(error))
            if baseline is not None:
                try:
                    after = life.inventory(suite.env)
                    life.check(after == baseline, "pre-existing catalog inventory changed")
                    (evidence / "inventory-after.json").write_text(after + "\n")
                except BaseException as error:
                    cleanup_errors.append(str(error))
        finally:
            try:
                if suite is not None and initial == 3:
                    suite.settle_control()  # Also seals any startup still in progress.
                    life.check(life.status() == 3, "initial stopped state not restored")
                elif original_instance is not None:
                    life.check(life.status() == 0 and life.server_record() == original_instance,
                               "pre-existing instance changed")
            except BaseException as error:
                cleanup_errors.append(str(error))
            finally:
                for s, handler in handlers.items():
                    signal.signal(s, handler)
        if cleanup_errors:
            print("CLEANUP FAILED: " + "; ".join(cleanup_errors) + "; inspect " + str(evidence), file=sys.stderr)
        else:
            print("CLEANUP: exact disposable objects removed; initial cluster lifecycle preserved", flush=True)
    if failure is not None:
        raise failure
    if cleanup_errors:
        raise RuntimeError("cleanup failed; see explicit ownership diagnostics")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--race", action="store_true")
    parser.add_argument("--go", type=Path, default=REPO / ".tools/go1.27.3-linux-arm64/go/bin/go")
    args = parser.parse_args(argv)
    os.umask(0o077)
    evidence = Path(tempfile.mkdtemp(prefix="softteros-step2a-test-", dir=Path.home() / ".cache"))
    print("EVIDENCE " + str(evidence), flush=True)
    try:
        with (life.ROOT / "sql-test-lifecycle.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            run(evidence, args.race, args.go)
    except life.Interrupted as error:
        print("STEP 2A INTERRUPTED: signal " + str(error.signum), file=sys.stderr)
        return 128 + error.signum
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print("STEP 2A FAILURE: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
