#!/usr/bin/env bash
# Local synthetic-data SQL tests. No sudo, installations, or application adapter.
set -euo pipefail
umask 077
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
user=$(id -un)
test "$(id -u)" != 0 || { echo "Run as the cluster's non-root owner"; exit 1; }
root="$HOME/.local/share/softteros/pg18-dev"
data="$root/data"
socket="$root/socket"
bin=/usr/lib/postgresql/18/bin
test "$(readlink -f "$data")" = "$data"
test "$(readlink -f "$socket")" = "$socket"
for directory in "$data" "$socket"; do
    test "$(stat -c %u "$directory")" = "$(id -u)"
    test "$(stat -c %a "$directory")" = 700
done
# Serialize cooperating harnesses for the complete lifecycle, not just startup.
# Children that can outlive the shell must not retain this lock.
test "$(readlink -f "$root")" = "$root"
test "$(stat -c %u "$root")" = "$(id -u)"
test "$(stat -c %a "$root")" = 700
test ! -L "$root/sql-test-lifecycle.lock"
exec 9>>"$root/sql-test-lifecycle.lock"
test "$(stat -c %u "$root/sql-test-lifecycle.lock")" = "$(id -u)"
test "$(stat -c %a "$root/sql-test-lifecycle.lock")" = 600
flock -w 5 9 || { echo "Another harness owns the cluster lifecycle lock" >&2; exit 75; }
test -x /usr/bin/python3
test "$("$bin/postgres" --version)" = "postgres (PostgreSQL) 18.6 (Ubuntu 18.6-0ubuntu0.26.04.1)"
test -z "$("$bin/postgres" -D "$data" -C listen_addresses)"
test "$("$bin/postgres" -D "$data" -C unix_socket_directories)" = "$socket"
control_id=$("$bin/pg_controldata" "$data" | sed -n 's/^Database system identifier: *//p')
test -n "$control_id"
# Do not read personal libpq/psql configuration or password files.
unset PGSERVICE PGSERVICEFILE PGHOST PGHOSTADDR PGPORT PGUSER PGDATABASE PGPASSWORD PGOPTIONS
export PGPASSFILE="$root/nonexistent-test-password-file"
export PGSERVICEFILE="$root/nonexistent-test-service-file"
export PGCONNECT_TIMEOUT=5
export PGOPTIONS="-c statement_timeout=10000 -c lock_timeout=500 -c idle_in_transaction_session_timeout=10000 -c transaction_timeout=20000"
export LC_ALL=C
startup_attempted=0
roles_created=0
db_a_oid=
db_b_oid=
holder_pid=
uuid=$(tr -d '-' </proc/sys/kernel/random/uuid)
prefix="stpg_$uuid"
owner_role="$prefix"_owner
runtime_role="$prefix"_runtime
writer_role="$prefix"_writer
lock_role="$prefix"_lock
db_a="$prefix"_a
db_b="$prefix"_b
marker="SoftterOs disposable SQL test $uuid"
logdir=$(mktemp -d "$HOME/.cache/softteros-sql-test.XXXXXX")
echo "RUN $uuid"
echo "ROLES $owner_role $runtime_role $writer_role $lock_role"
echo "DATABASES $db_a $db_b"
echo "LOGS $logdir"
psql_admin() {
    "$bin/psql" -X --no-password -h "$socket" -p 5432 -U "$user" -v ON_ERROR_STOP=1 -v VERBOSITY=verbose "$@"
}
identity() {
    test "$(psql_admin -d postgres -At -v expected_data="$data" -v expected_socket="$socket" -v expected_user="$user" -v expected_id="$control_id" <<'SQL'
SELECT current_user=:'expected_user' AND current_setting('server_version_num')='180006'
 AND current_setting('data_directory')=:'expected_data'
 AND current_setting('listen_addresses')=''
 AND current_setting('unix_socket_directories')=:'expected_socket'
 AND inet_server_addr() IS NULL
 AND (SELECT system_identifier::text FROM pg_control_system())=:'expected_id'
 AND NOT EXISTS (SELECT 1 FROM pg_hba_file_rules WHERE error IS NOT NULL OR auth_method='trust');
SQL
)" = t
}
cleanup() {
    # Cleanup runs once; repeated signals must not interrupt verified teardown.
    trap '' INT TERM
    code=$1
    trap - EXIT
    set +e
    if test -n "$holder_pid"; then wait "$holder_pid"; fi
    cleanup_failed=0
    if test "$startup_attempted" = 1; then
        /usr/bin/python3 "$repo/scripts/postgres-lifecycle.py" seal "$logdir" "$data" "$bin/postgres" "$uuid"
        if test $? != 0; then cleanup_failed=1; fi
    fi
    # A failed start with no SQL resources does not require a ready SQL server.
    if test "$roles_created" = 1 || test -n "$db_a_oid$db_b_oid"; then
      if identity; then
        for db in "$db_a" "$db_b"; do
            oid=
            if test "$db" = "$db_a"; then oid=$db_a_oid; else oid=$db_b_oid; fi
            if test -n "$oid"; then
                safe=$(psql_admin -d postgres -At -v target="$db" -v expected_oid="$oid" -v owner="$owner_role" -v marker="$marker" <<'SQL'
SELECT count(*)=1 FROM pg_database WHERE datname=:'target' AND oid=:'expected_oid'::oid
 AND datdba=to_regrole(:'owner') AND shobj_description(oid,'pg_database')=:'marker';
SQL
)
                if test "$safe" = t; then
                    psql_admin -d postgres -v target="$db" <<'SQL' >/dev/null
DROP DATABASE :"target";
SQL
                    if test $? != 0; then cleanup_failed=1; else echo "REMOVED DATABASE $db" | tee -a "$logdir/objects.txt"; fi
                else echo "Refusing unverified database cleanup: $db"; cleanup_failed=1; fi
            fi
        done
        if test "$roles_created" = 1 && test "$cleanup_failed" = 0; then
            for role in "$owner_role" "$runtime_role" "$writer_role" "$lock_role"; do
                safe=$(psql_admin -d postgres -At -v target="$role" -v marker="$marker" <<'SQL'
SELECT count(*)=1 FROM pg_roles WHERE rolname=:'target'
 AND shobj_description(oid,'pg_authid')=:'marker';
SQL
)
                if test "$safe" = t; then
                    psql_admin -d postgres -v target="$role" <<'SQL' >/dev/null
DROP ROLE :"target";
SQL
                    if test $? != 0; then cleanup_failed=1; else echo "REMOVED ROLE $role" | tee -a "$logdir/objects.txt"; fi
                else echo "Refusing unverified role cleanup: $role"; cleanup_failed=1; fi
            done
        fi
      else
        echo "Identity check failed; refusing database/role cleanup"; cleanup_failed=1
      fi
    fi
    if test "$startup_attempted" = 1; then
        /usr/bin/python3 "$repo/scripts/postgres-lifecycle.py" stop "$logdir" "$data" "$bin/postgres" "$uuid"
        if test $? != 0; then cleanup_failed=1; fi
    fi
    if test "$cleanup_failed" != 0; then
        echo "CLEANUP FAILED; inspect $logdir before manual recovery" >&2
        # Preserve the original failure/signal; a successful run becomes failure.
        if test "$code" = 0; then code=1; fi
    else
        echo "CLEANUP PASSED"
    fi
    exit "$code"
}
trap 'cleanup "$?"' EXIT
trap 'trap "" INT TERM; exit 130' INT
trap 'trap "" INT TERM; exit 143' TERM
if "$bin/pg_ctl" -D "$data" status >/dev/null 2>&1; then
    echo "Cluster initially running; preserving lifecycle"
else
    status=$?
    test "$status" = 3 || { echo "Unexpected pg_ctl status: $status"; exit 1; }
    # The launcher records the exact process before exec. Its gate closes on
    # exec, so cleanup can prohibit even a delayed launch after pg_ctl times out.
    : >"$logdir/startup.lock"
    : >"$logdir/startup.allowed"
    {
        echo '#!/usr/bin/env bash'
        echo 'exec 9>&-'
        printf 'exec /usr/bin/python3 %q launch %q %q %q %q "$@"\n' \
            "$repo/scripts/postgres-lifecycle.py" "$logdir" "$data" "$bin/postgres" "$uuid"
    } >"$logdir/postgres-launch"
    chmod 700 "$logdir/postgres-launch"
    startup_attempted=1
    "$bin/pg_ctl" -D "$data" -p "$logdir/postgres-launch" -l "$root/postgresql.log" -w -t 30 start 9>&-
    /usr/bin/python3 "$repo/scripts/postgres-lifecycle.py" verify "$logdir" "$data" "$bin/postgres" "$uuid"
fi
identity
# Names are fresh, and CREATE ROLE's transaction is all-or-nothing on collision.
psql_admin -d postgres -v owner_role="$owner_role" -v runtime_role="$runtime_role" \
    -v writer_role="$writer_role" -v lock_role="$lock_role" -v marker="$marker" \
    -f "$repo/db/bootstrap.sql" >"$logdir/bootstrap.log" 2>&1
roles_created=1
printf 'CREATED ROLE %s\n' "$owner_role" "$runtime_role" "$writer_role" "$lock_role" >"$logdir/objects.txt"
if psql_admin -d postgres -v owner_role="$owner_role" -v runtime_role="$runtime_role" \
    -v writer_role="$writer_role" -v lock_role="$lock_role" -v marker="$marker" \
    -f "$repo/db/bootstrap.sql" >"$logdir/bootstrap-collision.log" 2>&1; then
    echo "Unexpected role bootstrap overwrite"; exit 1
fi
grep -q '42710' "$logdir/bootstrap-collision.log"
for db in "$db_a" "$db_b"; do
    "$bin/createdb" --no-password -h "$socket" -p 5432 -U "$user" -T template0 -E UTF8 --locale=C -O "$owner_role" "$db"
    psql_admin -d postgres -v target="$db" -v marker="$marker" <<'SQL' >/dev/null
COMMENT ON DATABASE :"target" IS :'marker';
SQL
    oid=$(psql_admin -d postgres -At -v target="$db" <<'SQL'
SELECT oid FROM pg_database WHERE datname=:'target';
SQL
)
    if test "$db" = "$db_a"; then db_a_oid=$oid; else db_b_oid=$oid; fi
    printf 'CREATED DATABASE %s OID %s\n' "$db" "$oid" >>"$logdir/objects.txt"
    psql_admin -d "$db" -v target="$db" -v owner_role="$owner_role" -v runtime_role="$runtime_role" -v writer_role="$writer_role" <<'SQL' >/dev/null
REVOKE ALL ON DATABASE :"target" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"target" TO :"owner_role", :"runtime_role", :"writer_role";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
    for migration in "$repo"/db/migrations/*.sql; do
        psql_admin -d "$db" -v owner_role="$owner_role" -v runtime_role="$runtime_role" \
            -v writer_role="$writer_role" -v lock_role="$lock_role" \
            -f "$migration" >"$logdir/$db-$(basename "$migration").log" 2>&1
    done
    psql_admin -d "$db" -v owner_role="$owner_role" -v runtime_role="$runtime_role" \
        -v writer_role="$writer_role" -v lock_role="$lock_role" \
        -f "$repo/db/tests/integration.sql" >"$logdir/$db-tests.log" 2>&1
    echo "PASS fresh database migrations and SQL assertions: $db"
    for kind in missing_event missing_receipt pending_receipt; do
        pending=false
        missing=false
        message='invalid enquiry history'
        if test "$kind" = pending_receipt; then pending=true; message='incomplete command receipt'; fi
        if test "$kind" = missing_receipt; then missing=true; fi
        if psql_admin -d "$db" -v runtime_role="$runtime_role" -v pending_receipt="$pending" \
            -v missing_receipt="$missing" -f "$repo/db/tests/commit_denials.sql" \
            >"$logdir/commit-$kind-$db.log" 2>&1; then
            echo "Unexpected incomplete transaction commit: $kind"; exit 1
        fi
        grep -q 'REACHED_COMMIT' "$logdir/commit-$kind-$db.log"
        grep -q '23514' "$logdir/commit-$kind-$db.log"
        grep -q "$message" "$logdir/commit-$kind-$db.log"
        unchanged=$(psql_admin -d "$db" -At <<'SQL'
SELECT NOT EXISTS (SELECT 1 FROM softteros_enquiries.enquiries WHERE enquiry_id='commit-invalid')
 AND NOT EXISTS (SELECT 1 FROM softteros_enquiries.enquiry_events WHERE event_id='commit-invalid-event')
 AND NOT EXISTS (SELECT 1 FROM softteros_enquiries.enquiry_command_receipts WHERE request_key='commit-invalid');
SQL
)
        test "$unchanged" = t
        echo "PASS commit-time $kind denial and full rollback: $db"
    done
    # Reapplying a version must fail without overwriting existing resources.
    if psql_admin -d "$db" -v owner_role="$owner_role" -f "$repo/db/migrations/001_tables.sql" >"$logdir/reapply-$db.log" 2>&1; then
        echo "Unexpected migration reapplication success"; exit 1
    fi
    grep -q '42P06' "$logdir/reapply-$db.log"
    if psql_admin -d postgres -v target="$db" <<'SQL' >"$logdir/database-collision-$db.log" 2>&1
CREATE DATABASE :"target";
SQL
    then echo "Unexpected database overwrite"; exit 1; fi
    grep -q '42P04' "$logdir/database-collision-$db.log"
done

# Real separate connections: wait until the holder has both locks before testing
# a writer conflict. Bounded sleep is only the hold period, not the barrier.
PGAPPNAME="$prefix-holder" psql_admin -d "$db_a" -v runtime_role="$runtime_role" <<'SQL' >"$logdir/holder.log" 2>&1 &
BEGIN;
SET LOCAL ROLE :"runtime_role";
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-1',true);
SELECT * FROM softteros_access.lock_current_authority('actor-1','org-1');
SELECT pg_sleep(4);
COMMIT;
SQL
holder_pid=$!
ready=0
for attempt in $(seq 1 40); do
    waiting=$(psql_admin -d "$db_a" -At -v app="$prefix-holder" <<'SQL'
SELECT count(*)=1 FROM pg_stat_activity WHERE application_name=:'app' AND wait_event='PgSleep';
SQL
)
    if test "$waiting" = t; then ready=1; break; fi
    sleep 0.05
done
test "$ready" = 1
if psql_admin -d "$db_a" -v writer_role="$writer_role" <<'SQL' >"$logdir/lock-conflict.log" 2>&1
BEGIN;
SET LOCAL ROLE :"writer_role";
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-1',true);
UPDATE softteros_access.organization_authority_fences SET revision=revision+1 WHERE organization_id='org-1';
COMMIT;
SQL
then echo "Writer unexpectedly bypassed shared authority lock"; exit 1; fi
grep -q '55P03' "$logdir/lock-conflict.log"
wait "$holder_pid"
holder_pid=
echo "PASS writer lock conflict SQLSTATE 55P03"
psql_admin -d "$db_a" -v writer_role="$writer_role" <<'SQL' >"$logdir/writer-after-release.log" 2>&1
BEGIN;
SET LOCAL ROLE :"writer_role";
SELECT set_config('softteros.actor_id','actor-1',true),set_config('softteros.organization_id','org-1',true);
SELECT revision FROM softteros_access.actor_authority_fences WHERE actor_id='actor-1' FOR UPDATE;
UPDATE softteros_access.organization_authority_fences SET revision=revision+1 WHERE organization_id='org-1';
ROLLBACK;
SQL
echo "PASS writer proceeds after release (rolled back)"
echo "ALL SQL TESTS PASSED (cleanup still required)"

