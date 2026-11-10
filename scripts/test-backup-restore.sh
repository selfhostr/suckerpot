#!/usr/bin/env bash
# End-to-end proof that a dump made by the `backup` service can be restored by scripts/restore-db.sh,
# and that a damaged dump leaves the live database alone. Used by `just test-backup-restore` and CI.
#
#   COMPOSE_PROJECT_NAME=sp-br-1 SUCKERPOT_VOLUME_PREFIX=sp-br-1 scripts/test-backup-restore.sh
#
# It starts a throwaway compose project (db, redis, migrate, ingest, api; nothing is published,
# every volume is project-local with a "test-" name, see docker-compose.it.yml), then:
#   1. inserts sessions and events in two hypertable chunks and refreshes a continuous aggregate;
#   2. takes a dump with the backup service;
#   3. changes the data and restores the dump with scripts/restore-db.sh --yes;
#   4. checks the row counts, the migration head, the role grants, the TimescaleDB jobs and that no
#      side or previous database is left;
#   5. negative case: a truncated copy of the dump must make restore-db.sh fail while the live
#      database keeps its rows and ingest and api keep running.
# The project is always torn down at the end.
#
# SAFETY: it refuses to run unless COMPOSE_PROJECT_NAME is set, is not "suckerpot", does not start
# with "selfhostr", and SUCKERPOT_VOLUME_PREFIX equals it. Never point it at a live stack.
set -euo pipefail

cd "$(dirname "$0")/.."

die() { echo "test-backup-restore: $*" >&2; exit 1; }

project=${COMPOSE_PROJECT_NAME:-}
[ -n "$project" ] || die "COMPOSE_PROJECT_NAME must be set to a throwaway name (use 'just test-backup-restore')"
[[ $project =~ ^[a-z0-9][a-z0-9_-]{0,40}$ ]] || die "COMPOSE_PROJECT_NAME '$project' must match ^[a-z0-9][a-z0-9_-]{0,40}\$"
[ "$project" != "suckerpot" ] || die "refusing to run: '$project' is the live project name"
case $project in selfhostr*) die "refusing to run: '$project' looks like a live project name" ;; esac
[ "${SUCKERPOT_VOLUME_PREFIX:-}" = "$project" ] || die "SUCKERPOT_VOLUME_PREFIX must equal COMPOSE_PROJECT_NAME ('$project')"
echo "test-backup-restore: project $project"

command -v openssl > /dev/null || die "openssl is required to generate the throwaway secrets"

tmp=$(mktemp -d)
overlay="$tmp/overlay.yml"
# Test stack only: no published port, no extra network, no login (same switches as
# docker-compose.ci.yml). It is applied on top of docker-compose.it.yml.
cat > "$overlay" <<'EOF'
services:
  api:
    networks: !override [backend]
    ports: !override []
    environment:
      API_AUTH_DISABLED: "true"
      SUCKERPOT_DEMO: "1"
  ingest:
    networks: !override [backend]
EOF
# Compose reads these for every command, including the ones restore-db.sh runs itself. An empty env
# file keeps a local .env (and its live names) out of the picture.
export COMPOSE_PROJECT_NAME="$project"
export COMPOSE_FILE="$PWD/docker-compose.yml:$PWD/docker-compose.it.yml:$overlay"
export COMPOSE_ENV_FILES=/dev/null
export SUCKERPOT_BACKUPS_VOLUME="test-${project}_backups"

# Fresh throwaway secrets for every required variable, whatever the caller (or a loaded .env) has:
# the test stack never shares a password with a real one.
# shellcheck disable=SC2016  # the pattern is a literal ${NAME:? text of the compose file
for v in $(grep -o '\${[A-Z0-9_]*:?' docker-compose.yml | tr -d '${:?' | sort -u); do
  [ "$v" = SUCKERPOT_VOLUME_PREFIX ] && continue
  export "$v=$(openssl rand -hex 20)"
done
export ADMIN_PASSWORD_HASH=ci-placeholder
POSTGRES_COLLECTOR_PASSWORD=$(openssl rand -hex 20)
export POSTGRES_COLLECTOR_PASSWORD

dc() { docker compose "$@"; }
cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "test-backup-restore: FAILED (exit $rc), last logs:" >&2
    dc ps -a >&2 || true
    dc logs --no-color --tail=40 db migrate ingest api >&2 || true
  fi
  dc down -v --remove-orphans > /dev/null 2>&1 || true
  rm -rf "$tmp"
  exit "$rc"
}
trap cleanup EXIT

# Defence in depth: the effective configuration must not mention a live name.
effective=$(dc config) || die "docker compose config failed"
if grep -Eq 'name: (suckerpot|selfhostr)[_-]' <<< "$effective"; then
  die "the effective compose configuration names a live volume or network, refusing to start"
fi
grep -q "name: test-${project}_db-data" <<< "$effective" || die "the database volume is not project-local"

db=${POSTGRES_DB:-suckerpot}
image=$(awk '/^  db:/ {indb=1} indb && /image: / {print $2; exit}' docker-compose.yml)
backups_volume=$SUCKERPOT_BACKUPS_VOLUME

# psql as the owner, against the database $1; the remaining arguments go to psql.
dbq() {
  local database=$1
  shift
  # shellcheck disable=SC2016  # expanded inside the container, not here
  dc exec -T db sh -c \
    'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -X -At -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$POSTGRES_USER" -d "$0" "$@"' "$database" "$@"
}
# psql as a restricted role: role, password, statement.
roleq() {
  # shellcheck disable=SC2016  # expanded inside the container, not here
  dc exec -T db sh -c 'PGPASSWORD="$1" exec psql -X -At -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$0" -d "$POSTGRES_DB" -c "$2"' "$1" "$2" "$3"
}
# Runs a command on the backups volume as the backup user.
in_backups() {
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true \
    --user 70:70 -v "$backups_volume:/b" --entrypoint "$1" "$image" "${@:2}"
}
pass() { echo "ok: $*"; }
check_eq() { # description, expected, actual
  [ "$2" = "$3" ] || die "$1: expected '$2', got '$3'"
  pass "$1 ($3)"
}
healthy() { # service
  local cid
  cid=$(dc ps -q "$1")
  [ -n "$cid" ] || die "$1 is not running"
  [ "$(docker inspect --format '{{.State.Health.Status}}' "$cid")" = healthy ] || die "$1 is not healthy"
}

# Row counts of the tables that matter, the continuous aggregate (raw and materialised) and the chunks.
fingerprint() {
  local mat
  mat=$(dbq "$db" -c "SELECT format('%I.%I', materialization_hypertable_schema, materialization_hypertable_name) FROM timescaledb_information.continuous_aggregates WHERE view_name = 'events_hourly'")
  dbq "$db" -c "SELECT (SELECT count(*) FROM events) || '/' || (SELECT count(*) FROM sessions) || '/' || (SELECT count(*) FROM $mat) || '/' || (SELECT coalesce(sum(events), 0) FROM events_hourly) || '/' || (SELECT count(*) FROM timescaledb_information.chunks WHERE hypertable_name = 'events')"
}

echo "== start the stack"
dc up -d --build --wait --wait-timeout 600 db redis ingest api
healthy ingest
healthy api

echo "== insert a known set of rows"
dbq "$db" -c "
INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at, last_event_at, event_count, login_attempts, commands, tags) VALUES
  ('br-s1', 'ssh', '192.0.2.10', 40001, 22, now() - interval '3 days', now() - interval '3 days', 40, 30, 5, '{recon}'),
  ('br-s2', 'web', '198.51.100.7', 40002, 80, now() - interval '1 day', now() - interval '1 day', 60, 0, 0, '{}'),
  ('br-s3', 'telnet', '203.0.113.9', 40003, 23, now() - interval '1 day', now() - interval '1 day', 5, 3, 0, '{mirai}')" > /dev/null
dbq "$db" -c "
INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, data)
SELECT now() - interval '3 days' + g * interval '1 second', 'ssh', 'br-s1', 'login_attempt', '192.0.2.10'::inet, 40001, 22, jsonb_build_object('n', g)
FROM generate_series(1, 40) g" > /dev/null
dbq "$db" -c "
INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, data)
SELECT now() - interval '1 day' + g * interval '1 second', 'web', 'br-s2', 'http_request', '198.51.100.7'::inet, 40002, 80, jsonb_build_object('n', g)
FROM generate_series(1, 60) g" > /dev/null
dbq "$db" -c "CALL refresh_continuous_aggregate('events_hourly', NULL, NULL)" > /dev/null
dumped=$(fingerprint)
echo "dumped state (events/sessions/materialised/aggregate/chunks): $dumped"
[ "$(dbq "$db" -c "SELECT count(*) FROM timescaledb_information.chunks WHERE hypertable_name = 'events'")" -ge 2 ] || die "the events hypertable should hold at least two chunks"
case $dumped in 100/3/0/*) die "the continuous aggregate holds no materialised data" ;; 100/3/*) ;; *) die "unexpected dumped state $dumped" ;; esac

echo "== take a dump with the backup service"
dc create backup > /dev/null
# The volume is new and root-owned; the live one is made writable for uid 70 by scripts/ensure-volumes.sh.
docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges:true \
  --entrypoint chown -v "$backups_volume:/b" "$image" 70:70 /b
dc run --rm --no-deps backup now
dump=$(in_backups sh -c 'ls -1t /b/suckerpot-*.dump | head -n 1')
dump=${dump##*/}
[[ $dump =~ ^suckerpot-[0-9]{8}T[0-9]{6}Z\.dump$ ]] || die "the backup service wrote no dump (found '$dump')"
pass "dump $dump"

echo "== change the data"
dbq "$db" -c "DELETE FROM events WHERE ts < now() - interval '2 days'" -c "DELETE FROM sessions WHERE session_id = 'br-s1'" \
  -c "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at, last_event_at) VALUES ('br-extra', 'ssh', '192.0.2.99', 1, 22, now(), now())" > /dev/null
changed=$(fingerprint)
[ "$changed" != "$dumped" ] || die "the data did not change"
pass "state changed ($changed)"

echo "== restore the dump"
bash scripts/restore-db.sh --yes "volume:$dump"

echo "== assertions after the restore"
check_eq "row counts equal the dumped state" "$dumped" "$(fingerprint)"
current=$(dc run --rm migrate alembic current 2>&1) || die "alembic current failed: $current"
[[ $current == *"(head)"* ]] || die "alembic_version is not at head: $current"
pass "alembic_version is at head"
leftover=$(dbq postgres -c "SELECT count(*) FROM pg_database WHERE datname LIKE '%\_restore'")
check_eq "no _restore or _before_restore database is left" 0 "$leftover"
healthy ingest
healthy api
healthy backup

ingest_user=${POSTGRES_INGEST_USER:-suckerpot_ingest}
api_user=${POSTGRES_API_USER:-suckerpot_api}
collector_user=${POSTGRES_COLLECTOR_USER:-suckerpot_collector}
expect_denied() { # description, role, password, statement
  local out
  if out=$(roleq "$2" "$3" "$4" 2>&1); then die "$1: the statement was allowed"; fi
  case $out in *"permission denied"*) pass "$1 is refused" ;; *) die "$1 failed for another reason: $out" ;; esac
}
roleq "$ingest_user" "$POSTGRES_INGEST_PASSWORD" "SELECT count(*) FROM events" > /dev/null || die "ingest role cannot read events"
pass "ingest role logs in and reads events"
expect_denied "ingest role DELETE FROM events" "$ingest_user" "$POSTGRES_INGEST_PASSWORD" "DELETE FROM events WHERE false"
roleq "$api_user" "$POSTGRES_API_PASSWORD" "SELECT count(*) FROM sessions" > /dev/null || die "api role cannot read sessions"
pass "api role logs in and reads sessions"
expect_denied "api role DELETE FROM sessions" "$api_user" "$POSTGRES_API_PASSWORD" "DELETE FROM sessions WHERE false"
roleq "$collector_user" "$POSTGRES_COLLECTOR_PASSWORD" "SELECT count(*) FROM fetch_targets" > /dev/null || die "collector role cannot read fetch_targets"
pass "collector role logs in and reads fetch_targets"
expect_denied "collector role SELECT FROM events" "$collector_user" "$POSTGRES_COLLECTOR_PASSWORD" "SELECT count(*) FROM events"

# No restore flag left behind, and the policy jobs are scheduled and really run again.
check_eq "timescaledb.restoring is off" off "$(dbq "$db" -c "SHOW timescaledb.restoring")"
flags=$(dbq postgres -c "SELECT count(*) FROM pg_db_role_setting s JOIN pg_database d ON d.oid = s.setdatabase WHERE d.datname = '$db' AND s.setconfig::text LIKE '%timescaledb.restoring%'")
check_eq "no per-database timescaledb.restoring setting" 0 "$flags"
policies="'policy_refresh_continuous_aggregate', 'policy_retention'"
njobs=$(dbq "$db" -c "SELECT count(*) FROM timescaledb_information.jobs WHERE scheduled AND proc_name IN ($policies)")
[ "$njobs" -ge 2 ] || die "expected scheduled continuous aggregate and retention policy jobs, found $njobs"
pass "$njobs policy jobs are scheduled"
mark=$(dbq "$db" -c "SELECT clock_timestamp()")
dbq "$db" -c "SELECT count(*) FROM (SELECT alter_job(job_id, next_start => now()) FROM timescaledb_information.jobs WHERE proc_name IN ($policies)) s" > /dev/null
ran=0
for _ in $(seq 1 40); do
  ran=$(dbq "$db" -c "SELECT count(*) FROM timescaledb_information.job_stats js JOIN timescaledb_information.jobs j USING (job_id) WHERE j.proc_name IN ($policies) AND js.last_run_status = 'Success' AND js.last_run_started_at > '$mark'")
  [ "$ran" -ge "$njobs" ] && break
  sleep 3
done
[ "$ran" -ge "$njobs" ] || die "the TimescaleDB policy jobs did not run after the restore ($ran of $njobs)"
pass "the policy jobs ran again after the restore"

echo "== negative case: a truncated dump"
size=$(in_backups stat -c %s "/b/$dump" | tr -d '\r')
in_backups sh -c "head -c $((size / 2)) /b/$dump > /b/suckerpot-truncated.dump"
before=$(fingerprint)
if bash scripts/restore-db.sh --yes "volume:suckerpot-truncated.dump" > "$tmp/negative.log" 2>&1; then
  cat "$tmp/negative.log" >&2
  die "restoring a truncated dump succeeded"
fi
cat "$tmp/negative.log"
grep -q "nothing was changed" "$tmp/negative.log" || die "the failure message does not say that nothing was changed"
check_eq "the live database still holds its rows" "$before" "$(fingerprint)"
leftover=$(dbq postgres -c "SELECT count(*) FROM pg_database WHERE datname LIKE '%\_restore'")
check_eq "no side database is left after the failure" 0 "$leftover"
healthy ingest
healthy api
echo "test-backup-restore: all checks passed"
