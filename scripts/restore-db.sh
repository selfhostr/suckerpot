#!/usr/bin/env bash
# Restores a dump made by scripts/backup-db.sh or by the `backup` service into the running db
# container. THE CURRENT DATABASE IS REPLACED, but only once the dump has restored cleanly.
#
#   scripts/restore-db.sh [--yes] [--keep-previous] FILE|latest|volume:NAME
#
# FILE is a dump on the host (made by scripts/backup-db.sh). "latest" and "volume:NAME" read
# a dump of the daily `backup` service from the external suckerpot_backups volume. "latest" is
# the newest dump by modification time, of either kind: a regular one or a pre-update one
# (suckerpot-preupdate-*.dump, taken by `just update`). Both are complete database dumps, and the
# newest one loses the least data. Name a file with volume:NAME to pick a particular one.
# SUCKERPOT_BACKUPS_VOLUME names another backups volume (the end-to-end test uses it).
#
# The dump is restored into a SIDE database (<db>_restore) first, while ingest and api keep
# running on the live database. Only when that restore succeeded and the side database looks
# sane (alembic_version has one row, the events hypertable exists) are ingest, api and backup
# stopped and the two databases swapped with ALTER DATABASE ... RENAME: the live one becomes
# <db>_before_restore, the side one becomes the live one. Then the migrations run (they
# re-apply the role grants) and the services start. When all of it worked, <db>_before_restore
# is dropped, unless --keep-previous is given. When the restore fails before the swap, the side
# database is dropped and nothing was changed. When the migration or the start fails after the
# swap, both databases are kept and the exact commands to swap back are printed.
#
# The restore needs room for a second copy of the database. Sensors keep running; their events
# wait in Redis and are ingested afterwards.
set -euo pipefail

cd "$(dirname "$0")/.."
yes=0
keep_previous=0
while [ $# -gt 0 ]; do
  case $1 in
    --yes) yes=1; shift ;;
    --keep-previous) keep_previous=1; shift ;;
    *) break ;;
  esac
done
file=${1:-}
image=$(awk '/^  db:/ {indb=1} indb && /image: / {print $2; exit}' docker-compose.yml)
backups_volume=${SUCKERPOT_BACKUPS_VOLUME:-${SUCKERPOT_VOLUME_PREFIX:?SUCKERPOT_VOLUME_PREFIX must be set}_backups}
# Runs a command on the backups volume (read-only, no network).
in_backups() {
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true \
    --user 70:70 -v "$backups_volume:/b:ro" --entrypoint "$1" "$image" "${@:2}"
}
from_volume=""
case $file in
  latest)
    from_volume=$(in_backups sh -c 'ls -1t /b/suckerpot-*.dump 2>/dev/null | head -n 1' || true)
    from_volume=${from_volume##*/}
    [ -n "$from_volume" ] || { echo "restore: no dump in the backups volume" >&2; exit 2; }
    file="volume:$from_volume"
    ;;
  volume:*)
    from_volume=${file#volume:}
    case $from_volume in *[!A-Za-z0-9._-]* | .* | "") echo "restore: bad dump name" >&2; exit 2 ;; esac
    in_backups test -s "/b/$from_volume" || { echo "restore: $from_volume not found in the backups volume" >&2; exit 2; }
    ;;
  *)
    if [ -z "$file" ] || [ ! -f "$file" ]; then
      echo "usage: $0 [--yes] [--keep-previous] DUMP_FILE|latest|volume:NAME" >&2
      exit 2
    fi
    ;;
esac
# Streams the chosen dump to stdout.
read_dump() {
  if [ -n "$from_volume" ]; then in_backups cat "/b/$from_volume"; else cat "$file"; fi
}
if [ -n "$from_volume" ]; then
  dump_bytes=$(in_backups stat -c %s "/b/$from_volume" | tr -d '\r')
else
  dump_bytes=$(stat -c %s "$file")
fi

echo "restore: dump $file ($dump_bytes bytes)"
echo "restore: the restore needs room for a second copy of the database next to the current one"
if [ "$yes" -ne 1 ]; then
  echo "WARNING: this REPLACES the current SuckerPot database with:"
  echo "  $file"
  echo "The dump is restored into a separate database first. The current database is replaced"
  echo "only if the dump restores cleanly; otherwise nothing is changed."
  printf 'Type "restore" to continue: '
  read -r answer
  [ "$answer" = "restore" ] || { echo "aborted"; exit 1; }
fi

# Runs psql in the db container as the owner role, against the given database.
psqlx() {
  local database=$1
  shift
  docker compose exec -T db sh -c \
    'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -v ON_ERROR_STOP=1 -q -h 127.0.0.1 -U "$POSTGRES_USER" -d "$0" "$@"' "$database" "$@"
}

db=$(docker compose exec -T db sh -c 'printf %s "$POSTGRES_DB"' | tr -d '\r')
case $db in *[!A-Za-z0-9_]* | "") echo "restore: unexpected database name" >&2; exit 2 ;; esac
side="${db}_restore"
prev="${db}_before_restore"
failed="${db}_failed_restore"

echo "restore: checking that the dump is readable"
# Read the whole stream inside the container: pg_restore -l stops after the table of contents,
# and an early exit would make the writer fail with SIGPIPE under pipefail.
if ! read_dump | docker compose exec -T db sh -c 'pg_restore -l > /dev/null; rc=$?; cat > /dev/null; exit $rc'; then
  echo "restore: the dump is not readable (pg_restore -l failed), nothing was changed" >&2
  exit 1
fi

# The restore failed before the swap: drop the side database and say that nothing changed.
side_failed() {
  echo "restore: $1" >&2
  psqlx postgres -c "DROP DATABASE IF EXISTS \"$side\" WITH (FORCE)" > /dev/null 2>&1 || true
  echo "restore: nothing was changed: the live database and the running services are untouched" >&2
  exit 1
}

echo "restore: loading the dump into the side database $side (the live database is not touched)"
psqlx postgres -c "DROP DATABASE IF EXISTS \"$side\" WITH (FORCE)" -c "CREATE DATABASE \"$side\"" ||
  side_failed "could not create the side database"
psqlx "$side" -c "CREATE EXTENSION IF NOT EXISTS timescaledb" -c "SELECT timescaledb_pre_restore()" > /dev/null ||
  side_failed "could not prepare the side database for the restore"
# Owners and ACLs are not restored: the roles are re-created by the migration below.
docker compose exec -T db sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" exec pg_restore -h 127.0.0.1 -U "$POSTGRES_USER" -d "$0" --no-owner --no-acl --exit-on-error' "$side" \
  < <(read_dump) ||
  side_failed "pg_restore failed (the dump may be corrupted, or from a newer TimescaleDB)"
psqlx "$side" -c "SELECT timescaledb_post_restore()" > /dev/null ||
  side_failed "timescaledb_post_restore failed"

echo "restore: checking the side database"
versions=$(psqlx "$side" -At -c "SELECT count(*) FROM alembic_version" 2> /dev/null | tr -d '\r') || versions=""
[ "$versions" = "1" ] || side_failed "alembic_version is missing or does not have exactly one row (found: ${versions:-none})"
hyper=$(psqlx "$side" -At -c "SELECT count(*) FROM timescaledb_information.hypertables WHERE hypertable_name = 'events'" 2> /dev/null | tr -d '\r') || hyper=""
[ "$hyper" = "1" ] || side_failed "the events hypertable is missing"

# From here on the live database is replaced. Prints how to go back to the previous one.
swap_back_help() {
  cat >&2 <<EOF
restore: both databases are still in place. To go back to the previous database:

docker compose stop ingest api backup
docker compose exec -T db sh -c 'PGPASSWORD="\$POSTGRES_PASSWORD" exec psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "\$POSTGRES_USER" -d postgres' <<'SQL'
ALTER DATABASE "$db" ALLOW_CONNECTIONS false;
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$db' AND pid <> pg_backend_pid();
ALTER DATABASE "$db" RENAME TO "$failed";
ALTER DATABASE "$prev" RENAME TO "$db";
ALTER DATABASE "$db" ALLOW_CONNECTIONS true;
SQL
docker compose exec -T db sh -c 'PGPASSWORD="\$POSTGRES_PASSWORD" exec psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "\$POSTGRES_USER" -d "$db" -c "SELECT timescaledb_post_restore()"'
docker compose up -d --wait ingest api backup

The restored (new) database is kept as "$failed" until you drop it.
EOF
}

echo "restore: stopping ingest, api and backup"
docker compose stop ingest api backup

# Swap the databases. TimescaleDB keeps a background worker connected to every database with the
# extension, and the collector or a psql session may be connected too: new connections are refused
# and the existing ones are terminated before the rename, which is retried a few times. Both
# renames are one transaction: either both happen or none. The "previous" copy is dropped first:
# there is only ever one.
echo "restore: swapping the databases"
swapped=0
for attempt in 1 2 3 4 5; do
  if psqlx postgres \
    -c "ALTER DATABASE \"$db\" ALLOW_CONNECTIONS false" \
    -c "ALTER DATABASE \"$side\" ALLOW_CONNECTIONS false" \
    -c "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname IN ('$db', '$side') AND pid <> pg_backend_pid()" \
    -c "DROP DATABASE IF EXISTS \"$prev\" WITH (FORCE)" \
    -c "ALTER DATABASE \"$db\" RENAME TO \"$prev\"; ALTER DATABASE \"$side\" RENAME TO \"$db\"" > /dev/null; then
    swapped=1
    break
  fi
  echo "restore: the swap did not work (attempt $attempt of 5), retrying" >&2
  sleep 2
done
if [ "$swapped" -ne 1 ]; then
  # Nothing was renamed (the two renames are one transaction): reopen the live database.
  psqlx postgres -c "ALTER DATABASE \"$db\" ALLOW_CONNECTIONS true" > /dev/null 2>&1 || true
  psqlx postgres -c "DROP DATABASE IF EXISTS \"$side\" WITH (FORCE)" > /dev/null 2>&1 || true
  docker compose up -d --wait ingest api backup || true
  echo "restore: could not swap the databases, the live database was not replaced" >&2
  exit 1
fi
psqlx postgres -c "ALTER DATABASE \"$db\" ALLOW_CONNECTIONS true" -c "ALTER DATABASE \"$prev\" ALLOW_CONNECTIONS true" > /dev/null

# A renamed database loses its TimescaleDB scheduler: start the workers again and make sure no
# restore flag is left on, so continuous aggregate policies and retention run again.
echo "restore: starting the TimescaleDB background jobs on the restored database"
if ! { psqlx postgres -c "ALTER DATABASE \"$db\" RESET timescaledb.restoring" > /dev/null &&
  psqlx "$db" -c "SELECT timescaledb_post_restore()" > /dev/null; }; then
  echo "restore: could not restart the TimescaleDB background jobs" >&2
  swap_back_help
  exit 1
fi

echo "restore: running migrations"
if ! docker compose run --rm migrate; then
  echo "restore: the migration failed" >&2
  swap_back_help
  exit 1
fi
echo "restore: starting ingest, api and backup"
if ! docker compose up -d --wait ingest api backup; then
  echo "restore: the services did not become healthy" >&2
  swap_back_help
  exit 1
fi

if [ "$keep_previous" -eq 1 ]; then
  echo "restore: the previous database is kept as \"$prev\" (it uses disk space; drop it with DROP DATABASE \"$prev\" WITH (FORCE) once you no longer need it)"
else
  psqlx postgres -c "DROP DATABASE IF EXISTS \"$prev\" WITH (FORCE)" > /dev/null
fi
echo "restore: done"
