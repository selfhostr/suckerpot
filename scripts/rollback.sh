#!/usr/bin/env bash
# Puts SuckerPot back to the state recorded by the last `just update`: the previous code and
# version, and the database as it was in the dump taken just before the update, but only if the
# update changed the schema.
# Called by `just rollback`.
#
#   scripts/rollback.sh [--yes] [--restore-db | --keep-db]
#
# --yes skips both confirmations. Only scripts/auto-update.sh uses it, after a failed automatic
# update.
# --restore-db always replaces the database with the dump taken before the update.
# --keep-db never touches the database, even if the schema moved (the old code may then not
#   be able to read it).
# Without either flag the database is restored only when the Alembic revision now differs from the
# one recorded before the update (or cannot be read). When the schema did not move, only the code
# and images go back and every event is kept.
#
# RESTORING THE DATABASE REPLACES IT with the dump. Events received between the dump and now are
# lost. It asks you to type "rollback"; restoring the dump then asks its own confirmation.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

assume_yes=0
db_mode=auto
while [ $# -gt 0 ]; do
  case $1 in
    --yes | -y) assume_yes=1 ;;
    --restore-db) db_mode=restore ;;
    --keep-db) db_mode=keep ;;
    *) echo "rollback: unknown argument: $1 (usage: rollback.sh [--yes] [--restore-db | --keep-db])" >&2; exit 2 ;;
  esac
  shift
done

STATE_DIR=.suckerpot-state
STATE=$STATE_DIR/last-update.json
die() { echo "rollback: $*" >&2; exit 1; }

[ -f .env ] || die ".env not found"
need_project
env_drop_loaded
# restore-db.sh reads the volume prefix from the environment (just loads it from .env).
SUCKERPOT_VOLUME_PREFIX=$(env_get SUCKERPOT_VOLUME_PREFIX)
export SUCKERPOT_VOLUME_PREFIX
# One update or rollback at a time (the automatic updater holds this lock and says so).
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
if [ "${SELFHOSTR_UPDATE_LOCK_HELD:-}" != 1 ]; then
  exec 9> "$STATE_DIR/update.lock"
  flock -n 9 || die "another update or rollback is running (lock $STATE_DIR/update.lock)"
fi
[ -f "$STATE" ] || die "no update to roll back ($STATE not found)"

from_version=$(state_get "$STATE" from_version)
from_ref=$(state_get "$STATE" from_ref)
from_branch=$(state_get "$STATE" from_branch)
mode=$(state_get "$STATE" mode)
dump=$(state_get "$STATE" dump)
at=$(state_get "$STATE" at)

[[ $from_ref =~ ^[0-9a-f]{7,64}$ ]] || die "the state file has no valid commit"
case $mode in images | source) ;; *) die "the state file has a bad install mode" ;; esac
alembic_before=$(state_get "$STATE" alembic_before)
# The state file is only trusted for a plain revision id: anything else counts as "unknown".
[[ $alembic_before =~ ^[A-Za-z0-9_]{1,64}$ ]] || alembic_before=""
# A dump name that is set must be a plain file name, whatever the database decision is.
[ -z "$dump" ] || [[ $dump =~ ^suckerpot-[A-Za-z0-9._-]+\.dump$ ]] || die "the state file has a bad dump name"
[[ $from_version =~ ^[A-Za-z0-9._-]+$ ]] || die "the state file has a bad version"
git rev-parse -q --verify "$from_ref^{commit}" > /dev/null || die "commit $from_ref is not in this checkout"

# Did the schema move? Compare the revision recorded before the update with the live one.
alembic_now=$(docker compose exec -T db sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -q -At -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT version_num FROM alembic_version"' \
  2> /dev/null | tr -d '\r' | head -n 1 || true)
[[ $alembic_now =~ ^[A-Za-z0-9_]{1,64}$ ]] || alembic_now=""
case $db_mode in
  restore) restore_db=1; db_reason="--restore-db" ;;
  keep) restore_db=0; db_reason="--keep-db" ;;
  *)
    if [ -n "$alembic_before" ] && [ -n "$alembic_now" ] && [ "$alembic_before" = "$alembic_now" ]; then
      restore_db=0; db_reason="the schema did not change (Alembic revision $alembic_now)"
    elif [ -n "$alembic_before" ] && [ -n "$alembic_now" ]; then
      restore_db=1; db_reason="the schema changed ($alembic_before -> $alembic_now)"
    else
      restore_db=1; db_reason="the Alembic revision is missing, invalid or unreadable, so the database is restored unless --keep-db is given"
    fi ;;
esac

if [ "$restore_db" = 1 ]; then
  [ -n "$dump" ] \
    || die "the last update was made without a backup, so there is no database to restore (use --keep-db to roll back the code only)"
fi

# The dump must still be there BEFORE anything is changed (code, images or database).
if [ "$restore_db" = 1 ]; then
  db_image=$(awk '/^  db:/ {indb=1} indb && /image: / {print $2; exit}' docker-compose.yml)
  [ -n "$db_image" ] || die "could not read the db image from docker-compose.yml"
  # Never let docker create a missing volume (it would be empty, and a false "dump gone" answer).
  docker volume inspect "${SUCKERPOT_VOLUME_PREFIX}_backups" > /dev/null 2>&1 \
    || die "the backups volume ${SUCKERPOT_VOLUME_PREFIX}_backups does not exist. Nothing was changed."
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true --user 70:70 \
    -v "${SUCKERPOT_VOLUME_PREFIX}_backups:/b:ro" --entrypoint test "$db_image" -s "/b/$dump" \
    || die "the dump $dump is no longer in the backups volume (retention removed it?). Nothing was changed."
fi

echo "Rollback of the update made at $at:"
echo "  code:     back to $from_version (commit ${from_ref:0:9})"
echo "  images:   $mode mode, then $([ "$mode" = images ] && echo 'pull' || echo 'build')"
if [ "$restore_db" = 1 ]; then
  echo "  database: REPLACED by the dump $dump ($db_reason)"
  echo
  echo "Events received since that dump are lost."
else
  echo "  database: KEPT as it is, no event is lost ($db_reason)"
fi
if [ "$assume_yes" = 0 ]; then
  printf 'Type "rollback" to continue: '
  read -r answer || answer=""
  [ "$answer" = "rollback" ] || { echo "aborted"; exit 1; }
fi

echo "[1/4] Restoring the previous code"
if [ -n "$from_branch" ] && [ "$(git rev-parse -q --verify "refs/heads/$from_branch" 2> /dev/null || true)" = "$(git rev-parse "$from_ref^{commit}")" ]; then
  git checkout --quiet "$from_branch"
else
  git checkout --quiet --detach "$from_ref"
fi

echo "[2/4] Restoring the images"
if [ "$mode" = images ]; then
  env_set_line .env SUCKERPOT_VERSION "$from_version"
  env_drop_loaded
  # Same gate as an update: verify the signatures, pull the verified digests, run only those.
  bash scripts/verify-images.sh --pull "$from_version" \
    || die "the image signatures of $from_version could not be verified; nothing was started"
  docker compose pull --policy missing
else
  SUCKERPOT_BUILD_VERSION=$(git describe --tags --always --dirty 2> /dev/null || echo dev)
  SUCKERPOT_BUILD_COMMIT=$(git rev-parse --short HEAD 2> /dev/null || echo unknown)
  export SUCKERPOT_BUILD_VERSION SUCKERPOT_BUILD_COMMIT
  docker compose build
fi

if [ "$restore_db" = 1 ]; then
  echo "[3/4] Restoring the database from $dump"
  if [ "$assume_yes" = 1 ]; then
    bash scripts/restore-db.sh --yes "volume:$dump"
  else
    bash scripts/restore-db.sh "volume:$dump"
  fi
else
  echo "[3/4] Keeping the database ($db_reason)"
fi

echo "[4/4] Starting"
bash scripts/check-ports.sh --dotenv-only
if [ "$mode" = images ]; then
  compose_up_recreating -d --no-build --pull never --wait --wait-timeout 600
else
  compose_up_recreating -d --wait --wait-timeout 600
fi
# Mark the recorded update as resolved, so the next `just update` is not blocked by its lock.
tmp=$(mktemp ".suckerpot-state/.state.XXXXXX")
sed 's/"completed": false,/"completed": true,/' "$STATE" > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$STATE"
echo
echo "Rolled back to $from_version."
