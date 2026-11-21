#!/usr/bin/env bash
# shellcheck disable=SC2016 # dc exec ... sh -c '...': expanded by the shell inside the container
# Dumps the SuckerPot database (custom format, includes TimescaleDB data) from the
# running db container to a host directory.
#
#   scripts/backup-db.sh
#
# Environment:
#   BACKUP_DIR   where dumps go (default: ./backups, ignored by git)
#   BACKUP_KEEP  how many dumps to keep (default: 7); older ones are deleted
#
# The database credentials come from the container's own environment and are never
# printed. Dumps are written with mode 0600. They contain captured attack data:
# never commit them and never copy them to a public place.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/engine.sh
. scripts/lib/engine.sh
BACKUP_DIR=${BACKUP_DIR:-./backups}
BACKUP_KEEP=${BACKUP_KEEP:-7}
case $BACKUP_KEEP in '' | *[!0-9]* | 0) echo "BACKUP_KEEP must be a positive number" >&2; exit 2 ;; esac

umask 077
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Refuse to start when the disk is too full: need 2x the size of the last dump
# (or 1 GiB when there is no previous dump).
last=$(ls -1t "$BACKUP_DIR"/suckerpot-*.dump 2>/dev/null | head -n 1 || true)
need=$((1024 * 1024 * 1024))
if [ -n "$last" ]; then need=$(($(stat -c %s "$last") * 2)); fi
free=$(($(df -Pk "$BACKUP_DIR" | awk 'NR==2 {print $4}') * 1024))
if [ "$free" -lt "$need" ]; then
  echo "backup: not enough free disk space in $BACKUP_DIR (free: $free bytes, need: $need)" >&2
  exit 1
fi

name="suckerpot-$(date -u +%Y%m%dT%H%M%SZ).dump"
tmp="$BACKUP_DIR/.$name.partial"
trap 'rm -f "$tmp"' EXIT

dc exec -T db sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" exec pg_dump -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' \
  > "$tmp"

if [ ! -s "$tmp" ]; then
  echo "backup: the dump is empty" >&2
  exit 1
fi
chmod 600 "$tmp"
mv "$tmp" "$BACKUP_DIR/$name"
trap - EXIT
echo "backup: wrote $BACKUP_DIR/$name ($(stat -c %s "$BACKUP_DIR/$name") bytes)"

# Retention: keep the newest BACKUP_KEEP dumps.
ls -1t "$BACKUP_DIR"/suckerpot-*.dump | tail -n +"$((BACKUP_KEEP + 1))" | while read -r old; do
  rm -f -- "$old"
  echo "backup: removed old dump $old"
done
