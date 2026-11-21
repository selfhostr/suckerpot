#!/usr/bin/env bash
# Creates the external data volumes of the live stack (see the `volumes:` section of
# docker-compose.yml) when they are missing. `docker volume create` is idempotent. Run by
# `just up` before `docker compose up`.
#
#   scripts/ensure-volumes.sh [--force-empty]
#
# Safety check: when the database volume is MISSING but the backups volume holds dumps, the
# script stops instead of letting Postgres initialise an empty database on top of what was
# probably lost by accident. Restore the newest dump (`just restore latest`, after starting
# only db) or accept an empty database on purpose with `--force-empty` or
# SUCKERPOT_ALLOW_EMPTY_DB=1.
#
# It only ever CREATES volumes. It never removes or modifies the data of an existing one.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/engine.sh
. scripts/lib/engine.sh
if ! engine_ready; then
  echo "ensure-volumes: $ENGINE_UNREADY_MSG" >&2
  exit 1
fi
force=0
if [ "${1:-}" = "--force-empty" ] || [ "${SUCKERPOT_ALLOW_EMPTY_DB:-0}" = "1" ]; then force=1; fi

prefix=${SUCKERPOT_VOLUME_PREFIX:-}
if [ -z "$prefix" ]; then
  echo "ensure-volumes: SUCKERPOT_VOLUME_PREFIX is not set (it comes from .env on the live host)" >&2
  exit 1
fi
if ! [[ "$prefix" =~ ^[a-z0-9][a-z0-9_-]{0,40}$ ]]; then
  echo "ensure-volumes: SUCKERPOT_VOLUME_PREFIX must match ^[a-z0-9][a-z0-9_-]{0,40}\$" >&2
  exit 1
fi
mapfile -t volumes < <(grep -oE '^    name: \$\{SUCKERPOT_VOLUME_PREFIX:\?[^}]*\}_[a-z0-9-]+$' docker-compose.yml | sed -E "s/.*\}_/${prefix}_/")
if [ "${#volumes[@]}" -lt 10 ]; then
  echo "ensure-volumes: could not read the volume names from docker-compose.yml" >&2
  exit 1
fi
image=$(engine_image "$(awk '/^  db:/ {indb=1} indb && /image: / {print $2; exit}' docker-compose.yml)")
if [ -z "$image" ]; then
  echo "ensure-volumes: could not read the db image from docker-compose.yml" >&2
  exit 1
fi

exists() { ctr volume inspect "$1" > /dev/null 2>&1; }

if ! exists "${prefix}_db-data" && exists "${prefix}_backups"; then
  dumps=$(ctr run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true \
    --user 70:70 --entrypoint sh -v "${prefix}_backups":/b:ro "$image" \
    -c 'ls -1 /b/suckerpot-*.dump 2>/dev/null | wc -l') || dumps=unknown
  case $dumps in '' | *[!0-9]*) dumps=unknown ;; esac
  if [ "$dumps" != 0 ] && [ "$force" -ne 1 ]; then
    cat >&2 << EOF
ensure-volumes: STOP. The database volume "${prefix}_db-data" does not exist, but the
backups volume ${prefix}_backups holds $dumps dump(s) (unknown = could not be counted). Starting now would create an EMPTY database.

  - To restore the newest dump: create the volumes and start only the database, then restore:
        scripts/ensure-volumes.sh --force-empty && ${ENGINE_DC[*]} up -d --wait db && just restore latest
  - To really start from scratch: just up --force-empty   (or SUCKERPOT_ALLOW_EMPTY_DB=1)
EOF
    exit 3
  fi
fi

for v in "${volumes[@]}"; do
  if exists "$v"; then continue; fi
  ctr volume create "$v" > /dev/null
  echo "ensure-volumes: created $v"
  if [ "$v" = "${prefix}_backups" ]; then
    # The backup service runs as uid 70 (postgres); a new volume starts root-owned.
    ctr run --rm --network none --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges:true \
      --user 0:0 --entrypoint chown -v "$v:/b" "$image" 70:70 /b
  fi
  if [ "$v" = "${prefix}_vpn-config" ]; then
    # In participant mode (M32) the api never starts, so nobody else fixes the owner of this
    # volume. The vpn container (read-only mount) and a later switch to full mode (the api,
    # uid 10001) both expect uid 10001.
    ctr run --rm --network none --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges:true \
      --user 0:0 --entrypoint chown -v "$v:/b" "$image" 10001:10001 /b
  fi
  if [ "$v" = "${prefix}_trap-packs" ]; then
    # The signed trap pack bundle (M37): ingest (uid 10001) writes it, the web sensor (uid 10001)
    # reads it read-only.
    ctr run --rm --network none --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges:true \
      --user 0:0 --entrypoint chown -v "$v:/b" "$image" 10001:10001 /b
  fi
done
