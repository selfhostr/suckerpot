#!/usr/bin/env bash
# Brings an existing .env up to date after an update. Called by scripts/update.sh.
#
#   scripts/env-migrate.sh
#
# - Adds every secret of SECRET_VARS that is missing from .env, with a generated value
#   (never POSTGRES_PASSWORD: the database owner password lives in the data volume).
# - Adds the non-secret variables of MIGRATE_DEFAULTS that are missing, with their default.
# - Pins NETWORK_ENABLED=false on an install that predates the network default (see below).
# - Moves the two repository settings of the Theroxat -> selfhostr move (image prefix and update
#   check repository) when they hold exactly the old default value; any other value is yours and stays.
# - Never changes any other line that already exists.
# - Prints the NAMES it added, empty secrets it left alone, and optional variables that
#   .env.example has and .env does not. Never prints a value.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

[ -f .env ] || { echo "env-migrate: .env not found" >&2; exit 1; }

# This is the first script of the NEW checkout that an update runs, and the update that is running
# may be an older update.sh whose checkout was made under umask 077 (files 0600, folders 0700: the
# non-root users inside the containers cannot read them). Make the tracked files readable again.
# Tracked paths only: .env and the other private files are not touched.
fix_tracked_modes

stamp="# added by just update $(date -u +%Y-%m-%d)"
header_done=0
added=()
empty=()

add_header() {
  if [ "$header_done" -eq 0 ]; then
    printf '\n%s\n' "$stamp" >> .env
    header_done=1
  fi
}

skip_secret() {
  local n
  for n in "${NO_MIGRATE_SECRET_VARS[@]}"; do [ "$n" = "$1" ] && return 0; done
  return 1
}

# Every value already in use, so a new secret cannot collide with one.
used=$(sed -n 's/^[A-Z_]*=//p' .env | tr -d "\"'")

for name in "${SECRET_VARS[@]}"; do
  if env_has .env "$name"; then
    [ -n "$(env_get "$name")" ] || empty+=("$name")
    continue
  fi
  if skip_secret "$name"; then
    empty+=("$name")
    continue
  fi
  while :; do
    value=$(gen_for "$name")
    grep -qxF "$value" <<< "$used" || break
  done
  used+=$'\n'"$value"
  add_header
  printf '%s=%s\n' "$name" "$value" >> .env
  added+=("$name")
done

for pair in "${MIGRATE_DEFAULTS[@]}"; do
  name=${pair%%=*}
  if ! env_has .env "$name"; then
    add_header
    printf '%s\n' "$pair" >> .env
    added+=("$name")
  fi
done

# M33 made the network feature on by default. An install made before that has no
# NETWORK_DEFAULT_PINNED marker: if it also has no active NETWORK_ENABLED line, its owner never
# opted in (or turned it off by removing the line), so keep the old default, off. The marker makes
# this a one-time decision; installs made by the M33 installer carry it from the start.
if ! env_has .env NETWORK_DEFAULT_PINNED; then
  add_header
  if ! env_has .env NETWORK_ENABLED; then
    printf 'NETWORK_ENABLED=false\n' >> .env
    added+=(NETWORK_ENABLED)
    echo "env-migrate: NETWORK_ENABLED had no value; kept it off as before this version (turn it on: just set NETWORK_ENABLED=true)"
  fi
  printf 'NETWORK_DEFAULT_PINNED=1\n' >> .env
  added+=(NETWORK_DEFAULT_PINNED)
fi

# The project moved to the selfhostr organisation: an install made before that pinned the old image
# prefix (the installer writes it) and may carry the old update-check repository. Only the exact
# old defaults are rewritten, so a fork or a mirror keeps its own value. This does not weaken the
# signature checks: the verifiers still demand the release workflow of the repository named by
# the prefix.
if [ "$(env_get SUCKERPOT_IMAGE_PREFIX)" = "ghcr.io/theroxat/suckerpot" ]; then
  env_set_line .env SUCKERPOT_IMAGE_PREFIX "ghcr.io/selfhostr/suckerpot"
  echo "env-migrate: SUCKERPOT_IMAGE_PREFIX now points at ghcr.io/selfhostr/suckerpot (the project moved)"
fi
if [ "$(env_get UPDATE_CHECK_REPO)" = "Theroxat/suckerpot" ]; then
  env_set_line .env UPDATE_CHECK_REPO "selfhostr/suckerpot"
  echo "env-migrate: UPDATE_CHECK_REPO now points at selfhostr/suckerpot (the project moved)"
fi
chmod 600 .env

new_optional=()
if [ -f .env.example ]; then
  while IFS= read -r name; do
    env_has .env "$name" || grep -qE "^# $name=" .env || new_optional+=("$name")
  done < <(sed -n 's/^#\{0,1\} \{0,1\}\([A-Z][A-Z0-9_]*\)=.*/\1/p' .env.example | sort -u)
fi

echo "env-migrate: added ${#added[@]} variable(s)${added:+: ${added[*]}}"
if [ "${#empty[@]}" -gt 0 ]; then
  echo "env-migrate: still empty or missing, set them yourself: ${empty[*]}"
fi
if [ "${#new_optional[@]}" -gt 0 ]; then
  echo "env-migrate: optional variables in .env.example that .env does not have: ${new_optional[*]}"
fi
