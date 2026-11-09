#!/usr/bin/env bash
# Safe update of an installed SuckerPot: backup first, then new code, new images, restart, health
# check. Called by `just update [vX.Y.Z]`. See docs/design/m28.md section 6.
#
#   scripts/update.sh [--yes] [--no-backup] [--skip-verify] [--force] [--auto] [vX.Y.Z]
#
# --auto is for scripts/auto-update.sh: no prompt at all, a signed release manifest is mandatory
# (and the release must be old enough), and nothing is printed about a manual rollback.
#
# In images mode the signed release manifest (scripts/verify-release.sh) is checked before the
# code changes. A release older than v0.6.0 has none: a manual update warns and goes on.
#
# A database dump is taken first and recorded in .suckerpot-state/last-update.json, together with
# the commit and version you were on, so `just rollback` can put everything back. Migrations are
# forward-only: when the schema moved, a rollback restores the dump (events received since are
# lost); when it did not, a rollback keeps the data. The script never rolls back by itself.
#
# The health of every service is recorded before anything changes. The update fails only on a
# regression: a service that was healthy (or had no healthcheck) and is not healthy after
# UPDATE_HEALTH_WAIT_SECONDS (default 180). A service that was already unhealthy is only reported.
#
# Exit codes: 0 done, 1 failed, 2 bad usage, 10 failed because of the release itself (a
# regression, a failed migration, a wrong running version). scripts/auto-update.sh blacklists a version
# only on 10.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

STATE_DIR=.suckerpot-state
STATE=$STATE_DIR/last-update.json
TOTAL=9

assume_yes=0
no_backup=0
skip_verify=0
force=0
auto=0
target=""
target_commit=""
expect_file=""
while [ $# -gt 0 ]; do
  case $1 in
    --yes | -y) assume_yes=1 ;;
    --no-backup) no_backup=1 ;;
    --skip-verify) skip_verify=1 ;;
    --force) force=1 ;;
    --auto) auto=1; assume_yes=1 ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    v[0-9]*) target=$1 ;;
    *) echo "update: unknown argument: $1 (usage: update.sh [--yes] [--no-backup] [--skip-verify] [--force] [--auto] [vX.Y.Z])" >&2; exit 2 ;;
  esac
  shift
done
if [ -n "$target" ] && ! [[ $target =~ ^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "update: the version must look like v1.2.3" >&2
  exit 2
fi

if [ "$auto" = 1 ] && { [ "$no_backup" = 1 ] || [ "$skip_verify" = 1 ] || [ "$force" = 1 ]; }; then
  echo "update: --auto cannot be combined with --no-backup, --skip-verify or --force" >&2
  exit 2
fi

die() { echo "update: $*" >&2; exit 1; }
# A failure caused by the release itself (exit 10, see the header).
die_release() { echo "update: $*" >&2; exit 10; }
# "service state health" per line; an empty health means a container without a healthcheck.
health_snapshot() { docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' 2> /dev/null | tr -d '\r' | sort || true; }
# health_of SERVICE SNAPSHOT: prints the status of SERVICE, fails when it is absent. The status is
# the container state when it is not "running" (restarting, exited...), else its health (empty for
# a running container without a healthcheck, which is good).
health_of() { printf '%s\n' "$2" | awk -v s="$1" '$1 == s { print ($2 != "running") ? $2 : $3; f = 1 } END { exit !f }'; }
is_good() { [ "$1" = healthy ] || [ -z "$1" ]; }
# good_before SERVICE: true when SERVICE was healthy (or had no healthcheck) before the update.
good_before() {
  local h
  h=$(health_of "$1" "$health_before") || return 1
  is_good "$h"
}
# release_or_warn SERVICE MESSAGE: a release fault if SERVICE was good before the update, otherwise
# only a warning (the node was already degraded and the update did not change that).
release_or_warn() {
  if good_before "$1"; then die_release "$2"; fi
  echo "      warning: $2, but $1 was already unhealthy before the update. The update did not change that." >&2
}
# The Alembic revision the database is at ("" when it cannot be read).
db_alembic_revision() {
  local rev
  rev=$(docker compose exec -T db sh -c \
    'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -q -At -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT version_num FROM alembic_version"' \
    2> /dev/null | tr -d '\r' | head -n 1 || true)
  [[ $rev =~ ^[A-Za-z0-9_]{1,64}$ ]] || rev=""
  printf %s "$rev"
}
step() { printf '[%s/%s] %s\n' "$1" "$TOTAL" "$2"; }
confirm() {
  [ "$assume_yes" = 1 ] && return 0
  local a
  printf '%s [y/N]: ' "$1"
  read -r a || a=""
  [ "$a" = y ] || [ "$a" = yes ]
}

[ -f .env ] || die ".env not found. SuckerPot is not installed here (run ./scripts/install.sh)."
need_project
env_drop_loaded

mode=$(env_get SUCKERPOT_INSTALL_MODE source)
case $mode in images | source) ;; *) die "SUCKERPOT_INSTALL_MODE must be images or source" ;; esac
stack_mode=$(env_get SUCKERPOT_STACK_MODE full)
case $stack_mode in full | participant) ;; *) die "SUCKERPOT_STACK_MODE must be full or participant" ;; esac
dport=$(env_get DASHBOARD_PORT 8443)
bind=$(env_get DASHBOARD_BIND 127.0.0.1)
[ "$bind" = 0.0.0.0 ] && bind=127.0.0.1

# One update or rollback at a time (the automatic updater holds this lock and says so).
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
if [ "${SELFHOSTR_UPDATE_LOCK_HELD:-}" != 1 ]; then
  exec 9> "$STATE_DIR/update.lock"
  flock -n 9 || die "another update or rollback is running (lock $STATE_DIR/update.lock)"
fi

# Safe characters only, for anything that ends up in the state file.
clean() { printf %s "$1" | tr -cd 'A-Za-z0-9._:/@=,+-'; }

# ---------------------------------------------------------------- 1. preflight
step 1 "Checking the installation"
dirty=$(git status --porcelain --untracked-files=no 2> /dev/null || true)
if [ -n "$dirty" ]; then
  if [ "$mode" = source ]; then
    die "tracked files have local changes; commit or discard them first (git status)"
  fi
  echo "      warning: tracked files have local changes (the compose file comes from git too)" >&2
fi

backup_health=$(docker compose ps backup --format '{{.Health}}' 2> /dev/null | head -n 1 || true)
if [ "$backup_health" != healthy ]; then
  if [ "$no_backup" = 0 ]; then
    die "the stack is not up or the backup service is not healthy (state: ${backup_health:-none}). Run: just up"
  fi
  echo "      warning: the backup service is not healthy" >&2
fi

if [ "$force" = 0 ] && [ -f "$STATE" ] && grep -q '"completed": false' "$STATE"; then
  die "the previous update never finished (see $STATE). Run just rollback, or finish it, or retry with --force"
fi

from_ref=$(git rev-parse HEAD 2> /dev/null || true)
[ -n "$from_ref" ] || die "this folder is not a git checkout"
from_branch=$(git symbolic-ref --short -q HEAD 2> /dev/null || true)
from_version=$(git describe --tags --always 2> /dev/null || echo unknown)
if [ "$mode" = images ]; then
  from_version=$(env_get SUCKERPOT_VERSION "$from_version")
fi

fetched=1
git fetch --tags --quiet 2> /dev/null || fetched=0
[ "$fetched" = 1 ] || echo "      warning: could not fetch tags from the remote; using the local ones" >&2

pull_branch=0
if [ -z "$target" ]; then
  if [ "$mode" = source ] && [ -n "$from_branch" ]; then
    pull_branch=1
  else
    target=$(git tag -l 'v*.*.*' --sort=-v:refname | grep -E '^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -n 1 || true)
    [ -n "$target" ] || die "no release tag found"
  fi
fi
if [ -n "$target" ]; then
  git rev-parse -q --verify "refs/tags/$target" > /dev/null || die "tag $target not found"
  target_commit=$(git rev-parse "refs/tags/$target^{commit}")
  if [ "$target" = "$from_version" ] && [ "$(git rev-parse "$target^{commit}")" = "$from_ref" ]; then
    echo "Already on $target. Nothing to update."
    exit 0
  fi
fi

# The signed release manifest (M32): images mode only. Source mode builds what it has checked out.
if [ -n "$target" ] && [ "$mode" = images ]; then
  if [ "$skip_verify" = 1 ]; then
    echo "      warning: --skip-verify, the signed release manifest was NOT checked" >&2
  else
    vr_args=()
    [ "$auto" = 1 ] && vr_args+=(--auto)
    vr_rc=0
    vr_out=$(bash scripts/verify-release.sh ${vr_args[@]+"${vr_args[@]}"} "$target") || vr_rc=$?
    printf '%s\n' "$vr_out"
    case $vr_rc in
      0)
        # What was verified is what gets checked out, and what the images are compared with.
        target_commit=$(printf '%s\n' "$vr_out" | sed -n 's/^commit=//p' | head -n 1)
        [[ $target_commit =~ ^[0-9a-f]{40}$ ]] || die "the release check returned no commit"
        expect_file=$(mktemp)
        printf '%s\n' "$vr_out" | grep '^image\.' > "$expect_file" || true
        ;;
      3)
        [ "$auto" = 0 ] || die "$target has no signed release manifest; an automatic update refuses it"
        echo "      warning: $target has no signed release manifest (older than v0.6.0); going on" >&2
        ;;
      *) die "the signed release manifest of $target could not be verified (exit $vr_rc); nothing was changed. Retry with --skip-verify only if you accept the risk" ;;
    esac
  fi
fi

echo "      current: $from_version"
if [ "$pull_branch" = 1 ]; then
  echo "      target:  newest commit of branch $from_branch (git pull --ff-only)"
else
  echo "      target:  $target"
  notes=$(git tag -l --format='%(contents)' "$target" 2> /dev/null | tr -d '\000-\010\013-\037\177' || true)
  if [ -n "$notes" ]; then
    echo "      release notes:"
    printf '%s\n' "$notes" | sed 's/^/        /'
  fi
fi
confirm "Update now? A database backup is taken first." || { echo "aborted"; exit 1; }

# What the node looks like before anything changes: the update is judged against this.
wait_s=$(env_get UPDATE_HEALTH_WAIT_SECONDS "${UPDATE_HEALTH_WAIT_SECONDS:-180}")
[[ $wait_s =~ ^[0-9]{1,4}$ ]] || wait_s=180
# Let services that are still starting settle first (at most 60 s). One that is still starting
# after that counts as good: the release is then held to the normal standard for it.
pre_wait=$wait_s
[ "$pre_wait" -le 60 ] || pre_wait=60
for ((i = 0; i <= pre_wait / 5; i++)); do
  health_before=$(health_snapshot)
  printf '%s\n' "$health_before" | awk '$2 == "running" && $3 == "starting" { f = 1 } END { exit !f }' || break
  [ "$i" -lt $((pre_wait / 5)) ] && sleep 5
done
health_before=$(printf '%s\n' "$health_before" | awk '$2 == "running" && $3 == "starting" { $3 = "healthy" } { print }')
alembic_before=$(db_alembic_revision)

# ---------------------------------------------------------------- 2. backup
step 2 "Backing up the database"
dump=""
if [ "$no_backup" = 1 ]; then
  echo "      Without a backup there is NO way back for the database."
  printf '      Type "no backup" to continue without one: '
  read -r a || a=""
  [ "$a" = "no backup" ] || die "aborted"
else
  docker compose exec -T backup /bin/sh /backup-service.sh now preupdate \
    || die "the backup failed; nothing was changed"
  dump=$(docker compose exec -T backup sh -c 'ls -1t /backups/suckerpot-preupdate-*.dump 2>/dev/null | head -n 1' | tr -d '\r' || true)
  dump=${dump##*/}
  [[ $dump =~ ^suckerpot-preupdate-[A-Za-z0-9._-]+\.dump$ ]] || die "the backup ran but its file could not be found; nothing was changed"
  echo "      dump: $dump"
fi

# ---------------------------------------------------------------- 3. state file
step 3 "Recording how to roll back"
umask 077
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
images_json=""
while IFS='=' read -r svc img; do
  [ -n "$svc" ] && [ -n "$img" ] || continue
  id=$(docker image inspect --format '{{.Id}}' "$img" 2> /dev/null || true)
  [ -n "$id" ] || continue
  images_json+="${images_json:+,
}    \"$(clean "$svc")\": \"$(clean "$id")\""
done < <(docker compose ps -a --format '{{.Service}}={{.Image}}' 2> /dev/null || true)
tmp=$(mktemp "$STATE_DIR/.state.XXXXXX")
cat > "$tmp" << EOF
{
  "from_version": "$(clean "$from_version")",
  "from_ref": "$(clean "$from_ref")",
  "from_branch": "$(clean "$from_branch")",
  "mode": "$mode",
  "dump": "$(clean "$dump")",
  "alembic_before": "$(clean "$alembic_before")",
  "target": "$(clean "$target")",
  "at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "completed": false,
  "images": {
${images_json}
  }
}
EOF
chmod 600 "$tmp"
mv "$tmp" "$STATE"

changed=0
on_exit() {
  rc=$?
  [ -z "$expect_file" ] || rm -f "$expect_file"
  if [ "$rc" -ne 0 ] && [ "$changed" = 1 ]; then
    echo >&2
    if [ "$auto" = 1 ]; then
      echo "update FAILED after the code was changed (the automatic updater rolls back)." >&2
    else
      echo "update FAILED after the code was changed. Nothing was rolled back automatically." >&2
      echo "  To go back to $from_version and restore the database dump '${dump:-none}':" >&2
      echo "      just rollback" >&2
      echo "  (events received since the dump are lost only if the database schema changed)" >&2
    fi
  fi
}
trap on_exit EXIT

# ---------------------------------------------------------------- 4. code
step 4 "Fetching the new code"
changed=1
if [ "$pull_branch" = 1 ]; then
  git pull --ff-only --quiet || die "git pull --ff-only failed"
else
  # By commit, never by name: a local branch of the same name or a re-pointed tag must not win.
  git checkout --quiet --detach "$target_commit" || die "could not check out $target"
fi
new_ref=$(git rev-parse HEAD)
if [ "$pull_branch" = 0 ] && [ "$new_ref" != "$target_commit" ]; then
  die "the checkout is at ${new_ref:0:12}, not the verified ${target_commit:0:12}"
fi
[ -f scripts/lib/env.sh ] && . scripts/lib/env.sh

# ---------------------------------------------------------------- 5. environment
step 5 "Updating .env"
bash scripts/env-migrate.sh
env_drop_loaded

# ---------------------------------------------------------------- 6. images
step 6 "Getting the new images"
if [ "$mode" = images ]; then
  env_set_line .env SUCKERPOT_VERSION "$target"
  env_drop_loaded
  if [ "$skip_verify" = 1 ]; then
    echo "      warning: --skip-verify, the image signatures were NOT checked" >&2
    docker compose pull
  else
    # Verify the digest, pull exactly that digest, tag it: what runs is what was verified.
    bash scripts/verify-images.sh --pull ${expect_file:+--expect "$expect_file"} "$target" || die "the image signatures could not be verified; nothing was started. Run just rollback to go back, or retry with --skip-verify only if you accept the risk"
    docker compose pull --policy missing
  fi
  expected=$target
else
  expected=$(git describe --tags --always --dirty 2> /dev/null || echo dev)
  SUCKERPOT_BUILD_VERSION=$expected
  SUCKERPOT_BUILD_COMMIT=$(git rev-parse --short HEAD 2> /dev/null || echo unknown)
  export SUCKERPOT_BUILD_VERSION SUCKERPOT_BUILD_COMMIT
  docker compose build
fi

# ---------------------------------------------------------------- 7. start
step 7 "Restarting (migrations run first)"
bash scripts/check-ports.sh --dotenv-only
up_rc=0
if [ "$mode" = images ]; then
  compose_up_recreating -d --no-build --pull never --wait --wait-timeout 600 || up_rc=$?
else
  compose_up_recreating -d --wait --wait-timeout 600 || up_rc=$?
fi
if [ "$up_rc" -ne 0 ]; then
  # `up --wait` also fails for a service that was already unhealthy. Go on only when the
  # migrations ran and finished cleanly; the health check below then judges each service.
  migrate_state=$(docker compose ps -a migrate --format '{{.State}} {{.ExitCode}}' 2> /dev/null | tr -d '\r' | head -n 1 || true)
  [ "$migrate_state" = "exited 0" ] || die_release "docker compose up failed and the migrations did not finish cleanly (exit $up_rc)"
  echo "      warning: docker compose up reported an unhealthy service (exit $up_rc); judging each service below" >&2
fi

# ---------------------------------------------------------------- 8. health
step 8 "Checking health"
if [ "$stack_mode" = participant ]; then
  # No dashboard in this mode: the version check is on ingest, and the network client must answer.
  health_service=ingest
else
  health_service=api
  ok=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS --max-time 5 "http://$bind:$dport/healthz" > /dev/null 2>&1; then ok=1; break; fi
    sleep 3
  done
  [ "$ok" = 1 ] || release_or_warn api "the dashboard does not answer on http://$bind:$dport/healthz"
fi
# Judge each service against the snapshot taken before the update. Only a regression fails:
# healthy (or no healthcheck) before, not healthy after the wait. A service that was already
# bad, and still is, is reported but does not fail the update.
regressions=""
degraded=""
polls=$((wait_s / 5 + 1))
for ((i = 0; i < polls; i++)); do
  health_after=$(health_snapshot)
  regressions=""
  degraded=""
  pending=0
  while read -r svc _; do
    [ -n "$svc" ] || continue
    now_h=$(health_of "$svc" "$health_after" || true)
    is_good "$now_h" && continue
    if was_h=$(health_of "$svc" "$health_before") && ! is_good "$was_h"; then
      degraded+="$svc "
    else
      regressions+="$svc($now_h) "
      [ "$now_h" != starting ] || pending=1
    fi
  done <<< "$health_after"
  # A service that was healthy and is gone (stopped, crashed) is a regression too.
  while read -r svc _; do
    [ -n "$svc" ] || continue
    was_h=$(health_of "$svc" "$health_before" || true)
    is_good "$was_h" || continue
    health_of "$svc" "$health_after" > /dev/null || regressions+="$svc(not running) "
  done <<< "$health_before"
  # Wait only while a regression candidate is still starting; an unhealthy one is judged now.
  [ "$pending" = 1 ] || break
  sleep 5
done
for svc in $degraded; do
  echo "      warning: $svc was already unhealthy before the update and still is. The update did not change that." >&2
done
[ -z "$regressions" ] || die_release "not healthy after the update but healthy before: ${regressions% } (docker compose ps)"
running=$(docker compose exec -T "$health_service" printenv SUCKERPOT_RUNNING_VERSION 2> /dev/null | tr -d '\r' || true)
if [ "$running" != "$expected" ]; then
  die_release "the $health_service reports version '${running:-unknown}' but '$expected' was expected"
fi
if [ "$stack_mode" = participant ]; then
  docker compose exec -T ingest python -m ingest.network.cli status --json > /dev/null 2>&1 \
    || release_or_warn ingest "the network client of ingest does not answer (ingest.network.cli status)"
fi

# ---------------------------------------------------------------- 9. done
step 9 "Done"
changed=0
# Final step: mark the recorded update as finished (a new one is refused while this is false).
tmp=$(mktemp "$STATE_DIR/.state.XXXXXX")
sed 's/"completed": false,/"completed": true,/' "$STATE" > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$STATE"
echo
echo "SuckerPot is now on $expected (commit ${new_ref:0:9})."
if [ -n "$dump" ] && [ "$auto" = 0 ]; then
  echo "Rollback, if you need it: just rollback   (restores $dump and the previous version)"
fi
