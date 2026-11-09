#!/usr/bin/env bash
# Automatic update (M32), meant for the user's crontab or a systemd user timer. Never needs sudo.
#
#   scripts/auto-update.sh
#
# Installs the newest release of the SAME major version, and only when ALL of this holds:
#   - AUTO_UPDATE_ENABLED=true in .env, images install mode, no earlier update left unfinished;
#   - the release is newer than the running one and not in .suckerpot-state/bad-versions;
#   - its signed release manifest verifies (scripts/verify-release.sh --auto): signed by the
#     release workflow, its commit is the tag's commit, and the release is old enough (at least
#     48 h, more if the manifest or AUTO_UPDATE_MIN_AGE_H in .env asks for more);
#   - a release that is unsigned, whose manifest does not match its tag, or whose signature cosign
#     rejects is written to bad-versions with its reason (bad-versions.log) and the next newest candidate of the same
#     major version is tried, at most 3 per run; it never goes below the installed version;
#   - its images verify (scripts/verify-images.sh).
# Then it runs scripts/update.sh --yes --auto (backup first). If the update fails after the code
# changed, it runs scripts/rollback.sh --yes (which restores the database only if the schema
# moved). The version is remembered as bad and never retried only when the release itself is at
# fault (update.sh exit 10: a service that was healthy turned unhealthy, a migration or a
# verification failed). Any other failure is logged and retried on the next run, and a node that
# was already degraded before the update never blacklists a release.
#
# One run at a time (flock on .suckerpot-state/update.lock). A random wait of up to 30 minutes
# keeps a fleet from updating at the same second (AUTO_UPDATE_JITTER_S overrides the maximum).
# Output goes to .suckerpot-state/auto-update.log (rotated at 1 MiB); the outcome of the last run
# is in .suckerpot-state/auto-update.json: {last_run, last_result, from, to, error_code}.
#
# Turn it off: ./scripts/participant.sh auto-update off   (or: just set AUTO_UPDATE_ENABLED=false)
set -euo pipefail

export PATH="$PATH:/usr/local/bin:/usr/bin:/bin:/snap/bin"
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

STATE_DIR=.suckerpot-state
STATE=$STATE_DIR/last-update.json
RESULT=$STATE_DIR/auto-update.json
LOG=$STATE_DIR/auto-update.log
BAD=$STATE_DIR/bad-versions
LOCK=$STATE_DIR/update.lock

umask 077
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

[ -f .env ] || exit 0
[ "$(env_get AUTO_UPDATE_ENABLED false)" = true ] || exit 0

# One run at a time, quietly.
exec 9> "$LOCK"
flock -n 9 || exit 0
export SELFHOSTR_UPDATE_LOCK_HELD=1

if [ -f "$LOG" ] && [ "$(wc -c < "$LOG")" -gt 1048576 ]; then mv -f "$LOG" "$LOG.1"; fi
exec 3>&1
exec >> "$LOG" 2>&1
chmod 600 "$LOG" 2> /dev/null || true

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '%s %s\n' "$(now)" "$*"; }
safe() { printf '%s' "$1" | tr -cd 'A-Za-z0-9._-' | cut -c1-40; }

from_version=""
to_version=""
# record RESULT ERROR_CODE: writes the outcome file (constant codes only) and ends the run.
record() {
  local result=$1 code=$2 tmp
  tmp=$(mktemp "$STATE_DIR/.auto.XXXXXX")
  printf '{\n  "last_run": "%s",\n  "last_result": "%s",\n  "from": "%s",\n  "to": "%s",\n  "error_code": "%s"\n}\n' \
    "$(now)" "$result" "$(safe "$from_version")" "$(safe "$to_version")" "$code" > "$tmp"
  mv -f "$tmp" "$RESULT"
  log "result: $result${code:+ ($code)}"
  echo "auto-update: $result${code:+ ($code)}" >&3
  [ "$result" = failed ] && exit 1
  exit 0
}

log "auto-update starts"

if [ "$(env_get SUCKERPOT_INSTALL_MODE source)" != images ]; then record skipped source_mode; fi
if [ -f "$STATE" ] && grep -q '"completed": false' "$STATE"; then record skipped unfinished_update; fi

# Spread the fleet out.
jitter=${AUTO_UPDATE_JITTER_S:-1800}
[[ $jitter =~ ^[0-9]{1,5}$ ]] || jitter=1800
if [ "$jitter" -gt 0 ]; then sleep "$((RANDOM % (jitter + 1)))"; fi

from_version=$(env_get SUCKERPOT_VERSION)
[[ $from_version =~ ^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || record skipped unknown_version
cur_major=${from_version#v}
cur_major=${cur_major%%.*}

git fetch --tags --quiet || record failed fetch_failed

# Eligible candidates, newest first: same major, newer than the running one, not marked bad.
candidates=()
while IFS= read -r tag; do
  [[ $tag =~ ^v([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || continue
  [ "${BASH_REMATCH[1]}" = "$cur_major" ] || continue
  [ "$tag" != "$from_version" ] || continue
  ver_ge "${tag#v}" "${from_version#v}" || continue
  if [ -f "$BAD" ] && grep -qxF "$tag" "$BAD"; then continue; fi
  candidates+=("$tag")
done < <(git tag -l 'v*.*.*' --sort=-v:refname)
[ "${#candidates[@]}" -gt 0 ] || record ok up_to_date

# mark_bad TAG REASON: never try TAG again; the reason goes to bad-versions.log.
mark_bad() {
  printf '%s\n' "$1" >> "$BAD"
  printf '%s %s %s\n' "$(now)" "$1" "$2" >> "$BAD.log"
}

target=""
vr_out=""
last_code=""
tried=0
for tag in "${candidates[@]}"; do
  [ "$tried" -lt 3 ] || break
  tried=$((tried + 1))
  to_version=$tag
  log "candidate: $from_version -> $tag"
  vr_rc=0
  vr_out=$(bash scripts/verify-release.sh --auto "$tag") || vr_rc=$?
  printf '%s\n' "$vr_out"
  case $vr_rc in
    0) target=$tag; break ;;
    4) record refused too_young ;;
    # No verdict (network, Sigstore, Docker, disk): nothing is held against the release.
    9) record failed verification_unavailable ;;
    # A real verdict: unsigned, not matching its tag, or rejected by cosign. Never retried; the
    # next release may be fine.
    3) last_code=not_signed ;;
    5) last_code=commit_mismatch ;;
    6) last_code=signature_invalid ;;
    # Anything else (a malformed answer, a usage or local error) says nothing about the release.
    *) record refused manifest_invalid ;;
  esac
  mark_bad "$tag" "$last_code"
done
[ -n "$target" ] || record refused "${last_code:-manifest_invalid}"
to_version=$target

expect=$(mktemp "$STATE_DIR/.expect.XXXXXX")
printf '%s\n' "$vr_out" > "$expect"
vi_rc=0
bash scripts/verify-images.sh --expect "$expect" "$target" || vi_rc=$?
rm -f "$expect"
case $vi_rc in
  0) ;;
  7) record refused digest_mismatch ;;
  *) record refused images_unverified ;;
esac

head_before=$(git rev-parse HEAD)
up_rc=0
bash scripts/update.sh --yes --auto "$target" || up_rc=$?
if [ "$up_rc" -eq 0 ]; then record updated ""; fi

log "the update failed (exit $up_rc)"
mark_completed() {
  local tmp
  tmp=$(mktemp "$STATE_DIR/.state.XXXXXX")
  sed 's/"completed": false,/"completed": true,/' "$STATE" > "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$STATE"
}
if [ "$(git rev-parse HEAD)" = "$head_before" ]; then
  # The code never changed (backup, verification or checkout failed): nothing to put back.
  if [ -f "$STATE" ] && grep -q '"completed": false' "$STATE"; then mark_completed; fi
  record failed update_failed
fi

# Only a failure caused by the release itself blacklists it (update.sh exit 10).
release_fault=0
[ "$up_rc" -ne 10 ] || release_fault=1
if [ "$release_fault" = 0 ]; then
  log "not held against $target: the failure is not a regression introduced by that release (exit $up_rc); it is retried on the next run"
fi

log "rolling back to $from_version"
if bash scripts/rollback.sh --yes; then
  if [ "$release_fault" = 1 ]; then mark_bad "$target" update_regression; fi
  record failed update_failed_rolled_back
fi
if [ "$release_fault" = 1 ]; then mark_bad "$target" update_regression; fi
record failed rollback_failed
