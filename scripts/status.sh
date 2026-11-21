#!/usr/bin/env bash
# Shows what runs, what was sent to the network and how updates are doing (also: just status).
#
#   scripts/status.sh [--json] [--last-batch]
#
# Reads `docker compose ps`, .env (no secret is read into the report), the state file of the
# automatic updater and `python -m ingest.network.cli status --json` of the ingest container. The
# report is rendered INSIDE the ingest container (scripts/lib/status_render.py, standard library
# only), so the host needs nothing but Docker and bash.
#
# --json prints the same data as JSON, for monitoring. --last-batch prints the exact JSON of the
# last submission to the network (attacker addresses only, kept 7 days) and nothing else.
# Exit code: 0 OK, 1 warning, 2 error (design: docs/dev/design/m32.md section 10).
set -euo pipefail

cd "$(dirname "$0")/.."
# Read-only: an unknown SUCKERPOT_ENGINE falls back to docker with a warning (scripts/lib/engine.sh).
ENGINE_LENIENT=1
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh
# shellcheck source=scripts/lib/fwcheck.sh
. scripts/lib/fwcheck.sh

die() { echo "status: $*" >&2; exit 2; }

want_json=0
last_batch=0
while [ $# -gt 0 ]; do
  case $1 in
    --json) want_json=1 ;;
    --last-batch) last_batch=1 ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (usage: status.sh [--json] [--last-batch])" ;;
  esac
  shift
done

[ -f .env ] || die "no .env here: SuckerPot is not installed in this folder (./scripts/install.sh)"
command -v "${ENGINE_CTR[0]}" > /dev/null 2>&1 || die "$(engine_name) is not installed"

# JSON string with the escapes the renderer needs (control characters other than \n and \t go).
json_str() {
  printf '%s' "$1" | awk '
    BEGIN { ORS = ""; printf "\"" }
    { gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t"); gsub(/\r/, ""); if (NR > 1) printf "\\n"; print }
    END { printf "\"" }' | tr -d '\000-\010\013\014\016-\037'
}

stack=$(env_get SUCKERPOT_STACK_MODE full)
install=$(env_get SUCKERPOT_INSTALL_MODE source)
version=$(env_get SUCKERPOT_VERSION)

ps_lines=$(dc ps --format '{{.Service}} {{.State}} {{.Health}}' 2> /dev/null || true)
ingest_up=0
ps_json=""
while read -r svc state health _; do
  [ -n "${svc:-}" ] || continue
  [[ $svc =~ ^[a-z0-9_-]+$ ]] || continue
  [ "$svc" = ingest ] && [ "${state:-}" = running ] && ingest_up=1
  ps_json+="${ps_json:+,}[$(json_str "$svc"),$(json_str "${state:-}"),$(json_str "${health:-}")]"
done <<< "$ps_lines"

if [ "$last_batch" = 1 ]; then
  [ "$ingest_up" = 1 ] || die "ingest is not running"
  dc exec -T ingest python -m ingest.network.cli status --last-batch
  exit $?
fi

if [ "$ingest_up" = 0 ]; then
  if [ "$want_json" = 1 ]; then
    printf '{"stack":%s,"version":%s,"errors":["ingest_down"],"exit":2}\n' "$(json_str "$stack")" "$(json_str "$version")"
  else
    echo "SuckerPot ${version:-source build}, $stack mode, $install                       ERROR"
    echo
    echo "Ingest is not running, so nothing can be reported. Start it: ./scripts/install.sh --repair"
    echo "Or look at: docker compose ps, docker compose logs ingest"
  fi
  exit 2
fi

cli_raw=""
cli_error=""
if cli_raw=$(dc exec -T ingest python -m ingest.network.cli status --json 2> /dev/null); then
  :
else
  cli_raw=""
  cli_error="the network status command failed"
fi

auto_state=""
[ -f .suckerpot-state/auto-update.json ] && auto_state=$(head -c 4096 .suckerpot-state/auto-update.json)
auto_schedule=off
if [ -f scripts/lib/schedule.sh ]; then
  # shellcheck source=scripts/lib/schedule.sh
  . scripts/lib/schedule.sh
  auto_schedule=$(schedule_status 2> /dev/null || true)
  auto_schedule=${auto_schedule:-off}
fi
if [ "$(env_get AUTO_UPDATE_ENABLED false)" = true ]; then auto_enabled=true; else auto_enabled=false; fi

# The host firewall is a systemd unit of its own (scripts/host/install-firewall.sh). The unit file
# is readable without root; SUCKERPOT_FW_ROOT only exists for the tests.
# Installed is not enough: the unit must be active and its tables loaded (scripts/lib/fwcheck.sh;
# the tables are only read as root or with sudo -n).
if fw_installed; then
  case $(fw_state) in
    inactive | missing:*) firewall=not_loaded ;;
    *) firewall=installed ;;
  esac
else
  firewall=missing
fi

# The newest release of the same major version that this checkout knows (local tags only, no
# network; the automatic updater fetches them), and how old it is. Tags marked bad are skipped.
latest=""
latest_age_h=0
if [[ $version =~ ^v([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && command -v git > /dev/null 2>&1; then
  major=${BASH_REMATCH[1]}
  now_s=$(date +%s)
  while read -r tag ts; do
    [[ $tag =~ ^v${major}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || continue
    [[ ${ts:-} =~ ^[0-9]{1,12}$ ]] || continue
    if [ -f .suckerpot-state/bad-versions ] && grep -qxF "$tag" .suckerpot-state/bad-versions; then continue; fi
    latest=$tag
    latest_age_h=$(((now_s - ts) / 3600))
    break
  done < <(git for-each-ref --sort=-v:refname --format='%(refname:short) %(creatordate:unix)' 'refs/tags/v*' 2> /dev/null || true)
fi

ports_json=""
while read -r rp hp proto sname; do
  [ -n "${rp:-}" ] || continue
  ports_json+="${ports_json:+,}[$(json_str "$rp"),$(json_str "$hp"),$(json_str "$proto"),$(json_str "$sname")]"
done < <(ports_table)

doc=$(printf '{"stack":%s,"install":%s,"version":%s,"ps":[%s],"ports":[%s],"auto_enabled":%s,"auto_schedule":%s,"auto_state_raw":%s,"cli_raw":%s,"cli_error":%s,"firewall":%s,"latest":%s,"latest_age_h":%s}' \
  "$(json_str "$stack")" "$(json_str "$install")" "$(json_str "$version")" "$ps_json" "$ports_json" \
  "$auto_enabled" "$(json_str "$auto_schedule")" "$(json_str "$auto_state")" "$(json_str "$cli_raw")" "$(json_str "$cli_error")" \
  "$(json_str "$firewall")" "$(json_str "$latest")" "$latest_age_h")

src=$(cat scripts/lib/status_render.py)
rc=0
if [ "$want_json" = 1 ]; then
  printf '%s' "$doc" | dc exec -T ingest python -I -c "$src" --json || rc=$?
else
  printf '%s' "$doc" | dc exec -T ingest python -I -c "$src" || rc=$?
fi
exit "$rc"
