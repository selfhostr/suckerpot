#!/usr/bin/env bash
# Shows what runs, what was sent to the network and how updates are doing (also: just status).
#
#   scripts/status.sh [--json | --brief] [--last-batch] [--wait [SECONDS]]
#
# Reads `docker compose ps`, .env (no secret is read into the report), the state file of the
# automatic updater and `python -m ingest.network.cli status --json` of the ingest container. The
# report is rendered INSIDE the ingest container (scripts/lib/status_render.py, standard library
# only), so the host needs nothing but Docker and bash.
#
# --json prints the same data as JSON, for monitoring. --brief prints a few lines (stack, sensors,
# network, the first things to fix): the view of ./suckerpot.sh and of the end of the install.
# --last-batch prints the exact JSON of the last submission to the network (attacker addresses
# only, kept 7 days) and nothing else. --wait first waits (default 600 s) while the hub has not
# decided on a join in progress, for example the proof of work of a new node; Ctrl-C stops waiting.
# Exit code: 0 OK, 1 warning, 2 error (design: docs/dev/design/m32.md section 10).
set -euo pipefail

cd "$(dirname "$0")/.."
# Read-only: an unknown SUCKERPOT_ENGINE falls back to docker with a warning (scripts/lib/engine.sh).
ENGINE_LENIENT=1
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh
# shellcheck source=scripts/lib/fwcheck.sh
. scripts/lib/fwcheck.sh
# shellcheck source=scripts/lib/enrol_wait.sh
. scripts/lib/enrol_wait.sh
# shellcheck source=scripts/lib/ask.sh
. scripts/lib/ask.sh

die() { echo "status: $*" >&2; exit 2; }

want_json=0
want_brief=0
last_batch=0
wait_s=0
while [ $# -gt 0 ]; do
  case $1 in
    --json) want_json=1 ;;
    --brief) want_brief=1 ;;
    --last-batch) last_batch=1 ;;
    --wait)
      wait_s=600
      if [[ ${2:-} =~ ^[0-9]{1,5}$ ]]; then wait_s=$2; shift; fi
      ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (usage: status.sh [--json | --brief] [--last-batch] [--wait [SECONDS]])" ;;
  esac
  shift
done
[ "$want_json$want_brief" != 11 ] || die "--json and --brief exclude each other"

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
  if [ "$want_brief" = 1 ]; then
    echo "Stack    ingest is not running: ./scripts/install.sh --repair"
    echo "Overall  ERROR   (details: ./scripts/status.sh)"
  elif [ "$want_json" = 1 ]; then
    printf '{"stack":%s,"version":%s,"errors":["ingest_down"],"exit":2}\n' "$(json_str "$stack")" "$(json_str "$version")"
  else
    echo "SuckerPot ${version:-source build}, $stack mode, $install                       ERROR"
    echo
    echo "Ingest is not running, so nothing can be reported. Start it: ./scripts/install.sh --repair"
    echo "Or look at: docker compose ps, docker compose logs ingest"
  fi
  exit 2
fi

# --wait: while a join is in progress (the hub has not decided yet), wait for its answer.
if [ "$wait_s" -gt 0 ]; then
  # shellcheck disable=SC1003 # a backslash, not an escape
  waited=0 spin='|/-\' i=0 doc=""
  t_end=$(($(date +%s) + wait_s))
  stopped=0
  trap 'stopped=1' INT
  while [ "$stopped" = 0 ]; do
    doc=$(dc exec -T ingest python -m ingest.network.cli status --json 2> /dev/null) || doc=""
    # The top-level state: a join is in progress while it is enrolling, or not joined yet while
    # the membership is wanted (nested objects have their own "state" keys).
    st=$(printf '%s' "$doc" | json_top_string state)
    case $st in
      enrolling) ;;
      not_joined) case $doc in *'"desired": "member"'*) ;; *) break ;; esac ;;
      *) break ;;
    esac
    [ "$(date +%s)" -lt "$t_end" ] || break
    if [ "$waited" = 0 ]; then
      if [ -t 2 ]; then
        printf 'Waiting for the hub to accept this node (Ctrl-C stops waiting)...\n' >&2
      else
        echo "Waiting for the hub to accept this node, at most ${wait_s} s..." >&2
      fi
    fi
    for _ in 1 2 3 4 5; do
      [ "$stopped" = 0 ] || break
      if [ -t 2 ]; then
        el=$(( $(date +%s) - (t_end - wait_s) ))
        printf '\r  %s %d:%02d ' "${spin:$((i % 4)):1}" $((el / 60)) $((el % 60)) >&2
        i=$((i + 1))
      fi
      sleep 1
    done
    waited=1
  done
  trap - INT
  if [ "$waited" = 1 ] && [ -t 2 ]; then printf '\r\033[K' >&2; fi
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

# Podman: the engine version and the boot unit (scripts/host/install-stack-unit.sh).
engine=docker
stack_unit=""
if [ "$ENGINE_ID" = podman ]; then
  engine="podman $(ctr version --format '{{.Server.Version}}' 2> /dev/null || echo '?')"
  if ! engine_stack_unit_installed; then
    stack_unit=missing
  elif systemctl is-active --quiet suckerpot-stack.service 2> /dev/null; then
    stack_unit=active
  else
    stack_unit=inactive
  fi
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

# The version the containers really run (ingest says it), next to the one .env names: after an
# update that did not finish they differ, and the scripts are then newer than the images.
running=$(running_version)

unfinished=$(update_unfinished)

doc=$(printf '{"stack":%s,"install":%s,"version":%s,"running":%s,"unfinished":%s,"ps":[%s],"ports":[%s],"auto_enabled":%s,"auto_schedule":%s,"auto_state_raw":%s,"cli_raw":%s,"cli_error":%s,"firewall":%s,"latest":%s,"latest_age_h":%s,"engine":%s,"stack_unit":%s}' \
  "$(json_str "$stack")" "$(json_str "$install")" "$(json_str "$version")" "$(json_str "$running")" "$(json_str "$unfinished")" "$ps_json" "$ports_json" \
  "$auto_enabled" "$(json_str "$auto_schedule")" "$(json_str "$auto_state")" "$(json_str "$cli_raw")" "$(json_str "$cli_error")" \
  "$(json_str "$firewall")" "$(json_str "$latest")" "$latest_age_h" "$(json_str "$engine")" "$(json_str "$stack_unit")")

src=$(cat scripts/lib/status_render.py)
rc=0
if [ "$want_json" = 1 ]; then
  printf '%s' "$doc" | dc exec -T ingest python -I -c "$src" --json || rc=$?
elif [ "$want_brief" = 1 ]; then
  printf '%s' "$doc" | dc exec -T ingest python -I -c "$src" --brief | text_out 1 || rc=$?
else
  # On a terminal the long lines wrap at its width (word boundaries); otherwise unchanged.
  printf '%s' "$doc" | dc exec -T ingest python -I -c "$src" | text_out 1 || rc=$?
fi
exit "$rc"
