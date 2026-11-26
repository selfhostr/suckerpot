#!/usr/bin/env bash
# SuckerPot on this machine: one command for everything (also ./suckerpot.sh and `just menu`).
#
#   ./suckerpot.sh                       a menu: install, status, edit, update, ports, logs, remove
#   ./suckerpot.sh install [FLAGS]       install a node (scripts/install.sh; no flag: it asks)
#   ./suckerpot.sh status [--wait] [--brief | --json]
#                                     what runs, the network enrolment, the last batch
#   ./suckerpot.sh edit [SETTING [VALUE]]
#                                     name, country, sensors, vpn, auto-update, firewall
#   ./suckerpot.sh update [FLAGS]        the newest signed release, backup first (scripts/update.sh)
#   ./suckerpot.sh ports                 does the internet reach the sensors?
#   ./suckerpot.sh logs [SERVICE]        the last lines of the logs (all services, or one)
#   ./suckerpot.sh repair                run the install steps again, settings kept
#   ./suckerpot.sh leave | join          leave the network, or join it again (participant node)
#   ./suckerpot.sh remove [FLAGS]        uninstall (scripts/uninstall.sh): your data stays unless
#                                     you say so
#
# The menu needs a terminal; every other form works without one. Keys: Up/Down (or j/k) and
# Enter, or the key shown before an item; q quits. NO_COLOR turns the colours off. Each item
# runs the script that does the work, so each one also works on its own (see docs/install.md).
set -euo pipefail

cd "$(dirname "$0")/.."
# Read-only use of the engine name: an unknown SUCKERPOT_ENGINE falls back to docker with a warning.
ENGINE_LENIENT=1
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh
sudo_drop scripts/suckerpot.sh "$@"
# shellcheck source=scripts/lib/ask.sh
. scripts/lib/ask.sh

die() { echo "suckerpot: $*" >&2; exit 1; }

# ---------------------------------------------------------------- what is installed here

installed() { [ -f .env ]; }
stack() { env_get SUCKERPOT_STACK_MODE full; }
node_name() { sed -n 's/^NETWORK_PSEUDONYM=//p' .env | tail -n 1 | tr -d "\"'\r"; }

# ps_counts: "running healthy total" of the running services (one-shot jobs that ended are not
# counted; nothing running: "0 0 0").
ps_counts() {
  local svc state health run=0 ok=0 all=0
  while read -r svc state health _; do
    [ -n "${svc:-}" ] || continue
    all=$((all + 1))
    [ "$state" = running ] || continue
    run=$((run + 1))
    case ${health:-} in healthy | "") ok=$((ok + 1)) ;; esac
  done < <(dc ps --format '{{.Service}} {{.State}} {{.Health}}' 2> /dev/null || true)
  echo "$run $ok $all"
}

# net_state: the network state in a few words, from ingest (empty when ingest does not answer).
net_state() {
  local doc st standing
  doc=$(dc exec -T ingest python -m ingest.network.cli status --json 2> /dev/null) || return 0
  # shellcheck source=scripts/lib/enrol_wait.sh
  . scripts/lib/enrol_wait.sh
  st=$(printf '%s' "$doc" | json_top_string state)
  standing=$(printf '%s' "$doc" | json_top_string standing)
  case $st in
    member) echo "accepted, standing ${standing:-new}" ;;
    enrolling) echo "waiting for the hub's answer" ;;
    not_joined) case $doc in *'"desired": "member"'*) echo "joining" ;; *) echo "not joined" ;; esac ;;
    error) echo "refused: ./suckerpot.sh status" ;;
    left) echo "left" ;;
    "") ;;
    *) echo "$st" ;;
  esac
}

# ---------------------------------------------------------------- display

# What the header found, for the notices and the menu.
H_ALL=0 H_NET=""

# latest_release: the newest release tag this checkout knows ("" when none).
latest_release() { latest_known_release; }

# update_text: the running version and the newest known one, in a few words.
update_text() {
  local v latest
  [ "$(env_get SUCKERPOT_INSTALL_MODE source)" = images ] || { echo "built from source: just update pulls and builds"; return 0; }
  v=$(env_get SUCKERPOT_VERSION)
  latest=$(latest_release)
  if [ -n "$latest" ] && [ "$latest" != "$v" ] && ver_ge "${latest#v}" "${v#v}"; then
    echo "runs ${v:-?}; $latest is available (backup first)"
  else
    echo "runs ${v:-?}, the newest this checkout knows (it checks for newer ones)"
  fi
}

header() {
  local mode version run ok all net cc path line
  _ask_style
  echo 1>&"$ASK_OUT"
  if ! installed; then
    printf '  %s%sSuckerPot%s  not installed in %s\n' "$ASK_ACC" "$ASK_B" "$ASK_R" "$PWD" 1>&"$ASK_OUT"
    return 0
  fi
  mode=$(stack)
  version=$(env_get SUCKERPOT_VERSION)
  printf '  %s%sSuckerPot%s  %s · %s · %s\n' "$ASK_ACC" "$ASK_B" "$ASK_R" \
    "$([ "$mode" = participant ] && echo "participant node" || echo "full install")" "${version:-source build}" "$PWD" 1>&"$ASK_OUT"
  if [ "$mode" = participant ]; then
    cc=$(env_get NETWORK_COUNTRY)
    if [ -n "$(env_get VPN_WG_PRIVATE_KEY)" ]; then path="through your VPN"; else path="direct (no VPN)"; fi
    line="$(node_name)"
    printf '  %-9s  %s%s · %s\n' "Node" "${line:-no name}" "${cc:+ · $cc}" "$path" 1>&"$ASK_OUT"
  else
    printf '  %-9s  http://%s:%s (Admin user %s)\n' "Dashboard" "$(env_get DASHBOARD_BIND 127.0.0.1)" "$(env_get DASHBOARD_PORT 8443)" "$(env_get ADMIN_USERNAME admin)" 1>&"$ASK_OUT"
  fi
  # A node installed by get.sh: which bundle its files come from.
  if layout_bundle; then
    if [ "$(bundle_get signed)" = 1 ]; then line="the signed node bundle $(bundle_get version)"; else line="a TESTING build of $(bundle_get ref), not signed"; fi
    printf '  %-9s  %s\n' "Files" "$line" 1>&"$ASK_OUT"
  fi
  read -r run ok all < <(ps_counts)
  H_ALL=$all H_NET=""
  if [ "$all" = 0 ]; then
    line="stopped (no container): Repair starts it again"
  elif [ "$ok" = "$all" ]; then
    line="$all services running, all healthy"
  else
    line="$ok of $all services healthy"
  fi
  if [ "$run" -gt 0 ] && [ "$(env_get NETWORK_ENABLED false)" = true ]; then
    net=$(net_state)
    H_NET=$net
    [ -z "$net" ] || line="$line · network: $net"
  elif [ "$(env_get NETWORK_ENABLED false)" != true ] && [ "$mode" = participant ]; then
    line="$line · network: not joined"
  fi
  printf '  %-9s  %s\n' "Now" "$line" 1>&"$ASK_OUT"
}

# run_step TITLE CMD...: runs one item, says how it ended, waits for Enter (a terminal only).
run_step() {
  local title=$1 rc=0
  shift
  _ask_style
  printf '\n  %s%s%s\n\n' "$ASK_B" "$title" "$ASK_R" 1>&"$ASK_OUT"
  # Ctrl-C stops the item, not the menu.
  trap ':' INT
  "$@" || rc=$?
  trap - INT
  echo 1>&"$ASK_OUT"
  case $rc in
    0) printf '  %sDone.%s\n' "$ASK_OK" "$ASK_R" 1>&"$ASK_OUT" ;;
    130) printf '  %sStopped (Ctrl-C).%s\n' "$ASK_WARN" "$ASK_R" 1>&"$ASK_OUT" ;;
    *) printf '  %sEnded with exit code %s (the messages above say why).%s\n' "$ASK_WARN" "$rc" "$ASK_R" 1>&"$ASK_OUT" ;;
  esac
  ask_pause
  return 0
}

# ---------------------------------------------------------------- the items

ports_free() {
  local s var def proto busy="" mark
  if command -v ss > /dev/null 2>&1; then
    busy=" $(ss -Hltnu 2> /dev/null | awk '{n = split($5, a, ":"); print a[n]}' | sort -un | tr '\n' ' ') "
  else
    echo "  'ss' is not installed: the check needs it (package iproute2)."
    return 1
  fi
  echo "  The sensors listen on these ports of this machine. A busy one is skipped by the installer"
  echo "  (port 22 is your own SSH, most likely: the SSH sensor then takes 2222)."
  echo
  for s in "${SENSORS[@]}"; do
    while IFS=: read -r var def proto; do
      mark=free
      case $busy in *" $def "*) mark="IN USE" ;; esac
      printf '    %-9s %-6s %-8s %s\n' "$s" "$def" "${proto}" "$mark"
    done < <(sensor_ports "$s")
  done
}

logs_menu() {
  local a svc
  while :; do
    echo 1>&"$ASK_OUT"
    ask_menu a b "Logs" \
      "1|The network node|ingest, last 80 lines" \
      "2|All services|last 30 lines of each" \
      "3|One service|you choose which" \
      "4|Install log|install.log, last 60 lines" \
      "5|Automatic updates|.suckerpot-state/auto-update.log, last 60 lines" \
      "f|Follow the network node live|Ctrl-C to stop" \
      "b|Back|"
    [ "$ASK_EOF" = 0 ] || return 0
    case $a in
      1) run_step "Logs of ingest" dc logs --no-color --tail 80 ingest ;;
      2) run_step "Logs of all services" dc logs --no-color --tail 30 ;;
      3)
        mapfile -t svcs < <(dc ps --format '{{.Service}}' 2> /dev/null | sort)
        [ "${#svcs[@]}" -gt 0 ] || { echo "  No service runs." 1>&"$ASK_OUT"; continue; }
        ask_text svc "Service ($(echo "${svcs[*]}" | tr ' ' ','))" "ingest" || continue
        run_step "Logs of $svc" dc logs --no-color --tail 80 "$svc"
        ;;
      4) run_step "install.log" tail -n 60 install.log ;;
      5) run_step "auto-update.log" tail -n 60 .suckerpot-state/auto-update.log ;;
      f) run_step "Logs of ingest (live; Ctrl-C to stop)" dc logs --no-color --tail 20 -f ingest ;;
      *) return 0 ;;
    esac
  done
}

# status_item: the report; while the hub has not answered a join, it offers to wait for it first.
# The report's exit code (1 warning, 2 error) is already in its last line: the item ends as done.
status_item() {
  case $(net_state) in
    waiting* | joining)
      if ask_yn "The hub has not answered this node's join yet. Wait for its answer (at most 10 minutes)?" y; then
        bash scripts/status.sh --wait 600 || true
        return 0
      fi
      ;;
  esac
  bash scripts/status.sh || true
}

# The end-to-end test of the menu (test mode only) passes its throwaway project and source build to
# the installer this way; a real run never reads it.
install_extra=()
if [ "${SELFHOSTR_TEST_INSTALL:-}" = 1 ] && [ -n "${SELFHOSTR_INSTALL_EXTRA:-}" ]; then
  read -r -a install_extra <<< "$SELFHOSTR_INSTALL_EXTRA"
fi

menu_fresh() {
  local a
  ask_menu a 1 "What do you want to do?" \
    "1|Install a participant node|sensors only, joins the network (1 GiB+)" \
    "2|Full install|sensors, dashboard, VPN, reports (2 GiB+)" \
    "3|Check this machine's ports|which sensor ports are free here" \
    "q|Quit|"
  [ "$ASK_EOF" = 0 ] || [ "$a" != 1 ] || a=q
  case $a in
    1) run_step "Install a participant node" bash scripts/install.sh --participant ${install_extra[@]+"${install_extra[@]}"} ;;
    2) run_step "Full install" bash scripts/install.sh --full ${install_extra[@]+"${install_extra[@]}"} ;;
    3) run_step "Ports of this machine" ports_free ;;
    *) return 1 ;;
  esac
}

# notices: what is missing or worth doing, each with the key that does it (ASK_HIDDEN). Read
# from .env and from what the header found; nothing is asked of the network.
notices() {
  local mode v latest
  NOTICES=() ASK_HIDDEN=""
  mode=$(stack)
  note_add() { NOTICES+=("$1|$2"); ASK_HIDDEN+=" $1"; }
  [ "$H_ALL" != 0 ] || note_add r "SuckerPot is not running: press r to start it again (repair)"
  if [ "$(env_get SUCKERPOT_INSTALL_MODE source)" = images ]; then
    v=$(env_get SUCKERPOT_VERSION)
    latest=$(latest_release)
    if [ -n "$latest" ] && [ -n "$v" ] && [ "$latest" != "$v" ] && ver_ge "${latest#v}" "${v#v}"; then
      note_add u "Update available: $v -> $latest: press u to update (a backup is taken first)"
    fi
  fi
  if [ "$mode" = participant ]; then
    if [ "$(env_get NETWORK_ENABLED false)" != true ]; then
      note_add j "Not in the network: press j to join"
    else
      case $H_NET in
        waiting* | joining) note_add w "Not accepted by the hub yet (a new node first solves a puzzle): press w to wait for the answer" ;;
        refused*) note_add s "The hub refused this node: press s to see why and what to do" ;;
      esac
      [ -n "$(node_name)" ] || note_add n "No node name: the network shows a number. Press n to choose one"
      [ -n "$(env_get NETWORK_COUNTRY)" ] || note_add c "Country not set: press c to show one (optional)"
    fi
    if [ "$(env_get SUCKERPOT_NO_FIREWALL)" != 1 ]; then
      # shellcheck source=scripts/lib/fwcheck.sh
      . scripts/lib/fwcheck.sh
      fw_installed || note_add f "The host firewall is not installed: press f to install it (sudo)"
    fi
    if [ "$(env_get SUCKERPOT_INSTALL_MODE source)" = images ] && [ "$(env_get AUTO_UPDATE_ENABLED false)" != true ]; then
      note_add a "Automatic updates are off: press a to turn them on"
    fi
  fi
  local n
  _ask_style
  for n in "${NOTICES[@]}"; do ask_lines "$ASK_WARN" "! ${n#*|}"; done
  [ "${#NOTICES[@]}" = 0 ] || echo 1>&"$ASK_OUT"
}

# notice_action KEY: what the key of a notice does.
notice_action() {
  case $1 in
    r) run_step "Repair" bash scripts/install.sh --repair ;;
    u) run_step "Update" bash scripts/update.sh ;;
    j) run_step "Join the network" bash scripts/participant.sh join ;;
    w) run_step "Waiting for the hub" bash scripts/status.sh --wait 600 ;;
    s) run_step "Node status" status_item ;;
    n) run_step "Choose the node name" bash scripts/edit.sh name ;;
    c) run_step "Show a country" bash scripts/edit.sh country ;;
    f) run_step "Host firewall" bash scripts/participant.sh firewall install ;;
    a) run_step "Automatic updates" bash scripts/participant.sh auto-update on ;;
  esac
}

menu_installed() {
  local a mode joined items
  mode=$(stack)
  joined=$(env_get NETWORK_ENABLED false)
  notices
  items=("status|Node status|stack, sensors, network enrolment, last batch")
  if [ "$mode" = participant ]; then
    items+=("edit|Edit the node|see and change name, country, sensors, VPN, updates")
  else
    items+=("edit|Edit the install|sensors, updates, firewall (name, country: the dashboard)")
  fi
  items+=(
    "update|Update now|$(update_text)"
    "ports|Check the ports|does the internet reach the sensors?"
    "logs|Logs|the network node, a service, the install"
    "repair|Repair|run the install steps again, settings kept"
  )
  if [ "$mode" = participant ]; then
    if [ "$joined" = true ]; then items+=("net|Leave the network|the sensors keep running"); else items+=("net|Join the network|shows what is shared first"); fi
  fi
  items+=("remove|Remove the node|uninstall; your data stays unless you say so" "q|Quit|")
  ask_pick a status "What do you want to do?" "${items[@]}"
  ASK_HIDDEN=""
  [ "$ASK_EOF" = 0 ] || [ "$a" != status ] || a=q
  case $a in
    status) run_step "Node status" status_item ;;
    edit) bash scripts/edit.sh || true ;;
    update) run_step "Update" bash scripts/update.sh ;;
    ports) run_step "Ports check" bash scripts/participant.sh ports-check --wait 60 ;;
    logs) logs_menu ;;
    repair) run_step "Repair" bash scripts/install.sh --repair ;;
    [rujwsncfa]) notice_action "$a" ;;
    net)
      if [ "$joined" = true ]; then
        if ask_yn "Leave the network? The hub deletes this node and what it sent." n; then
          run_step "Leave the network" bash scripts/participant.sh leave
        fi
      else
        run_step "Join the network" bash scripts/participant.sh join
      fi
      ;;
    remove) run_step "Remove the node" bash scripts/uninstall.sh ;;
    *) return 1 ;;
  esac
}

# docker_group: this login was added to the docker group (by the installer's Docker setup) but
# does not have it yet: the menu starts again in that group (sg docker), so its items reach Docker.
docker_group() {
  [ "$ENGINE_ID" = docker ] && [ -z "${SELFHOSTR_MENU_SG:-}" ] || return 0
  command -v docker > /dev/null 2>&1 && command -v sg > /dev/null 2>&1 || return 0
  ctr version > /dev/null 2>&1 && return 0
  sg docker -c "docker version" > /dev/null 2>&1 || return 0
  exec sg docker -c "SELFHOSTR_MENU_SG=1 $(printf '%q ' bash "$PWD/scripts/suckerpot.sh")"
}

menu() {
  docker_group
  # A bundle install has no tags: it asks GitHub for the newest release at most every 6 hours.
  latest_release_refresh 6 || true
  ask_open
  ASK_IND="  "
  [ "$ASK_TTY" = 1 ] || die "the menu needs a terminal. Without one: ./suckerpot.sh help"
  while :; do
    header
    echo 1>&"$ASK_OUT"
    if installed; then menu_installed || break; else menu_fresh || break; fi
    docker_group
    [ "$ASK_EOF" = 0 ] || break
  done
  echo 1>&"$ASK_OUT"
}

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

need_install() { installed || die "nothing is installed in this folder: ./suckerpot.sh install"; }

cmd=${1:-}
[ $# -gt 0 ] && shift
case $cmd in
  "") menu ;;
  install) exec bash scripts/install.sh "$@" ;;
  status) need_install; exec bash scripts/status.sh "$@" ;;
  edit) need_install; exec bash scripts/edit.sh "$@" ;;
  update) need_install; exec bash scripts/update.sh "$@" ;;
  ports | ports-check) need_install; exec bash scripts/participant.sh ports-check "$@" ;;
  logs) need_install; if [ $# -gt 0 ]; then exec "${ENGINE_DC[@]}" logs --no-color --tail 100 "$@"; else exec "${ENGINE_DC[@]}" logs --no-color --tail 30; fi ;;
  repair) need_install; exec bash scripts/install.sh --repair "$@" ;;
  leave | join) need_install; exec bash scripts/participant.sh "$cmd" "$@" ;;
  remove | uninstall) need_install; exec bash scripts/uninstall.sh "$@" ;;
  help | -h | --help) usage ;;
  *) die "unknown command '$cmd' (./suckerpot.sh help)" ;;
esac
