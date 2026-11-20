#!/usr/bin/env bash
# Manage a participant install (docs/dev/design/m32.md section 5.6).
#
#   scripts/participant.sh status                    same as ./scripts/status.sh
#   scripts/participant.sh leave                     leave the network; sensors keep running
#   scripts/participant.sh join [--yes] [--pseudonym NAME]
#                                                    show the consent screen again and join
#   scripts/participant.sh vpn FILE.conf             send everything through your VPN
#   scripts/participant.sh vpn --remove              back to the direct path (no VPN)
#   scripts/participant.sh ports-check [--wait SECONDS] [--since ISO | --since-install]
#                                                    does the internet reach your sensors? (no outside connection)
#   scripts/participant.sh firewall [install|uninstall|status]
#                                                    render and load the host firewall (sudo), or remove it
#   scripts/participant.sh auto-update on|off       install or remove the daily update schedule
#   scripts/participant.sh uninstall [--yes]         leave, stop the stack, remove the schedule
#
# join, leave, vpn and uninstall are for participant installs. auto-update and ports-check work on any install.
# ports-check exits 0 when a public address reached a sensor, 3 when nothing did yet.
# Nothing here deletes data: uninstall prints the volume removal command and never runs it.
# Secrets are never printed.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

die() { echo "participant: $*" >&2; exit 1; }
note() { echo "  $*"; }

[ -f .env ] || die "no .env here: nothing is installed in this folder (./scripts/install.sh --participant)"
# `just` loads .env into the environment; the file we are about to change must win.
env_drop_loaded
need_project

stack=$(env_get SUCKERPOT_STACK_MODE full)
install_mode=$(env_get SUCKERPOT_INSTALL_MODE source)
need_participant() {
  [ "$stack" = participant ] || die "'$1' is for participant installs. This is a full install: use the dashboard (Network page)."
}

# docker compose up with the flags that match the install mode (signed images are never built over).
compose_up() {
  if [ "$install_mode" = images ]; then
    docker compose up -d --no-build --pull never --wait --wait-timeout 300 "$@"
  else
    docker compose up -d --build --wait --wait-timeout 600 "$@"
  fi
}

# Asks a yes/no question on the terminal; --yes (assume_yes=1) answers yes.
assume_yes=0
confirm() {
  local a=""
  [ "$assume_yes" = 1 ] && return 0
  tty=${SELFHOSTR_TTY:-/dev/tty}
  [ -r "$tty" ] || die "no terminal to ask on; use --yes"
  printf '%s [y/N] ' "$1" >&2
  IFS= read -r a < "$tty" || a=""
  case $a in y | Y | yes | YES | Yes) return 0 ;; *) return 1 ;; esac
}

# Keeps a private copy of .env while a change is applied, so it can be put back.
backup=""
cleanup() { [ -n "$backup" ] && rm -f "$backup"; return 0; }
trap cleanup EXIT
begin() {
  backup=$(mktemp)
  chmod 600 "$backup"
  cp .env "$backup"
}
revert() {
  cp "$backup" .env
  chmod 600 .env
}

# Prints the TOP-LEVEL "state" string of a JSON document on stdin. A grep over the whole document
# is wrong: the nested verifier, consent and membership objects have their own "state" keys, and
# an "off" there would end the wait before the worker has told the hub.
json_top_state() {
  awk 'BEGIN { RS = "\001" }
  {
    n = length($0); depth = 0; instr = 0; esc = 0; tok = ""; want = 0
    for (i = 1; i <= n; i++) {
      c = substr($0, i, 1)
      if (instr) {
        if (esc) { esc = 0; tok = tok c }
        else if (c == "\\") esc = 1
        else if (c == "\"") {
          instr = 0
          if (depth == 1) {
            if (want) { print tok; exit }
            j = i + 1
            while (substr($0, j, 1) == " ") j++
            if (substr($0, j, 1) == ":" && tok == "state") want = 1
          }
        } else tok = tok c
      } else if (c == "\"") { instr = 1; tok = "" }
      else if (c == "{" || c == "[") depth++
      else if (c == "}" || c == "]") depth--
    }
  }'
}

# True when the top-level state of the network status is off, left or not_joined.
cli_state_off() {
  local st
  st=$(docker compose exec -T ingest python -m ingest.network.cli status --json 2> /dev/null | json_top_state) || return 1
  case $st in off | left | not_joined) return 0 ;; *) return 1 ;; esac
}

do_leave() {
  if ! docker compose exec -T ingest python -m ingest.network.cli leave; then
    echo "participant: warning: ingest did not confirm the leave" >&2
    return 1
  fi
  local waited=0
  while [ "$waited" -lt 120 ]; do
    if cli_state_off; then break; fi
    sleep 5
    waited=$((waited + 5))
  done
  [ "$waited" -lt 120 ] || { echo "participant: warning: the node is not off after 2 minutes" >&2; return 1; }
  return 0
}

cmd=${1:-}
[ $# -gt 0 ] && shift

case $cmd in
  status)
    exec bash scripts/status.sh "$@"
    ;;

  leave)
    need_participant leave
    [ $# -eq 0 ] || die "usage: leave"
    do_leave || die "could not confirm the leave. Check: ./scripts/status.sh"
    begin
    env_set_line .env NETWORK_ENABLED false
    compose_up --no-deps ingest || { revert; die "ingest did not restart; .env was put back"; }
    echo "participant: you left the network. The sensors keep running. Join again: ./scripts/participant.sh join"
    ;;

  join)
    need_participant join
    new_pseudonym=""
    have_pseudonym=0
    while [ $# -gt 0 ]; do
      case $1 in
        --yes | -y) assume_yes=1 ;;
        --pseudonym)
          [ $# -ge 2 ] && [ -n "$2" ] || die "--pseudonym needs a value"
          new_pseudonym=$2
          have_pseudonym=1
          shift
          ;;
        *) die "usage: join [--yes] [--pseudonym NAME]" ;;
      esac
      shift
    done
    # shellcheck source=scripts/lib/pseudonym.sh
    . scripts/lib/pseudonym.sh
    if [ "$have_pseudonym" = 1 ]; then
      pseudonym_valid "$new_pseudonym" || die "bad --pseudonym"
      shown=$new_pseudonym
    else
      shown=$(sed -n 's/^NETWORK_PSEUDONYM=//p' .env | tail -n 1 | tr -d "\"'\r")
    fi
    vpn=0
    [ -z "$(env_get VPN_WG_PRIVATE_KEY)" ] || vpn=1
    echo
    consent_screen "$shown" "$vpn"
    confirm "Join the SuckerPot network as described?" || die "not joined; nothing was changed"
    begin
    env_set_line .env NETWORK_CONSENT "$(consent_record)"
    env_set_line .env NETWORK_ENABLED true
    if [ "$have_pseudonym" = 1 ]; then
      case $new_pseudonym in
        *" "*) env_set_line .env NETWORK_PSEUDONYM "'$new_pseudonym'" ;;
        *) env_set_line .env NETWORK_PSEUDONYM "$new_pseudonym" ;;
      esac
    fi
    compose_up --no-deps ingest || { revert; die "ingest did not restart; .env was put back"; }
    echo "participant: joined. Check: ./scripts/status.sh"
    ;;

  vpn)
    need_participant vpn
    [ $# -eq 1 ] || die "usage: vpn FILE.conf | vpn --remove"
    begin
    if [ "$1" = --remove ]; then
      for name in VPN_WG_PRIVATE_KEY VPN_WG_PEER_PUBLIC_KEY VPN_WG_ADDRESSES VPN_WG_DNS VPN_WG_ENDPOINT_IP VPN_WG_ENDPOINT_PORT; do
        env_set_line .env "$name" ""
      done
      env_set_line .env COMPOSE_PROFILES direct
      env_set_line .env EGRESS_MODE direct
      env_set_line .env EGRESS_PROXY_URL http://hubproxy:8888
      env_set_line .env EGRESS_CONTROL_URL http://hubproxy:8000
      feeds=0
      [ "$(env_get NETWORK_FEED_ENABLED false)" != true ] || feeds=1
      allow=$(hubproxy_allow "$feeds") || { revert; die "could not read the hub address from config/network-defaults.env"; }
      env_set_line .env HUBPROXY_ALLOW "$allow"
      # A verifier fetches files, and only through a VPN.
      if [ "$(env_get NETWORK_VERIFIER false)" = true ]; then
        env_set_line .env NETWORK_VERIFIER false
        env_set_line .env COLLECTOR_ENABLED false
        env_set_line .env COLLECTOR_VERIFY_ENABLED false
        note "the verifier role was turned off: it needs a VPN"
      fi
      stop_profile=egress
      stop_services="vpn collector analyzer"
    else
      wg_parse_conf "$1" " Check the file from your VPN provider." || { revert; die "unusable WireGuard file"; }
      env_set_line .env VPN_WG_PRIVATE_KEY "$wg_private"
      env_set_line .env VPN_WG_PEER_PUBLIC_KEY "$wg_peer"
      env_set_line .env VPN_WG_ADDRESSES "$wg_addr"
      env_set_line .env VPN_WG_DNS "$wg_dns"
      env_set_line .env VPN_WG_ENDPOINT_IP "$wg_ep_ip"
      env_set_line .env VPN_WG_ENDPOINT_PORT "$wg_ep_port"
      wg_private="" wg_peer=""
      env_set_line .env COMPOSE_PROFILES egress
      env_set_line .env EGRESS_MODE vpn
      env_set_line .env EGRESS_PROXY_URL http://vpn:8888
      env_set_line .env EGRESS_CONTROL_URL http://vpn:8000
      env_del_line .env HUBPROXY_ALLOW
      stop_profile=direct
      stop_services="hubproxy"
    fi
    env_drop_loaded
    scripts/check-vpn-env.sh || { revert; die "the VPN settings were refused; .env was put back"; }
    scripts/check-participant.sh || { revert; die "the settings were refused; .env was put back"; }
    # A service of a profile that is no longer on is not an orphan to compose: stop it by name.
    # shellcheck disable=SC2086
    docker compose --profile "$stop_profile" rm -sf $stop_services > /dev/null 2>&1 || true
    compose_up --remove-orphans || { revert; die "the stack did not become healthy; .env was put back (run: ./scripts/install.sh --repair)"; }
    if [ "$1" = --remove ]; then
      echo "participant: the VPN was removed. The hub now sees this machine's address (direct path)."
      echo "participant: re-run ./scripts/participant.sh firewall so the host firewall matches this path."
    else
      echo "participant: all network traffic now goes through your VPN."
      echo "participant: re-run ./scripts/participant.sh firewall so the host firewall allows the VPN endpoint."
    fi
    ;;

  ports-check)
    # shellcheck source=scripts/lib/ports-check.sh
    . scripts/lib/ports-check.sh
    rc=0
    ports_check_cli "$@" || rc=$?
    exit "$rc"
    ;;

  firewall)
    # Renders the host firewall for this install and loads it (sudo), or removes it.
    # shellcheck source=scripts/lib/firewall.sh
    . scripts/lib/firewall.sh
    sub=${1:-install}
    fw_mode=participant
    [ "$stack" = participant ] || fw_mode=full
    case $sub in
      install)
        tty=${SELFHOSTR_TTY:-/dev/tty}
        if [ -r "$tty" ]; then
          exec 4< "$tty"
          fw_step "$fw_mode" 4
        else
          fw_step "$fw_mode"
        fi
        ;;
      uninstall) bash scripts/host/install-firewall.sh --uninstall ;;
      status)
        if command -v nft > /dev/null 2>&1 && nft list table inet suckerpot_host > /dev/null 2>&1; then
          echo "participant: the host firewall table is loaded."
        else
          echo "participant: the host firewall table is not loaded (or reading it needs root: sudo nft list table inet suckerpot_host)."
        fi
        ;;
      *) die "usage: firewall [install|uninstall|status]" ;;
    esac
    ;;

  auto-update)
    [ $# -ge 1 ] || die "usage: auto-update on|off [--yes]"
    au_mode=$1
    shift
    while [ $# -gt 0 ]; do
      case $1 in
        --yes | -y) assume_yes=1 ;;
        *) die "usage: auto-update on|off [--yes]" ;;
      esac
      shift
    done
    # shellcheck source=scripts/lib/schedule.sh
    . scripts/lib/schedule.sh
    case $au_mode in
      on)
        [ "$install_mode" = images ] || die "automatic updates need the signed release images (this install builds from source)"
        if [ "$stack" != participant ]; then
          echo "Warning: update checks (GitHub, ghcr.io, Sigstore) go out from this machine's own address, not through the VPN." >&2
          confirm "Turn on automatic updates anyway?" || die "not turned on; nothing was changed"
        fi
        if sched=$(schedule_status 2> /dev/null); then
          schedule_upgrade || note "could not move the schedule to every 6 hours; it stays as it is"
          sched=$(schedule_status || echo off)
          note "already scheduled: $sched"
        else
          read -r sh sm < <(schedule_random_time)
          schedule_install "$sh" "$sm" || die "could not schedule the updates (no usable crontab or systemd user session)"
          sched=$(schedule_status || echo off)
        fi
        env_set_line .env AUTO_UPDATE_ENABLED true
        echo "participant: automatic updates are on (${sched}, local time)."
        ;;
      off)
        schedule_remove || die "could not remove the schedule; remove the 'selfhostr-auto-update' line from your crontab by hand"
        env_set_line .env AUTO_UPDATE_ENABLED false
        echo "participant: automatic updates are off. Update by hand with: just update"
        ;;
      *) die "usage: auto-update on|off" ;;
    esac
    ;;

  uninstall)
    need_participant uninstall
    while [ $# -gt 0 ]; do
      case $1 in
        --yes | -y) assume_yes=1 ;;
        *) die "usage: uninstall [--yes]" ;;
      esac
      shift
    done
    confirm "Leave the network and stop SuckerPot on this machine? (data volumes stay)" || die "aborted"
    if [ "$(env_get NETWORK_ENABLED false)" = true ]; then
      do_leave || echo "participant: warning: could not confirm the leave; continuing" >&2
    fi
    # shellcheck source=scripts/lib/schedule.sh
    . scripts/lib/schedule.sh
    schedule_remove || echo "participant: warning: could not remove the update schedule" >&2
    docker compose down
    prefix=$(env_get SUCKERPOT_VOLUME_PREFIX)
    echo "participant: stopped. The sensors and the node are down; the schedule is removed."
    echo "Your data volumes were NOT deleted. To delete them for good (this cannot be undone), run:"
    echo "  docker volume ls -q --filter \"name=^${prefix}_\" | xargs docker volume rm"
    ;;

  "" | -h | --help)
    sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
    ;;
  *)
    die "unknown command '$cmd' (status, leave, join, vpn, ports-check, auto-update, uninstall)"
    ;;
esac
