#!/usr/bin/env bash
# Manage a participant install (docs/dev/design/m32.md section 5.6).
#
#   scripts/participant.sh status                    same as ./scripts/status.sh
#   scripts/participant.sh leave                     leave the network; sensors keep running
#   scripts/participant.sh join [--yes] [--pseudonym NAME]
#                                                    show the consent screen again and join
#   scripts/participant.sh set-name NAME | --none    change the node name (the pseudonym) and
#                                                    send it to the hub; --none: no name
#   scripts/participant.sh set-country CC [--hide] | --none [--no-check]
#                                                    show a country (--hide: send it, do not show
#                                                    it); the code is checked against a GeoIP
#                                                    database on this machine only
#   scripts/participant.sh vpn FILE.conf             send everything through your VPN
#   scripts/participant.sh vpn --remove              back to the direct path (no VPN)
#   scripts/participant.sh ports-check [--wait SECONDS] [--since ISO | --since-install]
#                                                    does the internet reach your sensors? (no outside connection)
#   scripts/participant.sh firewall [install|uninstall|status]
#                                                    render and load the host firewall (sudo), or remove it
#   scripts/participant.sh auto-update on|off       install or remove the daily update schedule
#   scripts/participant.sh uninstall [--yes]         leave, stop the stack, remove the schedule
#
# join, leave, set-name, set-country, vpn and uninstall are for participant installs. auto-update and ports-check work on any install.
# ports-check exits 0 when a public address reached a sensor, 3 when nothing did yet.
# Nothing here deletes data: uninstall prints the volume removal command and never runs it.
# Secrets are never printed.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh
owner_init

# On a terminal the message wraps at its width (text_out, scripts/lib/ask.sh, once it is loaded).
die() {
  if declare -F text_out > /dev/null; then printf 'participant: %s\n' "$*" | text_out 2; else echo "participant: $*" >&2; fi
  exit 1
}
engine_ready || die "$ENGINE_UNREADY_MSG"
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
    engine_stack_up -d --no-build --pull never --wait --wait-timeout 300 "$@"
  else
    engine_stack_up -d --build --wait --wait-timeout 600 "$@"
  fi
}

# compose_up with its output kept out of the way: shown only when it fails.
quiet_up() {
  local out rc=0
  out=$(compose_up "$@" 2>&1) || rc=$?
  [ "$rc" = 0 ] || printf '%s\n' "$out" | tail -n 20 >&2
  return "$rc"
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
cleanup() { [ -n "$backup" ] && rm -f "$backup"; owner_fix; return 0; }
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

# shellcheck source=scripts/lib/enrol_wait.sh
. scripts/lib/enrol_wait.sh
# shellcheck source=scripts/lib/ask.sh
. scripts/lib/ask.sh
# tell TEXT / tell_err TEXT: a message, wrapped at the width of a terminal (as given without one).
tell() { printf '%s\n' "$*" | text_out 1; }
tell_err() { printf '%s\n' "$*" | text_out 2; }

# Prints the TOP-LEVEL "state" string of a JSON document on stdin. A grep over the whole document
# is wrong: the nested verifier, consent and membership objects have their own "state" keys, and
# an "off" there would end the wait before the worker has told the hub.
json_top_state() {
  json_top_string state
}

# cli_has_update: the running ingest has `ingest.network.cli update` (newer than v0.15.0).
cli_has_update() {
  dc exec -T ingest python -m ingest.network.cli update --help > /dev/null 2>&1
}

# old_ingest_text WHAT: why WHAT cannot change with the ingest that runs, and what to do.
old_ingest_text() {
  local running latest
  running=$(dc exec -T ingest printenv SUCKERPOT_RUNNING_VERSION 2> /dev/null | tr -d '\r' || true)
  latest=$(latest_known_release)
  if [ "$install_mode" = source ]; then
    printf 'this node runs images built from an older checkout (%s), whose ingest cannot change %s. Update first (./suckerpot.sh update rebuilds them from this checkout), then try again. Nothing was changed.' "${running:-unknown}" "$1"
  elif [ -n "$latest" ] && [ -n "$running" ] && [ "$latest" != "$running" ] && ver_ge "${latest#v}" "${running#v}"; then
    printf 'this node runs %s, whose ingest cannot change %s. Update first (./suckerpot.sh update, to %s), then try again; if it still says this, the change needs a release newer than %s. Nothing was changed.' "$running" "$1" "$latest" "$latest"
  else
    printf 'this node runs %s, whose ingest cannot change %s: that needs a release newer than %s (the scripts of this checkout are newer than the images). Nothing was changed.' "${running:-an older release}" "$1" "${running:-it}"
  fi
}

# The top-level state of the network status ("" when ingest does not answer).
cli_state() {
  dc exec -T ingest python -m ingest.network.cli status --json 2> /dev/null | json_top_state
}

# True when the top-level state of the network status is off, left or not_joined.
cli_state_off() {
  local st
  st=$(dc exec -T ingest python -m ingest.network.cli status --json 2> /dev/null | json_top_state) || return 1
  case $st in off | left | not_joined) return 0 ;; *) return 1 ;; esac
}

do_leave() {
  if ! dc exec -T ingest python -m ingest.network.cli leave > /dev/null; then
    echo "participant: warning: ingest did not confirm the leave" >&2
    return 1
  fi
  # The worker acts on the leave at its next cycle (every 15 minutes by default); a restart runs
  # that cycle now, so the hub hears of the leave before the stack may be stopped.
  echo "participant: telling the hub (this takes up to 2 minutes)..."
  dc restart ingest > /dev/null 2>&1 || true
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
    consent_screen "$shown" "$vpn" | text_out 1 --join
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
    # Clears a refused join (state error) or the leave marker, and hands a member its new name.
    cli_join=(python -m ingest.network.cli join)
    [ "$have_pseudonym" = 0 ] || cli_join+=(--pseudonym "$new_pseudonym")
    if answer=$(dc exec -T ingest "${cli_join[@]}" 2> /dev/null); then
      case $(printf '%s' "$answer" | json_top_string state) in
        # The worker only joins from a clean state at its start: restart it once more.
        error | off) dc restart ingest > /dev/null 2>&1 || echo "participant: warning: ingest did not restart" >&2 ;;
      esac
    else
      echo "participant: warning: ingest did not accept the join request" >&2
    fi
    echo "participant: waiting for the hub to enrol this node (this can take a few minutes)..."
    read -r st code < <(enrol_wait)
    name=$(dc exec -T ingest python -m ingest.network.cli status --json 2> /dev/null | json_top_string pseudonym) || name=""
    name=${name:-$shown}
    case $st in
      member) echo "participant: joined${name:+ as $name}. Check: ./scripts/status.sh" ;;
      error)
        if [ "$code" = pseudonym_taken ] && [ -n "$name" ]; then
          suggestion=$(pseudonym_suggest "$name") || suggestion=NEW-NAME
          echo "participant: the hub refused the pseudonym '$name': another node already uses it." >&2
          echo "  If that is your own earlier install, the hub frees the name after two days without contact, if that node never sent a batch." >&2
          echo "  Pick another name: ./scripts/participant.sh join --pseudonym $suggestion" >&2
          if [ "$assume_yes" = 0 ] && [ -r "${SELFHOSTR_TTY:-/dev/tty}" ] && confirm "Join as '$suggestion' instead?"; then
            exec bash scripts/participant.sh join --yes --pseudonym "$suggestion"
          fi
        else
          echo "participant: the hub refused to enrol this node (${code}). Details: ./scripts/status.sh" >&2
        fi
        exit 1
        ;;
      unknown) echo "participant: joined. Check: ./scripts/status.sh" ;;
      *) echo "participant: the join is still in progress. Check in a few minutes: ./scripts/status.sh" ;;
    esac
    ;;

  set-name | set-country)
    need_participant "$cmd"
    # shellcheck source=scripts/lib/pseudonym.sh
    . scripts/lib/pseudonym.sh
    # shellcheck source=scripts/lib/geocheck.sh
    . scripts/lib/geocheck.sh
    check=1 hide=0 value="" none=0 only_check=0
    while [ $# -gt 0 ]; do
      case $1 in
        --none) none=1 ;;
        --hide) [ "$cmd" = set-country ] || die "usage: set-name NAME | --none"; hide=1 ;;
        --no-check) [ "$cmd" = set-country ] || die "usage: set-name NAME | --none"; check=0 ;;
        --check) only_check=1 ;;
        -*) die "unknown option '$1'" ;;
        *) [ -z "$value" ] || die "one value only (quote a name with spaces)"; value=$1 ;;
      esac
      shift
    done
    if [ "$only_check" = 1 ]; then
      :
    elif [ "$cmd" = set-name ]; then
      { [ "$none" = 1 ] && [ -z "$value" ]; } || { [ "$none" = 0 ] && [ -n "$value" ]; } || die "usage: set-name NAME | --none"
      [ "$none" = 1 ] || pseudonym_valid "$value" || die "this name is not allowed"
      cli_args=(--pseudonym "$value")
      [ "$none" = 0 ] || cli_args=(--no-pseudonym)
    elif [ "$only_check" = 0 ]; then
      { [ "$none" = 1 ] && [ -z "$value" ] && [ "$hide" = 0 ]; } || { [ "$none" = 0 ] && [ -n "$value" ]; } || die "usage: set-country CC [--hide] | --none"
      if [ "$none" = 0 ]; then
        why=$(geo_code_ok "$value") || die "$why"
        value=${value^^}
        cli_args=(--country "$value")
        if [ "$hide" = 1 ]; then cli_args+=(--hide-country); else cli_args+=(--show-country); fi
      else
        cli_args=(--no-country)
      fi
    fi
    # The country is compared with a GeoIP database on this machine (never an outside service):
    # a mismatch is a warning, the owner's choice stands.
    # Before anything changes: a node in the network needs ingest to take the change in its own
    # record. The ingest of a release before this feature has no `update` command: a country
    # change is then refused here, with the version, and nothing is changed.
    st=""
    if [ "$(env_get NETWORK_ENABLED false)" = true ]; then
      st=$(cli_state) || st=""
      if [ -z "$st" ]; then
        # ingest is down or busy: start it first (with the settings as they are).
        quiet_up --no-deps ingest || die "ingest did not start; nothing was changed (./scripts/install.sh --repair)"
        st=$(cli_state) || st=""
      fi
      if [ "$cmd" = set-country ] && { [ "$st" = member ] || [ "$st" = enrolling ]; } && ! cli_has_update; then
        die "$(old_ingest_text "the country of a node that is in the network")"
      fi
    fi
    [ "$only_check" = 0 ] || exit 0
    if [ "$cmd" = set-country ] && [ "$none" = 0 ] && [ "$check" = 1 ]; then
      geo_check "$value"
      case $GEO_RESULT in
        match) note "$value matches: $GEO_SOURCE places this machine in $GEO_FOUND." ;;
        mismatch) echo "participant: warning: $GEO_SOURCE places this machine ($GEO_ADDR) in $GEO_FOUND, not in $value. $value is kept as you asked." >&2 ;;
        *) note "$value is not checked: $GEO_WHY." ;;
      esac
    fi
    begin
    if [ "$cmd" = set-name ]; then
      case $value in
        *" "*) env_set_line .env NETWORK_PSEUDONYM "'$value'" ;;
        *) env_set_line .env NETWORK_PSEUDONYM "$value" ;;
      esac
    else
      env_set_line .env NETWORK_COUNTRY "$value"
      if [ -n "$value" ] && [ "$hide" = 0 ]; then
        env_set_line .env NETWORK_SHOW_COUNTRY true
      else
        env_set_line .env NETWORK_SHOW_COUNTRY false
      fi
    fi
    what="node name"
    [ "$cmd" = set-name ] || what=country
    shown=${value:-none}
    if [ "$(env_get NETWORK_ENABLED false)" != true ]; then
      tell "participant: the $what is saved ($shown). This node is not in the network: it is used when you join (./scripts/participant.sh join)."
      exit 0
    fi
    case $st in
      member | enrolling | not_joined)
        # A member (or a join in progress) takes the change in its own record; the worker sends it to
        # the hub. Older ingest images have no update command: a name still goes through join.
        if ! answer=$(dc exec -T ingest python -m ingest.network.cli update "${cli_args[@]}" 2> /dev/null); then
          reason=$(printf '%s' "$answer" | json_top_string reason)
          if [ -z "$reason" ] && [ "$cmd" = set-name ] && [ "$none" = 0 ]; then
            dc exec -T ingest python -m ingest.network.cli join --pseudonym "$value" > /dev/null 2>&1 \
              || { revert; die "ingest did not take the new name; .env was put back"; }
            # An older ingest says nothing about the hub having it: no wait for that.
            old_cli=1
          elif [ "$reason" = not_member ]; then
            :
          elif [ -z "$reason" ]; then
            revert
            die "$(old_ingest_text "the $what of a node that is in the network") .env was put back."
          else
            revert
            die "ingest refused the change (${reason:-no answer}); .env was put back"
          fi
        fi
        ;;
    esac
    # A restart runs the worker's cycle at once: the hub gets the change now, and a node whose join
    # was refused (for example a taken name) tries again with the new name by itself.
    quiet_up --no-deps --force-recreate ingest || { revert; die "ingest did not restart; .env was put back"; }
    case $st in
      member)
        tell "participant: waiting for the hub to take the new $what..."
        waited=0 limit=${SUCKERPOT_PROFILE_WAIT:-90} synced="" code=""
        [ "${old_cli:-0}" = 0 ] || limit=15
        while [ "$waited" -lt "$limit" ]; do
          doc=$(dc exec -T ingest python -m ingest.network.cli status --json 2> /dev/null) || doc=""
          code=$(printf '%s' "$doc" | json_top_string error_code)
          case $code in pseudonym_taken | pseudonym_invalid) break ;; esac
          case $doc in *'"profile_synced": true'*) synced=1; break ;; esac
          sleep 5
          waited=$((waited + 5))
        done
        if [ "$code" = pseudonym_taken ]; then
          name=$(printf '%s' "$doc" | json_top_string pseudonym)
          kept="no name"
          [ -z "$name" ] || kept="the name '$name'"
          revert
          compose_up --no-deps ingest > /dev/null 2>&1 || true
          tell_err "participant: the hub refused the name '$value': another node already uses it. The node keeps $kept; .env was put back."
          tell_err "  Try another one: ./scripts/participant.sh set-name $(pseudonym_suggest "$value" || echo NEW-NAME)"
          exit 1
        elif [ "$code" = pseudonym_invalid ]; then
          revert
          compose_up --no-deps ingest > /dev/null 2>&1 || true
          die "the identity check or the hub refused the name '$value' (it may contain one of your own names). .env was put back."
        elif [ -n "$synced" ]; then
          tell "participant: the $what is now $shown, and the hub has it."
        else
          tell "participant: the $what is now $shown here. The hub gets it at the next contact (at most 15 minutes). Check: ./suckerpot.sh status"
        fi
        ;;
      error)
        tell "participant: the $what is saved ($shown). The node was refused before; it now tries to join again with it."
        tell "  Watch for the answer: ./suckerpot.sh status --wait"
        ;;
      enrolling | not_joined)
        tell "participant: the $what is saved ($shown) and goes with the join that is in progress. Check: ./suckerpot.sh status --wait"
        ;;
      *)
        tell "participant: the $what is saved ($shown). It is used when this node joins: ./scripts/participant.sh join"
        ;;
    esac
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
    dc --profile "$stop_profile" rm -sf $stop_services > /dev/null 2>&1 || true
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
        fw_rc=0
        if [ -r "$tty" ]; then
          exec 4< "$tty"
          fw_step "$fw_mode" 4 || fw_rc=$?
        else
          fw_step "$fw_mode" || fw_rc=$?
        fi
        # Podman: the firewall is required (fw_step returns 1 without it), and the boot unit
        # that binds the stack to it comes right after. Docker: fw_step never fails.
        [ "$fw_rc" = 0 ] || die "the host firewall is required on Podman and was not installed"
        if [ "$ENGINE_ID" = podman ]; then
          if fw_opted_out; then
            engine_install_boot_unit --no-firewall || die "the boot unit could not be installed"
          else
            engine_install_boot_unit || die "the boot unit could not be installed"
          fi
        fi
        ;;
      uninstall) bash scripts/host/install-firewall.sh --uninstall ;;
      status)
        # shellcheck source=scripts/lib/fwcheck.sh
        . scripts/lib/fwcheck.sh
        case $(fw_state) in
          loaded) echo "participant: the host firewall is active and its tables are loaded." ;;
          unknown) echo "participant: the host firewall unit is active; reading its tables needs root (sudo ./scripts/participant.sh firewall status)." ;;
          missing:*) echo "participant: the host firewall unit is active but its tables are gone: sudo systemctl reload suckerpot-firewall.service" ;;
          *) echo "participant: the host firewall is not active." ;;
        esac
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
    # Podman: the boot unit goes first, so the stack does not come back at the next boot.
    if [ "$ENGINE_ID" = podman ] && engine_stack_unit_installed; then
      engine_remove_boot_unit || echo "participant: warning: could not remove suckerpot-stack.service (sudo scripts/host/install-stack-unit.sh --uninstall)" >&2
    fi
    dc down
    prefix=$(env_get SUCKERPOT_VOLUME_PREFIX)
    tell "participant: stopped. The sensors and the node are down; the schedule is removed."
    tell "Your data volumes were NOT deleted. To delete them for good (this cannot be undone), run:"
    echo "  ${ENGINE_CTR[*]} volume ls -q --filter \"name=^${prefix}_\" | xargs ${ENGINE_CTR[*]} volume rm"
    # Podman: the socket group is root-equivalent; it stays until removed. With --yes it is removed
    # (the commands above then need sudo, or a new login back in the group).
    if [ "$ENGINE_ID" = podman ]; then
      if confirm "Also remove this user's access to the root Podman socket (group $ENGINE_SOCKET_GROUP, root-equivalent)?"; then
        engine_remove_socket_access || echo "participant: warning: could not remove the socket access (sudo scripts/host/podman-socket.sh --uninstall $(id -un))" >&2
      else
        echo "Your user stays in group $ENGINE_SOCKET_GROUP (root-equivalent) until: sudo scripts/host/podman-socket.sh --uninstall $(id -un)"
      fi
    fi
    ;;

  "" | -h | --help)
    sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
    ;;
  *)
    die "unknown command '$cmd' (status, leave, join, set-name, set-country, vpn, ports-check, firewall, auto-update, uninstall)"
    ;;
esac
