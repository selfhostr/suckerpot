#!/usr/bin/env bash
# Change the settings of an installed node from the terminal, and apply them at once.
#
#   scripts/edit.sh                       a menu of the settings (also: ./suckerpot.sh edit)
#   scripts/edit.sh name [NAME | --none]  the node name (participant; asks without a value)
#   scripts/edit.sh country [CC [--hide] | --none]
#                                         the country shown (participant; asks without a value)
#   scripts/edit.sh sensors [LIST]        recommended, all, or ssh,telnet,web,... (asks without)
#   scripts/edit.sh vpn [FILE.conf | --remove]
#                                         send the node's traffic through your VPN (participant)
#   scripts/edit.sh auto-update [on | off]
#   scripts/edit.sh firewall              render and load the host firewall again (sudo)
#
# Every change goes through the script that already owns it (participant.sh, env-set.sh), which
# checks it, keeps a copy of .env and puts it back when the stack does not take it. A full
# install changes its node name and country in the dashboard (Settings, Network).
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh
sudo_drop scripts/edit.sh "$@"
# shellcheck source=scripts/lib/ask.sh
. scripts/lib/ask.sh
# shellcheck source=scripts/lib/pseudonym.sh
. scripts/lib/pseudonym.sh
# shellcheck source=scripts/lib/geocheck.sh
. scripts/lib/geocheck.sh
# shellcheck source=scripts/lib/nodeprofile.sh
. scripts/lib/nodeprofile.sh

die() { echo "edit: $*" >&2; exit 1; }

[ -f .env ] || die "nothing is installed in this folder (no .env): ./suckerpot.sh install"
env_drop_loaded
stack=$(env_get SUCKERPOT_STACK_MODE full)
ask_open
ASK_IND="  "

need_participant() {
  [ "$stack" = participant ] || die "the $1 of a full install is changed in the dashboard (Settings, Network)"
}

cur_name() { sed -n 's/^NETWORK_PSEUDONYM=//p' .env | tail -n 1 | tr -d "\"'\r"; }
cur_sensors() {
  local s out=()
  for s in "${SENSORS[@]}"; do [ "$(env_get "$(sensor_var "$s")" 1)" = 0 ] || out+=("$s"); done
  (IFS=,; printf '%s' "${out[*]}")
}
country_text() {
  local cc
  cc=$(env_get NETWORK_COUNTRY)
  if [ -z "$cc" ]; then echo "none"; elif [ "$(env_get NETWORK_SHOW_COUNTRY false)" = true ]; then echo "$cc (shown)"; else echo "$cc (not shown)"; fi
}
vpn_text() { if [ -n "$(env_get VPN_WG_PRIVATE_KEY)" ]; then echo "through your VPN"; else echo "direct (no VPN)"; fi; }
auto_text() {
  local s
  # shellcheck source=scripts/lib/schedule.sh
  . scripts/lib/schedule.sh
  if [ "$(env_get AUTO_UPDATE_ENABLED false)" = true ] && s=$(schedule_status 2> /dev/null); then echo "on ($s)"; else echo "off"; fi
}
fw_text() {
  # shellcheck source=scripts/lib/fwcheck.sh
  . scripts/lib/fwcheck.sh
  if ! fw_installed; then echo "not installed"; else
    case $(fw_state) in loaded) echo "loaded" ;; unknown) echo "installed" ;; *) echo "installed, not loaded" ;; esac
  fi
}

need_tty() { [ "$ASK_TTY" = 1 ] || die "no terminal to ask on: give the value, for example: scripts/edit.sh $1 VALUE"; }

edit_name() {
  need_participant "node name"
  local v=${1:-}
  if [ $# -eq 0 ]; then
    need_tty name
    profile_ask_name "$(cur_name)" || die "no valid name was given; nothing was changed"
    if [ "$PROFILE_NAME" = "$(cur_name)" ]; then echo "edit: the node name stays $(cur_name)"; return 0; fi
    if [ -n "$PROFILE_NAME" ]; then v=$PROFILE_NAME; else v=--none; fi
  fi
  bash scripts/participant.sh set-name "$v"
}

edit_country() {
  need_participant country
  if [ $# -eq 0 ]; then
    need_tty country
    # An ingest too old to change the country of a member says so before any question.
    bash scripts/participant.sh set-country --check || return 0
    local cur
    cur=$(env_get NETWORK_COUNTRY)
    profile_ask_country "$cur" ask || die "no valid country was given; nothing was changed"
    if [ -z "$PROFILE_COUNTRY" ]; then
      [ -n "$cur" ] || { echo "edit: no country is shown, as before"; return 0; }
      bash scripts/participant.sh set-country --none
    else
      bash scripts/participant.sh set-country "$PROFILE_COUNTRY" --no-check
    fi
    return
  fi
  bash scripts/participant.sh set-country "$@"
}

_sensor_list_ok() {
  local s names=()
  case $1 in recommended | all) return 0 ;; "") echo "choose at least one sensor"; return 1 ;; esac
  IFS=, read -r -a names <<< "$1"
  for s in "${names[@]}"; do is_sensor "$s" || { echo "unknown sensor '$s' (known: ${SENSORS[*]})"; return 1; }; done
}

edit_sensors() {
  local list=${1:-} s on lite=0
  case ":$(env_get COMPOSE_FILE):" in *:docker-compose.lite.yml:*) lite=1 ;; esac
  if [ -z "$list" ]; then
    need_tty sensors
    {
      echo
      echo "  Sensors (the port the router forwards to it, and whether it runs now)"
      for s in "${SENSORS[@]}"; do
        on=off
        [ "$(env_get "$(sensor_var "$s")" 1)" = 0 ] || on=on
        printf '    %-9s %-4s %s\n' "$s" "$on" "$(sensor_ports "$s" | cut -d: -f2 | tr '\n' ' ')"
      done
      echo
      echo "  Recommended: ${RECOMMENDED_SENSORS[*]}"
      [ "$lite" = 0 ] || echo "  This is a lite node (1 GiB): more than ${LITE_SENSORS[*]} may not fit in its memory."
    } 1>&"$ASK_OUT"
    ask_text list "Sensors to run (a comma list, recommended or all)" "$(cur_sensors)" _sensor_list_ok || die "no valid list; nothing was changed"
    [ "$list" != "$(cur_sensors)" ] || { echo "edit: the sensors stay as they are"; return 0; }
  fi
  _sensor_list_ok "$list" > /dev/null || die "$(_sensor_list_ok "$list")"
  bash scripts/env-set.sh sensors "$list"
  bash scripts/compose-fresh.sh up -d --wait
  echo "edit: the sensors now running: $(cur_sensors). Forward their ports on your router (./scripts/status.sh lists them)."
}

edit_vpn() {
  need_participant VPN
  local f=${1:-}
  if [ -z "$f" ]; then
    need_tty vpn
    local a
    if [ -n "$(env_get VPN_WG_PRIVATE_KEY)" ]; then
      ask_menu a k "The node sends its traffic through your VPN now." \
        "k|Keep the VPN|" "r|Remove the VPN|back to the direct path: the hub sees this machine's address" \
        "n|Another VPN file|a WireGuard .conf from your provider"
      case $a in
        k) return 0 ;;
        r) f=--remove ;;
      esac
    fi
    if [ -z "$f" ]; then
      ask_text f "Path to the WireGuard .conf file (empty: cancel)" "" || return 0
      [ -n "$f" ] || return 0
    fi
  fi
  bash scripts/participant.sh vpn "$f"
  ask_yn "Render and load the host firewall again, for the new path (sudo)?" y && bash scripts/participant.sh firewall install || true
}

edit_auto() {
  local v=${1:-}
  if [ -z "$v" ]; then
    need_tty auto-update
    if ask_yn "Install signed releases by themselves (every 6 h, a release once 48 h old)?" y; then v=on; else v=off; fi
  fi
  bash scripts/participant.sh auto-update "$v"
}

version_text() {
  local v latest mode
  mode=$(env_get SUCKERPOT_INSTALL_MODE source)
  v=$(env_get SUCKERPOT_VERSION)
  latest=$(latest_known_release)
  if [ "$mode" != images ]; then
    echo "built from source ($(git describe --tags --always 2> /dev/null || echo unknown))"
  elif [ -n "$latest" ] && [ "$latest" != "$v" ] && ver_ge "${latest#v}" "${v#v}"; then
    echo "${v:-unknown} (signed images), $latest available: ./suckerpot.sh update"
  else
    echo "${v:-unknown} (signed images, the newest this checkout knows)"
  fi
}

# The configuration screen: every setting with its value; pick one to change it, then the screen
# comes back with the new value.
edit_menu() {
  local a items
  [ "$ASK_TTY" = 1 ] || die "no terminal for the menu; see: scripts/edit.sh --help"
  while :; do
    items=()
    if [ "$stack" = participant ]; then
      items+=("name|Node name|$(cur_name || true)" "country|Country|$(country_text)")
    fi
    items+=("sensors|Sensors|$(cur_sensors)")
    [ "$stack" != participant ] || items+=("vpn|VPN|$(vpn_text)")
    items+=("auto|Automatic updates|$(auto_text)" "firewall|Host firewall|$(fw_text)" "b|Back|")
    _ask_style
    printf '\n  %sThe configuration of this node%s\n' "$ASK_B" "$ASK_R" 1>&"$ASK_OUT"
    printf '  Pick a setting to change it; the change applies at once.\n\n' 1>&"$ASK_OUT"
    printf '  %-20s %s\n' "Version" "$(version_text)" 1>&"$ASK_OUT"
    [ "$stack" = participant ] || printf '  %-20s %s\n' "Name, country" "in the dashboard (Settings, Network)" 1>&"$ASK_OUT"
    echo 1>&"$ASK_OUT"
    ask_pick a b "" "${items[@]}"
    [ "$ASK_EOF" = 0 ] || [ "$a" != b ] || return 0
    case $a in
      name) edit_name || true ;;
      country) edit_country || true ;;
      sensors) edit_sensors || true ;;
      vpn) edit_vpn || true ;;
      auto) edit_auto || true ;;
      firewall) bash scripts/participant.sh firewall install || true ;;
      *) return 0 ;;
    esac
    [ "$ASK_EOF" = 0 ] || return 0
  done
}

cmd=${1:-}
[ $# -gt 0 ] && shift
case $cmd in
  "") edit_menu ;;
  name) edit_name "$@" ;;
  country) edit_country "$@" ;;
  sensors) [ $# -le 1 ] || die "usage: sensors [LIST]"; edit_sensors "$@" ;;
  vpn) [ $# -le 1 ] || die "usage: vpn [FILE.conf | --remove]"; edit_vpn "$@" ;;
  auto-update) [ $# -le 1 ] || die "usage: auto-update [on | off]"; edit_auto "$@" ;;
  firewall) bash scripts/participant.sh firewall install ;;
  -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' ;;
  *) die "unknown setting '$cmd' (name, country, sensors, vpn, auto-update, firewall)" ;;
esac
