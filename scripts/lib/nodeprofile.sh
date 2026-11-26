#!/usr/bin/env bash
# The two questions about how a participant node appears on the network: its node name (the
# pseudonym of the protocol) and its country. Used by install.sh and edit.sh. Sourced, never run;
# source it after scripts/lib/ask.sh, scripts/lib/pseudonym.sh and scripts/lib/geocheck.sh.
#
#   profile_ask_name CURRENT       sets PROFILE_NAME ("" = no name); returns 1 when nothing valid
#                                  was answered
#   profile_ask_country CURRENT [download]
#                                  sets PROFILE_COUNTRY ("" = none shown); runs the local country
#                                  check and asks before any download (download = the owner
#                                  already allowed it, --country-check download)
#   profile_host_name              this machine's host name as a valid node name, or nothing
#
# Both only ask and decide: the caller writes .env (install.sh) or applies the change
# (participant.sh set-name, set-country).

# shellcheck disable=SC2034 # PROFILE_NAME and PROFILE_COUNTRY are the results, read by the callers
true

# profile_host_name: the short host name, when the hub would accept it as a name.
profile_host_name() {
  local h
  h=$(hostname 2> /dev/null || uname -n 2> /dev/null || true)
  h=${h%%.*}
  [ -n "$h" ] || return 0
  case ${h,,} in localhost | debian | ubuntu | raspberrypi | vps | server | ubuntu-* | debian-*) return 0 ;; esac
  if pseudonym_valid "$h" 2> /dev/null; then printf '%s' "$h"; fi
  return 0
}

_profile_name_check() { [ -z "$1" ] || pseudonym_valid "$1"; }

# profile_ask_name CURRENT
profile_ask_name() {
  local cur=${1:-} random host choice def items=() own=""
  random=$(pseudonym_random 2> /dev/null || true)
  host=$(profile_host_name)
  _ask_say_block \
    "Node name" \
    "The network shows your node under this name (in the member list and in its figures), or as" \
    "\"Node\" and a number if you choose none. Do not use a name you use anywhere else: it would" \
    "link this node to you. You can change it later: ./suckerpot edit"
  def=keep
  if [ -n "$cur" ]; then items+=("keep|Keep $cur|the current name"); fi
  if [ -n "$random" ]; then items+=("random|$random|a random name (recommended)"); fi
  if [ -n "$host" ] && [ "$host" != "$cur" ]; then
    items+=("host|$host|this machine's host name: it may identify you")
  fi
  items+=("own|Type a name|3 to 24 letters, digits, space, _ . -" "none|No name|the network shows \"Node\" and a number")
  [ -n "$cur" ] || def=random
  [ -n "$random" ] || [ -n "$cur" ] || def=own
  # The keys are 1..n in the order shown, whatever choices this machine has.
  ask_pick choice "$def" "" "${items[@]}"
  case $choice in
    keep) PROFILE_NAME=$cur ;;
    random) PROFILE_NAME=$random ;;
    host)
      PROFILE_NAME=$host
      _ask_say_block "" "Your host name can be seen by others (for example in reverse DNS, TLS certificates or" \
        "your provider's panel). If it names you or your provider, pick another name."
      ask_yn "Use '$host' anyway?" n || { profile_ask_name "$cur"; return $?; }
      ;;
    own)
      ask_text own "Node name" "" _profile_name_check || return 1
      PROFILE_NAME=$own
      ;;
    none) PROFILE_NAME="" ;;
    *) return 1 ;;
  esac
  return 0
}

# _ask_say_block LINE...: a short block of text, one blank line before it. The first line is the
# title (bold); an empty title prints none.
# On a terminal the lines are one paragraph, wrapped at its width; without one they print as given.
_ask_say_block() {
  local title=$1
  shift
  _ask_style
  printf '\n' 1>&"$ASK_OUT"
  [ -z "$title" ] || printf '%s%s%s%s\n' "$ASK_IND" "$ASK_B" "$title" "$ASK_R" 1>&"$ASK_OUT"
  text_width "$ASK_OUT"
  if [ "$TEXT_W" -gt 0 ]; then
    ask_lines "" "$*"
  else
    ask_lines "" "$@"
  fi
  printf '\n' 1>&"$ASK_OUT"
}

_profile_cc_check() { geo_code_ok "$1"; }

# profile_ask_country CURRENT [download]
profile_ask_country() {
  local cur=${1:-} allow=${2:-ask} cc choice def=n
  _ask_say_block \
    "Country" \
    "You may show the country of this node next to its name. It is never detected or filled in" \
    "for you, and the network shows a country only once at least three nodes show it."
  [ -z "$cur" ] || def=y
  if ! ask_yn "Show a country for this node?" "$def"; then
    PROFILE_COUNTRY=""
    return 0
  fi
  while :; do
    ask_text cc "Country code (two letters, for example FR, DE, CH)" "$cur" _profile_cc_check || return 1
    cc=${cc^^}
    profile_check_country "$cc" "$allow"
    case $GEO_RESULT in
      match | unknown)
        PROFILE_COUNTRY=$cc
        return 0
        ;;
    esac
    # A mismatch: the owner decides; nothing is changed without an answer.
    local items=("1|Keep $cc|the node is shown in $cc anyway")
    items+=("2|Use $GEO_FOUND|where the local database places this machine")
    items+=("3|Type another code|" "4|Show no country|")
    ask_menu choice 3 "" "${items[@]}"
    case $choice in
      1) PROFILE_COUNTRY=$cc; return 0 ;;
      2) PROFILE_COUNTRY=$GEO_FOUND; return 0 ;;
      4) PROFILE_COUNTRY=""; return 0 ;;
      *) cur="" ;;
    esac
  done
}

# profile_check_country CC [ask|download|local|off]: runs the check and prints its result. With
# "ask" and no local database, it asks before the one download (on a terminal only).
profile_check_country() {
  local cc=$1 allow=${2:-ask}
  GEO_RESULT=unknown GEO_FOUND="" GEO_WHY=""
  [ "$allow" != off ] || return 0
  geo_check "$cc"
  if [ "$GEO_RESULT" = unknown ] && [ -n "$GEO_ADDR" ] && [ -z "$(geo_sources)" ]; then
    local fetch=0
    if [ "$allow" = download ]; then
      fetch=1
    elif [ "$allow" = ask ] && [ "$ASK_TTY" = 1 ]; then
      _ask_say_block "" \
        "There is no GeoIP database on this machine, so $cc cannot be checked yet. The check can" \
        "use DB-IP's free country list: one public file (about 5 MB) downloaded over HTTPS from" \
        "$GEO_DOWNLOAD_HOST, from this machine's own address. DB-IP sees that this address" \
        "downloaded its list, nothing more: the address is looked up here, never sent. The file" \
        "stays in .suckerpot-state/geoip/ for later checks."
      if ask_yn "Download it and check $cc?" n; then fetch=1; fi
    fi
    if [ "$fetch" = 1 ]; then
      printf '%sDownloading the country list from %s...\n' "$ASK_IND" "$GEO_DOWNLOAD_HOST" 1>&"$ASK_OUT"
      if geo_download 2> "${TMPDIR:-/tmp}/geo-download.$$"; then
        geo_check "$cc"
      else
        GEO_WHY="the download failed: $(cat "${TMPDIR:-/tmp}/geo-download.$$" 2> /dev/null)"
      fi
      rm -f "${TMPDIR:-/tmp}/geo-download.$$"
    fi
  fi
  _ask_style
  case $GEO_RESULT in
    match)
      ask_lines "$ASK_OK" "$cc matches: $GEO_SOURCE places $GEO_ADDR in $GEO_FOUND."
      ;;
    mismatch)
      printf '\n' 1>&"$ASK_OUT"
      ask_lines "$ASK_WARN" "! $GEO_SOURCE places this machine ($GEO_ADDR) in $GEO_FOUND, not in $cc."
      ask_lines "" "  A node shows the country it runs in. A VPS is often elsewhere than its owner." ""
      ;;
    *)
      ask_lines "" "$cc not checked: ${GEO_WHY:-no local GeoIP database}."
      ;;
  esac
  return 0
}
