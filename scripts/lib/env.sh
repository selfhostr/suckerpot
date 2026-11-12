#!/usr/bin/env bash
# Shared helpers for the SuckerPot host scripts (install.sh, env-set.sh, env-migrate.sh,
# update.sh, rollback.sh). Source this file; it defines functions and constants only and runs
# nothing. It never prints a secret value.

# Every secret of .env. The installer generates them all; env-migrate.sh adds the missing ones.
SECRET_VARS=(
  POSTGRES_PASSWORD POSTGRES_INGEST_PASSWORD POSTGRES_API_PASSWORD
  POSTGRES_COLLECTOR_PASSWORD POSTGRES_ANALYZER_PASSWORD
  REDIS_PASSWORD REDIS_HEALTH_PASSWORD REDIS_INGEST_PASSWORD REDIS_DEMO_PASSWORD
  REDIS_SENSOR_SSH_PASSWORD REDIS_SENSOR_RDP_PASSWORD REDIS_SENSOR_TELNET_PASSWORD
  REDIS_SENSOR_WEB_PASSWORD REDIS_SENSOR_REDIS_PASSWORD REDIS_SENSOR_DOCKER_PASSWORD
  REDIS_SENSOR_MYSQL_PASSWORD REDIS_SENSOR_MSSQL_PASSWORD REDIS_SENSOR_ADB_PASSWORD
  REDIS_SENSOR_SMB_PASSWORD REDIS_SENSOR_SIP_PASSWORD REDIS_SENSOR_SYNOLOGY_PASSWORD
  EGRESS_PROXY_PASSWORD SESSION_SECRET SETTINGS_ENCRYPTION_KEY
)

# Secrets that env-migrate.sh must never invent for an existing install: the database owner
# password lives inside the data volume, so a new value would lock the owner out.
NO_MIGRATE_SECRET_VARS=(POSTGRES_PASSWORD)

# Non-secret variables env-migrate.sh adds (with this default) to an .env that lacks them.
MIGRATE_DEFAULTS=(SUCKERPOT_INSTALL_MODE=source SUCKERPOT_STACK_MODE=full AUTO_UPDATE_ENABLED=false)

SENSORS=(ssh telnet web rdp redis docker mysql adb mssql smb sip synology)
RECOMMENDED_SENSORS=(ssh telnet web redis docker adb)
# Default of `install.sh --participant --lite` (1 GiB machines): the four busiest, cheapest sensors.
LITE_SENSORS=(ssh telnet web redis)

# Variables that `just set` may change. Patterns are shell globs.
SETTABLE_VARS=(
  '*_ENABLED' '*_HOST_PORT' DASHBOARD_BIND DASHBOARD_PORT COOKIE_SECURE
  API_ALLOWED_HOSTS API_ALLOWED_ORIGINS INDICATORS_IGNORE 'SITE_*' 'SENSOR_*'
  NETWORK_ENABLED NETWORK_HUB_URL NETWORK_HUB_KEY NETWORK_VERIFY_REVEALS NETWORK_VERIFIER
)
# NETWORK_CONSENT is deliberately absent: only the installer and scripts/participant.sh join write it.

# Prints "ENV_VAR:default_host_port:protocols" lines for a sensor (the single port table).
sensor_ports() {
  case $1 in
    ssh) echo "SSH_HOST_PORT:22:tcp" ;;
    telnet) echo "TELNET_HOST_PORT:23:tcp" ;;
    web) echo "HTTP_HOST_PORT:80:tcp"; echo "HTTPS_HOST_PORT:443:tcp" ;;
    rdp) echo "RDP_HOST_PORT:3389:tcp" ;;
    redis) echo "REDIS_HOST_PORT:6379:tcp" ;;
    docker) echo "DOCKER_HOST_PORT:2375:tcp" ;;
    mysql) echo "MYSQL_HOST_PORT:3306:tcp" ;;
    adb) echo "ADB_HOST_PORT:5555:tcp" ;;
    mssql) echo "MSSQL_HOST_PORT:1433:tcp" ;;
    smb) echo "SMB_HOST_PORT:445:tcp" ;;
    sip) echo "SIP_HOST_PORT:5060:udp,tcp" ;;
    synology) echo "SYNOLOGY_HTTP_HOST_PORT:5000:tcp"; echo "SYNOLOGY_HTTPS_HOST_PORT:5001:tcp" ;;
    *) return 1 ;;
  esac
}

# True when $1 is a known sensor name.
is_sensor() {
  local s
  for s in "${SENSORS[@]}"; do [ "$s" = "$1" ] && return 0; done
  return 1
}

# Name of the SENSOR_<NAME> variable of a sensor.
sensor_var() { printf 'SENSOR_%s' "$(printf %s "$1" | tr '[:lower:]' '[:upper:]')"; }

# Reads NAME from ${ENV_FILE:-.env}: last assignment wins, quotes and blanks removed.
# Prints $2 (default empty) when missing or empty.
env_get() {
  local file=${ENV_FILE:-.env} val=""
  if [ -f "$file" ]; then
    val=$(sed -n "s/^$1=//p" "$file" | tail -n 1 | tr -d "\"' \r")
  fi
  printf '%s' "${val:-${2:-}}"
}

# True when NAME has an active (uncommented) assignment in FILE.
env_has() { grep -qE "^$2=" "$1" 2>/dev/null; }

# Sets NAME=VALUE in FILE without touching other lines. The first active assignment is
# replaced (further duplicates are dropped); otherwise the first commented "# NAME=" line is
# replaced; otherwise the line is appended. The value goes through the environment, never
# through awk's escape processing or argv.
env_set_line() {
  local file=$1 name=$2 value=$3 tmp
  tmp=$(mktemp "${file}.XXXXXX")
  NAME="$name" VALUE="$value" awk '
    BEGIN { name = ENVIRON["NAME"]; value = ENVIRON["VALUE"]; pre = name "="; cpre = "# " name "=" }
    { lines[NR] = $0 }
    END {
      target = 0
      for (i = 1; i <= NR; i++) if (index(lines[i], pre) == 1) { target = i; break }
      if (!target) for (i = 1; i <= NR; i++) if (index(lines[i], cpre) == 1) { target = i; break }
      seen = 0
      for (i = 1; i <= NR; i++) {
        if (i == target) { print pre value; seen = 1; continue }
        if (seen && index(lines[i], pre) == 1) continue
        print lines[i]
      }
      if (!target) print pre value
    }' "$file" > "$tmp"
  chmod --reference="$file" "$tmp" 2>/dev/null || chmod 600 "$tmp"
  mv "$tmp" "$file"
}

# Prints a random alphanumeric secret of LEN characters.
gen_secret() {
  ( set +o pipefail; LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1" )
}

# Prints a base64 key made of 32 random bytes (44 characters).
gen_key() {
  head -c 32 /dev/urandom | base64 -w0
}

# Prints a new value for a secret variable (SESSION_SECRET is longer).
gen_for() {
  case $1 in
    SESSION_SECRET) gen_secret 64 ;;
    SETTINGS_ENCRYPTION_KEY) gen_key ;;
    *) gen_secret 40 ;;
  esac
}

# Succeeds when KEY may be changed by `just set` (allow-list, minus secret-looking names).
# NETWORK_HUB_KEY is the hub's PUBLIC key (M29), the one name ending in _KEY that is not a secret.
settable_key() {
  local key=$1 pat
  [[ $key =~ ^[A-Z][A-Z0-9_]{0,63}$ ]] || return 1
  [ "$key" = NETWORK_HUB_KEY ] && return 0
  case $key in
    *PASSWORD* | *SECRET* | *TOKEN* | *_HASH | *_KEY | VPN_WG_*) return 1 ;;
  esac
  for pat in "${SETTABLE_VARS[@]}"; do
    # shellcheck disable=SC2254
    case $key in $pat) return 0 ;; esac
  done
  return 1
}

# Succeeds when VALUE is safe to write unquoted into .env.
settable_value() { [[ $1 =~ ^[A-Za-z0-9._,:/@+_-]{0,512}$ ]]; }

# Version comparison: succeeds when $1 >= $2 (dotted numbers).
ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" = "$2" ]; }

# Succeeds inside a linked git worktree (a scratch checkout: never act on a live stack there).
in_linked_worktree() {
  git rev-parse --git-dir > /dev/null 2>&1 || return 1
  [ "$(git rev-parse --absolute-git-dir)" != "$(git rev-parse --path-format=absolute --git-common-dir)" ]
}

# with_public_umask COMMAND [ARG...]: runs COMMAND under umask 022, whatever umask the caller has.
# update.sh, rollback.sh and install.sh keep a restrictive umask for what is private (the state
# file, .env), and scripts/auto-update.sh runs under umask 077 as a whole. What git writes into
# the checkout, and what `docker compose build` reads, must stay readable by the non-root users
# inside the containers: run those commands through this function.
with_public_umask() ( umask 022; "$@" )

# fix_tracked_modes_exempt PATH: succeeds for a path that fix_tracked_modes must never touch, even
# if it is somehow part of the committed tree: every .env* file (the example files excepted),
# hub/.env, hub/secrets and .suckerpot-state.
fix_tracked_modes_exempt() {
  case $1 in hub/.env | hub/secrets | hub/secrets/* | .suckerpot-state | .suckerpot-state/*) return 0 ;; esac
  case ${1##*/} in .env.example) return 1 ;; .env*) return 0 ;; esac
  return 1
}

# fix_tracked_modes: makes every file and folder of the COMMITTED tree (git ls-tree HEAD, not the
# index) readable by group and others again (go+rX: executables stay executable, nothing is ever
# removed). A checkout made under umask 077 leaves files 0600 and folders 0700, which the non-root
# user of a container cannot read (the migrate container fails with "Permission denied" on its
# migrations). The folders that hold such files are opened too (hub/ becomes 0755), so hub/.env is
# set to 0600 afterwards. Never touched: .env*, hub/.env, hub/secrets and .suckerpot-state (see
# fix_tracked_modes_exempt), symlinks, anything under a symlinked folder, and any path whose real
# path is not inside the repository. Never fatal.
fix_tracked_modes() {
  local f p top ok i
  local paths=() real=() keep=()
  top=$(git rev-parse --show-toplevel 2> /dev/null) && top=$(realpath -e -- "$top" 2> /dev/null) || {
    echo "warning: could not find the top of the checkout; file modes were not repaired" >&2
    return 0
  }
  while IFS= read -r -d '' f; do
    fix_tracked_modes_exempt "$f" && continue
    { [ -e "$f" ] && [ ! -L "$f" ]; } || continue
    ok=1
    p=$f
    while [[ $p == */* ]]; do
      p=${p%/*}
      if [ -L "$p" ]; then ok=0; break; fi
    done
    [ "$ok" = 1 ] || continue
    paths+=("$f")
    p=$f
    while [[ $p == */* ]]; do
      p=${p%/*}
      paths+=("$p")
    done
  done < <(git ls-tree -rz --name-only HEAD 2> /dev/null)
  if [ "${#paths[@]}" -gt 0 ]; then
    mapfile -d '' paths < <(printf '%s\0' "${paths[@]}" | sort -zu)
    # Every path (files and folders) must resolve to a place inside the checkout. -m keeps one
    # answer per path, so the two lists stay aligned.
    mapfile -d '' real < <(printf '%s\0' "${paths[@]}" | xargs -0 realpath -m -z -- 2> /dev/null)
    if [ "${#real[@]}" -ne "${#paths[@]}" ]; then
      echo "warning: could not resolve the tracked paths; file modes were not repaired" >&2
    else
      for i in "${!paths[@]}"; do
        case ${real[i]} in "$top" | "$top"/*) keep+=("${paths[i]}") ;; esac
      done
      if [ "${#keep[@]}" -gt 0 ]; then
        printf '%s\0' "${keep[@]}" | xargs -0 chmod go+rX -- 2> /dev/null \
          || echo "warning: could not make every tracked file readable (a file owned by another user?)" >&2
      fi
    fi
  fi
  # hub/ may have just been opened: its secrets file must stay private.
  if [ -f hub/.env ] && [ ! -L hub/.env ]; then chmod 600 hub/.env 2> /dev/null || true; fi
  return 0
}

# Succeeds for a name that is allowed as compose project or volume prefix.
valid_project_name() {
  [[ $1 =~ ^[a-z0-9][a-z0-9_-]{0,40}$ ]] || return 1
  # The end-to-end test (scripts/e2e/participant.sh) installs under an sp-it-* name. Only that
  # one switch allows it, and then ONLY sp-it-* names are allowed, never a live name.
  if [ "${SELFHOSTR_TEST_INSTALL:-}" = 1 ]; then
    [[ $1 =~ ^sp-it-participant-[a-z0-9]{6,20}$ ]]
    return
  fi
  case $1 in sp-it-* | sp-test | sp-ci) return 1 ;; esac
  return 0
}

# Stops (exit 1) unless .env names the compose project and the volume prefix, they are valid and
# not throwaway names, and this is not a linked git worktree. Mirrors the justfile _need-project.
need_project() {
  local p x
  p=$(env_get COMPOSE_PROJECT_NAME)
  x=$(env_get SUCKERPOT_VOLUME_PREFIX)
  if [ -z "$p" ] || [ -z "$x" ]; then
    echo "COMPOSE_PROJECT_NAME and SUCKERPOT_VOLUME_PREFIX must both be set in .env (live install only)." >&2
    exit 1
  fi
  if ! valid_project_name "$p" || ! valid_project_name "$x"; then
    echo "COMPOSE_PROJECT_NAME / SUCKERPOT_VOLUME_PREFIX are invalid or throwaway names." >&2
    exit 1
  fi
  if in_linked_worktree; then
    echo "Refusing to run from a linked git worktree. Use the main checkout." >&2
    exit 1
  fi
}

# Reads a string field written by update.sh from the state file (one field per line).
state_get() {
  sed -n "s/^  \"$2\": \"\\(.*\\)\",\\{0,1\\}\$/\\1/p" "$1" | head -n 1
}

# Unsets every variable that .env defines. `just` loads .env into the environment before a recipe
# runs, and the shell environment beats .env for docker compose and for check-ports.sh: after a
# script changed .env, the old values would still win. Call this once .env is final (and again
# after changing it); compose then reads the new file itself.
env_drop_loaded() {
  local file=${ENV_FILE:-.env} name
  [ -f "$file" ] || return 0
  while IFS= read -r name; do
    case $name in PATH | HOME | PWD | SHELL | USER | LANG | TERM | BASH_ENV | ENV | IFS | ENV_FILE) continue ;; esac
    unset "$name" 2> /dev/null || true
  done < <(sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' "$file")
}

# ----------------------------------------------------------------------- participant mode (M32)

# Reads NAME from config/network-defaults.env (the public defaults shipped with each release).
# Prints nothing when the file or the name is missing.
network_default() {
  [ -f config/network-defaults.env ] || return 0
  sed -n "s/^$1=//p" config/network-defaults.env | tail -n 1 | tr -d "\"' \r"
}

# Prints the host name of an https URL (no port, no path).
url_host() {
  local h=${1#https://}
  h=${h%%/*}
  printf '%s' "${h%%:*}"
}

# Prints the HUBPROXY_ALLOW value: the hub host, plus the feed host when $1 is 1. The hub and feed
# URLs come from .env when set there, else from the shipped defaults.
hubproxy_allow() {
  local hub feed out
  hub=$(env_get NETWORK_HUB_URL "$(network_default NETWORK_HUB_URL)")
  feed=$(env_get NETWORK_FEED_URL "$(network_default NETWORK_FEED_URL)")
  hub=$(url_host "$hub")
  [ -n "$hub" ] || return 1
  out="$hub:443"
  if [ "${1:-0}" = 1 ]; then
    feed=$(url_host "$feed")
    [ -n "$feed" ] || return 1
    out="$out,$feed:443"
  fi
  printf '%s' "$out"
}

# Reads a WireGuard .conf as plain text (nothing in it is ever executed) and sets the globals
# wg_private, wg_peer, wg_addr, wg_dns, wg_ep_ip and wg_ep_port. $2 is appended to the error text.
# Prints the reason on stderr and returns 1 when the file cannot be used. Never prints a value.
wg_parse_conf() {
  local file=$1 hint=${2:-} section="" line k v
  wg_private="" wg_peer="" wg_addr="" wg_dns="" wg_ep_ip="" wg_ep_port=""
  [ -f "$file" ] || { echo "WireGuard file not found: $file" >&2; return 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%%#*}
    line=${line//$'\r'/}
    case $line in
      *"["*"]"*) section=$(printf %s "$line" | tr -d '[] \t' | tr '[:upper:]' '[:lower:]'); continue ;;
    esac
    [[ $line == *=* ]] || continue
    k=$(printf %s "${line%%=*}" | tr -d ' \t' | tr '[:upper:]' '[:lower:]')
    v=$(printf %s "${line#*=}" | sed -e 's/^[ \t]*//' -e 's/[ \t]*$//')
    case $section:$k in
      interface:privatekey) wg_private=$v ;;
      interface:address) wg_addr=$(printf %s "$v" | tr -d ' ') ;;
      interface:dns) wg_dns=$(printf %s "$v" | tr -d ' ') ;;
      peer:publickey) wg_peer=$v ;;
      peer:endpoint)
        wg_ep_port=${v##*:}
        wg_ep_ip=${v%:*}
        ;;
    esac
  done < "$file"
  if [ -z "$wg_private" ] || [ -z "$wg_peer" ] || [ -z "$wg_addr" ] || [ -z "$wg_ep_ip" ] || [ -z "$wg_ep_port" ]; then
    echo "the WireGuard file lacks PrivateKey, Address, PublicKey or Endpoint.$hint" >&2
    return 1
  fi
  if ! [[ $wg_ep_ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    echo "the WireGuard Endpoint must be an IPv4 address, not a host name.$hint" >&2
    return 1
  fi
  if ! [[ $wg_ep_port =~ ^[0-9]{1,5}$ ]]; then
    echo "bad WireGuard Endpoint port" >&2
    return 1
  fi
  for v in "$wg_private" "$wg_peer" "$wg_addr" "$wg_dns"; do
    if ! [[ $v =~ ^[A-Za-z0-9+/=_.,:-]*$ ]]; then
      echo "the WireGuard file has unexpected characters.$hint" >&2
      return 1
    fi
  done
  return 0
}

# Prints the router-port table of the enabled sensors from ${ENV_FILE:-.env}:
# "router_port host_port protocol sensor" per line. The router port is the standard port of the
# service; the host port is where the container is published on this machine.
ports_table() {
  local s var def proto host
  for s in "${SENSORS[@]}"; do
    [ "$(env_get "$(sensor_var "$s")" 1)" = 0 ] && continue
    while IFS=: read -r var def proto; do
      host=$(env_get "$var" "$def")
      printf '%s %s %s %s\n' "$def" "$host" "$(printf %s "$proto" | tr 'a-z,' 'A-Z/')" "$s"
    done < <(sensor_ports "$s")
  done
}

# Removes every active assignment of NAME from FILE (comments and other lines stay).
env_del_line() {
  local file=$1 name=$2 tmp
  tmp=$(mktemp "${file}.XXXXXX")
  grep -v "^$name=" "$file" > "$tmp" || true
  chmod --reference="$file" "$tmp" 2> /dev/null || chmod 600 "$tmp"
  mv "$tmp" "$file"
}

# Version of the consent text, and what the participant agrees to share.
CONSENT_VERSION=v2
CONSENT_ITEMS=sources,payloads,c2,files,rechecks,verify_reveals
# Full mode (M33) agrees to the five required items; the early-reveal item stays a separate opt-in.
CONSENT_ITEMS_FULL=sources,payloads,c2,files,rechecks

# Prints the NETWORK_CONSENT record for today (UTC): version, consent list, day.
# $1 = the item list (default: the participant list).
consent_record() {
  printf '%s:%s:%s' "$CONSENT_VERSION" "${1:-$CONSENT_ITEMS}" "$(date -u +%Y-%m-%d)"
}

# Prints the consent screen. $1 = pseudonym (empty = none), $2 = 1 when a VPN is used.
# The installer and `participant.sh join` print the same text.
consent_screen() {
  local pseudonym=$1 vpn=${2:-0}
  echo "SuckerPot participant mode (experimental preview)"
  echo
  echo "This machine will run honeypot sensors and send what they see to a hub run by the"
  echo "SuckerPot maintainers. What is sent, once a day and a few hours late:"
  echo "  - source addresses seen by your sensors, with the services they used, what they did and"
  echo "    rounded counts;"
  echo "  - download links attackers tried, as hashes; the clear link goes to the hub only when two or"
  echo "    more sensors saw the same link, so a verifier can check it;"
  echo "  - malware hashes and command-and-control addresses (only with a VPN and the collector);"
  echo "  - takedown checks for addresses the network reported."
  echo "Never sent: passwords, commands, your ports, your own address or names in any payload."
  echo
  echo "What you get back today: nothing yet. The shared feed is an experimental preview and stays"
  echo "empty until enough independent nodes exist. Its thresholds and protocol may change."
  echo
  echo "The hub is reached through a Cloudflare tunnel, so Cloudflare and the hub both see the"
  echo "address the request comes from."
  if [ "$vpn" = 1 ]; then
    echo "All of it leaves through your VPN: they see the VPN's exit address, not this machine's."
    echo "Remove the VPN at any time: ./scripts/participant.sh vpn --remove"
  else
    echo "Without a VPN that address is this machine's own public address, so it is not hidden."
    echo "Add a VPN at any time: ./scripts/participant.sh vpn <file.conf>"
  fi
  echo "Updates: signed releases install themselves once a day (turn off: --no-auto-update). The"
  echo "update checks contact GitHub, ghcr.io and Sigstore from this machine's own address, even"
  echo "with a VPN. Without a VPN, the hub name is also looked up through your normal DNS resolver."
  echo "Leave at any time: ./scripts/participant.sh leave"
  echo
  if [ -n "$pseudonym" ]; then
    echo "Pseudonym: $pseudonym   (change: --pseudonym NAME, none: --no-pseudonym)"
  else
    echo "Pseudonym: none (the network shows an anonymous node number)"
  fi
  echo
}

# Prints the consent screen of a full install. $1 = pseudonym (empty = none).
# The question "Join the SuckerPot network?" follows it; the default is no.
consent_screen_full() {
  local pseudonym=$1
  echo "The SuckerPot network (experimental preview, off unless you join)"
  echo
  echo "You can send what your sensors see to a hub run by the SuckerPot maintainers. What would be"
  echo "sent, once a day and a few hours late:"
  echo "  - source addresses seen by your sensors, with the services they used, what they did and"
  echo "    rounded counts;"
  echo "  - download links attackers tried, as hashes; the clear link goes to the hub only when two or"
  echo "    more sensors saw the same link, so a verifier can check it;"
  echo "  - malware hashes and command-and-control addresses (only with the collector);"
  echo "  - takedown checks for addresses the network reported."
  echo "Never sent: passwords, commands, your ports, your own address or names in any payload."
  echo
  echo "What you get back today: nothing yet. The shared feed is an experimental preview and stays"
  echo "empty until enough independent nodes exist. Its thresholds and protocol may change."
  echo
  echo "The hub is reached through a Cloudflare tunnel, so Cloudflare and the hub both see the"
  echo "address the request comes from: your VPN exit address once a VPN is configured (Settings >"
  echo "VPN). With no VPN, nothing is sent at all, and nothing is sent until your own public"
  echo "address is confirmed."
  echo "Leave at any time in the dashboard (Network page), or switch it all off with"
  echo "just set NETWORK_ENABLED=false. A leave is final: an update or a restart never joins you again."
  echo
  if [ -n "$pseudonym" ]; then
    echo "Pseudonym: $pseudonym   (you can change it in the dashboard)"
  else
    echo "Pseudonym: none (the network shows an anonymous node number)"
  fi
  echo
}

# compose_up_recreating ARGS...: `docker compose up ARGS...`; when it fails because a Docker
# network must be recreated (Docker cannot change the name or options of an existing bridge, and
# a release may change both), it runs `docker compose down --remove-orphans` once and starts
# again. Never `-v`: volumes stay. If a container of ANOTHER project is attached to one of our
# networks, the down cannot remove it: that is reported with the way to disconnect it, and
# nothing is disconnected here. Returns the status of the last `up`, or 1 when it had to stop.
# Needs `set -o pipefail` (every caller has it).
compose_up_recreating() {
  local out rc=0 down_out net project nets conns c
  out=$(mktemp)
  docker compose up "$@" 2>&1 | tee "$out" || rc=$?
  if [ "$rc" = 0 ]; then
    rm -f "$out"
    return 0
  fi
  # Only compose's own words for "this network cannot be reused as it is". A line such as
  # "Network x Created" or an unhealthy container must not stop the stack.
  if ! grep -qiE 'needs to be recreated|has active endpoints|network .*(config|option).*(changed|differ)|declared as external, but could not be found|incorrect label|network .* is still in use|resource is still in use' "$out"; then
    rm -f "$out"
    return "$rc"
  fi
  rm -f "$out"
  echo "      a Docker network must be recreated (its name or options changed): stopping the stack and starting it again once (data volumes are kept)" >&2
  project=$(env_get COMPOSE_PROJECT_NAME)
  down_out=$(mktemp)
  if ! docker compose down --remove-orphans > "$down_out" 2>&1; then
    cat "$down_out" >&2
    rm -f "$down_out"
    nets=""
    if [ -n "$project" ]; then
      nets=$(docker network ls --filter "label=com.docker.compose.project=$project" --format '{{.Name}}' 2> /dev/null || true)
    fi
    for net in $nets; do
      conns=$(docker network inspect "$net" --format '{{range .Containers}}{{.Name}} {{end}}' 2> /dev/null || true)
      [ -z "${conns// /}" ] && continue
      echo "      network $net still has containers that are not part of this stack: $conns" >&2
      for c in $conns; do
        echo "      disconnect one with: docker network disconnect $net $c  (then run the update again)" >&2
      done
    done
    echo "      nothing was disconnected for you." >&2
    return 1
  fi
  rm -f "$down_out"
  docker compose up "$@"
}
