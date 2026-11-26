#!/usr/bin/env bash
# Shared helpers for the SuckerPot host scripts (install.sh, env-set.sh, env-migrate.sh,
# update.sh, rollback.sh). Source this file; it defines functions and constants only and runs
# no command (scripts/lib/engine.sh reads SUCKERPOT_ENGINE from .env). It never prints a secret value.

# shellcheck source=scripts/lib/engine.sh
. "$(dirname "${BASH_SOURCE[0]}")/engine.sh" || return 1

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
MIGRATE_DEFAULTS=(SUCKERPOT_ENGINE=docker SUCKERPOT_INSTALL_MODE=source SUCKERPOT_STACK_MODE=full AUTO_UPDATE_ENABLED=false)

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

# env_drop_lines FILE REGEX: removes every active line whose name matches the extended regex
# REGEX (an exact variable name or a prefix pattern, matched against the text before the "=").
# Other lines are kept as they are, in order. Prints the removed NAMES (never a value), one per
# line. Nothing is written when no line matches.
env_drop_lines() {
  local file=$1 pattern=$2 tmp names
  names=$(sed -nE "s/^(${pattern})=.*/\\1/p" "$file")
  [ -n "$names" ] || return 0
  tmp=$(mktemp "${file}.XXXXXX")
  grep -vE "^(${pattern})=" "$file" > "$tmp" || true
  chmod --reference="$file" "$tmp" 2>/dev/null || chmod 600 "$tmp"
  mv "$tmp" "$file"
  printf '%s\n' "$names"
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
# ----------------------------------------------------------------------- node bundle (no git)
# A node installed with scripts/get.sh has no git checkout: it holds the files of a node bundle
# (config/node-bundle.list) and .suckerpot-bundle, which says what they are:
#   version=vX.Y.Z  ref=vX.Y.Z|<branch>  commit=<sha>  signed=1|0  latest=vX.Y.Z (newest release
#   known when the bundle was fetched)
# A git checkout keeps working as before; these helpers tell the two layouts apart.
BUNDLE_FILE=.suckerpot-bundle
SUCKERPOT_REPO_URL=${SUCKERPOT_REPO_URL:-https://github.com/selfhostr/suckerpot}
layout_bundle() { [ -f "$BUNDLE_FILE" ] && [ ! -e .git ]; }
bundle_get() { sed -n "s/^$1=//p" "$BUNDLE_FILE" 2> /dev/null | tail -n 1 | tr -cd 'A-Za-z0-9._/-'; }

# bundle_unpack FILE: unpacks a node bundle over this folder, after checking that it holds only
# plain files and folders, every path inside. The caller has verified FILE first.
bundle_unpack() {
  local f=$1
  tar -tvzf "$f" 2> /dev/null | awk '{ t = substr($1, 1, 1); if (t != "-" && t != "d") bad = 1 } END { exit bad }' \
    || { echo "the bundle holds links or special files" >&2; return 1; }
  if tar -tzf "$f" 2> /dev/null | grep -Eq '(^/|(^|/)\.\.(/|$))'; then echo "the bundle has a path outside its folder" >&2; return 1; fi
  ( umask 022 && tar -xzf "$f" -C . )
}

# bundle_save OUT: the files of this bundle install as they are now (config/node-bundle.list and
# .suckerpot-bundle), for a rollback.
bundle_save() {
  local out=$1 line f
  local -a files=()
  shopt -s nullglob
  if [ -f config/node-bundle.list ]; then
    while IFS= read -r line; do
      case $line in "" | \#*) continue ;; esac
      # shellcheck disable=SC2206 # a glob on purpose
      for f in $line; do [ -f "$f" ] && files+=("./$f"); done
    done < config/node-bundle.list
  fi
  shopt -u nullglob
  tar -czf "$out" "./$BUNDLE_FILE" ${files[@]+"${files[@]}"}
}

# latest_known_release: the newest release this install knows. A checkout: its tags. A bundle:
# the release named when its bundle was fetched, or later by latest_release_refresh.
latest_known_release() {
  local t c=.suckerpot-state/latest-release
  if ! layout_bundle; then
    git tag -l 'v*.*.*' --sort=-v:refname 2> /dev/null | grep -E '^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -n 1 || true
    return 0
  fi
  t=$(head -n 1 "$c" 2> /dev/null | tr -cd 'v0-9.')
  [ -n "$t" ] || t=$(bundle_get latest)
  [[ $t =~ ^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && printf '%s\n' "$t"
  return 0
}

# latest_release_fetch: the newest published release, asked of GitHub (the "latest" redirect: one
# HTTPS request from this machine's own address, as the update checks). Prints vX.Y.Z or fails.
latest_release_fetch() {
  local u
  u=$(curl -fsSLI --proto '=https' --tlsv1.2 --max-time 15 -o /dev/null -w '%{url_effective}' "$SUCKERPOT_REPO_URL/releases/latest" 2> /dev/null) || return 1
  u=${u##*/}
  [[ $u =~ ^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  printf '%s\n' "$u"
}

# latest_release_refresh [MAX_AGE_H]: a bundle install asks GitHub again when its note is older
# than MAX_AGE_H hours (default 6), and keeps the answer in .suckerpot-state/latest-release.
latest_release_refresh() {
  local c=.suckerpot-state/latest-release age=${1:-6} t
  layout_bundle || return 0
  if [ -f "$c" ] && [ -n "$(find "$c" -mmin "-$((age * 60))" 2> /dev/null)" ]; then return 0; fi
  t=$(latest_release_fetch) || return 0
  mkdir -p .suckerpot-state && printf '%s\n' "$t" > "$c"
}

# update_unfinished: the target of an update that was cut off ("completed": false in the state
# file), or "unknown" when the file names none; nothing when the last update finished.
update_unfinished() {
  local f=.suckerpot-state/last-update.json t
  [ -f "$f" ] && grep -q '"completed": false' "$f" || return 0
  t=$(sed -n 's/.*"target": "\(v[0-9.]*\)".*/\1/p' "$f" | head -n 1)
  printf '%s' "${t:-unknown}"
}

# update_mark_finished: the stack runs the version .env names, so a cut-off update is over (its
# state file says "completed": true, as a finished update leaves it). Used by install.sh --repair.
update_mark_finished() {
  local f=.suckerpot-state/last-update.json tmp
  [ -f "$f" ] && grep -q '"completed": false' "$f" || return 0
  tmp=$(mktemp "$f.XXXXXX") || return 0
  sed 's/"completed": false,/"completed": true,/' "$f" > "$tmp" && chmod 600 "$tmp" && mv "$tmp" "$f" || rm -f "$tmp"
}

# running_version: the version the ingest container reports (SUCKERPOT_RUNNING_VERSION), or nothing.
running_version() {
  local v
  v=$(dc exec -T ingest printenv SUCKERPOT_RUNNING_VERSION 2> /dev/null | tr -d '\r' | head -n 1 || true)
  [[ $v =~ ^[A-Za-z0-9._+-]{1,64}$ ]] && printf '%s' "$v"
  return 0
}

# ----------------------------------------------------------------------- the update lock
# update.sh, rollback.sh and auto-update.sh take .suckerpot-state/update.lock (flock); the one that
# holds it writes who it is next to it, so another one can say who it waits for.
lock_note() {
  printf 'pid=%s what=%s since=%s\n' "$$" "$1" "$(date +%s)" > .suckerpot-state/update.lock.info 2> /dev/null || true
}

# lock_holder: who holds the update lock, in words ("" when nothing tells).
lock_holder() {
  local f=.suckerpot-state/update.lock.info pid what since
  [ -f "$f" ] || return 0
  pid=$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' "$f")
  what=$(sed -n 's/.*what=\([a-z-]*\).*/\1/p' "$f")
  since=$(sed -n 's/.*since=\([0-9]*\).*/\1/p' "$f")
  [ -n "$pid" ] && kill -0 "$pid" 2> /dev/null || return 0
  printf '%s (pid %s, for %s min)' "${what:-an update}" "$pid" "$(( ($(date +%s) - ${since:-$(date +%s)}) / 60 ))"
}

# lock_sleeper: the pid of an automatic update of an older release that holds the lock while it
# only sleeps (its random wait); empty otherwise.
lock_sleeper() {
  local pid
  for pid in $(pgrep -u "$(id -u)" -f 'scripts/auto-update.sh' 2> /dev/null || true); do
    [ "$pid" != "$$" ] || continue
    if pgrep -P "$pid" -x sleep > /dev/null 2>&1; then printf '%s' "$pid"; return 0; fi
  done
  return 0
}

# lock_take FD WHAT: takes the update lock on FD, or says who holds it and fails. An older
# automatic update that only sleeps is offered to be stopped (on a terminal), then the lock taken.
lock_take() {
  local fd=$1 what=$2 who pid a=""
  if flock -n "$fd"; then lock_note "$what"; return 0; fi
  who=$(lock_holder)
  pid=$(lock_sleeper)
  if [ -n "$pid" ] && [ -z "$who" ]; then
    echo "An automatic update of an older release (pid $pid) holds the update lock while it only waits (its random delay before checking)." >&2
    if [ -r /dev/tty ] && (: < /dev/tty) 2> /dev/null; then
      printf 'Stop that wait and update now? [Y/n] ' > /dev/tty
      IFS= read -r a < /dev/tty || a=n
    fi
    case $a in
      "" | y | Y | yes)
        pkill -P "$pid" -x sleep 2> /dev/null || true
        kill "$pid" 2> /dev/null || true
        if flock -w 15 "$fd"; then lock_note "$what"; return 0; fi
        ;;
    esac
    echo "The update lock is still held: try again in a few minutes." >&2
    return 1
  fi
  if [ -n "$who" ]; then
    echo "another update or rollback is running: $who. Wait for it to end (the automatic one writes .suckerpot-state/auto-update.log)." >&2
  else
    echo "another update or rollback is running (lock .suckerpot-state/update.lock)." >&2
  fi
  return 1
}

# ----------------------------------------------------------------------- root and sudo
# The host scripts run as the user who starts them and ask for root only for the steps that need
# it (Docker's setup, the host firewall, the Podman units), through as_root:
#   - as root (a root login, or started with sudo): every step runs as it is, sudo is never
#     called and no password is ever asked. Started with sudo by the user who owns the checkout,
#     SUCKERPOT_OWNER is that user: the files the scripts write here (.env, install.log,
#     .suckerpot-state) are given back to them (owner_fix), the update schedule goes into their
#     crontab and the Docker setup adds them to the docker group.
#   - as another user: sudo, only for those steps. root_ready says once, before the first one,
#     that sudo will ask for a password, and only when it will (sudo -n true fails). With
#     passwordless sudo (NOPASSWD) nothing is asked. The scripts never read a password themselves.
#   - neither root nor sudo: root_ready says so and the step is skipped or stops with the command.
# SELFHOSTR_EUID stands in for the user id in the tests.

is_root() { [ "${SELFHOSTR_EUID:-$(id -u)}" = 0 ]; }
# root_free: root rights without any prompt (root, or passwordless sudo).
root_free() { is_root || { command -v sudo > /dev/null 2>&1 && sudo -n true > /dev/null 2>&1; }; }

# owner_init: as root started with sudo by the owner of this folder, SUCKERPOT_OWNER=that user.
owner_init() {
  local u=${SUDO_USER:-} owner
  SUCKERPOT_OWNER=${SUCKERPOT_OWNER:-}
  is_root && [ -n "$u" ] && [ "$u" != root ] || return 0
  [[ $u =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || return 0
  owner=$(stat -c %U . 2> /dev/null || true)
  # The tests, which cannot be root, name the owner of the folder (only with SELFHOSTR_EUID).
  [ -z "${SELFHOSTR_EUID:-}" ] || owner=${SELFHOSTR_DIR_OWNER:-$owner}
  [ "$owner" = "$u" ] || return 0
  SUCKERPOT_OWNER=$u
  export SUCKERPOT_OWNER
}

# owner_fix: gives the files written here back to SUCKERPOT_OWNER (nothing to do otherwise).
owner_fix() {
  [ -n "${SUCKERPOT_OWNER:-}" ] && is_root || return 0
  local f
  for f in .env .env.* install.log .suckerpot-state .suckerpot-bundle; do
    [ -e "$f" ] || continue
    chown -R "$SUCKERPOT_OWNER:" -- "$f" 2> /dev/null || true
  done
  return 0
}

# root_ready REASON: before a step that needs root. Returns 0 when root rights are there (root,
# passwordless sudo, or sudo that may ask on the terminal: it says so once, here), 1 when sudo
# would ask and there is no terminal to ask on, 3 without sudo. Prints why on stderr for 1 and 3.
ROOT_ASKED=0
root_ready() {
  is_root && return 0
  if ! command -v sudo > /dev/null 2>&1; then
    echo "${1:-this step} needs root rights, and sudo is not installed: run it as root" >&2
    return 3
  fi
  sudo -n true > /dev/null 2>&1 && return 0
  if [ -n "${ROOT_NO_TTY:-}" ] || ! { [ -r /dev/tty ] && (: < /dev/tty) 2> /dev/null; }; then
    echo "${1:-this step} needs sudo, which asks for a password, and there is no terminal to ask on" >&2
    return 1
  fi
  # Once: say why, and let sudo itself ask on the terminal (the scripts never read a password).
  # Later steps, also those that run in the background, use what sudo remembers.
  if [ "$ROOT_ASKED" = 0 ]; then
    echo "  ${1:-this step} needs root rights: sudo asks for your password." > /dev/tty
    ROOT_ASKED=1
  fi
  # shellcheck disable=SC2024 # the terminal, on purpose
  sudo -v < /dev/tty > /dev/tty 2>&1 || { echo "sudo did not give root rights" >&2; return 1; }
  return 0
}

# as_root CMD...: CMD as root: as it is for root, else through sudo (which may ask on the terminal
# when root_ready said so; with passwordless sudo it never does).
as_root() {
  if is_root; then "$@"; else sudo -- "$@"; fi
}

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
  # A node bundle is unpacked readable (umask 022, scripts/get.sh); it has no git tree to walk.
  if layout_bundle; then return 0; fi
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

# Prints the consent screen. $1 = pseudonym (empty = none), $2 = 1 when a VPN is used, $3 = ask
# when the node name and the country are asked right after it (the installer on a terminal).
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
  echo "Updates: checked every 6 h, a signed release installs once 48 h old (off: --no-auto-update). The"
  echo "update checks contact GitHub, ghcr.io and Sigstore from this machine's own address, even"
  echo "with a VPN. Without a VPN, the hub name is also looked up through your normal DNS resolver."
  echo "Leave at any time: ./scripts/participant.sh leave"
  echo
  if [ "${3:-}" = ask ]; then
    echo "Node name and country: you choose them after this screen."
  elif [ -n "$pseudonym" ]; then
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

# compose_up_recreating ARGS...: `dc up ARGS...`; when it fails because a Docker
# network must be recreated (Docker cannot change the name or options of an existing bridge, and
# a release may change both), it runs `dc down --remove-orphans` once and starts
# again. Never `-v`: volumes stay. If a container of ANOTHER project is attached to one of our
# networks, the down cannot remove it: that is reported with the way to disconnect it, and
# nothing is disconnected here. Returns the status of the last `up`, or 1 when it had to stop.
# Needs `set -o pipefail` (every caller has it).
compose_up_recreating() {
  local out rc=0 down_out net project nets conns c
  # Podman: the networks are external, made by scripts/ensure-networks.sh, so compose never needs
  # to recreate one. A network in use that must change (exit 3) stops the stack once first.
  if [ "${ENGINE_ID:-docker}" = podman ]; then
    engine_prepare_networks || rc=$?
    if [ "$rc" = 3 ]; then
      echo "      a network must be recreated (its options changed): stopping the stack and starting it again once (data volumes are kept)" >&2
      dc down --remove-orphans || return 1
      rc=0
      engine_prepare_networks || rc=$?
    fi
    [ "$rc" = 0 ] || return "$rc"
    engine_stack_up "$@"
    return
  fi
  out=$(mktemp)
  dc up "$@" 2>&1 | tee "$out" || rc=$?
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
  if ! dc down --remove-orphans > "$down_out" 2>&1; then
    cat "$down_out" >&2
    rm -f "$down_out"
    nets=""
    if [ -n "$project" ]; then
      nets=$(ctr network ls --filter "label=com.docker.compose.project=$project" --format '{{.Name}}' 2> /dev/null || true)
    fi
    for net in $nets; do
      conns=$(ctr network inspect "$net" --format '{{range .Containers}}{{.Name}} {{end}}' 2> /dev/null || true)
      [ -z "${conns// /}" ] && continue
      echo "      network $net still has containers that are not part of this stack: $conns" >&2
      for c in $conns; do
        echo "      disconnect one with: ${ENGINE_CTR[*]} network disconnect $net $c  (then run the update again)" >&2
      done
    done
    echo "      nothing was disconnected for you." >&2
    return 1
  fi
  rm -f "$down_out"
  dc up "$@"
}
