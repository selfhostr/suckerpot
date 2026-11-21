#!/usr/bin/env bash
# SuckerPot installer. Run it from a checkout of a release tag:
#
#   git clone <repository-url> suckerpot && cd suckerpot
#   git switch --detach "$(git describe --tags --abbrev=0)"   # the latest release
#   ./scripts/install.sh
#
# It checks the machine, asks a few questions, generates every secret on this host, writes .env
# (mode 0600), creates the data volumes and starts the stack. See docs/dev/design/m28.md section 2.
#
# It never overwrites an existing .env, never adopts existing data volumes, never edits the
# host's sshd configuration and never looks up this machine's public address (that request would
# leave from the home address). Host traffic (git, image pulls) is outside the anonymous egress
# of the stack and uses this host's own address.
#
#   scripts/install.sh [--yes] [--source | --images] [--version vX.Y.Z]
#                      [--project NAME] [--prefix NAME]
#                      [--sensors recommended|all|ssh,telnet,...]
#                      [--dashboard-bind 127.0.0.1] [--dashboard-port 8443]
#                      [--public-host HOST]  (dashboard behind an HTTPS tunnel: sets the host
#                                             and origin allow-lists and COOKIE_SECURE=true)
#                      [--admin-user admin] [--admin-password-stdin]
#                      [--admin-ssh-port N] [--lowmem auto|on|off] [--wg-conf PATH] [--skip-verify]
#                      [--allow-lan]  (publish the dashboard on a non-loopback address WITHOUT an
#                                      https tunnel: plain http, cookies lose Secure; not for the internet)
#                      [--join-network]  (join the experimental SuckerPot network; without it the answer is no)
#                      [--no-network]  (do not ask about the SuckerPot network)
#                      [--dry-run --env-out PATH]
#                      [--plain]  (one line per step, as without a terminal)
#
#   Participant mode (docs/dev/design/m32.md): sensors, database, ingest and the network node, no
#   dashboard, no admin account, no VPN needed (the hub is reached through hubproxy):
#   scripts/install.sh --participant [--yes] [--pseudonym NAME | --no-pseudonym]
#                      [--country CC [--show-country]] [--wg-conf PATH [--verifier]]
#                      [--no-auto-update] [--feeds] [--self-address ADDR] [--sensors LIST]
#                      [--lite]  (1 GiB VPS or Raspberry Pi: lowest memory limits, sensors
#                                 ssh,telnet,web,redis unless --sensors is given; docs/vps.md)
#   scripts/install.sh --full         on a participant install: switch to full mode (keeps data)
#   scripts/install.sh --repair       existing install: volumes, start and schedule steps again
#
# --yes takes the defaults; it reads the admin password from stdin with --admin-password-stdin
# or generates one and prints it once. --yes never joins the SuckerPot network in full mode: that
# needs --join-network (or a typed y at the question). With --participant, running the mode is the
# consent to join.
# --dry-run --env-out writes the would-be .env to PATH with a placeholder admin hash and makes
# no Docker call (used by the tests).
# On a terminal the installer shows a step list with a progress bar and writes the output of every
# command to install.log. Without a terminal, with TERM=dumb or with --plain, it prints one line per
# step and the command output, as it always did. NO_COLOR keeps the display without colours.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

TOTAL=10
LOG=install.log

# shellcheck source=scripts/lib/ui.sh
. scripts/lib/ui.sh
UI_PREFIX=install

# Plain mode (no terminal, TERM=dumb, --plain) prints exactly what the installer always printed.
# On a terminal, scripts/lib/ui.sh shows a step list with a progress bar instead, and the output
# of every command goes to install.log (docs/dev/design/installer-ux.md).
die() {
  if [ -n "$UI_LOG" ]; then UI_FAIL_LOGLINE="$(date -u +%Y-%m-%dT%H:%M:%SZ) FAILED: $*"; else log "FAILED: $*"; fi
  # Once this run has written .env, a new run only says "already installed": --repair goes on.
  local fix=""
  [ "${env_written:-0}" = 0 ] || fix="when the cause is fixed: ./scripts/install.sh --repair"
  ui_fail "$*" "$fix"
}
log() { [ "$dry_run" = 1 ] || printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"; }
# STEP_ROW maps the ten numbered steps onto the shorter list of the rich display ("" = no change).
declare -A STEP_ROW=()
step() {
  if [ "$UI_MODE" = plain ]; then printf '[%s/%s] %s\n' "$1" "$TOTAL" "$2"; fi
  log "step $1: $2"
  if [ -n "${STEP_ROW[$1]:-}" ]; then ui_begin "${STEP_ROW[$1]}"; fi
}
# note: a line under the step (plain), the short result of the step (rich).
note() {
  if [ "$UI_MODE" = plain ]; then echo "      $*"; else echo "      $*"; ui_detail "$*"; fi
}
warn() {
  if [ "$UI_MODE" = plain ]; then echo "      warning: $*" >&2; else echo "      warning: $*"; ui_warn "$*"; fi
}
# say: text for the person at the terminal (stdout in plain mode, the display in rich mode).
say() { echo "$@" 1>&"$UI_OUT"; }
# quiet CMD...: CMD with its stdout dropped (its errors still reach the log).
quiet() { "$@" > /dev/null; }
# answered: after an answer read on fd 3. A typed answer ends its line on the terminal; an answer
# from a file does not, so the rich display ends it (the list must not draw over the question).
answered() { [ "$UI_MODE" = plain ] || [ -t 3 ] || echo 1>&"$UI_ERR"; }

# ---------------------------------------------------------------- arguments
assume_yes=0
mode=""
version=""
project=""
prefix=""
sensors_arg=""
bind=""
dport=""
public_host=""
admin_user=""
pw_stdin=0
admin_ssh_port=""
lowmem=""
skip_verify=0
allow_lan=0
wg_conf=""
dry_run=0
env_out=""
stack=""
pseudonym_arg=""
no_pseudonym=0
no_network=0
join_flag=0
country=""
show_country=0
verifier=0
no_auto_update=0
feeds=0
self_address=""
repair=0
lite=0
plain=0
need_value() { [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"; }
while [ $# -gt 0 ]; do
  case $1 in
    --yes | -y) assume_yes=1 ;;
    --source) mode=source ;;
    --images) mode=images ;;
    --version) need_value "$@"; version=$2; shift ;;
    --project) need_value "$@"; project=$2; shift ;;
    --prefix) need_value "$@"; prefix=$2; shift ;;
    --sensors) need_value "$@"; sensors_arg=$2; shift ;;
    --dashboard-bind) need_value "$@"; bind=$2; shift ;;
    --dashboard-port) need_value "$@"; dport=$2; shift ;;
    --public-host) need_value "$@"; public_host=$2; shift ;;
    --admin-user) need_value "$@"; admin_user=$2; shift ;;
    --admin-password-stdin) pw_stdin=1 ;;
    --admin-ssh-port) need_value "$@"; admin_ssh_port=$2; shift ;;
    --lowmem) need_value "$@"; lowmem=$2; shift ;;
    --wg-conf) need_value "$@"; wg_conf=$2; shift ;;
    --skip-verify) skip_verify=1 ;;
    --allow-lan) allow_lan=1 ;;
    --dry-run) dry_run=1 ;;
    --env-out) need_value "$@"; env_out=$2; shift ;;
    --participant) [ "$stack" != full ] || die "--participant and --full exclude each other"; stack=participant ;;
    --full) [ "$stack" != participant ] || die "--participant and --full exclude each other"; stack=full ;;
    --pseudonym) need_value "$@"; pseudonym_arg=$2; shift ;;
    --no-pseudonym) no_pseudonym=1 ;;
    --no-network) no_network=1 ;;
    --join-network) join_flag=1 ;;
    --country) need_value "$@"; country=$2; shift ;;
    --show-country) show_country=1 ;;
    --verifier) verifier=1 ;;
    --no-auto-update) no_auto_update=1 ;;
    --feeds) feeds=1 ;;
    --self-address) need_value "$@"; self_address=$2; shift ;;
    --repair) repair=1 ;;
    --lite) lite=1 ;;
    --plain) plain=1 ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done


if [ "$dry_run" = 1 ] && [ -z "$env_out" ]; then die "--dry-run needs --env-out PATH"; fi
if [ "$dry_run" = 0 ] && [ -n "$env_out" ]; then die "--env-out is only for --dry-run"; fi

# The display. The dry run writes no log, as before.
if [ "$dry_run" = 1 ]; then ui_init "" "$plain"; else ui_init "$LOG" "$plain"; fi
if [ "$UI_MODE" = rich ]; then
  case $stack in participant) ui_ctx="participant node" ;; full) ui_ctx="full install" ;; *) ui_ctx="installer" ;; esac
  [ "$repair" = 0 ] || ui_ctx="$ui_ctx · repair"
  [ "$dry_run" = 0 ] || ui_ctx="$ui_ctx · dry run"
  [ "$UI_UTF8" = 1 ] || ui_ctx=${ui_ctx// · / - }
  ui_header "$ui_ctx"
fi
log "install.sh started ($UI_MODE display)"
case ${lowmem:-auto} in auto | on | off) ;; *) die "--lowmem must be auto, on or off" ;; esac
lowmem=${lowmem:-auto}
# Applies what --lite implies for --lowmem. Also called when the installer switches to lite itself.
lite_lowmem() {
  case $lowmem in auto | on) lowmem=on ;; *) die "--lite needs the low-memory overlay: it cannot be combined with --lowmem off" ;; esac
}
if [ "$lite" = 1 ]; then lite_lowmem; fi

# A machine sold as "2 GB" reports clearly less than 2 GiB to the kernel (a real one: MemTotal
# 2009976 kB), so the 2 GiB bar is 1.75 GiB. The low-memory setup runs there, with swap.
full_min_kb=$((2 * 1024 * 1024 - 262144))
# A "1 GiB" machine reports a little less than 1 GiB to the kernel.
lite_min_kb=$((1024 * 1024 - 131072))

# gib KB: memory in GiB with one decimal.
gib() { awk -v k="$1" 'BEGIN {printf "%.1f", k / 1048576}'; }

# swap_check "what the machine is": warns when there is little swap, then asks (not with --yes).
# Containers never swap (memswap_limit equals mem_limit). Host swap only gives the host room
# when a burst of attacks pushes the whole machine, so the global OOM killer is less likely
# to restart the database.
swap_check() {
  swap_kb=$(awk '/^SwapTotal:/ {print $2}' "$meminfo" 2> /dev/null || true)
  [[ ${swap_kb:-} =~ ^[0-9]+$ ]] || swap_kb=0
  if [ "$swap_kb" -lt $((512 * 1024)) ]; then
    warn "this machine has less than 512 MiB of swap. On $1, a burst of attacks can make the kernel kill a container (the database included). Add 1 GiB of swap first (docs/vps.md)."
    if [ "$assume_yes" = 0 ]; then
      ask_always a "Continue without enough swap? (yes/no)" no
      case $a in y | yes) ;; *) die "add swap, then run the installer again" ;; esac
    fi
  fi
}

# Interactive answers come from the terminal (or SELFHOSTR_TTY, used by the tests), so that
# stdin stays free for --admin-password-stdin.
if [ "$assume_yes" = 0 ]; then
  tty=${SELFHOSTR_TTY:-/dev/tty}
  [ -r "$tty" ] || die "no terminal to ask questions on; use --yes"
  exec 3< "$tty"
fi

# noask is 1 when no question may be asked: --yes, or participant mode (its only prompt is the
# consent screen). Questions then take their default.
noask=$assume_yes

# ask VAR "question" "default": sets VAR to the answer (the default with --yes or on Enter).
ask() {
  local __var=$1 __q=$2 __d=$3 __ans=""
  if [ "$noask" = 1 ]; then
    printf -v "$__var" %s "$__d"
    return 0
  fi
  ui_pause
  printf '  %s [%s]: ' "$__q" "$__d" 1>&"$UI_ERR"
  IFS= read -r __ans <&3 || __ans=""
  answered
  printf -v "$__var" %s "${__ans:-$__d}"
}

# ask_always: like ask, but participant mode does not skip the question. Only --yes does.
ask_always() {
  local __keep=$noask
  noask=$assume_yes
  ask "$@"
  noask=$__keep
}

# ---------------------------------------------------------------- 1. preflight
step 1 "Checking this machine"

[ "${BASH_VERSINFO[0]}" -ge 4 ] || die "Bash 4 or newer is required"
[ "$(uname -s)" = Linux ] || die "Linux is required"
case $(uname -m) in x86_64 | aarch64) ;; *) die "unsupported CPU architecture $(uname -m) (x86_64 or aarch64)" ;; esac
if in_linked_worktree; then
  die "this is a linked git worktree, a scratch checkout. Install from a normal clone."
fi

target=${env_out:-.env}
existing=0
switching=0
if [ -e .env ]; then
  [ "$dry_run" = 0 ] || die "SuckerPot is already installed here (.env exists). The dry run needs a checkout without .env."
  existing=1
  cur_stack=$(env_get SUCKERPOT_STACK_MODE full)
  case $cur_stack in full | participant) ;; *) die "SUCKERPOT_STACK_MODE in .env must be full or participant" ;; esac
  if [ "$repair" = 1 ]; then
    [ -z "$stack" ] || [ "$stack" = "$cur_stack" ] \
      || die "--repair keeps the mode of the install ($cur_stack); use --full to switch a participant install"
    stack=$cur_stack
  elif [ -z "$stack" ] || [ "$stack" = "$cur_stack" ]; then
    say "SuckerPot is already installed here in $cur_stack mode (.env exists). Nothing was changed."
    say "Update: just update. Start the steps again without changing settings: ./scripts/install.sh --repair"
    if [ -f scripts/status.sh ]; then bash scripts/status.sh 1>&"$UI_OUT" 2>&"$UI_ERR" || true; fi
    exit 0
  elif [ "$cur_stack" = participant ] && [ "$stack" = full ]; then
    case ":$(env_get COMPOSE_FILE docker-compose.yml):" in
      *:docker-compose.lite.yml:*) die "a lite node cannot switch to full mode: its memory limits and database settings are too small for the dashboard. Reinstall without --lite." ;;
    esac
    switching=1
  else
    die "switching a full install to participant mode would remove the dashboard; not supported"
  fi
else
  [ "$repair" = 0 ] || die "--repair needs an existing install (no .env here)"
fi
stack=${stack:-full}
fresh=$((1 - existing))
# The container engine. An existing install keeps the one in its .env (none there means Docker).
# A fresh install takes SUCKERPOT_ENGINE from the environment, else the engine this host has.
if [ "$fresh" = 1 ] && [ "$ENGINE_FROM" = default ]; then engine_use "$(engine_detect)"; fi
engine_ready || die "$ENGINE_UNREADY_MSG"

# The rich display: a fixed list of steps (weights for the bar), and where the numbered steps go.
if [ "$stack" = participant ]; then
  ui_plan "check|Check this machine|4" "settings|Settings and secrets|8" "volumes|Data volumes and checks|4" \
    "images|Verify and download images|35" "start|Start SuckerPot|30" "updates|Automatic updates|2" \
    "firewall|Host firewall|5" "reach|Sensor reachability|12"
else
  ui_plan "check|Check this machine|4" "settings|Settings and secrets|8" "admin|Admin account|12" \
    "volumes|Data volumes and checks|4" "images|Verify and download images|35" "start|Start SuckerPot|30" \
    "dashboard|Dashboard answers|7"
fi
STEP_ROW=([1]=check [2]=settings [3]=settings [4]=settings [5]=settings [7]=volumes [8]=volumes)
if [ "$stack" = full ]; then STEP_ROW[5]="admin"; fi
ui_begin check
# dash is 1 when the dashboard questions apply: a fresh full install, or the switch to full mode.
dash=0
if [ "$stack" = full ] && [ "$repair" = 0 ]; then dash=1; fi

# Flags that belong to one mode only.
if [ "$stack" = participant ]; then
  bad=()
  [ -z "$bind" ] || bad+=(--dashboard-bind)
  [ -z "$dport" ] || bad+=(--dashboard-port)
  [ -z "$public_host" ] || bad+=(--public-host)
  [ -z "$admin_user" ] || bad+=(--admin-user)
  [ "$pw_stdin" = 0 ] || bad+=(--admin-password-stdin)
  [ "$allow_lan" = 0 ] || bad+=(--allow-lan)
  [ "$no_network" = 0 ] || bad+=(--no-network)
  [ "$join_flag" = 0 ] || bad+=(--join-network)
  [ "${#bad[@]}" -eq 0 ] || die "these flags need --full: ${bad[*]}"
  noask=1
else
  bad=()
  [ -z "$pseudonym_arg" ] || bad+=(--pseudonym)
  [ "$no_pseudonym" = 0 ] || bad+=(--no-pseudonym)
  [ -z "$country" ] || bad+=(--country)
  [ "$show_country" = 0 ] || bad+=(--show-country)
  [ "$verifier" = 0 ] || bad+=(--verifier)
  [ "$no_auto_update" = 0 ] || bad+=(--no-auto-update)
  [ "$feeds" = 0 ] || bad+=(--feeds)
  [ -z "$self_address" ] || bad+=(--self-address)
  [ "$lite" = 0 ] || bad+=(--lite)
  [ "${#bad[@]}" -eq 0 ] || die "these flags need --participant: ${bad[*]}"
fi
if [ "$existing" = 1 ]; then
  # An existing install keeps its settings: only the switch to full mode asks (dashboard) questions.
  bad=()
  [ -z "$version" ] || bad+=(--version)
  [ -z "$mode" ] || bad+=(--source/--images)
  [ -z "$project" ] || bad+=(--project)
  [ -z "$prefix" ] || bad+=(--prefix)
  [ -z "$sensors_arg" ] || bad+=(--sensors)
  [ -z "$wg_conf" ] || bad+=(--wg-conf)
  [ "$no_network" = 0 ] || bad+=(--no-network)
  [ "$join_flag" = 0 ] || bad+=(--join-network)
  [ "$lowmem" = auto ] || bad+=(--lowmem)
  [ "$lite" = 0 ] || bad+=(--lite)
  [ "${#bad[@]}" -eq 0 ] || die "an existing install keeps its settings; these flags are only for a fresh install: ${bad[*]}. Change settings with: just set, just sensors, ./scripts/participant.sh"
  if [ "$repair" = 1 ] && [ "$pw_stdin" = 1 ]; then die "--repair does not change settings: --admin-password-stdin"; fi
fi

if [ "$stack" = participant ] && [ "$fresh" = 1 ]; then
  # shellcheck source=scripts/lib/pseudonym.sh
  . scripts/lib/pseudonym.sh
  [ -f docker-compose.participant.yml ] || die "this checkout has no docker-compose.participant.yml: participant mode needs a current release"
  [ -f config/network-defaults.env ] || die "this checkout has no config/network-defaults.env: participant mode needs a current release"
  [ "$no_pseudonym" = 0 ] || [ -z "$pseudonym_arg" ] || die "--pseudonym and --no-pseudonym exclude each other"
  if [ -n "$pseudonym_arg" ]; then
    pseudonym_valid "$pseudonym_arg" || die "bad --pseudonym"
  fi
  if [ -n "$country" ]; then
    [[ $country =~ ^[A-Za-z]{2}$ ]] || die "--country must be a two-letter country code"
    country=$(printf %s "$country" | tr '[:lower:]' '[:upper:]')
  fi
  [ "$show_country" = 0 ] || [ -n "$country" ] || die "--show-country needs --country CC"
  [ "$verifier" = 0 ] || [ -n "$wg_conf" ] || die "--verifier needs --wg-conf: a verifier fetches files, and only through a VPN"
  [[ -z $self_address || $self_address =~ ^[0-9A-Fa-f.:,]+$ ]] || die "the public address has unexpected characters"
fi

if [ "$existing" = 0 ]; then
  [ -f .env.example ] || die ".env.example not found: run this from a SuckerPot checkout"
  if [ "$dry_run" = 1 ] && [ -e "$env_out" ]; then
    die "$env_out already exists; the dry run does not overwrite files"
  fi
  project=${project:-suckerpot}
  prefix=${prefix:-$project}
else
  project=$(env_get COMPOSE_PROJECT_NAME)
  prefix=$(env_get SUCKERPOT_VOLUME_PREFIX)
  mode=$(env_get SUCKERPOT_INSTALL_MODE source)
  version=${version:-$(env_get SUCKERPOT_VERSION)}
fi
[ -n "$project" ] && [ -n "$prefix" ] || die "project and prefix must not be empty"
valid_project_name "$project" || die "bad project name '$project': use lowercase letters, digits, - and _ (at most 41 characters), and not sp-it-*, sp-test or sp-ci"
valid_project_name "$prefix" || die "bad volume prefix '$prefix': use lowercase letters, digits, - and _ (at most 41 characters), and not sp-it-*, sp-test or sp-ci"

# A machine sold as "2 GB" reports a bit less than 2 GiB. In participant mode the installer then
# offers the lite setup and, once accepted, goes on exactly as if --lite had been given. Reading
# /proc/meminfo needs no Docker, so this is decided before anything depends on $lite.
if [ "$dry_run" = 0 ] && [ "$stack" = participant ] && [ "$lite" = 0 ] && { [ "$fresh" = 1 ] || [ "$switching" = 1 ]; }; then
  early_kb=$(awk '/^MemTotal:/ {print $2}' "${SELFHOSTR_MEMINFO:-/proc/meminfo}" 2> /dev/null || true)
  if [[ ${early_kb:-} =~ ^[0-9]+$ ]] && [ "$early_kb" -lt "$full_min_kb" ] \
    && [ "$early_kb" -ge "$lite_min_kb" ]; then
    early_gib=$(gib "$early_kb")
    note "This machine reports $early_gib GiB of memory. The default setup needs 2 GiB."
    if [ "$assume_yes" = 1 ]; then
      note "Taking the lite setup (--lite): four sensors (SSH, Telnet, web, Redis) and lower memory limits."
    fi
    ask_always a "Use the lite setup instead? Four sensors (SSH, Telnet, web, Redis) and lower memory limits. (yes/no)" yes
    case $a in
      y | yes) lite=1; lite_lowmem ;;
      *) die "SuckerPot needs 2 GiB of memory, and this machine reports $early_gib GiB. Use a machine with 2 GiB or more, or run: ./scripts/install.sh --participant --lite" ;;
    esac
  fi
fi

mem_kb=0
if [ "$dry_run" = 1 ]; then
  note "dry run: Docker, memory, disk and volume checks skipped"
else
  command -v docker > /dev/null 2>&1 || die "Docker is not installed"
  engine=$(ctr version --format '{{.Server.Version}}' 2> /dev/null) \
    || die "Docker does not answer for this user. Try: sudo usermod -aG docker \$USER, then log in again."
  if ! ver_ge "${engine%%[-+]*}" 24.0; then
    # With the podman-docker package, `docker` is Podman and reports the Podman version.
    case $(ctr --version 2> /dev/null) in [Pp]odman*) die "$ENGINE_UNREADY_MSG (the docker command on this host is Podman $engine)" ;; esac
    die "Docker Engine 24 or newer is required (found $engine)"
  fi
  if ! ver_ge "${engine%%[-+]*}" 28.0; then
    warn "Docker Engine $engine is older than 28. On this engine the internal networks are NOT isolated from the host (the isolation needs gateway_mode_ipv4: isolated, from Engine 28). Upgrading Docker Engine to 28 or newer is strongly recommended."
  fi
  cver=$(dc version --short 2> /dev/null) || die "Docker Compose v2 is not available"
  ver_ge "${cver#v}" 2.24 || die "Docker Compose 2.24 or newer is required (found $cver)"

  meminfo=${SELFHOSTR_MEMINFO:-/proc/meminfo}
  mem_kb=$(awk '/^MemTotal:/ {print $2}' "$meminfo" 2> /dev/null || true)
  [[ ${mem_kb:-} =~ ^[0-9]+$ ]] || die "cannot read the memory size from $meminfo"
  if [ "$fresh" = 1 ] || [ "$switching" = 1 ]; then
    if [ "$lite" = 1 ]; then
      if [ "$mem_kb" -lt "$lite_min_kb" ]; then
        die "this machine reports $(gib "$mem_kb") GiB of memory: even --lite needs a machine with 1 GiB (and some swap)"
      fi
      swap_check "1 GiB"
    elif [ "$mem_kb" -lt "$full_min_kb" ]; then
      mem_gib=$(gib "$mem_kb")
      if [ "$mem_kb" -ge "$lite_min_kb" ]; then
        die "this machine reports $mem_gib GiB of memory and the full setup needs 2 GiB. Only the participant lite setup fits here: ./scripts/install.sh --participant --lite"
      fi
      die "this machine reports $mem_gib GiB of memory: SuckerPot needs at least 2 GiB, or 1 GiB with --participant --lite"
    elif [ "$mem_kb" -lt $((2 * 1024 * 1024)) ]; then
      # Sold as 2 GB: the low-memory limits add up to about the whole machine.
      swap_check "about 2 GiB"
    fi
  fi
  if [ "$fresh" = 1 ]; then

    root=$(engine_data_root 2> /dev/null || true)
    free_kb=${SELFHOSTR_FREE_DISK_KB:-$(df -Pk "${root:-/}" 2> /dev/null | awk 'NR==2 {print $4}')}
    [[ ${free_kb:-} =~ ^[0-9]+$ ]] || die "cannot read the free disk space"
    if [ "$free_kb" -lt $((15 * 1024 * 1024)) ]; then
      die "less than 15 GiB free under Docker's data folder"
    elif [ "$free_kb" -lt $((30 * 1024 * 1024)) ]; then
      warn "less than 30 GiB free under Docker's data folder; logs and payloads need room"
    fi

    # Never adopt or mix with an existing install: its database password lives inside the data.
    if [ -n "$(ctr volume ls -q --filter "name=^${prefix}_" 2> /dev/null | head -n 1)" ]; then
      die "Data volumes named '${prefix}_*' already exist. Restore your old .env, or pick another --prefix. (They are never adopted: the database password lives inside the data.)"
    fi
    if [ -n "$(ctr ps -a -q --filter "label=com.docker.compose.project=$project" 2> /dev/null | head -n 1)" ]; then
      die "Containers of the compose project '$project' already exist. Pick another --project, or remove that stack yourself first."
    fi
  fi
  if [ "$stack" = participant ] && ! command -v crontab > /dev/null 2>&1 && ! command -v systemctl > /dev/null 2>&1; then
    warn "neither crontab nor systemctl was found: automatic updates cannot be scheduled (update by hand with: just update)"
  fi
fi

# ---------------------------------------------------------------- 2. questions
step 2 "Settings"

chosen=()
sensor_on() {
  local s
  for s in "${chosen[@]}"; do [ "$s" = "$1" ] && return 0; done
  return 1
}
pseudonym=""
self_addr=""
update_check=false
keep_auto=yes
wg_private="" wg_peer="" wg_addr="" wg_dns="" wg_ep_ip="" wg_ep_port=""

if [ "$fresh" = 1 ]; then
  if [ -z "$mode" ]; then
    if [ "$stack" = participant ]; then
      mode=images
    else
      ask a "Install mode: images (download) or source (build here)" images
      case $a in images | source) mode=$a ;; *) die "install mode must be images or source" ;; esac
    fi
  fi

  if [ -z "$sensors_arg" ]; then
    if [ "$stack" = participant ] && [ "$lite" = 1 ]; then
      sensors_arg=$(IFS=,; echo "${LITE_SENSORS[*]}")
    elif [ "$stack" = participant ]; then
      sensors_arg=recommended
    else
      ask sensors_arg "Sensors: recommended, all, or a list like ssh,web" recommended
    fi
  fi
  case $sensors_arg in
    recommended) chosen=("${RECOMMENDED_SENSORS[@]}") ;;
    all) chosen=("${SENSORS[@]}") ;;
    *)
      IFS=, read -r -a chosen <<< "$sensors_arg"
      [ "${#chosen[@]}" -gt 0 ] || die "no sensor chosen"
      for s in "${chosen[@]}"; do
        is_sensor "$s" || die "unknown sensor '$s' (known: ${SENSORS[*]})"
      done
      ;;
  esac
fi

if [ "$dash" = 1 ]; then
  if [ -z "$bind" ] && [ -z "$public_host" ]; then
    ask a "Dashboard reached [l]ocally or through an SSH tunnel, or through an [h]ttps tunnel such as cloudflared" l
    case $a in
      l | local) ;;
      h | https)
        ask public_host "Public host name of the dashboard (for example dash.example.org)" ""
        [ -n "$public_host" ] || die "a host name is required for an https tunnel"
        ;;
      *) die "answer l or h" ;;
    esac
  fi
  bind=${bind:-127.0.0.1}
  dport=${dport:-8443}
  [[ $bind =~ ^[0-9.]{7,15}$ ]] || die "--dashboard-bind must be an IPv4 address"
  [[ $dport =~ ^[0-9]{1,5}$ ]] && [ "$dport" -ge 1 ] && [ "$dport" -le 65535 ] || die "--dashboard-port must be a port number"
  if [[ $bind != 127.* ]] && [ -z "$public_host" ] && [ "$allow_lan" = 0 ]; then
    die "--dashboard-bind $bind would publish the login page over plain http. Keep 127.0.0.1 (reach it with an SSH tunnel), give --public-host for an https tunnel, or pass --allow-lan if you accept it on a trusted network only."
  fi
  if [ -n "$public_host" ]; then
    [[ $public_host =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || die "bad --public-host"
  fi

  if [ -z "$admin_user" ]; then ask admin_user "Admin user name" admin; fi
  [[ $admin_user =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "the admin user name may only contain letters, digits, . _ -"
fi

pw=""
pw_generated=0
if [ "$dash" = 1 ]; then
  if [ "$pw_stdin" = 1 ]; then
    IFS= read -r pw || true
  elif [ "$noask" = 1 ]; then
    pw=$(gen_secret 24)
    pw_generated=1
  else
    ui_pause
    printf '  Admin password (at least 12 characters, empty = generate one): ' 1>&"$UI_ERR"
    IFS= read -rs pw <&3 || pw=""
    echo 1>&"$UI_ERR"
    if [ -z "$pw" ]; then
      pw=$(gen_secret 24)
      pw_generated=1
    else
      printf '  Repeat the password: ' 1>&"$UI_ERR"
      IFS= read -rs pw2 <&3 || pw2=""
      echo 1>&"$UI_ERR"
      [ "$pw" = "$pw2" ] || die "the two passwords differ"
      unset pw2
    fi
  fi
  [ "${#pw}" -ge 12 ] || die "the admin password must have at least 12 characters"
fi

if [ "$fresh" = 1 ]; then
  if [ "$lowmem" = auto ]; then
    if [ "$dry_run" = 1 ]; then
      lowmem=off
    elif [ "$mem_kb" -lt $((6 * 1024 * 1024)) ]; then
      if [ "$stack" = participant ]; then
        # Participant mode asks nothing: the low-memory overlay is used when the machine needs it.
        if [ -f docker-compose.lowmem.yml ]; then lowmem=on; else lowmem=off; fi
      else
        ask a "This machine has less than 6 GiB of memory. Use the low-memory mode? (yes/no)" yes
        case $a in y | yes) lowmem=on ;; *) lowmem=off ;; esac
      fi
    else
      lowmem=off
    fi
  fi
  if [ "$lowmem" = on ] && [ ! -f docker-compose.lowmem.yml ]; then
    die "this checkout has no docker-compose.lowmem.yml, so --lowmem on is not possible"
  fi
  if [ "$lite" = 1 ] && [ ! -f docker-compose.lite.yml ]; then
    die "this checkout has no docker-compose.lite.yml, so --lite is not possible"
  fi
fi

if [ "$stack" = full ] && [ "$fresh" = 1 ]; then
  ask update_check "Check once a day whether a newer release exists? (one anonymous request through the VPN, never installs anything) (y or n)" n
  case $update_check in y | Y | yes | true) update_check=true ;; *) update_check=false ;; esac
fi
if [ "$switching" = 1 ]; then
  if [ "$(env_get AUTO_UPDATE_ENABLED false)" = true ]; then
    ask keep_auto "Keep the automatic daily updates? (yes/no)" yes
    case $keep_auto in n | no) keep_auto=no ;; *) keep_auto=yes ;; esac
  fi
fi

if [ "$fresh" = 1 ]; then
  if [ -z "$wg_conf" ] && [ "$stack" = full ]; then
    ask wg_conf "Path to a WireGuard .conf from your VPN provider (empty = upload it later in the dashboard)" ""
  fi
  if [ -n "$wg_conf" ]; then
    if [ "$stack" = full ]; then
      wg_parse_conf "$wg_conf" " Upload it in the dashboard instead." || die "unusable WireGuard file"
    else
      wg_parse_conf "$wg_conf" " Check the file from your VPN provider." || die "unusable WireGuard file"
    fi
  fi

  if [ "$stack" = full ]; then
    ask self_addr "Your own public address, if you know it (the dashboard learns it from traffic otherwise; this script never looks it up)" ""
  else
    self_addr=$self_address
  fi
  [[ -z $self_addr || $self_addr =~ ^[0-9A-Fa-f.:,]+$ ]] || die "the public address has unexpected characters"
elif [ "$switching" = 1 ]; then
  note "the install keeps its sensors, ports, volumes, secrets and network membership"
elif [ "$repair" = 1 ]; then
  note "settings kept as installed"
fi

# Participant consent: shown before the only prompt. --yes is the consent and skips the prompt.
if [ "$stack" = participant ] && [ "$fresh" = 1 ]; then
  if [ "$no_pseudonym" = 1 ]; then
    pseudonym=""
  elif [ -n "$pseudonym_arg" ]; then
    pseudonym=$pseudonym_arg
  else
    pseudonym=$(pseudonym_random) || die "could not make a pseudonym"
  fi
  vpn_flag=0
  [ -z "$wg_conf" ] || vpn_flag=1
  ui_pause
  say
  consent_screen "$pseudonym" "$vpn_flag" 1>&"$UI_OUT"
  if [ "$assume_yes" = 1 ]; then
    say "--yes was given: this counts as your agreement to join as described above."
    say
  else
    printf 'Join the SuckerPot network as described? [y/N] ' 1>&"$UI_ERR"
    IFS= read -r a <&3 || a=""
    answered
    case $a in
      y | Y | yes | YES | Yes) ;;
      *) echo "Not joined. Nothing was installed." 1>&"$UI_ERR"; log "consent declined"; exit 1 ;;
    esac
  fi
fi

# Full mode: the network question, default NO. It sits after the other questions, so nothing is
# asked after a "no". The answer is a consent record in .env; ingest joins from it once a VPN is
# configured. Only an explicit --join-network or a typed y joins: --yes alone never does.
[ "$join_flag" = 0 ] || [ "$no_network" = 0 ] || die "--join-network and --no-network exclude each other"
join_network=0
if [ "$stack" = full ] && [ "$fresh" = 1 ] && [ "$no_network" = 0 ]; then
  if [ "$join_flag" = 1 ]; then
    # shellcheck source=scripts/lib/pseudonym.sh
    . scripts/lib/pseudonym.sh
    ui_pause
    say
    pseudonym=$(pseudonym_random) || die "could not make a pseudonym"
    consent_screen_full "$pseudonym" 1>&"$UI_OUT"
    say "--join-network was given: this counts as your agreement to join as described above."
    say
    join_network=1
  elif [ "$assume_yes" = 1 ]; then
    note "the SuckerPot network is off: --yes does not join it (add --join-network to join)"
  else
    # shellcheck source=scripts/lib/pseudonym.sh
    . scripts/lib/pseudonym.sh
    ui_pause
    say
    pseudonym=$(pseudonym_random) || die "could not make a pseudonym"
    consent_screen_full "$pseudonym" 1>&"$UI_OUT"
    printf 'Join the SuckerPot network? [y/N] ' 1>&"$UI_ERR"
    # End of input is not a yes: only a typed y is.
    IFS= read -r a <&3 || die "no answer to the network question; use --join-network or --no-network"
    answered
    case $a in
      y | Y | yes | YES | Yes) join_network=1 ;;
      "" | n | N | no | NO | No) pseudonym=""; log "network declined" ;;
      *) die "please answer y or n" ;;
    esac
  fi
fi

# ---------------------------------------------------------------- 3. ports
step 3 "Checking ports"
declare -A port_override=()
declare -A sensor_off=()

busy_ports=""
if [ "$dry_run" = 1 ]; then
  note "dry run: port check skipped"
elif [ "$repair" = 1 ]; then
  note "ports kept as installed"
elif command -v ss > /dev/null 2>&1; then
  busy_ports=$(ss -Hltnu 2> /dev/null | awk '{n = split($5, a, ":"); print a[n]}' | sort -un | tr '\n' ' ' || true)
else
  warn "'ss' is not available; the port check is skipped"
fi
is_busy() { [[ " $busy_ports " == *" $1 "* ]]; }

ssh_moved=0
if [ "$fresh" = 1 ]; then
  for s in "${chosen[@]}"; do
    while IFS=: read -r var def _; do
      port=$def
      if is_busy "$port"; then
        if [ "$s" = ssh ] && [ "$port" = 22 ]; then
          note "Port 22 is used on this machine (its own sshd, most likely)."
          ask a "SSH sensor: [m]ap it to host port 2222 and forward router port 22 to it, leave it [o]ff, or [k]eep 22 (you moved the admin SSH: sudo ./scripts/move-admin-ssh.sh)" m
          case $a in
            m | map) port_override[$var]=2222; ssh_moved=1 ;;
            o | off) sensor_off[$s]=1 ;;
            k | keep) die "port 22 is still in use. Move your admin SSH first with: sudo ./scripts/move-admin-ssh.sh (this installer never edits sshd_config), then run it again." ;;
            *) die "answer m, o or k" ;;
          esac
          [ "$noask" = 1 ] && [ -z "${sensor_off[$s]:-}" ] && note "Mapped the SSH sensor to host port 2222."
        elif [ "$noask" = 1 ]; then
          warn "port $port ($var) is in use: the $s sensor is left off. Free the port and run: just sensors ..."
          sensor_off[$s]=1
        else
          ask a "Port $port ($var) is in use. Another host port, or 'off' to skip the $s sensor" off
          if [ "$a" = off ]; then
            sensor_off[$s]=1
          elif [[ $a =~ ^[0-9]{1,5}$ ]] && [ "$a" -ge 1 ] && [ "$a" -le 65535 ] && ! is_busy "$a"; then
            port_override[$var]=$a
          else
            die "'$a' is not a free port"
          fi
        fi
      fi
    done < <(sensor_ports "$s")
  done
fi
if [ "$dry_run" = 0 ] && [ "$stack" = full ] && [ "$repair" = 0 ] && is_busy "$dport"; then
  die "the dashboard port $dport is in use on this machine; pass --dashboard-port with a free port"
fi
if [ "$fresh" = 1 ]; then
  if [ -z "$admin_ssh_port" ]; then
    if [ "$ssh_moved" = 1 ] || { [ "$dry_run" = 0 ] && is_busy 22; }; then admin_ssh_port=22; fi
    if [ -z "$admin_ssh_port" ] && [ "$dry_run" = 0 ] && [ "$stack" = participant ]; then
      # Port 22 is free: the admin SSH may already have been moved (docs/vps.md). Use what sshd
      # is configured for, so the host firewall protects that port.
      # shellcheck source=scripts/lib/firewall.sh
      . scripts/lib/firewall.sh
      read -r fw_port fw_src <<< "$(fw_admin_port)"
      if [ "$fw_src" != default ] && [ "$fw_port" != 22 ]; then admin_ssh_port=$fw_port; fi
    fi
    if [ "$noask" = 0 ]; then
      ask admin_ssh_port "Port of this machine's own admin SSH (so no sensor can take it; empty = none)" "$admin_ssh_port"
    fi
  fi
  [[ -z $admin_ssh_port || $admin_ssh_port =~ ^[0-9]{1,5}$ ]] || die "bad admin SSH port"
fi

# ---------------------------------------------------------------- 4. secrets
step 4 "Generating secrets"
declare -A secret=()
if [ "$fresh" = 1 ]; then
  declare -A seen=()
  for name in "${SECRET_VARS[@]}"; do
    while :; do
      value=$(gen_for "$name")
      [ -z "${seen[$value]:-}" ] && break
    done
    seen[$value]=1
    secret[$name]=$value
  done
  unset seen
  note "${#SECRET_VARS[@]} secrets generated (written to .env only)"
else
  note "secrets kept as installed"
fi

# ---------------------------------------------------------------- 5. admin hash / image check
if [ "$stack" = participant ]; then
  step 5 "Checking the images (no admin account in participant mode)"
else
  step 5 "Hashing the admin password"
fi
if [ "$mode" = images ] && [ -z "$version" ]; then
  version=$(git describe --tags --exact-match HEAD 2> /dev/null || true)
fi
if [ "$mode" = images ]; then
  if [ -z "$version" ]; then
    [ "$dry_run" = 1 ] && version=dev || die "images mode needs --version vX.Y.Z (or install from a release tag, or use --source)"
  fi
  [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ || ( $dry_run = 1 && $version = dev ) ]] || die "--version must look like v1.2.3"
fi
if [ "$existing" = 1 ]; then
  image_prefix=$(env_get SUCKERPOT_IMAGE_PREFIX "${SUCKERPOT_IMAGE_PREFIX:-ghcr.io/selfhostr/suckerpot}")
else
  image_prefix=${SUCKERPOT_IMAGE_PREFIX:-ghcr.io/selfhostr/suckerpot}
fi
[[ $image_prefix =~ ^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$ ]] \
  || die "SUCKERPOT_IMAGE_PREFIX must look like ghcr.io/<owner>/<name>"
hash=""
if [ "$stack" = participant ]; then
  if [ "$repair" = 1 ]; then
    note "nothing to do"
  elif [ "$dry_run" = 1 ] || [ "$mode" = source ]; then
    note "no image check needed here"
  elif [ "$skip_verify" = 1 ]; then
    ui_run --expect 60 -- quiet ctr pull "${image_prefix}-ingest:${version}" || die "could not pull ${image_prefix}-ingest:${version}"
  else
    ui_run --expect 60 -- env SUCKERPOT_IMAGE_PREFIX="$image_prefix" bash scripts/verify-images.sh --pull --only ingest "$version" \
      || die "the ingest image could not be verified, so nothing was started. Check the version, or only if you accept the risk: --skip-verify"
  fi
  if [ "$fresh" = 1 ]; then
    # Inert placeholders: the dashboard (api) never starts in participant mode, so nothing reads this
    # hash. It is random, so it matches no password; it only satisfies the base file's required check.
    hash="\$argon2id\$v=19\$m=65536,t=3,p=4\$$(gen_secret 22)\$$(gen_secret 43)"
  fi
elif [ "$dash" = 1 ]; then
  if [ "$dry_run" = 1 ]; then
    hash='$argon2id$v=19$m=65536,t=3,p=4$cGxhY2Vob2xkZXI$cGxhY2Vob2xkZXItaGFzaC1ub3QtcmVhbA'
    note "dry run: placeholder hash"
  else
    if [ "$mode" = images ]; then
      api_image="${image_prefix}-api:${version}"
      if [ "$skip_verify" = 1 ]; then
        ui_run --expect 60 -- quiet ctr pull "$api_image" || die "could not pull $api_image"
      else
        # Verify before the image ever runs (it hashes the password): pulled by the verified digest.
        ui_run --expect 60 -- env SUCKERPOT_IMAGE_PREFIX="$image_prefix" bash scripts/verify-images.sh --pull --only api "$version" \
          || die "the api image could not be verified, so it was not run. Check the version, or only if you accept the risk: --skip-verify"
      fi
    else
      api_image=suckerpot-install-api
      # The end-to-end test must not retag anything that a live install may use.
      [ "${SELFHOSTR_TEST_INSTALL:-}" != 1 ] || api_image="local/${project}-install-api:test"
      ui_run --expect 120 -- quiet ctr build -q -f api/Dockerfile -t "$api_image" . || die "could not build the api image"
    fi
    hash=$(printf '%s\n' "$pw" | ctr run --rm -i --network none --cap-drop ALL \
      --security-opt no-new-privileges:true "$api_image" python -m api.hashpw --stdin) \
      || die "could not hash the admin password"
    hash=${hash//$'\r'/}
  fi
fi
if [ "$repair" = 0 ] && { [ "$stack" = participant ] && [ "$fresh" = 1 ] || [ "$dash" = 1 ]; }; then
  case $hash in '$argon2'*) ;; *) die "the password hasher returned something unexpected" ;; esac
fi
if [ "$pw_stdin" = 1 ] || [ "$pw_generated" = 0 ]; then pw=""; fi

# ---------------------------------------------------------------- 6. .env
if [ "$repair" = 1 ]; then
  step 6 "Keeping .env as it is"
else
  step 6 "Writing $target"
  # Private only while the secrets are being written: the build and the start below must not run
  # under it (see with_public_umask in scripts/lib/env.sh).
  caller_umask=$(umask)
  umask 077
  tmp="${target}.tmp"
  rm -f "$tmp"
  trap 'rm -f "$tmp"; ui_exit' EXIT
  if [ "$switching" = 1 ]; then cp .env "$tmp"; else cp .env.example "$tmp"; fi
  chmod 600 "$tmp"

  setv() { env_set_line "$tmp" "$1" "$2"; }

  if [ "$switching" = 1 ]; then
    # Only the lines that make the stack a participant stack change; secrets, volume prefix,
    # sensors, ports, network lines and the update choice stay.
    cf=$(env_get COMPOSE_FILE docker-compose.yml)
    cf=${cf//:docker-compose.participant.yml/}
    cf=${cf//docker-compose.participant.yml:/}
    [ "$cf" != docker-compose.participant.yml ] || cf=docker-compose.yml
    setv SUCKERPOT_STACK_MODE full
    setv COMPOSE_FILE "$cf"
    setv COMPOSE_PROFILES egress
    setv EGRESS_MODE vpn
    setv EGRESS_PROXY_URL http://vpn:8888
    setv EGRESS_CONTROL_URL http://vpn:8000
    env_del_line "$tmp" HUBPROXY_ALLOW
    setv SELF_TERMS_AUTO_CONFIRM false
    [ "$keep_auto" = yes ] || setv AUTO_UPDATE_ENABLED false
  else
    setv COMPOSE_PROJECT_NAME "$project"
    setv SUCKERPOT_VOLUME_PREFIX "$prefix"
    for name in "${SECRET_VARS[@]}"; do setv "$name" "${secret[$name]}"; done
    unset secret
  fi
  if [ -n "$hash" ]; then setv ADMIN_PASSWORD_HASH "'$hash'"; fi
  unset hash
  if [ "$dash" = 1 ]; then
    setv ADMIN_USERNAME "$admin_user"
    setv DASHBOARD_BIND "$bind"
    setv DASHBOARD_PORT "$dport"
    if [ -n "$public_host" ]; then
      setv API_ALLOWED_HOSTS "$public_host"
      setv API_ALLOWED_ORIGINS "https://$public_host"
      setv COOKIE_SECURE true
    elif [ "$allow_lan" = 1 ] && [[ $bind != 127.* ]]; then
      # Plain http on a network address: browsers refuse Secure cookies there.
      setv COOKIE_SECURE false
    else
      # http://127.0.0.1 and http://localhost accept Secure cookies, so the safe value stays on.
      setv COOKIE_SECURE true
    fi
  fi
  if [ "$fresh" = 1 ]; then
    [ -n "$admin_ssh_port" ] && setv ADMIN_SSH_PORT "$admin_ssh_port"
    [ -n "$self_addr" ] && setv INDICATORS_IGNORE "$self_addr"
    if [ "$stack" = full ]; then setv COMPOSE_PROFILES egress; fi
    if [ "$join_network" = 1 ]; then
      setv NETWORK_ENABLED true
      setv NETWORK_CONSENT "$(consent_record "$CONSENT_ITEMS_FULL")"
      case $pseudonym in
        *" "*) setv NETWORK_PSEUDONYM "'$pseudonym'" ;;
        *) setv NETWORK_PSEUDONYM "$pseudonym" ;;
      esac
    fi
    if [ -n "$wg_conf" ]; then
      setv VPN_WG_PRIVATE_KEY "$wg_private"
      setv VPN_WG_PEER_PUBLIC_KEY "$wg_peer"
      setv VPN_WG_ADDRESSES "$wg_addr"
      [ -n "$wg_dns" ] && setv VPN_WG_DNS "$wg_dns"
      setv VPN_WG_ENDPOINT_IP "$wg_ep_ip"
      setv VPN_WG_ENDPOINT_PORT "$wg_ep_port"
      wg_private="" wg_peer=""
    fi

    printf '\n# Added by the SuckerPot installer\n' >> "$tmp"
    setv UPDATE_CHECK_ENABLED "$update_check"
    setv NETWORK_DEFAULT_PINNED 1
    setv SUCKERPOT_ENGINE "$ENGINE_ID"
    setv SUCKERPOT_INSTALL_MODE "$mode"
    if [ "$mode" = images ]; then
      setv SUCKERPOT_IMAGE_PREFIX "$image_prefix"
      setv SUCKERPOT_VERSION "$version"
    fi
    for s in "${SENSORS[@]}"; do
      if sensor_on "$s" && [ -z "${sensor_off[$s]:-}" ]; then v=1; else v=0; fi
      setv "$(sensor_var "$s")" "$v"
    done
    for var in "${!port_override[@]}"; do setv "$var" "${port_override[$var]}"; done

    if [ "$stack" = full ]; then
      if [ "$lowmem" = on ]; then setv COMPOSE_FILE docker-compose.yml:docker-compose.lowmem.yml; fi
    else
      # Participant mode (docs/dev/design/m32.md section 4.1). The hub address and key are NOT copied:
      # ingest reads the defaults baked into the signed image; an explicit value here would win.
      cf=docker-compose.yml
      if [ "$lowmem" = on ]; then cf="$cf:docker-compose.lowmem.yml"; fi
      # Lite (M35) lives in COMPOSE_FILE like the low-memory overlay, so updates keep it.
      if [ "$lite" = 1 ]; then cf="$cf:docker-compose.lite.yml"; fi
      setv COMPOSE_FILE "$cf:docker-compose.participant.yml"
      setv SUCKERPOT_STACK_MODE participant
      if [ -n "$wg_conf" ]; then
        setv COMPOSE_PROFILES egress
        setv EGRESS_MODE vpn
        setv EGRESS_PROXY_URL http://vpn:8888
        setv EGRESS_CONTROL_URL http://vpn:8000
      else
        setv COMPOSE_PROFILES direct
        setv EGRESS_MODE direct
        setv EGRESS_PROXY_URL http://hubproxy:8888
        setv EGRESS_CONTROL_URL http://hubproxy:8000
        allow=$(hubproxy_allow "$feeds") || die "could not read the hub address from config/network-defaults.env"
        setv HUBPROXY_ALLOW "$allow"
      fi
      if [ "$feeds" = 1 ]; then setv NETWORK_FEED_ENABLED true; fi
      setv NETWORK_ENABLED true
      setv NETWORK_CONSENT "$(consent_record)"
      case $pseudonym in
        *" "*) setv NETWORK_PSEUDONYM "'$pseudonym'" ;;
        *) setv NETWORK_PSEUDONYM "$pseudonym" ;;
      esac
      if [ -n "$country" ]; then
        setv NETWORK_COUNTRY "$country"
        if [ "$show_country" = 1 ]; then setv NETWORK_SHOW_COUNTRY true; fi
      fi
      setv SELF_TERMS_AUTO_CONFIRM true
      [ -n "$self_addr" ] && setv SELF_ADDRESS "$self_addr"
      setv NETWORK_VERIFY_REVEALS true
      setv DB_MAX_SIZE_GB 4
      if [ "$verifier" = 1 ]; then
        setv NETWORK_VERIFIER true
        setv COLLECTOR_ENABLED true
        setv COLLECTOR_VERIFY_ENABLED true
      fi
      if [ "$no_auto_update" = 1 ] || [ "$mode" != images ]; then
        setv AUTO_UPDATE_ENABLED false
        if [ "$mode" != images ] && [ "$no_auto_update" = 0 ]; then
          note "automatic updates need the signed release images, so they stay off in source mode"
        fi
      else
        setv AUTO_UPDATE_ENABLED true
      fi
    fi
  fi

  if [ "${SELFHOSTR_TEST_INSTALL:-}" = 1 ] && [ "$switching" = 0 ]; then
    # End-to-end test: the overlay that makes the stack hermetic (local images, local volumes, no
    # published port, no network with a route out). valid_project_name already limited this to
    # sp-it-participant-* names.
    ENV_FILE=$tmp
    cf=$(env_get COMPOSE_FILE docker-compose.yml)
    unset ENV_FILE
    setv COMPOSE_FILE "$cf:docker-compose.participant-it.yml"
  fi

  # Final checks on the file before it goes live.
  if grep -v '^[[:space:]]*#' "$tmp" | grep -q 'change-me'; then
    rm -f "$tmp"
    die "a placeholder (change-me) is still in the generated file"
  fi
  ENV_FILE=$tmp
  export ENV_FILE
  for name in "${SECRET_VARS[@]}"; do
    v=$(env_get "$name")
    if [ "${#v}" -lt 24 ]; then
      rm -f "$tmp"
      die "$name is missing or shorter than 24 characters in the generated file"
    fi
  done
  unset ENV_FILE
  if [ "$switching" = 1 ]; then
    # A backup of the participant database first. If it fails, .env is left exactly as it was.
    note "taking a database backup before the switch"
    if ! ui_run --expect 60 -- dc exec -T backup /bin/sh /backup-service.sh now preswitch; then
      rm -f "$tmp"
      die "the backup before the switch failed; nothing was changed"
    fi
    # Keep a copy of the participant .env until the switch has worked.
    cp -p .env .env.participant.bak
    chmod 600 .env.participant.bak
  fi
  mv "$tmp" "$target"
  trap ui_exit EXIT
  chmod 600 "$target"
  note "wrote $target (mode 0600)"
  [ "$dry_run" = 1 ] || env_written=1
  umask "$caller_umask"
fi

if [ "$dry_run" = 1 ]; then
  ui_skip_rest "dry run"
  ui_end
  say
  say "Dry run finished: $target holds the would-be configuration. No Docker call was made."
  exit 0
fi

# ---------------------------------------------------------------- 7. volumes
step 7 "Creating the data volumes"
if [ "${SELFHOSTR_TEST_INSTALL:-}" = 1 ]; then
  # End-to-end test (scripts/e2e/participant.sh): the test overlay makes every volume local to the
  # throwaway project, so there is nothing to create here.
  note "test install: volumes are local to the throwaway project"
else
  ui_run --expect 10 -- env SUCKERPOT_VOLUME_PREFIX="$prefix" bash scripts/ensure-volumes.sh \
    || die "the data volumes could not be created (see the messages above)"
  ui_detail "data volumes ready"
fi

# ---------------------------------------------------------------- 8. guards
step 8 "Checking the port layout and VPN settings"
ui_run -- scripts/check-ports.sh || die "the port layout check failed (see the messages above)"
# Empty VPN_WG_* values are valid (the vpn container idles until a file is uploaded), so this
# always runs: it still checks the egress passwords and any WireGuard values that were written.
# It does nothing unless the egress profile is on.
ui_run -- scripts/check-vpn-env.sh || die "the VPN settings check failed (see the messages above)"
if [ "$stack" = participant ]; then
  ui_run -- scripts/check-participant.sh || die "the participant settings check failed (see the messages above)"
elif [ -z "$(env_get VPN_WG_PRIVATE_KEY)" ]; then
  note "no WireGuard file given: upload it in the dashboard (Settings > VPN); the gate stays closed until then"
fi
ui_done

# ---------------------------------------------------------------- 9. start
step 9 "Starting SuckerPot (this can take several minutes)"
# A clone made under a restrictive umask (077) has files the non-root users inside the containers
# cannot read. Tracked paths only, so .env and the other private files keep their mode.
fix_tracked_modes
up_extra=()
if [ "$switching" = 1 ]; then
  # hubproxy goes away, api and vpn start. A service of a profile that is no longer on is not an
  # orphan to compose, so it is stopped by name.
  dc --profile direct rm -sf hubproxy > /dev/null 2>&1 || true
  up_extra=(--remove-orphans)
fi
ui_begin images
if [ "$mode" = images ]; then
  if [ "$skip_verify" = 1 ]; then
    warn "--skip-verify: the image signatures were NOT checked"
    ui_run --expect 120 -- dc pull || die "could not pull the images. Check the version and your network, then run: docker compose pull"
  else
    ui_run --count "^  ok " 19 -- env SUCKERPOT_IMAGE_PREFIX="$image_prefix" bash scripts/verify-images.sh --pull "$version" || die "the image signatures could not be verified, so nothing was started. Check the version, or run scripts/verify-images.sh $version. Only if you accept the risk: --skip-verify"
    # Our images are now local (pulled by verified digest); this fetches only the pinned third-party ones.
    ui_detail "${UI_COUNT:-0} signatures valid, now the database and VPN images"
    ui_run --expect 60 -- dc pull --policy missing || die "could not pull the remaining images (database, VPN). Check your network, then run: docker compose pull --policy missing"
  fi
  if [ "$skip_verify" = 1 ]; then ui_done "pulled, signatures NOT checked"; else ui_done "${UI_COUNT:-0} signatures valid"; fi
  ui_begin start
  ui_run --expect 150 -- dc up -d --no-build --pull never --wait --wait-timeout 600 ${up_extra[@]+"${up_extra[@]}"} || die "the stack did not become healthy. See: docker compose ps, docker compose logs"
else
  SUCKERPOT_BUILD_VERSION=$(git describe --tags --always --dirty 2> /dev/null || echo dev)
  SUCKERPOT_BUILD_COMMIT=$(git rev-parse --short HEAD 2> /dev/null || echo unknown)
  export SUCKERPOT_BUILD_VERSION SUCKERPOT_BUILD_COMMIT
  ui_skip "source mode: built during the start"
  ui_begin start
  ui_run --expect 600 -- with_public_umask dc up -d --build --wait --wait-timeout 900 ${up_extra[@]+"${up_extra[@]}"} || die "the stack did not become healthy. See: docker compose ps, docker compose logs"
fi
ui_done "all services healthy"
if [ "$stack" = full ]; then
  if [ "$repair" = 1 ]; then
    bind=$(env_get DASHBOARD_BIND 127.0.0.1)
    dport=$(env_get DASHBOARD_PORT 8443)
    public_host=""
  fi
  hbind=$bind
  [ "$hbind" = 0.0.0.0 ] && hbind=127.0.0.1
  ui_begin dashboard
  # Host: localhost is always accepted by the API, whatever address the dashboard is bound to.
  dashboard_wait() {
    local _
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      if curl -fsS --max-time 5 -H "Host: localhost" "http://$hbind:$dport/healthz" > /dev/null 2>&1; then return 0; fi
      sleep 3
    done
    return 1
  }
  ui_run --expect 10 -- dashboard_wait || die "the dashboard does not answer on http://$hbind:$dport/healthz. See: docker compose logs api"
  ui_done "http://$hbind:$dport"
fi

# ---------------------------------------------------------------- rich final screens
# The rich display ends with a short screen. Plain mode prints the full text below, unchanged.

# sched_text: the update schedule in a few words.
sched_text() {
  local when=${sched#* }
  when=${when%/6h}
  case $sched in
    "cron "*/6h | "systemd "*/6h) echo "every 6 h from ${when} local time" ;;
    "cron "* | "systemd "*) echo "daily at ${when} local time" ;;
    *) echo "off" ;;
  esac
}

# Host firewall on the rich display: the same question and the same loader as fw_step, with the
# sudo password asked in the open (the list is off the screen while sudo asks).
fw_rich() {
  local ans=y out
  # shellcheck source=scripts/lib/firewall.sh
  . scripts/lib/firewall.sh
  if [ "$assume_yes" = 0 ]; then
    ui_pause
    printf '  Install the host firewall now? It stops a compromised sensor from reaching this machine or the internet. Needs sudo. [Y/n] ' 1>&"$UI_ERR"
    IFS= read -r ans <&3 || ans=n
    answered
    case $ans in "" | y | Y | yes | YES | Yes) ans=y ;; *) ans=n ;; esac
  fi
  if [ "$ans" = n ]; then
    ui_skip "later: ./scripts/participant.sh firewall"
    return 0
  fi
  if ! fw_can_sudo; then
    if [ "$assume_yes" = 1 ] || ! command -v sudo > /dev/null 2>&1; then
      ui_skip "needs sudo: ./scripts/participant.sh firewall"
      return 0
    fi
    ui_pause
    printf '  The host firewall needs root rights: sudo asks for your password.\n' 1>&"$UI_ERR"
    # shellcheck disable=SC2024 # the redirects are the terminal, on purpose
    if ! sudo -v < /dev/tty > /dev/tty 2>&1; then
      ui_skip "sudo failed: ./scripts/participant.sh firewall"
      return 0
    fi
  fi
  ui_detail "loading"
  out=$(fw_step participant 4 4<<< y 2>&1) || true
  printf '%s\n' "$out"
  case $out in
    *"The host firewall is loaded"*) ui_done "loaded, starts at every boot" ;;
    *"could not be rendered"*) ui_skip "not rendered (see the log): ./scripts/participant.sh firewall" ;;
    *) ui_skip "not installed (see the log): ./scripts/participant.sh firewall" ;;
  esac
}

participant_rich() {
  local adm rp hp proto sname ports="" line pc_rc=0 pc_since pc_ans
  ui_begin firewall
  fw_rich
  ui_begin reach
  # shellcheck source=scripts/lib/ports-check.sh
  . scripts/lib/ports-check.sh
  pc_since=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)
  ui_run --expect 90 -- ports_check_run 90 "$pc_since" || pc_rc=$?
  while [ "$pc_rc" = 3 ] && [ "$assume_yes" = 0 ]; do
    ui_pause
    printf '  Ports not reachable yet. [r]echeck now (after you opened them), or [c]ontinue and open them later? [c] ' 1>&"$UI_ERR"
    pc_ans=""
    IFS= read -r pc_ans <&3 || pc_ans=c
    answered
    case $pc_ans in
      r | R) pc_rc=0; ui_run --expect 60 -- ports_check_run 60 "$pc_since" || pc_rc=$? ;;
      *) break ;;
    esac
  done
  case $pc_rc in
    0) ui_done "the internet reaches your sensors" ;;
    3) ui_done "no traffic yet (normal before the port forwards)" ;;
    *) ui_skip "could not check: ./scripts/participant.sh ports-check" ;;
  esac
  ui_end

  while read -r rp hp proto sname; do
    if [ "$rp" = "$hp" ]; then line="$rp $sname"; else line="$rp→$hp $sname"; fi
    [ "$UI_UTF8" = 1 ] || line=${line//→/->}
    [ "$proto" = TCP ] || line="$line/${proto,,}"
    ports+="${ports:+   }$line"
  done < <(ports_table)
  adm=$(env_get ADMIN_SSH_PORT)
  {
    echo
    if [ "$repair" = 1 ]; then
      printf '  %sSuckerPot is repaired and running in participant mode (%s).%s\n' "$UI_B" "${version:-source build}" "$UI_R"
    else
      printf '  %sSuckerPot is running in participant mode (%s).%s\n' "$UI_B" "${version:-source build}" "$UI_R"
    fi
    printf '    Pseudonym  %s\n    Path       %s\n    Hub        %s\n    Updates    %s\n' "${pseudonym:-none}" "$path" "${hub_host:-unknown}" "$(sched_text)"
    echo
    echo "  Forward these router ports to this machine (port forwards, not a DMZ):"
    printf '%s\n' "$ports" | fold -s -w $((UI_COLS > 20 ? UI_COLS - 5 : 60)) | sed 's/^/    /'
    if [ -n "$adm" ]; then
      echo "  Never forward your admin SSH port ($adm on this machine)."
    else
      echo "  Never forward the admin SSH port of this machine."
    fi
    echo
    printf '  %sNext%s   %s./scripts/participant.sh ports-check%s   once the ports are forwarded\n' "$UI_B" "$UI_R" "$UI_PR" "$UI_R"
    printf '         %s./scripts/status.sh%s                    any time (what needs attention)\n' "$UI_PR" "$UI_R"
    printf '  %sMore%s   docs/participate.md: DMZ, firewall, updates. Take a snapshot of this machine now.\n' "$UI_B" "$UI_R"
    printf '  %sLog%s    %s\n' "$UI_B" "$UI_R" "$(_ui_abs "$LOG")"
  } 1>&"$UI_OUT"
}

full_rich() {
  ui_end
  {
    echo
    printf '  %sSuckerPot is running.%s\n' "$UI_B" "$UI_R"
    if [ -n "$public_host" ]; then
      printf '    Dashboard   %shttps://%s%s  (through your tunnel to http://%s:%s)\n' "$UI_PR" "$public_host" "$UI_R" "$hbind" "$dport"
    else
      printf '    Dashboard   %shttp://%s:%s%s\n' "$UI_PR" "$hbind" "$dport" "$UI_R"
      if [ "$bind" = 127.0.0.1 ]; then
        printf '    Tunnel      ssh -L %s:127.0.0.1:%s <you>@<this-host>   (on a remote machine)\n' "$dport" "$dport"
      fi
    fi
    printf '    Admin user  %s\n' "$(env_get ADMIN_USERNAME)"
    if [ "$pw_generated" = 1 ]; then
      echo "  Admin password (shown once, store it in your password manager now): $pw"
    fi
    if [ "$switching" = 1 ]; then
      echo
      echo "  Switched from participant mode to full mode. Your data and your network membership are kept."
      echo "  The participant settings are in .env.participant.bak (delete it once all is well)."
    fi
    if [ "${join_network:-0}" = 1 ]; then
      echo "  Network     joined; it starts once a VPN is configured (Settings > VPN)"
    elif [ "$fresh" = 1 ]; then
      echo "  Network     not joined (you can join later in the dashboard)"
    fi
    echo
    printf '  %sNext%s   1. Sign in. The setup opens by itself.\n' "$UI_B" "$UI_R"
    echo "         2. Forward the ports listed on the Ports page (never $dport or your admin SSH port)."
    printf '         3. %s./scripts/participant.sh firewall%s   (the host firewall)\n' "$UI_PR" "$UI_R"
    echo "         4. Take a snapshot of the machine."
    printf '  %sLog%s    %s\n' "$UI_B" "$UI_R" "$(_ui_abs "$LOG")"
  } 1>&"$UI_OUT"
  pw=""
}

# ---------------------------------------------------------------- 10. summary
step 10 "Done"
if [ "$stack" = participant ] || [ "$switching" = 1 ]; then ui_begin updates; fi

# Automatic updates: the schedule is a line in the crontab of this user (or a systemd user timer).
sched=off
if [ "$stack" = participant ] || [ "$switching" = 1 ]; then
  # shellcheck source=scripts/lib/schedule.sh
  . scripts/lib/schedule.sh
  if [ "$switching" = 1 ] && [ "$keep_auto" = no ]; then
    schedule_remove || warn "could not remove the update schedule; see ./scripts/participant.sh auto-update off"
  elif [ "$(env_get AUTO_UPDATE_ENABLED false)" = true ]; then
    if sched=$(schedule_status 2> /dev/null); then
      # A once-a-day schedule from an older release moves to every 6 hours.
      schedule_upgrade || warn "could not move the update schedule to every 6 hours; it stays as it is"
      sched=$(schedule_status || echo off)
    else
      read -r sh sm < <(schedule_random_time)
      if schedule_install "$sh" "$sm"; then
        sched=$(schedule_status || echo off)
      else
        # The flag stays on: a later --repair tries the schedule again, and ./scripts/status.sh
        # reports "off" until a schedule exists.
        warn "could not schedule the automatic updates. Try again with: ./scripts/participant.sh auto-update on (until then, update by hand with: just update)"
        sched=off
      fi
    fi
  fi
fi
if [ "$stack" = participant ]; then ui_done "$(sched_text)"; fi

if [ "$stack" = participant ]; then
  hub_host=$(url_host "$(env_get NETWORK_HUB_URL "$(network_default NETWORK_HUB_URL)")")
  if [ "$fresh" = 0 ]; then
    pseudonym=$(sed -n 's/^NETWORK_PSEUDONYM=//p' .env | tail -n 1 | tr -d "\"'\r")
  fi
  if [ -n "$(env_get VPN_WG_PRIVATE_KEY)" ]; then path="through your VPN"; else path="direct (no VPN)"; fi
  if [ "$UI_MODE" = rich ]; then
    participant_rich
    exit 0
  fi
  echo
  if [ "$repair" = 1 ]; then echo "SuckerPot is repaired and running in participant mode (${version:-source build})."; else echo "SuckerPot is running in participant mode (${version:-source build})."; fi
  echo "  Pseudonym: ${pseudonym:-none}   Hub: ${hub_host:-unknown}   Path: $path"
  echo
  echo "Open these ports on your router or firewall, all to this machine:"
  printf '  %-12s  ->  %-12s  %-9s  %s\n' "Router port" "This machine" "Protocol" "Sensor"
  while read -r rp hp proto sname; do
    printf '  %-12s  ->  %-12s  %-9s  %s\n' "$rp" "$hp" "$proto" "$sname"
  done < <(ports_table)
  adm=$(env_get ADMIN_SSH_PORT)
  if [ -n "$adm" ]; then
    echo "Never forward your admin SSH port ($adm on this machine)."
  else
    echo "Never forward the admin SSH port of this machine."
  fi
  echo "Use port forwards, not your router's DMZ. A DMZ puts every service of this machine on the"
  echo "internet, the real sshd included. It is acceptable only if this machine runs nothing else"
  echo "and its admin SSH port is not 22. The host firewall does not filter internet traffic to this"
  echo "machine's own services: under a DMZ the admin SSH faces the internet, so allow key-only SSH"
  echo "and add a rule on the router or on this machine for the admin port."
  # The host firewall (scripts/host/): offered here, never fatal, only asked on a terminal.
  # shellcheck source=scripts/lib/firewall.sh
  . scripts/lib/firewall.sh
  if [ "$assume_yes" = 0 ]; then fw_step participant 3; else fw_step participant auto; fi
  echo
  echo "Check it any time:      ./scripts/status.sh"
  sched_when=${sched#* }
  sched_when=${sched_when%/6h}
  case $sched in
    "cron "*/6h | "systemd "*/6h) echo "Automatic updates:      every 6 h from ${sched_when%/6h} local time (off: ./scripts/participant.sh auto-update off)" ;;
    "cron "* | "systemd "*) echo "Automatic updates:      daily at ${sched_when} local time (off: ./scripts/participant.sh auto-update off)" ;;
    *) echo "Automatic updates:      off (on: ./scripts/participant.sh auto-update on)" ;;
  esac
  echo "The network counts your sensor after a short probation period set by the hub. The date shows in ./scripts/status.sh."
  echo "Take a snapshot of this machine now if you can."
  # Does the internet already reach the sensors? Local evidence only, no outside connection.
  # Never fatal, never blocks with --yes or without a terminal.
  # shellcheck source=scripts/lib/ports-check.sh
  . scripts/lib/ports-check.sh
  echo
  echo "Checking whether the internet reaches your sensors..."
  pc_since=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)
  pc_rc=0
  ports_check_run 90 "$pc_since" || pc_rc=$?
  if [ "$pc_rc" = 3 ]; then
    pc_done=0
    while [ "$assume_yes" = 0 ] && [ "$pc_done" = 0 ]; do
      printf '  Ports not reachable yet. [r]echeck now (after you opened them), or [c]ontinue and open them later? [c] ' >&2
      pc_ans=""
      IFS= read -r pc_ans <&3 || pc_ans=c
      case $pc_ans in
        r | R)
          pc_rc=0
          ports_check_run 60 "$pc_since" || pc_rc=$?
          [ "$pc_rc" = 3 ] || pc_done=1
          ;;
        *) pc_done=1 ;;
      esac
    done
    if [ "$pc_rc" = 3 ]; then
      echo "Check again any time: ./scripts/participant.sh ports-check"
    fi
  elif [ "$pc_rc" != 0 ]; then
    echo "Check again any time: ./scripts/participant.sh ports-check"
  fi
  exit 0
fi

if [ "$UI_MODE" = rich ]; then
  full_rich
  exit 0
fi
echo
echo "SuckerPot is running."
if [ -n "$public_host" ]; then
  echo "  Dashboard: https://$public_host  (through your tunnel to http://$hbind:$dport)"
else
  echo "  Dashboard: http://$hbind:$dport"
  if [ "$bind" = 127.0.0.1 ]; then
    echo "  On a remote machine, open a tunnel first:"
    echo "    ssh -L $dport:127.0.0.1:$dport <you>@<this-host>"
  fi
fi
echo "  Admin user: $(env_get ADMIN_USERNAME)"
if [ "$pw_generated" = 1 ]; then
  echo "  Admin password (shown once, store it in your password manager now): $pw"
fi
pw=""
echo
if [ "$switching" = 1 ]; then
  echo "Switched from participant mode to full mode. Your data and your network membership are kept."
  echo "Without a VPN file the network worker waits until you upload one in Settings > VPN."
  echo "The settings of the participant install are in .env.participant.bak (delete it once all is well)."
  echo
fi
if [ "${join_network:-0}" = 1 ]; then
  echo "SuckerPot network: you agreed to join. It starts once a VPN is configured (Settings > VPN) and"
  echo "your own public address is known. Leave at any time in the dashboard."
  echo
elif [ "$fresh" = 1 ]; then
  echo "SuckerPot network: not joined. You can join later in the dashboard."
  echo
fi
echo "Next steps:"
echo "  1. Sign in. The setup opens by itself."
echo "  2. Forward the ports listed on the Ports page of the dashboard on your router."
echo "     Never forward the dashboard port ($dport) or your admin SSH port."
echo "  3. Install the host firewall: ./scripts/participant.sh firewall (details: docs/deployment.md#host-firewall)"
echo "  4. Take a snapshot of the machine."
