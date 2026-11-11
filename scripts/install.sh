#!/usr/bin/env bash
# SuckerPot installer. Run it from a checkout of a release tag:
#
#   git clone --depth 1 --branch vX.Y.Z <repository-url> suckerpot && cd suckerpot
#   ./scripts/install.sh
#
# It checks the machine, asks a few questions, generates every secret on this host, writes .env
# (mode 0600), creates the data volumes and starts the stack. See docs/design/m28.md section 2.
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
#
#   Participant mode (docs/design/m32.md): sensors, database, ingest and the network node, no
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
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh

TOTAL=10
LOG=install.log

die() {
  echo "install: $*" >&2
  log "FAILED: $*"
  exit 1
}
log() { [ "$dry_run" = 1 ] || printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"; }
step() {
  printf '[%s/%s] %s\n' "$1" "$TOTAL" "$2"
  log "step $1: $2"
}
note() { echo "      $*"; }
warn() { echo "      warning: $*" >&2; }

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
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done


if [ "$dry_run" = 1 ] && [ -z "$env_out" ]; then die "--dry-run needs --env-out PATH"; fi
if [ "$dry_run" = 0 ] && [ -n "$env_out" ]; then die "--env-out is only for --dry-run"; fi
case ${lowmem:-auto} in auto | on | off) ;; *) die "--lowmem must be auto, on or off" ;; esac
lowmem=${lowmem:-auto}
# Applies what --lite implies for --lowmem. Also called when the installer switches to lite itself.
lite_lowmem() {
  case $lowmem in auto | on) lowmem=on ;; *) die "--lite needs the low-memory overlay: it cannot be combined with --lowmem off" ;; esac
}
if [ "$lite" = 1 ]; then lite_lowmem; fi

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
  printf '  %s [%s]: ' "$__q" "$__d" >&2
  IFS= read -r __ans <&3 || __ans=""
  printf -v "$__var" %s "${__ans:-$__d}"
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
    echo "SuckerPot is already installed here in $cur_stack mode (.env exists). Nothing was changed."
    echo "Update: just update. Start the steps again without changing settings: ./scripts/install.sh --repair"
    if [ -f scripts/status.sh ]; then bash scripts/status.sh || true; fi
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
  if [[ ${early_kb:-} =~ ^[0-9]+$ ]] && [ "$early_kb" -lt $((2 * 1024 * 1024 - 65536)) ] \
    && [ "$early_kb" -ge $((1024 * 1024 - 131072)) ]; then
    early_gib=$(awk -v k="$early_kb" 'BEGIN {printf "%.1f", k / 1048576}')
    note "This machine reports $early_gib GiB of memory. The default setup needs 2 GiB."
    if [ "$assume_yes" = 1 ]; then
      note "Taking the lite setup (--lite): four sensors (SSH, Telnet, web, Redis) and lower memory limits."
      a=yes
    else
      noask=0
      ask a "Use the lite setup instead? Four sensors (SSH, Telnet, web, Redis) and lower memory limits. (yes/no)" yes
      noask=1
    fi
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
  engine=$(docker version --format '{{.Server.Version}}' 2> /dev/null) \
    || die "Docker does not answer for this user. Try: sudo usermod -aG docker \$USER, then log in again."
  ver_ge "${engine%%[-+]*}" 24.0 || die "Docker Engine 24 or newer is required (found $engine)"
  if ! ver_ge "${engine%%[-+]*}" 28.0; then
    warn "Docker Engine $engine is older than 28. On this engine the internal networks are NOT isolated from the host (the isolation needs gateway_mode_ipv4: isolated, from Engine 28). Upgrading Docker Engine to 28 or newer is strongly recommended."
  fi
  cver=$(docker compose version --short 2> /dev/null) || die "Docker Compose v2 is not available"
  ver_ge "${cver#v}" 2.24 || die "Docker Compose 2.24 or newer is required (found $cver)"

  meminfo=${SELFHOSTR_MEMINFO:-/proc/meminfo}
  mem_kb=$(awk '/^MemTotal:/ {print $2}' "$meminfo" 2> /dev/null || true)
  [[ ${mem_kb:-} =~ ^[0-9]+$ ]] || die "cannot read the memory size from $meminfo"
  if [ "$fresh" = 1 ] || [ "$switching" = 1 ]; then
    if [ "$lite" = 1 ]; then
      # A "1 GiB" machine reports a little less than 1 GiB to the kernel.
      if [ "$mem_kb" -lt $((1024 * 1024 - 131072)) ]; then
        die "this machine reports $(awk -v k="$mem_kb" 'BEGIN {printf "%.1f", k / 1048576}') GiB of memory: even --lite needs a machine with 1 GiB (and some swap)"
      fi
      # Containers never swap (memswap_limit equals mem_limit). Host swap only gives the host room
      # when a burst of attacks pushes the whole machine, so the global OOM killer is less likely
      # to restart the database.
      swap_kb=$(awk '/^SwapTotal:/ {print $2}' "$meminfo" 2> /dev/null || true)
      [[ ${swap_kb:-} =~ ^[0-9]+$ ]] || swap_kb=0
      if [ "$swap_kb" -lt $((512 * 1024)) ]; then
        warn "this machine has less than 512 MiB of swap. On 1 GiB, a burst of attacks can make the kernel kill a container (the database included). Add 1 GiB of swap first (docs/vps.md)."
        if [ "$assume_yes" = 0 ]; then
          ask a "Continue without enough swap? (yes/no)" no
          case $a in y | yes) ;; *) die "add swap, then run the installer again" ;; esac
        fi
      fi
    elif [ "$mem_kb" -lt $((2 * 1024 * 1024 - 65536)) ]; then
      mem_gib=$(awk -v k="$mem_kb" 'BEGIN {printf "%.1f", k / 1048576}')
      if [ "$mem_kb" -ge $((1024 * 1024 - 131072)) ]; then
        die "this machine reports $mem_gib GiB of memory and the full setup needs 2 GiB. Only the participant lite setup fits here: ./scripts/install.sh --participant --lite"
      fi
      die "this machine reports $mem_gib GiB of memory: SuckerPot needs at least 2 GiB, or 1 GiB with --participant --lite"
    fi
  fi
  if [ "$fresh" = 1 ]; then

    root=$(docker info --format '{{.DockerRootDir}}' 2> /dev/null || true)
    free_kb=${SELFHOSTR_FREE_DISK_KB:-$(df -Pk "${root:-/}" 2> /dev/null | awk 'NR==2 {print $4}')}
    [[ ${free_kb:-} =~ ^[0-9]+$ ]] || die "cannot read the free disk space"
    if [ "$free_kb" -lt $((15 * 1024 * 1024)) ]; then
      die "less than 15 GiB free under Docker's data folder"
    elif [ "$free_kb" -lt $((30 * 1024 * 1024)) ]; then
      warn "less than 30 GiB free under Docker's data folder; logs and payloads need room"
    fi

    # Never adopt or mix with an existing install: its database password lives inside the data.
    if [ -n "$(docker volume ls -q --filter "name=^${prefix}_" 2> /dev/null | head -n 1)" ]; then
      die "Data volumes named '${prefix}_*' already exist. Restore your old .env, or pick another --prefix. (They are never adopted: the database password lives inside the data.)"
    fi
    if [ -n "$(docker ps -a -q --filter "label=com.docker.compose.project=$project" 2> /dev/null | head -n 1)" ]; then
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
    printf '  Admin password (at least 12 characters, empty = generate one): ' >&2
    IFS= read -rs pw <&3 || pw=""
    echo >&2
    if [ -z "$pw" ]; then
      pw=$(gen_secret 24)
      pw_generated=1
    else
      printf '  Repeat the password: ' >&2
      IFS= read -rs pw2 <&3 || pw2=""
      echo >&2
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
  echo
  consent_screen "$pseudonym" "$vpn_flag"
  if [ "$assume_yes" = 1 ]; then
    echo "--yes was given: this counts as your agreement to join as described above."
    echo
  else
    printf 'Join the SuckerPot network as described? [y/N] ' >&2
    IFS= read -r a <&3 || a=""
    case $a in
      y | Y | yes | YES | Yes) ;;
      *) echo "Not joined. Nothing was installed." >&2; log "consent declined"; exit 1 ;;
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
    echo
    pseudonym=$(pseudonym_random) || die "could not make a pseudonym"
    consent_screen_full "$pseudonym"
    echo "--join-network was given: this counts as your agreement to join as described above."
    echo
    join_network=1
  elif [ "$assume_yes" = 1 ]; then
    note "the SuckerPot network is off: --yes does not join it (add --join-network to join)"
  else
    # shellcheck source=scripts/lib/pseudonym.sh
    . scripts/lib/pseudonym.sh
    echo
    pseudonym=$(pseudonym_random) || die "could not make a pseudonym"
    consent_screen_full "$pseudonym"
    printf 'Join the SuckerPot network? [y/N] ' >&2
    # End of input is not a yes: only a typed y is.
    IFS= read -r a <&3 || die "no answer to the network question; use --join-network or --no-network"
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
    docker pull "${image_prefix}-ingest:${version}" > /dev/null || die "could not pull ${image_prefix}-ingest:${version}"
  else
    SUCKERPOT_IMAGE_PREFIX=$image_prefix bash scripts/verify-images.sh --pull --only ingest "$version" \
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
        docker pull "$api_image" > /dev/null || die "could not pull $api_image"
      else
        # Verify before the image ever runs (it hashes the password): pulled by the verified digest.
        SUCKERPOT_IMAGE_PREFIX=$image_prefix bash scripts/verify-images.sh --pull --only api "$version" \
          || die "the api image could not be verified, so it was not run. Check the version, or only if you accept the risk: --skip-verify"
      fi
    else
      api_image=suckerpot-install-api
      # The end-to-end test must not retag anything that a live install may use.
      [ "${SELFHOSTR_TEST_INSTALL:-}" != 1 ] || api_image="local/${project}-install-api:test"
      docker build -q -f api/Dockerfile -t "$api_image" . > /dev/null || die "could not build the api image"
    fi
    hash=$(printf '%s\n' "$pw" | docker run --rm -i --network none --cap-drop ALL \
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
  umask 077
  tmp="${target}.tmp"
  rm -f "$tmp"
  trap 'rm -f "$tmp"' EXIT
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
      # Participant mode (docs/design/m32.md section 4.1). The hub address and key are NOT copied:
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
    if ! docker compose exec -T backup /bin/sh /backup-service.sh now preswitch; then
      rm -f "$tmp"
      die "the backup before the switch failed; nothing was changed"
    fi
    # Keep a copy of the participant .env until the switch has worked.
    cp -p .env .env.participant.bak
    chmod 600 .env.participant.bak
  fi
  mv "$tmp" "$target"
  trap - EXIT
  chmod 600 "$target"
  note "wrote $target (mode 0600)"
fi

if [ "$dry_run" = 1 ]; then
  echo
  echo "Dry run finished: $target holds the would-be configuration. No Docker call was made."
  exit 0
fi

# ---------------------------------------------------------------- 7. volumes
step 7 "Creating the data volumes"
if [ "${SELFHOSTR_TEST_INSTALL:-}" = 1 ]; then
  # End-to-end test (scripts/e2e/participant.sh): the test overlay makes every volume local to the
  # throwaway project, so there is nothing to create here.
  note "test install: volumes are local to the throwaway project"
else
  SUCKERPOT_VOLUME_PREFIX=$prefix bash scripts/ensure-volumes.sh
fi

# ---------------------------------------------------------------- 8. guards
step 8 "Checking the port layout and VPN settings"
scripts/check-ports.sh
# Empty VPN_WG_* values are valid (the vpn container idles until a file is uploaded), so this
# always runs: it still checks the egress passwords and any WireGuard values that were written.
# It does nothing unless the egress profile is on.
scripts/check-vpn-env.sh
if [ "$stack" = participant ]; then
  scripts/check-participant.sh
elif [ -z "$(env_get VPN_WG_PRIVATE_KEY)" ]; then
  note "no WireGuard file given: upload it in the dashboard (Settings > VPN); the gate stays closed until then"
fi

# ---------------------------------------------------------------- 9. start
step 9 "Starting SuckerPot (this can take several minutes)"
up_extra=()
if [ "$switching" = 1 ]; then
  # hubproxy goes away, api and vpn start. A service of a profile that is no longer on is not an
  # orphan to compose, so it is stopped by name.
  docker compose --profile direct rm -sf hubproxy > /dev/null 2>&1 || true
  up_extra=(--remove-orphans)
fi
if [ "$mode" = images ]; then
  if [ "$skip_verify" = 1 ]; then
    warn "--skip-verify: the image signatures were NOT checked"
    docker compose pull || die "could not pull the images. Check the version and your network, then run: docker compose pull"
  else
    SUCKERPOT_IMAGE_PREFIX=$image_prefix bash scripts/verify-images.sh --pull "$version" || die "the image signatures could not be verified, so nothing was started. Check the version, or run scripts/verify-images.sh $version. Only if you accept the risk: --skip-verify"
    # Our images are now local (pulled by verified digest); this fetches only the pinned third-party ones.
    docker compose pull --policy missing || die "could not pull the remaining images (database, VPN). Check your network, then run: docker compose pull --policy missing"
  fi
  docker compose up -d --no-build --pull never --wait --wait-timeout 600 ${up_extra[@]+"${up_extra[@]}"} || die "the stack did not become healthy. See: docker compose ps, docker compose logs"
else
  SUCKERPOT_BUILD_VERSION=$(git describe --tags --always --dirty 2> /dev/null || echo dev)
  SUCKERPOT_BUILD_COMMIT=$(git rev-parse --short HEAD 2> /dev/null || echo unknown)
  export SUCKERPOT_BUILD_VERSION SUCKERPOT_BUILD_COMMIT
  docker compose up -d --build --wait --wait-timeout 900 ${up_extra[@]+"${up_extra[@]}"} || die "the stack did not become healthy. See: docker compose ps, docker compose logs"
fi
if [ "$stack" = full ]; then
  if [ "$repair" = 1 ]; then
    bind=$(env_get DASHBOARD_BIND 127.0.0.1)
    dport=$(env_get DASHBOARD_PORT 8443)
    public_host=""
  fi
  hbind=$bind
  [ "$hbind" = 0.0.0.0 ] && hbind=127.0.0.1
  ok=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS --max-time 5 "http://$hbind:$dport/healthz" > /dev/null 2>&1; then ok=1; break; fi
    sleep 3
  done
  [ "$ok" = 1 ] || die "the dashboard does not answer on http://$hbind:$dport/healthz. See: docker compose logs api"
fi

# ---------------------------------------------------------------- 10. summary
step 10 "Done"

# Automatic updates: the schedule is a line in the crontab of this user (or a systemd user timer).
sched=off
if [ "$stack" = participant ] || [ "$switching" = 1 ]; then
  # shellcheck source=scripts/lib/schedule.sh
  . scripts/lib/schedule.sh
  if [ "$switching" = 1 ] && [ "$keep_auto" = no ]; then
    schedule_remove || warn "could not remove the update schedule; see ./scripts/participant.sh auto-update off"
  elif [ "$(env_get AUTO_UPDATE_ENABLED false)" = true ]; then
    if sched=$(schedule_status 2> /dev/null); then
      :
    else
      read -r sh sm < <(schedule_random_time)
      if schedule_install "$sh" "$sm"; then
        sched=$(schedule_status || echo off)
      else
        warn "could not schedule the automatic updates. Update by hand with: just update"
        env_set_line .env AUTO_UPDATE_ENABLED false
        sched=off
      fi
    fi
  fi
fi

if [ "$stack" = participant ]; then
  hub_host=$(url_host "$(env_get NETWORK_HUB_URL "$(network_default NETWORK_HUB_URL)")")
  if [ "$fresh" = 0 ]; then
    pseudonym=$(sed -n 's/^NETWORK_PSEUDONYM=//p' .env | tail -n 1 | tr -d "\"'\r")
  fi
  if [ -n "$(env_get VPN_WG_PRIVATE_KEY)" ]; then path="through your VPN"; else path="direct (no VPN)"; fi
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
  if [ "$assume_yes" = 0 ]; then fw_step participant 3; else fw_step participant; fi
  echo
  echo "Check it any time:      ./scripts/status.sh"
  case $sched in
    "cron "* | "systemd "*) echo "Automatic updates:      daily at ${sched#* } local time (off: ./scripts/participant.sh auto-update off)" ;;
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
