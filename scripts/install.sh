#!/usr/bin/env bash
# SuckerPot installer. Run it from a checkout of a release tag:
#
#   git clone <repository-url> suckerpot && cd suckerpot
#   git switch --detach "$(git describe --tags --abbrev=0)"   # the latest release
#   ./scripts/install.sh
#
# It checks the machine, asks at most two questions (the install type, and the participant consent),
# generates every secret on this host, writes .env (mode 0600), creates the data volumes and starts
# the stack. Everything else has a default and a flag. See docs/dev/design/m28.md section 2 and
# docs/dev/design/installer-ux.md.
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
#                      [--admin-user admin] [--admin-password-stdin]  (default: a generated password,
#                                                                   shown once at the end)
#                      [--admin-ssh-port N] [--lowmem auto|on|off] [--wg-conf PATH] [--skip-verify]
#                      [--allow-lan]  (publish the dashboard on a non-loopback address WITHOUT an
#                                      https tunnel: plain http, cookies lose Secure; not for the internet)
#                      [--join-network]  (join the experimental SuckerPot network; without it the answer is no)
#                      [--no-network]  (accepted for older scripts: the network is off unless --join-network)
#                      [--update-check]  (check once a day whether a newer release exists; off by default)
#                      [--self-address ADDR]  (your own public address; the dashboard learns it otherwise)
#                      [--dry-run --env-out PATH]
#                      [--plain]  (one line per step, as without a terminal)
#                      [--no-firewall]  (participant mode: skip the host firewall, installed by default)
#                      [--engine docker|podman]  (the container engine; Podman is experimental and
#                                 needs the host firewall; asked only when both are installed)
#
#   Participant mode (docs/dev/design/m32.md): sensors, database, ingest and the network node, no
#   dashboard, no admin account, no VPN needed (the hub is reached through hubproxy):
#   scripts/install.sh --participant [--yes] [--pseudonym NAME | --no-pseudonym]
#                      [--country CC [--show-country]] [--wg-conf PATH [--verifier]]
#                      [--country-check local|download|off]  (compare --country with a GeoIP
#                                 database on this machine; download: fetch DB-IP's free country
#                                 list first, from download.db-ip.com; default local, never sent)
#                      [--no-auto-update] [--feeds] [--self-address ADDR] [--sensors LIST]
#                      [--lite]  (1 GiB VPS or Raspberry Pi: lowest memory limits, sensors
#                                 ssh,telnet,web,redis unless --sensors is given; docs/vps.md)
#   scripts/install.sh --full         on a participant install: switch to full mode (keeps data)
#   scripts/install.sh --repair       existing install: volumes, start and schedule steps again
#
# Without --participant or --full, a fresh install asks which one on a terminal; without a
# terminal (or with --yes) it is a full install, as before. A participant install shows the consent
# screen and asks to join; --yes is that consent. On a terminal it then asks for the node name
# (the pseudonym; --node-name and --no-node-name are the same as --pseudonym and --no-pseudonym)
# and whether to show a country, unless flags answer them. --non-interactive never reads the
# terminal: the run behaves as without one (the consent then needs --yes).
# --yes takes the defaults. The admin password is generated and printed once, or read from stdin
# with --admin-password-stdin. A full install never joins the SuckerPot network without
# --join-network. When Docker is missing, it shows the commands that install it from Docker's
# package repository and, on a terminal, runs them after one "yes".
# Plain output (no terminal, TERM=dumb, --plain) ends with a "result: ok|failed ..." line.
# --dry-run --env-out writes the would-be .env to PATH with a placeholder admin hash and makes
# no Docker call (used by the tests).
# On a terminal the installer shows a step list with a progress bar and writes the output of every
# command to install.log. Without a terminal, with TERM=dumb or with --plain, it prints one line per
# step and the command output, as it always did. NO_COLOR keeps the display without colours.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh
owner_init

TOTAL=10
LOG=install.log

# shellcheck source=scripts/lib/ui.sh
. scripts/lib/ui.sh
# shellcheck source=scripts/lib/ask.sh
. scripts/lib/ask.sh
# shellcheck source=scripts/lib/stackop.sh
. scripts/lib/stackop.sh
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
# Plain mode: "[n/N] title" when a step starts, "[n/N] ok" when the next one starts, and one
# "result:" line at the end (docs/dev/design/installer-ux.md, 3.9).
cur_step=""
step() {
  if [ "$UI_MODE" = plain ]; then
    [ -z "$cur_step" ] || printf '[%s/%s] ok\n' "$cur_step" "$TOTAL"
    printf '[%s/%s] %s\n' "$1" "$TOTAL" "$2"
  fi
  cur_step=$1
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
# plain_result STATUS: the last plain lines, for scripts and CI. Called by ui_exit.
plain_result() {
  local where="none"
  [ "$UI_MODE" = plain ] || return 0
  [ -z "$UI_LOG" ] || where=$(_ui_abs "$UI_LOG")
  if [ -n "${stopped_why:-}" ]; then
    echo "result: stopped reason=$stopped_why step=${cur_step:-0} log=$where"
  elif [ "$1" = 0 ]; then
    [ -z "$cur_step" ] || printf '[%s/%s] ok\n' "$cur_step" "$TOTAL"
    echo "result: ok type=${stack:-none} version=${version:-source} engine=${ENGINE_ID:-docker} log=$where"
  else
    [ -z "$cur_step" ] || printf '[%s/%s] failed\n' "$cur_step" "$TOTAL"
    echo "result: failed step=${cur_step:-0} log=$where"
  fi
}
# At the end, however it ends: the plain result line, and the files given back to the owner of
# the folder when the installer runs as root through sudo (owner_fix, scripts/lib/env.sh).
install_exit() { owner_fix; plain_result "$1"; }
UI_ON_EXIT=install_exit
# A command that fails where no message was planned (set -e) names itself and its line, on the
# screen and in install.log, instead of a bare "failed" step.
on_err() {
  printf 'install: unexpected failure at line %s: %s\n' "$1" "$2" >&2
  log "unexpected failure at line $1: $2"
}
trap 'on_err "$LINENO" "$BASH_COMMAND"' ERR
# say: text for the person at the terminal (stdout in plain mode, the display in rich mode, where it
# is indented like the rest of the screen).
say() { if [ -n "$*" ]; then echo "${UI_IND}$*" 1>&"$UI_OUT"; else echo 1>&"$UI_OUT"; fi; }
# show CMD...: the output of CMD for the terminal, indented in rich mode, unchanged otherwise.
show() {
  # Rich: indented and wrapped at the width of the terminal (the consent text is wider than 80).
  # The lines broken by hand are joined again and wrapped at the terminal's width minus 4.
  if [ "$UI_MODE" = rich ]; then "$@" | text_wrap --join $((UI_COLS > 30 ? UI_COLS - 4 : 76)) | sed 's/^./  &/' 1>&"$UI_OUT"; else "$@"; fi
}
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
update_check_flag=0
no_firewall=0
engine_arg=""
non_interactive=0
country_check=""
# The arguments as given: the installer starts again with them after installing Docker (O4).
orig_args=("$@")
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
    --pseudonym | --node-name) need_value "$@"; pseudonym_arg=$2; shift ;;
    --no-pseudonym | --no-node-name) no_pseudonym=1 ;;
    --country-check) need_value "$@"; country_check=$2; shift ;;
    --non-interactive) non_interactive=1 ;;
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
    --update-check) update_check_flag=1 ;;
    --no-firewall) no_firewall=1 ;;
    --engine) need_value "$@"; engine_arg=$2; shift ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done


if [ "$dry_run" = 1 ] && [ -z "$env_out" ]; then die "--dry-run needs --env-out PATH"; fi
if [ "$dry_run" = 0 ] && [ -n "$env_out" ]; then die "--env-out is only for --dry-run"; fi

# The display. The dry run writes no log, as before.
if [ "$dry_run" = 1 ]; then ui_init "" "$plain"; else ui_init "$LOG" "$plain"; fi
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

# swap_check "what the machine is": warns when there is little swap, and goes on (the final screen
# and ./scripts/status.sh repeat the advice).
# Containers never swap (memswap_limit equals mem_limit). Host swap only gives the host room
# when a burst of attacks pushes the whole machine, so the global OOM killer is less likely
# to restart the database.
swap_check() {
  swap_kb=$(awk '/^SwapTotal:/ {print $2}' "$meminfo" 2> /dev/null || true)
  [[ ${swap_kb:-} =~ ^[0-9]+$ ]] || swap_kb=0
  if [ "$swap_kb" -lt $((512 * 1024)) ]; then
    warn "this machine has less than 512 MiB of swap. On $1, a burst of attacks can make the kernel kill a container (the database included). Add 1 GiB of swap (docs/vps.md), then: ./scripts/install.sh --repair"
  fi
}

# At most two questions (docs/dev/design/installer-ux.md, phase C): the install type, when no
# --participant or --full says it, and the participant consent. Everything else takes a default or
# a flag. Answers come from the terminal (or SELFHOSTR_TTY, used by the tests), so that stdin stays
# free for --admin-password-stdin. Without a terminal, only --yes may stand in for the consent.
has_tty=0
if [ "$assume_yes" = 0 ] && [ "$non_interactive" = 0 ]; then
  tty=${SELFHOSTR_TTY:-/dev/tty}
  if [ -r "$tty" ] && ( : < "$tty" ) 2> /dev/null; then
    exec 3< "$tty"
    has_tty=1
  fi
fi
# need_tty WHAT: dies when WHAT must be asked and there is no terminal.
need_tty() { [ "$has_tty" = 1 ] || die "no terminal to ask $1 on; use --yes"; }



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
# The install type. A flag that belongs to one mode says it; otherwise the first question asks it
# on a terminal. Without a terminal, or with --yes, the default stays the full install, as before.
header_done=0
if [ -z "$stack" ] && [ "$existing" = 0 ] && [ "$has_tty" = 1 ]; then
  if [ -n "$pseudonym_arg$country$country_check" ] || [ "$no_pseudonym$show_country$verifier$no_auto_update$feeds$lite" != 000000 ]; then
    stack=participant
  elif [ -n "$bind$dport$public_host$admin_user" ] || [ "$pw_stdin$allow_lan$no_network$join_flag$update_check_flag" != 00000 ]; then
    stack=full
  else
    if [ "$UI_MODE" = rich ]; then
      ui_header "installer"
      header_done=1
    fi
    type_kb=$(awk '/^MemTotal:/ {print $2}' "${SELFHOSTR_MEMINFO:-/proc/meminfo}" 2> /dev/null || true)
    full_note="For a home server. 2 GiB of memory or more."
    if [[ ${type_kb:-} =~ ^[0-9]+$ ]] && [ "$type_kb" -lt "$full_min_kb" ]; then
      full_note="Needs 2 GiB of memory; this machine reports $(gib "$type_kb") GiB."
    fi
    ui_pause
    {
      [ "$UI_MODE" = rich ] || echo
      echo "${UI_IND}What do you want to install?"
      echo
      echo "${UI_IND}  1  Participant node   Sensors only. Joins the SuckerPot network."
      echo "${UI_IND}                        For a VPS. 1 GiB of memory or more."
      echo "${UI_IND}  2  Full install       Sensors, dashboard, VPN egress, reports."
      echo "${UI_IND}                        $full_note"
      echo
      printf '%sChoose 1 or 2 [1]: ' "$UI_IND"
    } 1>&"$UI_ERR"
    IFS= read -r a <&3 || a=""
    answered
    case $a in
      "" | 1 | p | participant) stack=participant ;;
      2 | f | full) stack=full ;;
      *) die "answer 1 (participant node) or 2 (full install)" ;;
    esac
    log "install type: $stack"
  fi
fi
# Without a terminal the full install is the default only when --yes says "take the defaults", as
# before (the old installer stopped on /dev/tty). An explicit --full or --participant is enough.
if [ -z "$stack" ] && [ "$existing" = 0 ] && [ "$has_tty" = 0 ] && [ "$assume_yes" = 0 ]; then
  die "no terminal to ask which install you want; use --yes (a full install), --full or --participant"
fi
stack=${stack:-full}
fresh=$((1 - existing))

# The release of the images. A checkout of a release tag uses that tag. A checkout of a branch (dev,
# main) has no release of its own: on a terminal the installer asks whether to run the signed
# images of the newest release, or to build this checkout from source. Without a terminal it stops
# at step 5 as before, unless --version (latest or vX.Y.Z) or --source says it.
release_hint=""
release_args=()
latest_release() { latest_known_release; }
if [ "$version" = latest ]; then
  version=$(latest_release)
  [ -n "$version" ] || die "--version latest: this checkout knows no release tag (git fetch --tags, then try again)"
  log "release: $version (--version latest)"
fi
# A node bundle (scripts/get.sh, no git): its own release, or for a testing bundle of a branch the
# newest release it knows. It holds no sources, so it never builds.
if layout_bundle && [ "$fresh" = 1 ]; then
  [ "$mode" != source ] || die "a node bundle holds no sources, so --source cannot build here: use the signed images (the default), or a git checkout to build"
  mode=images
  if [ -z "$version" ]; then
    if [ "$(bundle_get signed)" = 1 ]; then
      version=$(bundle_get version)
    else
      version=$(latest_release)
      [ -n "$version" ] || die "this testing bundle ($(bundle_get ref)) knows no release to take the images from: pass --version vX.Y.Z"
      note "testing scripts of $(bundle_get ref) (not signed), with the signed images of $version"
    fi
  fi
fi
if [ "$fresh" = 1 ] && [ "$dry_run" = 0 ] && [ "$mode" != source ] && [ -z "$version" ] \
  && ! git describe --tags --exact-match HEAD > /dev/null 2>&1; then
  rel_latest=$(latest_release)
  rel_where=$(git symbolic-ref --short -q HEAD 2> /dev/null || git rev-parse --short HEAD 2> /dev/null || echo "this checkout")
  if [ -n "$rel_latest" ]; then
    release_hint="this checkout (${rel_where}) is not a release tag: pass --version latest (the signed images of $rel_latest), --version vX.Y.Z or --source"
    if [ "$has_tty" = 1 ] && [ -z "$mode" ]; then
      if [ "$UI_MODE" = rich ] && [ "$header_done" = 0 ]; then
        if [ "$stack" = participant ]; then ui_header "participant node"; else ui_header "full install"; fi
        header_done=1
      fi
      ui_pause
      ASK_TTY=1 ASK_OUT=$UI_ERR ASK_IND=$UI_IND
      [ "$UI_MODE" = rich ] || ASK_PLAIN=1
      echo 1>&"$UI_ERR"
      ask_lines "" "This checkout is the branch $rel_where, not a release. Which images should run?"
      echo 1>&"$UI_ERR"
      rel_choice=images
      ask_pick rel_choice images "" \
        "images|Signed images of $rel_latest|recommended: verified, ready to run" \
        "source|Build from this checkout|slower; for testing the branch"
      case $rel_choice in
        source) mode=source; release_args=(--source) ;;
        *) mode=images; version=$rel_latest; release_args=(--version "$rel_latest") ;;
      esac
      log "release: ${version:-source build of $rel_where} (asked)"
    elif [ "$mode" = images ] && [ "$has_tty" = 1 ]; then
      version=$rel_latest
      release_args=(--version "$rel_latest")
      note "--images on the branch $rel_where: the signed images of $rel_latest"
    fi
  fi
fi
# The container engine. An existing install keeps the one in its .env (none there means Docker).
# A fresh install takes --engine, else SUCKERPOT_ENGINE from the environment, else the engine this
# host has. With both installed (UI phase D), a terminal asks; Docker wins while it is active,
# because Podman refuses a host where Docker runs too (docs/dev/design/podman.md N3).
# docker_active: Docker runs, or nothing can tell (no systemd): then Docker is assumed, as before.
docker_active() {
  command -v systemctl > /dev/null 2>&1 || return 0
  systemctl is-active --quiet docker.service 2> /dev/null || systemctl is-active --quiet docker.socket 2> /dev/null
}
choose_engine() {
  local a def=1 dv pv c=${SUCKERPOT_CONF_ROOT:-}
  if ! command -v docker > /dev/null 2>&1 || ! command -v podman > /dev/null 2>&1; then
    engine_use "$(engine_detect)"
    return 0
  fi
  # Both commands. Docker while it runs (Podman refuses a host where Docker is active), and also
  # when this is not a packaged Podman with its socket unit (a podman command alone proves little).
  if docker_active || { [ ! -e "$c/usr/lib/systemd/system/podman.socket" ] && [ ! -e "$c/lib/systemd/system/podman.socket" ]; }; then
    log "engine: Docker and Podman are both installed; Docker is used (Docker is active, or Podman has no socket unit; --engine podman chooses Podman)"
    engine_use docker
    return 0
  fi
  # Docker is off (Fedora's docker-compose package brings the docker command along, for example).
  # Without a terminal, or with --yes: Podman, the engine this machine can run.
  if [ "$has_tty" = 0 ] || [ "$assume_yes" = 1 ]; then
    log "engine: Docker and Podman are both installed and Docker is off: Podman is used (--engine docker chooses Docker)"
    engine_use podman
    return 0
  fi
  pv=$(podman --version 2> /dev/null | sed -n 's/^podman version \([0-9.]*\).*/\1/p' || true)
  dv=$(ctr --version 2> /dev/null | sed -n 's/^Docker version \([0-9.]*\).*/\1/p' || true)
  def=2
  ui_pause
  {
    [ "$UI_MODE" = rich ] || echo
    echo "${UI_IND}Docker ${dv:-?} and Podman ${pv:-?} are both installed. Docker is not active."
    echo
    echo "${UI_IND}  1  Docker"
    echo "${UI_IND}  2  Podman   experimental; the host firewall is required"
    echo
    printf '%sChoose 1 or 2 [%s]: ' "$UI_IND" "$def"
  } 1>&"$UI_ERR"
  IFS= read -r a <&3 || a=""
  answered
  case ${a:-$def} in
    1 | d | docker) engine_use docker ;;
    2 | p | podman) engine_use podman ;;
    *) die "answer 1 (Docker) or 2 (Podman)" ;;
  esac
  log "engine: $ENGINE_ID"
}
if [ -n "$engine_arg" ]; then
  case $engine_arg in docker | podman) ;; *) die "--engine must be docker or podman" ;; esac
  if [ "$fresh" = 0 ] && [ "$engine_arg" != "$ENGINE_ID" ]; then
    die "this install runs on $(engine_name); --engine $engine_arg cannot change that. Move it with a backup and a new install (docs/install.md)."
  fi
  engine_use "$engine_arg"
elif [ "$fresh" = 1 ] && [ "$ENGINE_FROM" = default ]; then
  choose_engine
fi
# A fresh Podman install is checked in step 1, once this user can reach the root Podman socket
# (podman_prepare); an existing one has its overlay in COMPOSE_FILE and is checked here.
if [ "$ENGINE_ID" != podman ] || [ "$fresh" = 0 ]; then
  engine_ready || die "$ENGINE_UNREADY_MSG"
fi
# Podman runs the signed release images only (design D6): source builds stay on Docker.
if [ "$ENGINE_ID" = podman ] && [ "$fresh" = 1 ] && [ "$mode" = source ]; then
  die "--source is not supported on Podman yet: use the release images (the default), or Docker"
fi
# The helper scripts (verify-images.sh, ensure-volumes.sh...) run before .env exists: they read
# the engine from the environment.
export SUCKERPOT_ENGINE

# The header names the install once its mode is known (an existing install keeps its own).
if [ "$UI_MODE" = rich ] && [ "$header_done" = 0 ]; then
  if [ "$stack" = participant ]; then ui_ctx="participant node"; else ui_ctx="full install"; fi
  [ "$switching" = 0 ] || ui_ctx="$ui_ctx · switch from participant mode"
  [ "$repair" = 0 ] || ui_ctx="$ui_ctx · repair"
  [ "$dry_run" = 0 ] || ui_ctx="$ui_ctx · dry run"
  [ "$UI_UTF8" = 1 ] || ui_ctx=${ui_ctx// · / - }
  ui_header "$ui_ctx"
fi
# The rich display: a fixed list of steps (weights for the bar), and where the numbered steps go.
if [ "$stack" = participant ]; then
  ui_plan "check|Check this machine|4" "settings|Settings and secrets|8" "volumes|Data volumes and checks|4" \
    "images|Verify and download images|35" "start|Start SuckerPot|30" "updates|Automatic updates|2" \
    "firewall|Host firewall|5" "enrol|Join the network|8" "reach|Sensor reachability|12"
else
  ui_plan "check|Check this machine|4" "settings|Settings and secrets|8" "admin|Admin account|12" \
    "volumes|Data volumes and checks|4" "images|Verify and download images|35" "start|Start SuckerPot|30" \
    "dashboard|Dashboard answers|7"
fi
STEP_ROW=([1]=check [2]=settings [3]=settings [4]=settings [5]=settings [6]=settings [7]=volumes [8]=volumes)
# A full install hashes the admin password (step 5) after the settings, then writes .env (step 6).
if [ "$stack" = full ]; then STEP_ROW[5]="admin" STEP_ROW[6]="admin"; fi
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
  [ "$update_check_flag" = 0 ] || bad+=(--update-check)
  [ "${#bad[@]}" -eq 0 ] || die "these flags need --full: ${bad[*]}"
else
  bad=()
  [ -z "$pseudonym_arg" ] || bad+=(--pseudonym)
  [ "$no_pseudonym" = 0 ] || bad+=(--no-pseudonym)
  [ -z "$country" ] || bad+=(--country)
  [ "$show_country" = 0 ] || bad+=(--show-country)
  [ "$verifier" = 0 ] || bad+=(--verifier)
  [ "$no_auto_update" = 0 ] || bad+=(--no-auto-update)
  [ "$feeds" = 0 ] || bad+=(--feeds)
  [ "$lite" = 0 ] || bad+=(--lite)
  [ -z "$country_check" ] || bad+=(--country-check)
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
  [ "$update_check_flag" = 0 ] || bad+=(--update-check)
  [ -z "$self_address" ] || bad+=(--self-address)
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
  case ${country_check:-local} in local | download | off) ;; *) die "--country-check must be local, download or off" ;; esac
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
# takes the lite setup and goes on exactly as if --lite had been given. Reading
# /proc/meminfo needs no Docker, so this is decided before anything depends on $lite.
if [ "$dry_run" = 0 ] && [ "$stack" = participant ] && [ "$lite" = 0 ] && { [ "$fresh" = 1 ] || [ "$switching" = 1 ]; }; then
  early_kb=$(awk '/^MemTotal:/ {print $2}' "${SELFHOSTR_MEMINFO:-/proc/meminfo}" 2> /dev/null || true)
  if [[ ${early_kb:-} =~ ^[0-9]+$ ]] && [ "$early_kb" -lt "$full_min_kb" ] \
    && [ "$early_kb" -ge "$lite_min_kb" ]; then
    early_gib=$(gib "$early_kb")
    note "This machine reports $early_gib GiB of memory. The default setup needs 2 GiB."
    note "Taking the lite setup (--lite): four sensors (SSH, Telnet, web, Redis) and lower memory limits."
    lite=1
    lite_lowmem
  fi
fi

# Docker's signing keys (checked 2026-11-21 against download.docker.com/linux/<distro>/gpg).
DOCKER_KEY_DEB=9DC858229FC7DD38854AE2D88D81803C0EBFCD88  # Debian, Ubuntu (public; gitleaks:allow)
DOCKER_KEY_RPM=060A61C51B558A7F742B77AAC52FEB6B621E9F35  # Fedora, RHEL (public; gitleaks:allow)

# docker_test_keys: the guardrail tests pin throwaway keys with SELFHOSTR_DOCKER_KEY_DEB/RPM. Only
# the test mode (SELFHOSTR_TEST_INSTALL=1) honours them; a real run warns and keeps Docker's keys.
docker_test_keys() {
  [ -n "${SELFHOSTR_DOCKER_KEY_DEB:-}${SELFHOSTR_DOCKER_KEY_RPM:-}" ] || return 0
  if [ "${SELFHOSTR_TEST_INSTALL:-}" = 1 ]; then
    DOCKER_KEY_DEB=${SELFHOSTR_DOCKER_KEY_DEB:-$DOCKER_KEY_DEB}
    DOCKER_KEY_RPM=${SELFHOSTR_DOCKER_KEY_RPM:-$DOCKER_KEY_RPM}
  else
    warn "SELFHOSTR_DOCKER_KEY_DEB and SELFHOSTR_DOCKER_KEY_RPM are for the tests only (SELFHOSTR_TEST_INSTALL=1): ignored, Docker's pinned keys are used"
  fi
  return 0
}

# docker_key_cmd FPR: the command that turns the downloaded key file into a file holding ONLY the
# pinned key. The download is imported into a throwaway keyring; a file with more than one key is
# refused; only the pinned fingerprint is exported, and the export is checked to be exactly that
# one key. The package manager gets the export, never the download.
docker_key_cmd() {
  local in=.suckerpot-state/docker-download.gpg out=.suckerpot-state/docker.asc
  # shellcheck disable=SC2016 # the command is shown and run as written
  printf '( g=$(mktemp -d) && gpg --homedir "$g" --batch --quiet --import %s && test "$(gpg --homedir "$g" --batch --with-colons --list-keys | grep -c ^pub:)" = 1 && gpg --homedir "$g" --batch --export --armor %s > %s && test "$(gpg --batch --with-colons --show-keys %s | grep -c ^pub:)" = 1 && test "$(gpg --batch --with-colons --show-keys %s | awk -F: '\''/^fpr/ {print $10; exit}'\'')" = %s; r=$?; rm -rf "$g"; exit $r )' \
    "$in" "$1" "$out" "$out" "$out" "$1"
}

# docker_plan USER: fills DOCKER_CMDS with the commands that install Docker Engine from Docker's
# own package repository on this distribution (no script piped to a shell: the project's rule).
# Every value put into a command is checked first (a known distribution, a plain codename and user
# name). Returns 1 on a distribution it does not know.
docker_plan() {
  local user=$1 osr=${SELFHOSTR_OS_RELEASE:-/etc/os-release} id="" code="" repo
  local dl=.suckerpot-state/docker-download.gpg key=.suckerpot-state/docker.asc
  id=$(sed -n 's/^ID=//p' "$osr" 2> /dev/null | tr -d '"' | head -n 1)
  code=$(sed -n 's/^VERSION_CODENAME=//p' "$osr" 2> /dev/null | tr -d '"' | head -n 1)
  [ -n "$code" ] || code=$(sed -n 's/^UBUNTU_CODENAME=//p' "$osr" 2> /dev/null | tr -d '"' | head -n 1)
  [[ $user =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || return 1
  DOCKER_CMDS=()
  case $id in
    debian | ubuntu)
      [[ $code =~ ^[a-z0-9-]{1,32}$ ]] || return 1
      DOCKER_CMDS=(
        "sudo apt-get update"
        "sudo apt-get install -y ca-certificates curl gnupg"
        "mkdir -p .suckerpot-state && curl -fsSL https://download.docker.com/linux/$id/gpg -o $dl"
        "$(docker_key_cmd "$DOCKER_KEY_DEB")"
        "printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$id $code stable\\n' \"\$(dpkg --print-architecture)\" > .suckerpot-state/docker.list"
        "sudo install -m 0755 -d /etc/apt/keyrings"
        "sudo install -m 0644 $key /etc/apt/keyrings/docker.asc"
        "sudo install -m 0644 .suckerpot-state/docker.list /etc/apt/sources.list.d/docker.list"
        "sudo apt-get update"
        "sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin"
      )
      ;;
    fedora | rhel | centos | rocky | almalinux)
      case $id in fedora) repo=fedora ;; rhel) repo=rhel ;; *) repo=centos ;; esac
      DOCKER_CMDS=(
        "mkdir -p .suckerpot-state && curl -fsSL https://download.docker.com/linux/$repo/gpg -o $dl"
        "$(docker_key_cmd "$DOCKER_KEY_RPM")"
        "sudo rpm --import $key"
        "curl -fsSL https://download.docker.com/linux/$repo/docker-ce.repo -o .suckerpot-state/docker-ce.repo"
        "sudo install -m 0644 .suckerpot-state/docker-ce.repo /etc/yum.repos.d/docker-ce.repo"
        "sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin"
        "sudo systemctl enable --now docker"
      )
      ;;
    *)
      return 1
      ;;
  esac
  # root needs no group; anyone else joins the docker group.
  [ "$user" = root ] || DOCKER_CMDS+=("sudo usermod -aG docker $user")
  # As root, sudo is not needed (and may not be installed on a minimal VPS).
  if is_root; then
    local i
    for i in "${!DOCKER_CMDS[@]}"; do DOCKER_CMDS[i]=${DOCKER_CMDS[i]//sudo /}; done
  fi
  return 0
}

# offer_docker: no container engine on this host (decision O4). Shows the commands that install
# Docker Engine from Docker's repository and, on a terminal, runs them after one "yes"; then the
# installer starts again under `sg docker`, so this login needs no new session for the group.
# Without a terminal, on "no", or on an unknown distribution: the commands, and stop. Every path where
# nothing was installed ends with status 1 (and a plain "result: stopped" line).
# Podman is not offered here (only Docker is installed for the owner); a Podman host is detected.
offer_docker() {
  local a again user c reason
  docker_test_keys
  # The user who will run docker: the one who called sudo, when the installer runs under sudo
  # (never root's own group). id -un prints the number when this uid has no name (a container).
  user=$(id -un 2> /dev/null || true)
  [[ $user =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || user=${USER:-}
  if [ "$user" = root ] && [[ ${SUDO_USER:-} =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] && [ "$SUDO_USER" != root ]; then user=$SUDO_USER; fi
  if [ "${SELFHOSTR_DOCKER_INSTALLED:-0}" = 1 ]; then
    die "Docker was installed, but the docker command is still not found. Log out and back in, then run the installer again."
  fi
  ui_pause
  if ! docker_plan "$user"; then
    say
    say "No container engine was found. SuckerPot needs Docker Engine."
    say "This distribution is not one the installer knows how to set up (Debian, Ubuntu, Fedora, RHEL family)."
    say "Install Docker Engine as described on https://docs.docker.com/engine/install/ then run the installer again."
    stopped_why=docker-missing
    UI_ENDED=1
    exit 1
  fi
  say
  say "No container engine was found. SuckerPot needs Docker Engine."
  say "These commands install it from Docker's own package repository (the key is checked first):"
  for c in "${DOCKER_CMDS[@]}"; do say "  $c"; done
  if [ "$has_tty" = 0 ]; then
    say "Run them, log out and back in, then run the installer again."
    stopped_why=docker-missing
    UI_ENDED=1
    exit 1
  fi
  if is_root; then
    printf '%sRun them now? [Y/n] ' "$UI_IND" 1>&"$UI_ERR"
  elif command -v sudo > /dev/null 2>&1 && sudo -n true > /dev/null 2>&1; then
    printf '%sRun them now (with sudo)? [Y/n] ' "$UI_IND" 1>&"$UI_ERR"
  else
    printf '%sRun them now? sudo asks for your password. [Y/n] ' "$UI_IND" 1>&"$UI_ERR"
  fi
  IFS= read -r a <&3 || a=n
  answered
  case $a in
    "" | y | Y | yes | YES | Yes) ;;
    *)
      say "Run them yourself, log out and back in, then run the installer again."
      stopped_why=docker-missing
      UI_ENDED=1
      exit 1
      ;;
  esac
  root_ready "Installing Docker" || die "Docker was not installed: run the commands above as root, or with sudo."
  for c in "${DOCKER_CMDS[@]}"; do
    ui_detail "installing Docker: ${c:0:60}"
    ui_run --expect 30 -- bash -c "$c" || die "this command failed (see the log): $c"
  done
  log "Docker installed; starting again in the docker group"
  ui_pause
  if is_root && [ "$(id -un 2> /dev/null)" = root ]; then
    # root uses Docker without a group: the installer simply starts again.
    again=("$PWD/scripts/install.sh" "${orig_args[@]}")
    case " ${orig_args[*]} " in *" --participant "* | *" --full "*) ;; *) again+=("--$stack") ;; esac
    again+=(${release_args[@]+"${release_args[@]}"})
    say "Docker is installed. The installer starts again."
    UI_ENDED=1
    exec 1>&"$UI_OUT" 2>&"$UI_ERR" 3<&-
    SELFHOSTR_DOCKER_INSTALLED=1 exec bash "${again[@]}"
  fi
  # The new group is active only in a new login; sg gives it to the new run. Check it first.
  if ! reason=$(sg docker -c true 2>&1); then
    say "Docker is installed. Log out and back in, then run the installer again."
    say "(sg could not start a shell in the docker group: ${reason:-no reason given})"
    stopped_why=relogin
    UI_ENDED=1
    exit 1
  fi
  # The new run asks nothing again: it gets the install type as a flag.
  again=("$PWD/scripts/install.sh" "${orig_args[@]}")
  case " ${orig_args[*]} " in *" --participant "* | *" --full "*) ;; *) again+=("--$stack") ;; esac
  again+=(${release_args[@]+"${release_args[@]}"})
  say "Docker is installed. The installer starts again in the docker group (sg docker)."
  UI_ENDED=1
  # The new run draws its own screen and asks its own questions on the terminal, not in the log.
  exec 1>&"$UI_OUT" 2>&"$UI_ERR" 3<&-
  exec sg docker -c "SELFHOSTR_DOCKER_INSTALLED=1 $(printf '%q ' bash "${again[@]}")"
}

# podman_prepare: a fresh Podman install, after every check that needs no engine (memory, disk,
# the consent), so that a refused run leaves the host unchanged. The scripts talk to the root
# Podman service through its socket (never a rootless Podman of this user). When the socket does
# not answer, this user is given access through the group suckerpot-podman
# (scripts/host/podman-socket.sh, sudo; the group is root-equivalent, like the docker group), and
# the installer starts again under `sg`, so this login needs no new session; the answers given so
# far go with it. Then the host must pass engine_check_podman, and no data of an earlier install
# may be there.
podman_prepare() {
  local again problems reason user
  user=$(id -un 2> /dev/null) || user=USER
  [[ $user =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || user=USER
  if ! ctr version > /dev/null 2>&1; then
    [ "${SELFHOSTR_PODMAN_GROUP:-0}" = 0 ] ||
      die "the root Podman socket still does not answer for this user. Log out and back in, then run the installer again."
    is_root || command -v sudo > /dev/null 2>&1 || die "sudo is needed to open the root Podman socket to this user. As root: scripts/host/podman-socket.sh USER"
    if ! root_free && { [ "$has_tty" = 0 ] || [ "$assume_yes" = 1 ]; }; then
      die "the root Podman socket is not open to this user, and sudo needs a password. Run: sudo scripts/host/podman-socket.sh $user, then the installer again."
    fi
    # Always on screen, before anything changes: what is about to be given, and why.
    ui_pause
    {
      echo "${UI_IND}Podman: SuckerPot talks to the root Podman service. This user joins the group"
      echo "${UI_IND}suckerpot-podman, which may use the root Podman socket. That group is root-equivalent"
      echo "${UI_IND}(like the docker group): remove it later with sudo scripts/host/podman-socket.sh --uninstall $user."
    } 1>&"$UI_ERR"
    root_ready "Opening the Podman socket" || die "sudo failed: the Podman socket was not opened"
    ui_run --expect 10 -- engine_setup_socket_access || die "the root Podman socket could not be opened to this user (see the log)"
    if ! reason=$(sg suckerpot-podman -c true 2>&1); then
      say "Podman is ready for this user. Log out and back in, then run the installer again."
      say "(sg could not start a shell in the group suckerpot-podman: ${reason:-no reason given})"
      stopped_why=relogin
      UI_ENDED=1
      exit 1
    fi
    # The new run asks nothing again: the type, the engine, the pseudonym and the consent go along.
    again=("$PWD/scripts/install.sh" "${orig_args[@]}")
    case " ${orig_args[*]} " in *" --participant "* | *" --full "*) ;; *) again+=("--$stack") ;; esac
    again+=(${release_args[@]+"${release_args[@]}"})
    case " ${orig_args[*]} " in *" --engine "*) ;; *) again+=(--engine podman) ;; esac
    if [ -n "${pseudonym:-}" ] && [ -z "$pseudonym_arg" ] && [ "$no_pseudonym" = 0 ]; then again+=(--pseudonym "$pseudonym"); fi
    if [ -z "${pseudonym:-}" ] && [ "${ask_name:-0}" = 1 ]; then again+=(--no-pseudonym); fi
    if [ "${ask_country:-0}" = 1 ] && [ -n "$country" ]; then again+=(--country "$country" --show-country); fi
    say "Podman is open to this user. The installer starts again in the group suckerpot-podman (sg)."
    UI_ENDED=1
    exec 1>&"$UI_OUT" 2>&"$UI_ERR" 3<&-
    exec sg suckerpot-podman -c "SELFHOSTR_PODMAN_GROUP=1 SELFHOSTR_PODMAN_CONSENT=${consent_given:-0} $(printf '%q ' bash "${again[@]}")"
  fi
  problems=$(engine_check_podman) ||
    die "this host does not meet the Podman requirements: $(printf '%s' "$problems" | tr '\n' ';' | sed 's/;$//; s/;/; /g') (docs/install.md#podman-experimental)"
  # Never adopt or mix with an existing install: its database password lives inside the data.
  if [ -n "$(ctr volume ls -q --filter "name=^${prefix}_" 2> /dev/null | head -n 1)" ]; then
    die "Data volumes named '${prefix}_*' already exist. Restore your old .env, or pick another --prefix. (They are never adopted: the database password lives inside the data.)"
  fi
  if [ -n "$(ctr ps -a -q --filter "label=com.docker.compose.project=$project" 2> /dev/null | head -n 1)" ]; then
    die "Containers of the compose project '$project' already exist. Pick another --project, or remove that stack yourself first."
  fi
}

mem_kb=0
if [ "$dry_run" = 1 ]; then
  note "dry run: Docker, memory, disk and volume checks skipped"
else
  if [ "$ENGINE_ID" = podman ]; then
    # Nothing on this host changes before the checks that need no engine (podman_prepare, step 2).
    command -v podman > /dev/null 2>&1 ||
      die "Podman is not installed. Debian 13 or Ubuntu 26.04: sudo apt install podman docker-compose nftables. Fedora: sudo dnf install podman docker-compose nftables"
    command -v docker-compose > /dev/null 2>&1 || die "docker-compose is not installed (2.26 or newer): sudo apt install docker-compose, or sudo dnf install docker-compose"
    warn "Podman support is experimental (docs/install.md#podman-experimental). The host firewall is required."
  else
    command -v docker > /dev/null 2>&1 || offer_docker
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
  fi

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

    # Only a single absolute path counts: a Podman client that cannot reach its socket prints its
    # own version block on stdout, which once ended the install without a word.
    root=""
    if data_root=$(engine_data_root 2> /dev/null) && [[ $data_root == /* && $data_root != *$'\n'* ]]; then root=$data_root; fi
    # Podman before its socket is open to this user (podman_prepare): its default storage folder.
    if [ -z "$root" ] && [ "$ENGINE_ID" = podman ]; then root=/var/lib/containers; fi
    free_kb=${SELFHOSTR_FREE_DISK_KB:-$(df -Pk "${root:-/}" 2> /dev/null | awk 'NR==2 {print $4}' || true)}
    [[ ${free_kb:-} =~ ^[0-9]+$ ]] || die "cannot read the free disk space"
    if [ "$free_kb" -lt $((15 * 1024 * 1024)) ]; then
      die "less than 15 GiB free under $(engine_name)'s data folder"
    elif [ "$free_kb" -lt $((30 * 1024 * 1024)) ]; then
      warn "less than 30 GiB free under $(engine_name)'s data folder; logs and payloads need room"
    fi

    # Never adopt or mix with an existing install: its database password lives inside the data.
    # (Podman: checked in podman_prepare, once the socket is open to this user.)
    if [ "$ENGINE_ID" != podman ] && [ -n "$(ctr volume ls -q --filter "name=^${prefix}_" 2> /dev/null | head -n 1)" ]; then
      die "Data volumes named '${prefix}_*' already exist. Restore your old .env, or pick another --prefix. (They are never adopted: the database password lives inside the data.)"
    fi
    if [ "$ENGINE_ID" != podman ] && [ -n "$(ctr ps -a -q --filter "label=com.docker.compose.project=$project" 2> /dev/null | head -n 1)" ]; then
      die "Containers of the compose project '$project' already exist. Pick another --project, or remove that stack yourself first."
    fi
  fi
  if [ "$stack" = participant ] && ! command -v crontab > /dev/null 2>&1 && ! command -v systemctl > /dev/null 2>&1; then
    warn "neither crontab nor systemctl was found: automatic updates cannot be scheduled (update by hand with: just update)"
  fi
fi

# ---------------------------------------------------------------- 2. settings
# Defaults (decisions of docs/dev/design/installer-ux.md, section 7); each one has its flag.
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
  mode=${mode:-images}

  if [ -z "$sensors_arg" ]; then
    if [ "$stack" = participant ] && [ "$lite" = 1 ]; then
      sensors_arg=$(IFS=,; echo "${LITE_SENSORS[*]}")
    else
      sensors_arg=recommended
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
  # The dashboard listens on 127.0.0.1 (an SSH tunnel), unless --public-host or --dashboard-bind.
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

  admin_user=${admin_user:-admin}
  [[ $admin_user =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "the admin user name may only contain letters, digits, . _ -"
fi

pw=""
pw_generated=0
if [ "$dash" = 1 ]; then
  # A generated password, shown once at the end (decision O3), or your own on stdin.
  if [ "$pw_stdin" = 1 ]; then
    IFS= read -r pw || true
  else
    pw=$(gen_secret 24)
    pw_generated=1
  fi
  [ "${#pw}" -ge 12 ] || die "the admin password must have at least 12 characters"
fi

if [ "$fresh" = 1 ]; then
  if [ "$lowmem" = auto ]; then
    if [ "$dry_run" = 1 ]; then
      lowmem=off
    elif [ "$mem_kb" -lt $((6 * 1024 * 1024)) ]; then
      # Below 6 GiB the low-memory overlay is used (--lowmem off to refuse it).
      if [ -f docker-compose.lowmem.yml ]; then lowmem=on; else lowmem=off; fi
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
  # Once a day, one anonymous request through the VPN; it never installs anything (--update-check).
  if [ "$update_check_flag" = 1 ]; then update_check=true; else update_check=false; fi
fi
if [ "$switching" = 1 ]; then
  if [ "$(env_get AUTO_UPDATE_ENABLED false)" = true ]; then
    # The switch keeps the automatic updates (./scripts/participant.sh auto-update off stops them).
    keep_auto=yes
  fi
fi

if [ "$fresh" = 1 ]; then
  if [ -n "$wg_conf" ]; then
    if [ "$stack" = full ]; then
      wg_parse_conf "$wg_conf" " Upload it in the dashboard instead." || die "unusable WireGuard file"
    else
      wg_parse_conf "$wg_conf" " Check the file from your VPN provider." || die "unusable WireGuard file"
    fi
  fi

  # Your own public address (--self-address): the dashboard learns it from traffic otherwise, and
  # this script never looks it up.
  self_addr=$self_address
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
  # Podman: the run that starts again in the socket group (podman_prepare) keeps the answer given.
  podman_consent=0
  [ "${SELFHOSTR_PODMAN_GROUP:-0}" != 1 ] || [ "${SELFHOSTR_PODMAN_CONSENT:-0}" != 1 ] || podman_consent=1
  [ "$assume_yes" = 1 ] || [ "$podman_consent" = 1 ] || need_tty "the participant consent"
  # On a terminal, after the consent: the node name and the country, unless flags answer them.
  ask_name=0 ask_country=0
  if [ "$has_tty" = 1 ] && [ "$assume_yes" = 0 ] && [ "$podman_consent" = 0 ]; then
    [ -n "$pseudonym_arg" ] || [ "$no_pseudonym" = 1 ] || ask_name=1
    [ -n "$country" ] || ask_country=1
  fi
  ui_pause
  say
  if [ "$ask_name" = 1 ]; then
    show consent_screen "" "$vpn_flag" ask
  else
    show consent_screen "$pseudonym" "$vpn_flag"
  fi
  if [ "$assume_yes" = 1 ]; then
    say "--yes was given: this counts as your agreement to join as described above."
    say
  elif [ "$podman_consent" = 1 ]; then
    say "You agreed before the installer started again in the group suckerpot-podman."
    say
  else
    printf '%sJoin the SuckerPot network as described? [y/N] ' "$UI_IND" 1>&"$UI_ERR"
    IFS= read -r a <&3 || a=""
    answered
    case $a in
      y | Y | yes | YES | Yes) ;;
      *) echo "${UI_IND}Not joined. Nothing was installed." 1>&"$UI_ERR"; log "consent declined"; UI_ENDED=1; exit 1 ;;
    esac
  fi
  consent_given=1
  # The node name (the pseudonym) and the country, asked on the terminal (scripts/lib/nodeprofile.sh).
  # shellcheck source=scripts/lib/geocheck.sh
  . scripts/lib/geocheck.sh
  GEO_SELF_ADDRESS=$self_address
  if [ "$ask_name$ask_country" != 00 ]; then
    # shellcheck source=scripts/lib/nodeprofile.sh
    . scripts/lib/nodeprofile.sh
    ASK_TTY=1 ASK_OUT=$UI_ERR ASK_IND=$UI_IND
    [ "$UI_MODE" = rich ] || ASK_PLAIN=1
    if [ "$ask_name" = 1 ]; then
      profile_ask_name "" || die "no valid node name was given (run again, or pass --node-name NAME or --no-node-name)"
      pseudonym=$PROFILE_NAME
      if [ -n "$pseudonym" ]; then log "node name chosen (set)"; else log "node name chosen (none)"; fi
    fi
    if [ "$ask_country" = 1 ]; then
      profile_ask_country "" "${country_check:-ask}" || die "no valid country was given (run again, or pass --country CC --show-country)"
      country=$PROFILE_COUNTRY
      if [ -n "$country" ]; then show_country=1; fi
      log "country: ${country:-none shown}"
    fi
    say
  fi
  # A country from the flags is checked against a GeoIP database on this machine (no download
  # unless --country-check download). A mismatch is a warning: the owner's choice stands.
  if [ -n "$country" ] && [ "$ask_country" = 0 ] && [ "$dry_run" = 0 ] && [ "${country_check:-local}" != off ]; then
    if [ "$country_check" = download ] && [ -z "$(geo_sources)" ]; then
      geo_download || warn "could not download the country list from $GEO_DOWNLOAD_HOST; the country is not checked"
    fi
    geo_check "$country"
    case $GEO_RESULT in
      match) log "country check: $country matches the local database" ;;
      mismatch) warn "--country $country: $GEO_SOURCE places this machine ($GEO_ADDR) in $GEO_FOUND, not in $country. The node shows $country as asked; change it later with: ./scripts/participant.sh set-country CC" ;;
      *) log "country check: not done ($GEO_WHY)" ;;
    esac
  fi
fi

# Full mode: the SuckerPot network is off unless --join-network says so (decision O2: no question;
# join later in the dashboard). The consent is a record in .env; ingest joins from it once a VPN
# is configured.
[ "$join_flag" = 0 ] || [ "$no_network" = 0 ] || die "--join-network and --no-network exclude each other"
join_network=0
if [ "$stack" = full ] && [ "$fresh" = 1 ] && [ "$no_network" = 0 ]; then
  if [ "$join_flag" = 1 ]; then
    # shellcheck source=scripts/lib/pseudonym.sh
    . scripts/lib/pseudonym.sh
    ui_pause
    say
    pseudonym=$(pseudonym_random) || die "could not make a pseudonym"
    show consent_screen_full "$pseudonym"
    say "--join-network was given: this counts as your agreement to join as described above."
    say
    join_network=1
  elif [ "$assume_yes" = 1 ]; then
    note "the SuckerPot network is off: --yes does not join it (add --join-network to join)"
  else
    note "the SuckerPot network is off: join it later in the dashboard, or install with --join-network"
  fi
fi

# Podman: the system changes (socket group, membership) come only now, after every refusal that
# needs no engine (memory, disk, consent), so a refused run leaves the host as it was.
if [ "$ENGINE_ID" = podman ] && [ "$fresh" = 1 ] && [ "$dry_run" = 0 ]; then
  podman_prepare
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
          # Its own sshd, most likely: the sensor takes host port 2222, and the router forwards 22 to it.
          note "Port 22 is used on this machine (its own sshd, most likely)."
          if is_busy 2222; then
            warn "ports 22 and 2222 are both in use: the ssh sensor is left off. Free port 2222 and run: just sensors ..."
            sensor_off[$s]=1
          else
            port_override[$var]=2222
            ssh_moved=1
            note "Mapped the SSH sensor to host port 2222."
          fi
        else
          warn "port $port ($var) is in use: the $s sensor is left off. Free the port and run: just sensors ..."
          sensor_off[$s]=1
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
    if [ -z "$admin_ssh_port" ] && [ "$dry_run" = 0 ]; then
      # Port 22 is free: the admin SSH may already have been moved (docs/vps.md). Use what sshd
      # is configured for, so the host firewall protects that port.
      # shellcheck source=scripts/lib/firewall.sh
      . scripts/lib/firewall.sh
      read -r fw_port fw_src <<< "$(fw_admin_port)"
      if [ "$fw_src" != default ] && [ "$fw_port" != 22 ]; then admin_ssh_port=$fw_port; fi
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
    [ "$dry_run" = 1 ] && version=dev || die "images mode needs --version vX.Y.Z (or install from a release tag, or use --source)${release_hint:+: $release_hint}"
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
  trap 'rc=$?; rm -f "$tmp"; ui_exit $rc' EXIT
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
    # --no-firewall: the owner filters elsewhere (read by lib/firewall.sh and the Podman boot unit).
    [ "$no_firewall" = 0 ] || setv SUCKERPOT_NO_FIREWALL 1
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

  # Podman: the overlay that makes every network external (scripts/ensure-networks.sh creates them
  # with netavark's isolation options). Last, after every other overlay.
  if [ "$ENGINE_ID" = podman ]; then
    ENV_FILE=$tmp
    cf=$(env_get COMPOSE_FILE docker-compose.yml)
    unset ENV_FILE
    case ":$cf:" in
      *:docker-compose.podman.yml:*) ;;
      # A test install (SELFHOSTR_TEST_INSTALL): before the test overlay, whose networks replace
      # the live sp-* ones with throwaway names.
      *:docker-compose.participant-it.yml:*) setv COMPOSE_FILE "${cf/:docker-compose.participant-it.yml/:$(engine_compose_overlay):docker-compose.participant-it.yml}" ;;
      *) setv COMPOSE_FILE "$cf:$(engine_compose_overlay)" ;;
    esac
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
  trap 'ui_exit $?' EXIT
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
# Podman (design D5): the host firewall carries isolation that Docker gives by itself, so it is
# installed before anything starts, then the boot unit that binds the stack to it. --no-firewall
# (the owner filters elsewhere) skips the firewall with a warning; the unit then does not need it.
start_cmd=(dc up)
if [ "$ENGINE_ID" = podman ]; then
  # shellcheck source=scripts/lib/firewall.sh
  . scripts/lib/firewall.sh
  fw_mode=participant
  [ "$stack" = participant ] || fw_mode=full
  [ "$(env_get SUCKERPOT_NO_FIREWALL)" != 1 ] || no_firewall=1
  ui_detail "host firewall (required on Podman)"
  if [ "$no_firewall" = 1 ]; then
    warn "--no-firewall on Podman: sensors can reach the internet and each other unless you filter the sp-* bridges elsewhere"
    ui_run --expect 5 -- engine_install_boot_unit --no-firewall || die "the boot unit could not be installed (see the log)"
  else
    if ! fw_can_sudo; then
      if [ "$has_tty" = 0 ] || [ "$assume_yes" = 1 ] || ! command -v sudo > /dev/null 2>&1; then
        die "on Podman the host firewall is required, and it needs sudo without a password here. Run the installer on a terminal, or pass --no-firewall if you filter elsewhere."
      fi
      ui_pause
      root_ready "The host firewall (required on Podman)" || die "sudo failed: on Podman the host firewall is required"
    fi
    ui_run --expect 10 -- fw_step "$fw_mode" auto || die "on Podman the host firewall is required and was not installed (see the log)"
    ui_run --expect 5 -- engine_install_boot_unit || die "the boot unit could not be installed (see the log)"
  fi
  # Every start goes through the boot unit (engine_stack_up): networks, firewall check, then up.
  start_cmd=(engine_stack_up)
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
  # What an interrupted restart left behind would make the start fail (scripts/lib/stackop.sh).
  stack_clean_leftovers
  ui_run --expect 150 -- "${start_cmd[@]}" -d --no-build --pull never --wait --wait-timeout 600 ${up_extra[@]+"${up_extra[@]}"} || die "the stack did not become healthy. See: docker compose ps, docker compose logs"
else
  SUCKERPOT_BUILD_VERSION=$(git describe --tags --always --dirty 2> /dev/null || echo dev)
  SUCKERPOT_BUILD_COMMIT=$(git rev-parse --short HEAD 2> /dev/null || echo unknown)
  export SUCKERPOT_BUILD_VERSION SUCKERPOT_BUILD_COMMIT
  ui_skip "source mode: built during the start"
  ui_begin start
  # What an interrupted restart left behind would make the start fail (scripts/lib/stackop.sh).
  stack_clean_leftovers
  ui_run --expect 600 -- with_public_umask "${start_cmd[@]}" -d --build --wait --wait-timeout 900 ${up_extra[@]+"${up_extra[@]}"} || die "the stack did not become healthy. See: docker compose ps, docker compose logs"
fi
ui_done "all services healthy"
# An update that was cut off leaves its state file unfinished; once the stack runs the version of
# .env, there is nothing left to finish.
if [ "$repair" = 1 ] && [ -n "$(update_unfinished)" ]; then
  if [ "$(env_get SUCKERPOT_INSTALL_MODE source)" != images ] || [ "$(running_version)" = "$(env_get SUCKERPOT_VERSION)" ]; then
    update_mark_finished
    say "The update that was cut off is over: the stack runs $(env_get SUCKERPOT_VERSION source)."
  fi
fi
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

# Host firewall on the rich display: on by default (decision O7), no question; the same loader as
# fw_step, with the sudo password asked in the open (the list is off the screen while sudo asks).
fw_rich() {
  local out
  # shellcheck source=scripts/lib/firewall.sh
  . scripts/lib/firewall.sh
  if [ "$no_firewall" = 1 ]; then
    ui_skip "off (--no-firewall): ./scripts/participant.sh firewall installs it"
    return 0
  fi
  # Podman: installed before the start (required there).
  if [ "$ENGINE_ID" = podman ]; then
    ui_done "loaded before the start (required on Podman)"
    return 0
  fi
  if ! fw_can_sudo; then
    if [ "$assume_yes" = 1 ] || ! command -v sudo > /dev/null 2>&1; then
      ui_skip "needs sudo: ./scripts/participant.sh firewall"
      return 0
    fi
    ui_pause
    if ! root_ready "The host firewall"; then
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
  local adm rp hp proto sname ports="" line pc_rc=0 pc_since enrol_file enrol_st="" enrol_code="" enrol_msg="" cc
  ui_begin firewall
  fw_rich
  # Did the hub accept the join? Same check as in plain mode, with the answer shown on the row.
  ui_begin enrol
  if [ "$(env_get NETWORK_ENABLED false)" = true ]; then
    # shellcheck source=scripts/lib/enrol_wait.sh
    . scripts/lib/enrol_wait.sh
    # shellcheck source=scripts/lib/pseudonym.sh
    . scripts/lib/pseudonym.sh
    enrol_file=$(mktemp)
    # shellcheck disable=SC2329 # run by ui_run
    enrol_to_file() { enrol_wait "$1" > "$enrol_file"; }
    ui_run --expect 60 -- enrol_to_file "${SUCKERPOT_ENROL_WAIT:-180}" || true
    read -r enrol_st enrol_code < "$enrol_file" || true
    # Not decided yet: the proof of work of a new node can take minutes on a small machine. On a
    # terminal the owner may wait longer here; otherwise the final screen says how to check later.
    while [ "$enrol_st" = enrolling ] && [ "$has_tty" = 1 ] && [ "$assume_yes" = 0 ]; do
      ASK_TTY=1 ASK_OUT=$UI_ERR ASK_IND=$UI_IND
      ui_pause
      echo 1>&"$UI_ERR"
      ask_lines "" "The hub has not accepted this node yet. A new node first solves a proof-of-work puzzle, which can take several minutes on a small machine; SuckerPot keeps trying by itself."
      ask_yn "Wait up to 10 more minutes for the answer?" y || break
      ui_detail "waiting for the hub's answer"
      ui_run --expect 300 -- enrol_to_file 600 || true
      read -r enrol_st enrol_code < "$enrol_file" || true
    done
    rm -f "$enrol_file"
    case $enrol_st in
      member) ui_done "accepted${pseudonym:+ as $pseudonym}" ;;
      error)
        if [ "$enrol_code" = pseudonym_taken ] && [ -n "$pseudonym" ]; then
          ui_failed "the pseudonym '$pseudonym' is taken"
          enrol_msg="Join with another name: ./scripts/participant.sh join --pseudonym $(pseudonym_suggest "$pseudonym" || echo NEW-NAME)"
        else
          ui_failed "refused ($enrol_code): ./scripts/status.sh"
        fi
        ;;
      enrolling)
        ui_done "not decided yet: ./suckerpot.sh status --wait"
        enrol_msg="The hub has not decided yet. Watch for its answer: ./suckerpot.sh status --wait (or ./scripts/status.sh later)."
        ;;
      *) ui_skip "no answer yet: ./scripts/status.sh" ;;
    esac
  else
    ui_skip "not joined"
  fi
  ui_begin reach
  # shellcheck source=scripts/lib/ports-check.sh
  . scripts/lib/ports-check.sh
  pc_since=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)
  ui_run --expect 90 -- ports_check_run 90 "$pc_since" || pc_rc=$?
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
  echo 1>&"$UI_OUT"
  if [ "$repair" = 1 ]; then
    ui_wrap 2 "SuckerPot is repaired and running in participant mode (${version:-source build})." b
  else
    ui_wrap 2 "SuckerPot is running in participant mode (${version:-source build})." b
  fi
  ui_kv 4 11 "Node name" "${pseudonym:-none (shown as \"Node\" and a number)}"
  cc=$(env_get NETWORK_COUNTRY)
  if [ -n "$cc" ] && [ "$(env_get NETWORK_SHOW_COUNTRY false)" = true ]; then
    ui_kv 4 11 Country "$cc (shown)"
  elif [ -n "$cc" ]; then
    ui_kv 4 11 Country "$cc (not shown)"
  else
    ui_kv 4 11 Country "none"
  fi
  ui_kv 4 11 Path "$path"
  ui_kv 4 11 Hub "${hub_host:-unknown}"
  ui_kv 4 11 Updates "$(sched_text)"
  ui_wrap 2 ""
  ui_wrap 2 "Forward these router ports to this machine (port forwards, not a DMZ):"
  ui_wrap 4 "$ports"
  if [ -n "$adm" ]; then
    ui_wrap 2 "Never forward your admin SSH port ($adm on this machine)."
  else
    ui_wrap 2 "Never forward the admin SSH port of this machine."
  fi
  [ -z "$enrol_msg" ] || ui_wrap 2 "$enrol_msg"
  # The node as status.sh sees it now (stack, sensors, network): the same view as ./suckerpot.sh status.
  if [ -f scripts/status.sh ]; then
    ui_wrap 2 ""
    ui_wrap 2 "Status now:" b
    # "Label    value" lines: the value wraps under itself.
    while IFS= read -r line; do
      ui_kv 4 9 "$(printf '%s' "${line:0:9}" | tr -d ' ')" "${line:9}"
    done < <(bash scripts/status.sh --brief 2> /dev/null || true)
  fi
  ui_wrap 2 ""
  ui_kv 2 7 Next "./suckerpot.sh   the menu: status, edit, update, logs, remove"
  ui_kv 2 7 "" "./scripts/participant.sh ports-check   once the ports are forwarded"
  ui_kv 2 7 "" "./scripts/status.sh   any time (what needs attention)"
  ui_kv 2 7 More "docs/participate.md#open-the-ports (DMZ, firewall, updates). Take a snapshot of this machine now."
  ui_kv 2 7 Log "$(_ui_abs "$LOG")"
}

full_rich() {
  ui_end
  echo 1>&"$UI_OUT"
  ui_wrap 2 "SuckerPot is running." b
  if [ -n "$public_host" ]; then
    ui_kv 4 12 Dashboard "https://$public_host (through your tunnel to http://$hbind:$dport)"
  else
    ui_kv 4 12 Dashboard "http://$hbind:$dport"
    if [ "$bind" = 127.0.0.1 ]; then
      ui_kv 4 12 Tunnel "ssh -L $dport:127.0.0.1:$dport <you>@<this-host>   (on a remote machine)"
    fi
  fi
  ui_kv 4 12 "Admin user" "$(env_get ADMIN_USERNAME)"
  if [ "${join_network:-0}" = 1 ]; then
    ui_kv 4 12 Network "joined; it starts once a VPN is configured (Settings > VPN)"
  elif [ "$fresh" = 1 ]; then
    ui_kv 4 12 Network "not joined (you can join later in the dashboard)"
  fi
  if [ "$pw_generated" = 1 ]; then
    # The label wraps; the password stays whole on its own line.
    ui_wrap 2 ""
    ui_wrap 2 "Admin password (shown once, store it in your password manager now):"
    printf '    %s\n' "$pw" 1>&"$UI_OUT"
  fi
  pw=""
  if [ "$switching" = 1 ]; then
    ui_wrap 2 ""
    ui_wrap 2 "Switched from participant mode to full mode. Your data and your network membership are kept. The participant settings are in .env.participant.bak (delete it once all is well)."
  fi
  ui_wrap 2 ""
  ui_kv 2 7 Next "1. Sign in. The setup opens by itself."
  ui_kv 2 7 "" "2. Forward the ports listed on the Ports page (never $dport or your admin SSH port)."
  ui_kv 2 7 "" "3. ./scripts/participant.sh firewall   (the host firewall)"
  ui_kv 2 7 "" "4. Take a snapshot of the machine."
  ui_kv 2 7 Log "$(_ui_abs "$LOG")"
}

# ---------------------------------------------------------------- 10. summary
step 10 "Done"
# An install made with --no-firewall keeps that choice for --repair.
[ "$(env_get SUCKERPOT_NO_FIREWALL)" != 1 ] || no_firewall=1
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
if [ "$stack" = participant ]; then
  if [ "$sched" != off ]; then
    ui_done "$(sched_text)"
  elif [ "$(env_get AUTO_UPDATE_ENABLED false)" = true ]; then
    ui_skip "not scheduled: ./scripts/participant.sh auto-update on"
  else
    ui_skip "off (on: ./scripts/participant.sh auto-update on)"
  fi
fi

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
  echo "Use port forwards, not your router's DMZ (why: docs/participate.md#open-the-ports)."
  # The host firewall (scripts/host/): on by default (decision O7), never fatal on Docker. On a
  # terminal sudo asks for the password; with --yes it installs only when sudo needs none.
  # shellcheck source=scripts/lib/firewall.sh
  . scripts/lib/firewall.sh
  if [ "$ENGINE_ID" = podman ] && [ "$no_firewall" = 0 ]; then
    echo
    echo "Host firewall"
    echo "  Loaded before the start (required on Podman); the boot unit starts the stack after it."
  elif [ "$no_firewall" = 1 ]; then
    echo
    echo "Host firewall"
    echo "  Skipped (--no-firewall). Install it later: ./scripts/participant.sh firewall"
  else
    if [ "$assume_yes" = 0 ] && [ "$has_tty" = 1 ] && ! fw_can_sudo && command -v sudo > /dev/null 2>&1; then
      echo
      root_ready "The host firewall" || true
    fi
    fw_step participant auto
  fi
  # Did the hub accept the join? A refused pseudonym used to fail silently (2026-11-21 report).
  if [ "$(env_get NETWORK_ENABLED false)" = true ]; then
    # shellcheck source=scripts/lib/enrol_wait.sh
    . scripts/lib/enrol_wait.sh
    # shellcheck source=scripts/lib/pseudonym.sh
    . scripts/lib/pseudonym.sh
    echo
    echo "Waiting for the hub to enrol this node (this can take a few minutes)..."
    read -r enrol_st enrol_code < <(enrol_wait "${SUCKERPOT_ENROL_WAIT:-180}")
    case $enrol_st in
      member) echo "  The hub accepted this node${pseudonym:+ as $pseudonym}." ;;
      error)
        if [ "$enrol_code" = pseudonym_taken ] && [ -n "$pseudonym" ]; then
          echo "  The hub refused the pseudonym '$pseudonym': another node already uses it."
          echo "  If that is your own earlier install, the hub frees the name after two days without contact, if that node never sent a batch."
          echo "  Join with another name: ./scripts/participant.sh join --pseudonym $(pseudonym_suggest "$pseudonym" || echo NEW-NAME)"
        else
          echo "  The hub refused to enrol this node ($enrol_code). Details: ./scripts/status.sh"
        fi
        ;;
      enrolling) echo "  Not decided yet. Check in a few minutes: ./scripts/status.sh" ;;
    esac
  fi
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
  if [ "$pc_rc" != 0 ]; then
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
