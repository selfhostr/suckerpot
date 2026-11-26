#!/usr/bin/env bash
# Schedule for the automatic updater (M32). Source this file; it defines functions only.
#
#   schedule_random_time          prints "HOUR MINUTE", a random time between 03:00 and 05:59
#   schedule_install HOUR MINUTE  installs the job (idempotent: replaces its own line). It runs
#                                 every 6 hours at that minute: HOUR, HOUR+6, HOUR+12, HOUR+18
#   schedule_remove               removes the job (idempotent, never touches other lines)
#   schedule_status               prints "cron HH:MM/6h", "systemd HH:MM/6h" or "off" (HH:MM is the
#                                 first run of the day); exit 0 when on. A schedule from before
#                                 v0.11.10 runs once a day and prints "cron HH:MM" (no "/6h")
#   schedule_upgrade              moves a once-a-day schedule to every 6 hours, same minute
#
# Every 6 hours, not once a day: a release still waits its minimum age (48 h), but it is installed
# at most 6 hours after that instead of up to a day after.
#
# The job runs scripts/auto-update.sh of this checkout, as the CURRENT user: first from the user's
# crontab, and when there is no usable crontab, from a systemd USER timer. It never uses sudo.
# The cron line ends with a marker comment (`# selfhostr-auto-update <project>`), so only the
# line of this project is ever replaced or removed. The project comes from COMPOSE_PROJECT_NAME in
# .env (or SCHEDULE_PROJECT). After schedule_install, SCHEDULE_METHOD is "cron" or "systemd".

# shellcheck disable=SC2015
SCHEDULE_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
SCHEDULE_WORD="selfhostr-auto-update"
# Set by schedule_install: "cron" or "systemd" (read by the caller).
export SCHEDULE_METHOD=""

if ! declare -F env_get > /dev/null 2>&1; then
  # shellcheck source=scripts/lib/env.sh
  . "$(dirname "${BASH_SOURCE[0]}")/env.sh"
fi

_schedule_err() { echo "schedule: $*" >&2; }
# _crontab ARGS: the crontab of this user; as root started with sudo by the owner of the checkout
# (SUCKERPOT_OWNER, scripts/lib/env.sh), the owner's crontab, so the updates run as them.
_crontab() {
  if [ -n "${SUCKERPOT_OWNER:-}" ] && [ "${SELFHOSTR_EUID:-$(id -u)}" = 0 ]; then
    crontab -u "$SUCKERPOT_OWNER" "$@"
  else
    crontab "$@"
  fi
}

# Prints the project name, or fails.
_schedule_project() {
  local p=${SCHEDULE_PROJECT:-}
  [ -n "$p" ] || p=$(cd "$SCHEDULE_ROOT" && ENV_FILE="$SCHEDULE_ROOT/.env" env_get COMPOSE_PROJECT_NAME)
  [[ $p =~ ^[a-z0-9][a-z0-9_-]{0,40}$ ]] || { _schedule_err "no valid COMPOSE_PROJECT_NAME in .env"; return 1; }
  printf '%s' "$p"
}

_schedule_unit_dir() { printf '%s/systemd/user' "${XDG_CONFIG_HOME:-$HOME/.config}"; }

# _schedule_hours HOUR: prints the 4 hours of the day, comma-separated ("4,10,16,22").
_schedule_hours() {
  local first=$((10#$1 % 6))
  printf '%d,%d,%d,%d' "$first" "$((first + 6))" "$((first + 12))" "$((first + 18))"
}

schedule_random_time() {
  printf '%s %s\n' "$((3 + RANDOM % 3))" "$((RANDOM % 60))"
}

# Prints the crontab without the lines of this project. Returns 1 when the crontab cannot be read.
_schedule_cron_without() {
  local project=$1 current rc=0
  command -v crontab > /dev/null 2>&1 || return 1
  current=$(_crontab -l 2>&1) || rc=$?
  if [ "$rc" -ne 0 ]; then
    # "no crontab for user" is fine (empty); anything else means we must not overwrite it.
    printf '%s' "$current" | grep -qi 'no crontab' || return 1
    current=""
  fi
  [ -n "$current" ] || return 0
  printf '%s\n' "$current" | grep -v -E "# $SCHEDULE_WORD $project\$" || true
}

_schedule_systemd_install() {
  local project=$1 hour=$2 minute=$3 dir name linger
  command -v systemctl > /dev/null 2>&1 && systemctl --user show-environment > /dev/null 2>&1 \
    || { _schedule_err "neither a usable crontab nor a systemd user session was found"; return 1; }
  dir=$(_schedule_unit_dir)
  name="$SCHEDULE_WORD-$project"
  mkdir -p "$dir"
  cat > "$dir/$name.service" << EOF
[Unit]
Description=SuckerPot automatic update ($project)

[Service]
Type=oneshot
WorkingDirectory=$SCHEDULE_ROOT
ExecStart=/usr/bin/env bash scripts/auto-update.sh
EOF
  cat > "$dir/$name.timer" << EOF
[Unit]
Description=SuckerPot automatic update, every 6 hours ($project)

[Timer]
OnCalendar=*-*-* $(_schedule_hours "$hour"):$(printf '%02d' "$((10#$minute))"):00
Persistent=false

[Install]
WantedBy=timers.target
EOF
  systemctl --user daemon-reload && systemctl --user enable --now "$name.timer" > /dev/null 2>&1 \
    || { _schedule_err "could not enable the systemd user timer"; return 1; }
  linger=$(loginctl show-user "$(id -un)" -p Linger --value 2> /dev/null || true)
  if [ "$linger" != yes ]; then
    _schedule_err "warning: lingering is off, so the timer runs only while you are logged in (loginctl enable-linger, needs admin rights)"
  fi
  SCHEDULE_METHOD=systemd
}

schedule_install() {
  local hour=${1:-} minute=${2:-} project line others rc=0
  [[ $hour =~ ^[0-9]{1,2}$ ]] && [ "$((10#$hour))" -le 23 ] || { _schedule_err "hour must be 0 to 23"; return 1; }
  [[ $minute =~ ^[0-9]{1,2}$ ]] && [ "$((10#$minute))" -le 59 ] || { _schedule_err "minute must be 0 to 59"; return 1; }
  [[ $SCHEDULE_ROOT =~ ^[A-Za-z0-9._/@+-]+$ ]] \
    || { _schedule_err "the install path has characters that cannot be quoted safely for cron"; return 1; }
  project=$(_schedule_project) || return 1
  line="$((10#$minute)) $(_schedule_hours "$hour") * * * cd $SCHEDULE_ROOT && bash scripts/auto-update.sh > /dev/null 2>&1 # $SCHEDULE_WORD $project"
  if others=$(_schedule_cron_without "$project"); then
    { [ -z "$others" ] || printf '%s\n' "$others"; printf '%s\n' "$line"; } | _crontab - && rc=0 || rc=$?
    if [ "$rc" -eq 0 ]; then SCHEDULE_METHOD=cron; return 0; fi
  fi
  _schedule_systemd_install "$project" "$hour" "$minute"
}

schedule_remove() {
  local project others dir name had=0
  project=$(_schedule_project) || return 1
  if command -v crontab > /dev/null 2>&1 && _crontab -l 2> /dev/null | grep -qE "# $SCHEDULE_WORD $project\$"; then
    if others=$(_schedule_cron_without "$project"); then
      if [ -n "$others" ]; then printf '%s\n' "$others" | _crontab -; else _crontab -r; fi
    else
      _schedule_err "could not rewrite the crontab; remove the '$SCHEDULE_WORD $project' line by hand"
      return 1
    fi
  fi
  dir=$(_schedule_unit_dir)
  name="$SCHEDULE_WORD-$project"
  [ -e "$dir/$name.timer" ] && had=1
  if [ "$had" = 1 ]; then
    command -v systemctl > /dev/null 2>&1 && systemctl --user disable --now "$name.timer" > /dev/null 2>&1 || true
    rm -f "$dir/$name.timer" "$dir/$name.service"
    command -v systemctl > /dev/null 2>&1 && systemctl --user daemon-reload > /dev/null 2>&1 || true
  fi
  return 0
}

# _schedule_when HOURS MINUTE: prints "HH:MM/6h" for "H,H+6,H+12,H+18", "HH:MM" for one hour,
# "??:??" for anything else.
_schedule_when() {
  local hours=$1 minute=$2
  [[ $minute =~ ^[0-9]{1,2}$ ]] || { echo "??:??"; return 0; }
  if [[ $hours =~ ^[0-9]{1,2}$ ]]; then
    printf '%02d:%02d\n' "$((10#$hours))" "$((10#$minute))"
  elif [[ $hours =~ ^([0-9]{1,2}),[0-9]{1,2},[0-9]{1,2},[0-9]{1,2}$ ]] && [ "$hours" = "$(_schedule_hours "${BASH_REMATCH[1]}")" ]; then
    printf '%02d:%02d/6h\n' "$((10#${BASH_REMATCH[1]}))" "$((10#$minute))"
  else
    echo "??:??"
  fi
}

schedule_status() {
  local project line dir name spec
  project=$(_schedule_project) || { echo off; return 1; }
  if command -v crontab > /dev/null 2>&1; then
    line=$(_crontab -l 2> /dev/null | grep -E "# $SCHEDULE_WORD $project\$" | head -n 1 || true)
    if [ -n "$line" ]; then
      echo "cron $(_schedule_when "$(printf '%s' "$line" | awk '{print $2}')" "$(printf '%s' "$line" | awk '{print $1}')")"
      return 0
    fi
  fi
  dir=$(_schedule_unit_dir)
  name="$SCHEDULE_WORD-$project"
  if [ -f "$dir/$name.timer" ]; then
    spec=$(sed -n 's/^OnCalendar=\*-\*-\* \([0-9,]*\):\([0-9][0-9]\):00$/\1 \2/p' "$dir/$name.timer" | head -n 1)
    if [ -n "$spec" ]; then
      echo "systemd $(_schedule_when "${spec% *}" "${spec#* }")"
    else
      echo "systemd ??:??"
    fi
    return 0
  fi
  echo off
  return 1
}

# Moves a once-a-day schedule (before v0.11.10) to every 6 hours, keeping its hour and minute.
# Does nothing when there is no schedule, when it already runs every 6 hours, or when its time
# cannot be read. Returns non-zero only when the reinstall itself failed.
schedule_upgrade() {
  local status when project hour minute
  status=$(schedule_status 2> /dev/null) || return 0
  when=${status#* }
  [[ $when =~ ^([0-9]{2}):([0-9]{2})$ ]] || return 0
  hour=${BASH_REMATCH[1]} minute=${BASH_REMATCH[2]}
  # Keep the method it had: a systemd timer stays a systemd timer, even if a crontab works now.
  if [ "${status%% *}" = systemd ]; then
    project=$(_schedule_project) || return 1
    _schedule_systemd_install "$project" "$hour" "$minute"
  else
    schedule_install "$hour" "$minute"
  fi
}
