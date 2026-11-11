#!/usr/bin/env bash
# Moves this machine's own SSH daemon to another port, for example off port 22 so the SSH sensor
# can use it. Debian and Ubuntu.
#
#   sudo ./scripts/move-admin-ssh.sh          move the admin SSH to port 22222
#   sudo ./scripts/move-admin-ssh.sh 48022    move it to a port of your choice (1024 to 65535)
#   sudo ./scripts/move-admin-ssh.sh --undo   go back to port 22 (stop SuckerPot first: its SSH
#                                             sensor holds port 22)
#
#   -y, --yes    do not ask before changing anything
#   -h, --help   show this help
#
# The move goes from the port your SSH uses now to the new one, never through a third port. The
# new port is opened NEXT TO the current one first. The script then waits until you are logged in
# on the new port from a second terminal, and only then closes the current one. If the login does
# not come in 5 minutes, or the script is interrupted or fails, SSH goes back to the port it was
# on. A run that was killed outright is put back on its recorded port at the next start. Your open
# session stays connected all along.
#
# It writes /etc/ssh/sshd_config.d/10-admin-port.conf and, when SSH is started by systemd socket
# activation (Ubuntu 24.04 and newer), /etc/systemd/system/ssh.socket.d/override.conf. Every file
# it writes starts with a marker line. A file of yours that is in the way is backed up next to it
# (*.suckerpot.bak). It opens the new port in ufw or firewalld when the firewall lets SSH in from
# anywhere. It never looks up this machine's address and makes no network connection.
set -euo pipefail

# SuckerPot's own ports: the sensors' host ports, the SSH sensor's container port and the default
# dashboard port. The admin SSH must not use any of them.
RESERVED_PORTS="22 23 80 443 445 1433 2222 2375 3306 3389 5000 5001 5060 5555 6379 8443"
DEFAULT_PORT=22222
# How long to wait for the login on the new port, in seconds. The tests shorten it.
WAIT_SECONDS=${MOVE_SSH_WAIT_SECONDS:-300}
POLL_SECONDS=2

# MOVE_SSH_ROOT prefixes every /etc and /proc path (empty on a real machine, a scratch folder in
# the tests).
R=${MOVE_SSH_ROOT:-}
CFG=$R/etc/ssh/sshd_config
DROPIN_DIR=$R/etc/ssh/sshd_config.d
DROPIN=$DROPIN_DIR/10-admin-port.conf
SOCK_DIR=$R/etc/systemd/system/ssh.socket.d
OVERRIDE=$SOCK_DIR/override.conf
BAK=.suckerpot.bak
MARK="# move-admin-ssh.sh: managed file. Undo with: ./scripts/move-admin-ssh.sh --undo"
INC_MARK="# move-admin-ssh.sh: added Include"
OFF_MARK="# move-admin-ssh.sh disabled: "

# Admin tools live in sbin, which a plain `su` shell may not have. Appended last: PATH wins.
PATH="$PATH:/usr/sbin:/sbin"

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; }
note() { echo "  $*"; }
warn() { echo "  warning: $*" >&2; }
die() {
  echo "move-admin-ssh: $*" >&2
  exit 1
}

# ---------------------------------------------------------------- arguments
port=""
undo=0
assume_yes=0
while [ "$#" -gt 0 ]; do
  case $1 in
    -h | --help) usage; exit 0 ;;
    -y | --yes) assume_yes=1 ;;
    --undo) undo=1 ;;
    -*) die "unknown option $1 (see --help)" ;;
    *)
      [ -z "$port" ] || die "only one port can be given (see --help)"
      port=$1
      ;;
  esac
  shift
done
[ "$undo" = 0 ] || [ -z "$port" ] || die "--undo takes no port"
explicit=0
[ -z "$port" ] || explicit=1
if [ "$undo" = 1 ]; then to=22; else to=${port:-$DEFAULT_PORT}; fi

# ---------------------------------------------------------------- helpers
# Ports sshd is configured for, as a sorted list, from the effective configuration.
effective_ports() {
  sshd -T -f "$CFG" 2> /dev/null | awk '$1 == "port" {print $2}' | sort -n | tr '\n' ' ' | sed 's/ $//'
}

# Listening TCP sockets on port $1 (lines of `ss -ltnp`).
listeners() {
  ss -Hltnp 2> /dev/null | awk -v p="$1" '{n = split($4, a, ":"); if (a[n] == p) print}' || true
}

in_list() { [[ " $2 " == *" $1 "* ]]; }

socket_activated() {
  systemctl is-enabled --quiet ssh.socket 2> /dev/null || systemctl is-active --quiet ssh.socket 2> /dev/null
}

# What ssh.socket listens on, one "ADDRESS:PORT" per line.
socket_listen() {
  systemctl show ssh.socket -p Listen --value 2> /dev/null | awk 'NF {print $1}'
}

# Ports that ssh.socket listens on, as a list.
socket_ports() {
  socket_listen | awk '{n = split($1, a, ":"); print a[n]}' | sort -un | tr '\n' ' ' | sed 's/ $//'
}

# True when the SSH daemon listens on port $1: sshd itself, or systemd holding a port that
# ssh.socket lists. A socket of any other unit on that port does not count.
ssh_listens() {
  local l
  l=$(listeners "$1")
  case $l in *'"sshd"'*) return 0 ;; esac
  case $l in
    *'"systemd"'*) socket_activated && in_list "$1" "$(socket_ports)" ;;
    *) return 1 ;;
  esac
}

# Every port the SSH daemon listens on now, as a sorted list.
ssh_ports() {
  {
    ss -Hltnp 2> /dev/null | { grep '"sshd"' || true; } | awk '{n = split($4, a, ":"); print a[n]}'
    if socket_activated; then socket_ports | tr ' ' '\n'; fi
  } | sed '/^$/d' | sort -un | tr '\n' ' ' | sed 's/ $//'
}

# True for an address that means "every address".
wildcard() {
  local v=$1
  case $v in
    \[*\]:[0-9]* | *.*.*.*:[0-9]* | \*:[0-9]*) v=${v%:*} ;;
  esac
  case $v in 0.0.0.0 | '[::]' | '::' | '*') return 0 ;; esac
  return 1
}

# Prints the first address SSH is bound to that is not a wildcard, if any.
specific_bind() {
  local a
  while read -r a; do
    [ -n "$a" ] || continue
    wildcard "$a" || {
      echo "$a"
      return 0
    }
  done < <(sshd -T -f "$CFG" 2> /dev/null | awk '$1 == "listenaddress" {print $2}'; if socket_activated; then socket_listen; fi)
  return 1
}

# Writes stdin to file $1 through a temporary file, so a reader never sees half a file.
put() {
  local tmp
  tmp=$(mktemp "$1.XXXXXX")
  cat > "$tmp"
  chmod 644 "$tmp"
  mv -f "$tmp" "$1"
}

is_ours() { [ -f "$1" ] && [ "$(head -n 1 "$1")" = "$MARK" ]; }

# Keeps the first backup only: it is the user's original file.
backup() { [ -e "$1$BAK" ] || cp -p "$1" "$1$BAK"; }

# $1 = ports. BindIPv6Only keeps the two entries of a port from colliding on one dual-stack socket.
write_socket_override() {
  mkdir -p "$SOCK_DIR"
  if [ -f "$OVERRIDE" ] && ! is_ours "$OVERRIDE"; then
    backup "$OVERRIDE"
    note "Your file $OVERRIDE is kept as $OVERRIDE$BAK."
  fi
  {
    echo "$MARK"
    echo "[Socket]"
    echo "ListenStream="
    for p in $1; do
      echo "ListenStream=0.0.0.0:$p"
      echo "ListenStream=[::]:$p"
    done
    echo "BindIPv6Only=ipv6-only"
  } | put "$OVERRIDE"
}

# $1 = ports. With two ports, the second line records the port to go back to ($from).
write_dropin() {
  mkdir -p "$DROPIN_DIR"
  if [ -f "$DROPIN" ] && ! is_ours "$DROPIN"; then
    backup "$DROPIN"
    note "Your file $DROPIN is kept as $DROPIN$BAK."
  fi
  {
    echo "$MARK"
    [ "$(wc -w <<< "$1")" -le 1 ] || echo "# moving from $from"
    for p in $1; do echo "Port $p"; done
  } | put "$DROPIN"
}

# The main sshd_config must not set a Port of its own, and must read the drop-in folder. Both
# would break "the effective ports are exactly the wanted ones". Only these two things are
# edited, and unfix_main_config reverses exactly them.
fix_main_config() {
  [ -f "$CFG" ] || return 0
  local own_port=0 no_include=0 tmp
  grep -Eiq '^[[:space:]]*Port[[:space:]=]' "$CFG" && own_port=1
  grep -Eiq '^[[:space:]]*Include[[:space:]].*sshd_config\.d' "$CFG" || no_include=1
  [ "$own_port" = 1 ] || [ "$no_include" = 1 ] || return 0
  if [ -e "$CFG$BAK" ]; then
    note "Backup $CFG$BAK already exists and is kept."
  else
    cp -p "$CFG" "$CFG$BAK"
  fi
  tmp=$(mktemp "$CFG.XXXXXX")
  {
    if [ "$no_include" = 1 ]; then
      echo "$INC_MARK"
      echo "Include /etc/ssh/sshd_config.d/*.conf"
    fi
    sed -E "s/^([[:space:]]*Port[[:space:]=].*)$/$OFF_MARK\\1/I" "$CFG"
  } > "$tmp"
  chmod --reference="$CFG" "$tmp" 2> /dev/null || chmod 644 "$tmp"
  mv -f "$tmp" "$CFG"
  note "Your $CFG was changed to match. A plain copy of the original is kept as $CFG$BAK."
}

# Reverses only this script's edits of the main config, so later edits of yours are kept.
unfix_main_config() {
  [ -f "$CFG" ] || return 0
  grep -qF -e "$OFF_MARK" -e "$INC_MARK" "$CFG" || return 0
  local tmp
  tmp=$(mktemp "$CFG.XXXXXX")
  awk -v off="$OFF_MARK" -v inc="$INC_MARK" '
    skip { skip = 0; next }
    $0 == inc { skip = 1; next }
    index($0, off) == 1 { print substr($0, length(off) + 1); next }
    { print }' "$CFG" > "$tmp"
  chmod --reference="$CFG" "$tmp" 2> /dev/null || chmod 644 "$tmp"
  mv -f "$tmp" "$CFG"
}

# Removes what this script wrote and puts your own files back, in an order that leaves the
# recorded "moving from" line in the drop-in until the end. Safe to run at any time.
revert_files() {
  if is_ours "$OVERRIDE"; then rm -f "$OVERRIDE"; fi
  if [ ! -e "$OVERRIDE" ] && [ -e "$OVERRIDE$BAK" ]; then mv -f "$OVERRIDE$BAK" "$OVERRIDE"; fi
  unfix_main_config
  if is_ours "$DROPIN"; then rm -f "$DROPIN"; fi
  if [ ! -e "$DROPIN" ] && [ -e "$DROPIN$BAK" ]; then mv -f "$DROPIN$BAK" "$DROPIN"; fi
  rmdir "$SOCK_DIR" 2> /dev/null || true
}

# The ports a socket override of yours lists.
override_ports() {
  sed -n 's/^ListenStream=.*:\([0-9][0-9]*\)$/\1/p' "$OVERRIDE" | sort -un | tr '\n' ' ' | sed 's/ $//'
}

# Puts the files in place so that sshd is configured for exactly the ports in $1. For port 22
# alone that is the original state, unless something of yours still sets another port.
set_ports() {
  if [ "$1" = 22 ]; then
    revert_files
    if [ "$(effective_ports)" = 22 ] && { ! socket_activated || [ ! -e "$OVERRIDE" ] || [ "$(override_ports)" = 22 ]; }; then
      return 0
    fi
  fi
  if [ "$(wc -w <<< "$1")" -gt 1 ]; then
    write_dropin "$1"
    fix_main_config
    if socket_activated; then write_socket_override "$1"; fi
  else
    if socket_activated; then write_socket_override "$1"; fi
    fix_main_config
    write_dropin "$1"
  fi
}

# Checks the configuration, then makes sshd use it. Open sessions stay connected.
apply() {
  sshd -t -f "$CFG" || return 1
  systemctl daemon-reload || return 1
  if socket_activated; then
    # If systemd refuses to restart the socket while the service runs, stop the service (open
    # sessions survive) and start the socket: sshd then starts on the next connection.
    if ! systemctl restart ssh.socket; then
      systemctl stop ssh.service && systemctl start ssh.socket || return 1
    fi
    systemctl try-restart ssh.service || return 1
  else
    systemctl restart ssh || return 1
  fi
}

# Checks the result: the configuration, then the listeners. $1 = ports sshd must listen on,
# $2 = ports it must not listen on any more. Waits a few seconds for the daemon to come up.
verify() {
  local p bad
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [ "$(effective_ports)" = "$1" ]; then
      bad=0
      for p in $1; do ssh_listens "$p" || bad=1; done
      for p in $2; do ! ssh_listens "$p" || bad=1; done
      [ "$bad" = 0 ] && return 0
    fi
    sleep 1
  done
  return 1
}

# The one way back: SSH on the ports in $1, nothing on the ports in $2. One last restart if the
# first try does not hold, then the exact steps for the user. Never exits by itself.
recover_to() {
  set_ports "$1"
  if apply && verify "$1" "$2"; then return 0; fi
  if socket_activated; then systemctl restart ssh.socket || true; else systemctl restart ssh || true; fi
  if verify "$1" "$2"; then return 0; fi
  {
    echo "move-admin-ssh: could not confirm that SSH listens on port $1."
    echo "Do NOT close this session. Run these two commands here:"
    echo "    sudo systemctl restart ssh"
    echo "    sudo ss -ltnp | grep -E 'sshd|systemd'"
  } >&2 || true
  return 1
}

# True when the firewall lets SSH in from anywhere: a rule for $1 or for the OpenSSH profile.
ufw_ssh_open() {
  ufw status 2> /dev/null | sed 's/ (v6)//g' | awk -v p="$1" '
    ($1 == p || $1 == p "/tcp" || $1 == "OpenSSH") && /ALLOW|LIMIT/ && $NF == "Anywhere" {found = 1}
    END {exit !found}'
}

firewalld_ssh_open() {
  { firewall-cmd --list-services 2> /dev/null | tr ' ' '\n' | grep -qx ssh; } ||
    { firewall-cmd --list-ports 2> /dev/null | tr ' ' '\n' | grep -qx "$1/tcp"; }
}

# Opens $2 where the firewall lets SSH ($1) in from anywhere. A firewall that limits SSH to some
# sources is left alone: the user knows which sources, and says so in this open session.
open_firewall() {
  if command -v ufw > /dev/null 2>&1 && ufw status 2> /dev/null | grep -qi '^Status: active'; then
    if ufw_ssh_open "$1"; then
      ufw allow "$2/tcp" > /dev/null || warn "could not open $2/tcp in ufw"
      note "ufw: allowed $2/tcp (the rule stays after the move)."
    else
      note "ufw limits SSH to certain sources. Allow port $2 the same way before you go on, in this"
      note "open session: ufw allow from ADDRESS to any port $2 proto tcp"
    fi
  elif command -v firewall-cmd > /dev/null 2>&1 && systemctl is-active --quiet firewalld 2> /dev/null; then
    if firewalld_ssh_open "$1"; then
      if firewall-cmd --permanent --add-port="$2/tcp" > /dev/null && firewall-cmd --reload > /dev/null; then
        note "firewalld: allowed $2/tcp (the rule stays after the move)."
      else
        warn "could not open $2/tcp in firewalld"
      fi
    else
      note "firewalld does not let SSH in from everywhere. Allow port $2 the same way before you go on,"
      note "in this open session (firewall-cmd --add-port=$2/tcp with your source rule)."
    fi
  fi
  note "If your provider has a firewall panel, allow TCP $2 there too. This script cannot do that."
}

# Is somebody logged in on port $1? A connection alone proves nothing: a scanner can sit in the
# pre-login phase. The owner of the connection must be a real sshd process (its executable, not
# just its title) and its title must be an authenticated session: "sshd: USER@pts/0" or
# "sshd: USER@notty" ("sshd-session: ..." on newer OpenSSH). "[accepted]", "USER [priv]" and
# "USER [net]" are the pre-login phase and do not count.
login_seen() {
  local pid title exe
  for pid in $(ss -Htnp 2> /dev/null | awk -v p="$1" '$1 == "ESTAB" {n = split($4, a, ":"); if (a[n] == p) print}' | { grep -Eo 'pid=[0-9]+' || true; } | cut -d= -f2 | sort -u); do
    exe=$(readlink "$R/proc/$pid/exe" 2> /dev/null) || continue
    exe=${exe% (deleted)}
    case ${exe##*/} in sshd | sshd-session) ;; *) continue ;; esac
    title=$(ps -o args= -p "$pid" 2> /dev/null) || continue
    case $title in
      *'[accepted]'* | *'[priv]'* | *'[net]'*) ;;
      'sshd: '*@pts/* | 'sshd: '*@notty* | 'sshd-session: '*@pts/* | 'sshd-session: '*@notty*) return 0 ;;
    esac
  done
  return 1
}

# ---------------------------------------------------------------- cleanup on any exit
# phase: none = nothing written yet, open = a change is on disk, finished = all done.
# Whatever goes wrong while a change is on disk ends here: back to $from.
phase=none
from=""
# Output that may fail (the terminal can be gone after a hangup) must never stop the cleanup.
say() { echo "$@" 2> /dev/null || true; }
on_exit() {
  local rc=$?
  set +e
  trap '' INT TERM HUP PIPE
  if [ "$phase" = open ]; then
    phase=none
    say
    say "Going back to port $from."
    if recover_to "$from" "$to"; then
      say "Done: SSH listens on port $from again. Nothing else was changed."
    fi
    [ "$rc" -ne 0 ] || rc=1
  fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap 'exit 141' PIPE

# ---------------------------------------------------------------- preconditions
[ "$(uname -s)" = Linux ] || die "Linux is required."
[ "$(id -u)" -eq 0 ] || die "run it as root: sudo ./scripts/move-admin-ssh.sh"
for tool in sshd systemctl ss; do
  command -v "$tool" > /dev/null 2>&1 || die "$tool not found. Install the OpenSSH server and iproute2 first."
done
unsupported="only Debian and Ubuntu are supported. For other systems follow the manual steps in docs/vps.md."
systemctl cat ssh.service > /dev/null 2>&1 || die "no ssh.service unit: $unsupported"

if [ "$undo" = 0 ]; then
  case $to in '' | *[!0-9]*) die "the port must be a number from 1024 to 65535, not '$to'." ;; esac
  { [ "${#to}" -le 5 ] && [ "$to" -ge 1024 ] && [ "$to" -le 65535 ]; } ||
    die "the port must be a number from 1024 to 65535 (to go back to port 22 use --undo)."
  in_list "$to" "$RESERVED_PORTS" && die "port $to is used by SuckerPot ($RESERVED_PORTS). Pick another one."
fi

# ---------------------------------------------------------------- a run that was killed
# Its drop-in records the port it started from: go back there first, never guess.
if is_ours "$DROPIN" && grep -q '^# moving from [0-9][0-9]*$' "$DROPIN"; then
  from=$(sed -n 's/^# moving from \([0-9][0-9]*\)$/\1/p' "$DROPIN" | head -n 1)
  gone=$(awk -v r="$from" '$1 == "Port" && $2 != r {printf "%s ", $2}' "$DROPIN" | sed 's/ $//')
  note "An earlier run of this script was interrupted. Going back to port $from first."
  recover_to "$from" "$gone" || exit 1
  note "SSH listens on port $from again."
fi

# ---------------------------------------------------------------- starting state
current=$(ssh_ports)
[ -n "$current" ] || die "sshd does not seem to listen anywhere. Start it first, then run this again."
[ "$(wc -w <<< "$current")" -eq 1 ] ||
  die "sshd listens on several ports ($current) that this script did not set up. That setup is unusual: follow \"By hand\" in docs/vps.md."
from=$current
if [ "$from" = "$to" ]; then
  echo "Your admin SSH already listens on port $to only. Nothing to do."
  exit 0
fi
if [ "$from" != 22 ] && [ "$explicit" = 0 ] && [ "$undo" = 0 ]; then
  echo "Your admin SSH is already off port 22: it listens on port $from."
  echo "Port 22 is free for the SSH sensor. Nothing was changed."
  echo "To use another port, give it: ./scripts/move-admin-ssh.sh PORT"
  exit 0
fi
if bound=$(specific_bind); then
  die "SSH is bound to a specific address ($bound). This script never changes where SSH listens: follow \"By hand\" in docs/vps.md."
fi
for f in "$DROPIN_DIR"/*.conf; do
  [ -e "$f" ] || continue
  [ "$f" != "$DROPIN" ] || continue
  if grep -Eiq '^[[:space:]]*Port[[:space:]=]' "$f"; then
    die "$f sets a Port itself. Remove that line or follow \"By hand\" in docs/vps.md, then run this again."
  fi
done
if [ -n "$(listeners "$to")" ]; then
  if [ "$to" = 22 ]; then
    die "port 22 is used by another program, most likely the SSH sensor. Stop SuckerPot first (docker compose down, in the suckerpot folder), then run this again."
  fi
  die "port $to is already used by another program. Pick another one."
fi

# ---------------------------------------------------------------- confirmation
user=${SUDO_USER:-your-user}
both=$(printf '%s\n%s\n' "$from" "$to" | sort -n | tr '\n' ' ' | sed 's/ $//')
echo "This moves your admin SSH from port $from to port $to, in two steps."
echo "  1. It opens port $to next to port $from. Nothing is closed yet."
echo "  2. It waits until you are logged in on port $to from a second terminal. Only then does it close port $from."
echo "If the login does not happen, port $from stays as it is. Your open session stays connected."
if [ "$assume_yes" = 0 ]; then
  printf 'Continue? [y/N] '
  read -r answer || answer=""
  case $answer in y | Y | yes | YES) ;; *) die "cancelled, nothing was changed." ;; esac
fi

# ---------------------------------------------------------------- phase 1: both ports
echo
echo "Opening port $to next to port $from ..."
open_firewall "$from" "$to"
phase=open
set_ports "$both"
apply || die "the new configuration was refused or could not start."
verify "$both" "" || die "SSH does not listen on both port $from and port $to."
note "SSH now listens on port $from and port $to."

# ---------------------------------------------------------------- wait for the login
echo
echo "Keep this window open."
echo "Open a second terminal on your computer and connect:"
echo
echo "    ssh -p $to $user@YOUR-SERVER"
echo
echo "Log in fully and leave that session open. Waiting up to $((WAIT_SECONDS / 60)) minutes until you are logged in on port $to ..."
waited=0
seen=0
while [ "$waited" -lt "$WAIT_SECONDS" ]; do
  if login_seen "$to"; then seen=$((seen + 1)); else seen=0; fi
  [ "$seen" -lt 2 ] || break
  sleep "$POLL_SECONDS"
  waited=$((waited + POLL_SECONDS))
  if [ $((waited % 30)) -eq 0 ] && [ "$waited" -lt "$WAIT_SECONDS" ]; then
    note "still waiting, $(((WAIT_SECONDS - waited) / 60 + 1)) min left (Ctrl-C to cancel)"
  fi
done
if [ "$seen" -lt 2 ]; then
  if [ "$to" = 22 ]; then
    die "no login on port 22 was seen in time. If SuckerPot's SSH sensor is running, it holds port 22: stop SuckerPot first (docker compose down, in the suckerpot folder)."
  fi
  die "no login on port $to was seen in time."
fi
echo "Login on port $to seen."

# ---------------------------------------------------------------- phase 2: close the old port
echo
echo "Closing port $from ..."
set_ports "$to"
apply || die "the new configuration was refused or could not start."
verify "$to" "$from" || die "SSH does not listen on port $to only."
phase=finished

echo
echo "Done. Your admin SSH listens on port $to only."
note "Connect with: ssh -p $to $user@YOUR-SERVER"
if [ "$to" = 22 ]; then
  note "Port 22 is SSH's again: start SuckerPot's SSH sensor on another host port if you use it."
else
  note "Port 22 is free for the SSH sensor."
  note "Next step: ./scripts/install.sh --participant"
fi
note "To change the port again: sudo ./scripts/move-admin-ssh.sh PORT. To go back to 22: stop SuckerPot, then sudo ./scripts/move-admin-ssh.sh --undo"
