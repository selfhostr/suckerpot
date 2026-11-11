#!/usr/bin/env bash
# Moves this machine's own SSH daemon off port 22, so the SSH sensor can use it. Debian and Ubuntu.
#
#   sudo ./scripts/move-admin-ssh.sh          move the admin SSH to port 22222
#   sudo ./scripts/move-admin-ssh.sh 48022    move it to a port of your choice (1024 to 65535)
#   sudo ./scripts/move-admin-ssh.sh --undo   go back to port 22
#
#   -y, --yes    do not ask before changing anything
#   -h, --help   show this help
#
# You are never locked out: the new port is opened NEXT TO port 22 first. The script then waits
# until you are logged in on the new port from a second terminal, and only then closes port 22.
# If the login does not come in 5 minutes, or the script is interrupted or fails, port 22 stays as it
# was. Your open session stays connected all along.
#
# It writes /etc/ssh/sshd_config.d/10-admin-port.conf and, when SSH is started by systemd socket
# activation (Ubuntu 24.04 and newer), /etc/systemd/system/ssh.socket.d/override.conf. Every file
# it writes starts with a marker line. A file of yours that is in the way is backed up next to it
# (*.suckerpot.bak). It opens the new port in ufw or firewalld when one is active. It never looks
# up this machine's address and makes no network connection.
set -euo pipefail

# SuckerPot's own ports: the sensors' host ports, the SSH sensor's container port and the default
# dashboard port. The admin SSH must not use any of them.
RESERVED_PORTS="22 23 80 443 445 1433 2222 2375 3306 3389 5000 5001 5060 5555 6379 8443"
DEFAULT_PORT=22222
# How long to wait for the login on the new port, in seconds. The tests shorten it.
WAIT_SECONDS=${MOVE_SSH_WAIT_SECONDS:-300}
POLL_SECONDS=2

# MOVE_SSH_ROOT prefixes every /etc path (empty on a real machine, a scratch folder in the tests).
R=${MOVE_SSH_ROOT:-}
CFG=$R/etc/ssh/sshd_config
DROPIN_DIR=$R/etc/ssh/sshd_config.d
DROPIN=$DROPIN_DIR/10-admin-port.conf
SOCK_DIR=$R/etc/systemd/system/ssh.socket.d
OVERRIDE=$SOCK_DIR/override.conf
BAK=.suckerpot.bak
MARK="# move-admin-ssh.sh: managed file. Undo with: ./scripts/move-admin-ssh.sh --undo"

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
[ -n "$port" ] || port=$DEFAULT_PORT

# ---------------------------------------------------------------- helpers
# Ports sshd listens on, as a sorted list, from the effective configuration.
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

# Ports that ssh.socket listens on, as a list.
socket_ports() {
  systemctl show ssh.socket -p Listen --value 2> /dev/null | awk 'NF {n = split($1, a, ":"); print a[n]}' | sort -un | tr '\n' ' ' | sed 's/ $//'
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

# True when a program that is not the SSH daemon listens on port $1.
foreign_listens() { [ -n "$(listeners "$1")" ] && ! ssh_listens "$1"; }

# Every port the SSH daemon listens on now, as a sorted list.
ssh_ports() {
  {
    ss -Hltnp 2> /dev/null | { grep '"sshd"' || true; } | awk '{n = split($4, a, ":"); print a[n]}'
    if socket_activated; then socket_ports | tr ' ' '\n'; fi
  } | sed '/^$/d' | sort -un | tr '\n' ' ' | sed 's/ $//'
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
  } | put "$OVERRIDE"
}

write_dropin() {
  mkdir -p "$DROPIN_DIR"
  if [ -f "$DROPIN" ] && ! is_ours "$DROPIN"; then
    backup "$DROPIN"
    note "Your file $DROPIN is kept as $DROPIN$BAK."
  fi
  {
    echo "$MARK"
    for p in $1; do echo "Port $p"; done
  } | put "$DROPIN"
}

# The main sshd_config must not set a Port of its own, and must read the drop-in folder.
# Both would break "the effective ports are exactly the wanted ones".
fix_main_config() {
  [ -f "$CFG" ] || return 0
  local own_port=0 no_include=0
  grep -Eiq '^[[:space:]]*Port[[:space:]=]' "$CFG" && own_port=1
  grep -Eiq '^[[:space:]]*Include[[:space:]].*sshd_config\.d' "$CFG" || no_include=1
  [ "$own_port" = 1 ] || [ "$no_include" = 1 ] || return 0
  if [ -e "$CFG$BAK" ]; then
    note "Backup $CFG$BAK already exists and is kept."
  else
    cp -p "$CFG" "$CFG$BAK"
  fi
  local tmp
  tmp=$(mktemp "$CFG.XXXXXX")
  {
    if [ "$no_include" = 1 ]; then
      echo "$MARK"
      echo "Include /etc/ssh/sshd_config.d/*.conf"
    fi
    sed -E "s/^([[:space:]]*Port[[:space:]=].*)$/# move-admin-ssh.sh disabled: \1/I" "$CFG"
  } > "$tmp"
  chmod --reference="$CFG" "$tmp" 2> /dev/null || chmod 644 "$tmp"
  mv -f "$tmp" "$CFG"
  note "Your $CFG was changed to match: a copy is saved as $CFG$BAK."
}

restore_main_config() {
  if [ -f "$CFG$BAK" ] && grep -q 'move-admin-ssh.sh' "$CFG" 2> /dev/null; then
    cp -p "$CFG$BAK" "$CFG"
    rm -f "$CFG$BAK"
  fi
}

# Removes what this script wrote and puts the user's own files back. Safe to run at any time.
revert_files() {
  local f
  for f in "$OVERRIDE" "$DROPIN"; do
    if is_ours "$f"; then rm -f "$f"; fi
    if [ ! -e "$f" ] && [ -e "$f$BAK" ]; then mv -f "$f$BAK" "$f"; fi
  done
  restore_main_config
  rmdir "$SOCK_DIR" 2> /dev/null || true
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

open_firewall() {
  if command -v ufw > /dev/null 2>&1 && ufw status 2> /dev/null | grep -qi '^Status: active'; then
    ufw allow "$1/tcp" > /dev/null || warn "could not open $1/tcp in ufw"
    note "ufw: allowed $1/tcp (the rule stays after --undo)."
  elif command -v firewall-cmd > /dev/null 2>&1 && systemctl is-active --quiet firewalld 2> /dev/null; then
    if firewall-cmd --permanent --add-port="$1/tcp" > /dev/null && firewall-cmd --reload > /dev/null; then
      note "firewalld: allowed $1/tcp (the rule stays after --undo)."
    else
      warn "could not open $1/tcp in firewalld"
    fi
  fi
  note "If your provider has a firewall panel, allow TCP $1 there too. This script cannot do that."
}

# Is somebody logged in on port $1? A connection alone proves nothing: a scanner can sit in the
# pre-login phase. The owner of the connection must be an authenticated session, whose process
# title reads "sshd: USER@pts/0" or "sshd: USER@notty" ("sshd-session: ..." on newer OpenSSH).
# "[accepted]", "USER [priv]" and "USER [net]" are the pre-login phase and do not count.
login_seen() {
  local pid title
  for pid in $(ss -Htnp 2> /dev/null | awk -v p="$1" '$1 == "ESTAB" {n = split($4, a, ":"); if (a[n] == p) print}' | { grep -Eo 'pid=[0-9]+' || true; } | cut -d= -f2 | sort -u); do
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
phase=none
on_exit() {
  local rc=$?
  trap '' INT TERM HUP
  if [ "$phase" = open ]; then
    phase=none
    echo
    echo "Going back to port 22 only."
    revert_files
    if apply && verify "22" "$port"; then
      echo "Done: SSH listens on port 22 again. Nothing else was changed."
    else
      # One last attempt, straight at the service.
      if socket_activated; then systemctl restart ssh.socket || true; else systemctl restart ssh || true; fi
      if verify "22" "$port"; then
        echo "Done: SSH listens on port 22 again. Nothing else was changed."
      else
        {
          echo "move-admin-ssh: could not confirm that SSH listens on port 22."
          echo "Do NOT close this session. Run these two commands here:"
          echo "    sudo systemctl restart ssh"
          echo "    sudo ss -ltnp | grep -E 'sshd|systemd'"
        } >&2
      fi
    fi
    [ "$rc" -ne 0 ] || rc=1
  fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# ---------------------------------------------------------------- preconditions
[ "$(uname -s)" = Linux ] || die "Linux is required."
[ "$(id -u)" -eq 0 ] || die "run it as root: sudo ./scripts/move-admin-ssh.sh"
for tool in sshd systemctl ss; do
  command -v "$tool" > /dev/null 2>&1 || die "$tool not found. Install the OpenSSH server and iproute2 first."
done
unsupported="only Debian and Ubuntu are supported. For other systems follow the manual steps in docs/vps.md."
systemctl cat ssh.service > /dev/null 2>&1 || die "no ssh.service unit: $unsupported"

if [ "$undo" = 0 ]; then
  case $port in '' | *[!0-9]*) die "the port must be a number from 1024 to 65535, not '$port'." ;; esac
  { [ "${#port}" -le 5 ] && [ "$port" -ge 1024 ] && [ "$port" -le 65535 ]; } ||
    die "the port must be a number from 1024 to 65535 (to go back to port 22 use --undo)."
  in_list "$port" "$RESERVED_PORTS" && die "port $port is used by SuckerPot ($RESERVED_PORTS). Pick another one."
  foreign_listens "$port" && die "port $port is already used by another program. Pick another one."
fi

# ---------------------------------------------------------------- undo
if [ "$undo" = 1 ]; then
  old_port=""
  if is_ours "$DROPIN"; then old_port=$(awk '$1 == "Port" && $2 != 22 {print $2; exit}' "$DROPIN"); fi
  ours=0
  { is_ours "$OVERRIDE" || is_ours "$DROPIN" || [ -e "$CFG$BAK" ]; } && ours=1
  if [ "$ours" = 0 ]; then
    if [ "$(effective_ports)" = 22 ] && ssh_listens 22; then
      echo "Admin SSH is already on port 22. Nothing to do."
      exit 0
    fi
    die "this script did not change your SSH setup, so it has nothing to undo. Follow docs/vps.md by hand."
  fi
  port=${old_port:-0}
  echo "This puts your admin SSH back on port 22."
  if [ "$assume_yes" = 0 ]; then
    printf 'Continue? [y/N] '
    read -r answer || answer=""
    case $answer in y | Y | yes | YES) ;; *) die "cancelled, nothing was changed." ;; esac
  fi
  revert_files
  apply || die "the configuration was refused after the undo. Check it with: sshd -t"
  verify "22" "$port" || die "SSH does not listen on port 22 only. Check by hand: ss -ltnp | grep -E 'sshd|systemd'"
  echo "Done: SSH listens on port 22 again."
  note "The firewall rule for the old port was left in place. Remove it yourself if you want to."
  exit 0
fi

# ---------------------------------------------------------------- idempotence
if [ "$(effective_ports)" = "$port" ] && ssh_listens "$port" && ! ssh_listens 22; then
  echo "Admin SSH already listens on port $port and not on port 22. Nothing to do."
  exit 0
fi

# ---------------------------------------------------------------- starting state
# A run that was killed (kill -9, power loss) leaves its files behind: put them back first.
if is_ours "$OVERRIDE" || is_ours "$DROPIN" || { [ -e "$CFG$BAK" ] && grep -q 'move-admin-ssh.sh' "$CFG" 2> /dev/null; }; then
  note "Changes from an earlier run of this script are still in place. Putting them back first."
  revert_files
  apply || die "the configuration was refused after putting the earlier changes back. Check it with: sshd -t"
  verify "$(effective_ports)" "" || die "SSH does not listen on the ports it is configured for. Check by hand: ss -ltnp | grep -E 'sshd|systemd'"
fi
current=$(ssh_ports)
[ -n "$current" ] || die "sshd does not seem to listen anywhere. Start it first, then run this again."
if ! in_list 22 "$current"; then
  echo "Your admin SSH is already off port 22 (it listens on: $current)."
  echo "Port 22 is free for the SSH sensor. Nothing to do."
  exit 0
fi
[ "$current" = 22 ] || die "sshd listens on port 22 and on other ports ($current) that this script did not set up. That setup is unusual: follow \"By hand\" in docs/vps.md."

# ---------------------------------------------------------------- confirmation
user=${SUDO_USER:-your-user}
echo "This moves your admin SSH from port 22 to port $port, in two steps."
echo "  1. It opens port $port next to port 22. Nothing is closed yet."
echo "  2. It waits until you are logged in on port $port from a second terminal. Only then does it close port 22."
echo "If the login does not happen, port 22 stays as it is. Your open session stays connected."
if [ "$assume_yes" = 0 ]; then
  printf 'Continue? [y/N] '
  read -r answer || answer=""
  case $answer in y | Y | yes | YES) ;; *) die "cancelled, nothing was changed." ;; esac
fi

# ---------------------------------------------------------------- phase 1: both ports
echo
echo "Opening port $port next to port 22 ..."
open_firewall "$port"
phase=open
write_dropin "22 $port"
fix_main_config
socket_activated && write_socket_override "22 $port"
apply || die "the new configuration was refused (sshd -t)."
verify "22 $port" "" || die "SSH does not listen on both port 22 and port $port."
note "SSH now listens on port 22 and port $port."

# ---------------------------------------------------------------- wait for the login
echo
echo "Keep this window open."
echo "Open a second terminal on your computer and connect:"
echo
echo "    ssh -p $port $user@YOUR-SERVER"
echo
echo "Log in fully and leave that session open. Waiting up to $((WAIT_SECONDS / 60)) minutes until you are logged in on port $port ..."
waited=0
seen=0
while [ "$waited" -lt "$WAIT_SECONDS" ]; do
  if login_seen "$port"; then seen=$((seen + 1)); else seen=0; fi
  [ "$seen" -lt 2 ] || break
  sleep "$POLL_SECONDS"
  waited=$((waited + POLL_SECONDS))
  if [ $((waited % 30)) -eq 0 ] && [ "$waited" -lt "$WAIT_SECONDS" ]; then
    note "still waiting, $(((WAIT_SECONDS - waited) / 60 + 1)) min left (Ctrl-C to cancel)"
  fi
done
[ "$seen" -ge 2 ] || die "no login on port $port was seen in time."
echo "Login on port $port seen."

# ---------------------------------------------------------------- phase 2: close 22
echo
echo "Closing port 22 ..."
write_dropin "$port"
socket_activated && write_socket_override "$port"
apply || die "the new configuration was refused (sshd -t)."
verify "$port" "22" || die "SSH does not listen on port $port only."
phase=finished

echo
echo "Done. Your admin SSH listens on port $port only."
note "Connect with: ssh -p $port $user@YOUR-SERVER"
note "Port 22 is free for the SSH sensor."
note "Next step: ./scripts/install.sh --participant"
note "To go back to port 22: sudo ./scripts/move-admin-ssh.sh --undo"
