#!/usr/bin/env bash
# Lets one user reach the root Podman socket through a group (docs/dev/design/podman.md, D3), the
# way a Docker user reaches Docker through the docker group. The group is root-equivalent: a member
# can start a privileged container that mounts the host's /.
#
#   podman-socket.sh USER          create the group, add USER, open the socket to the group
#   podman-socket.sh --uninstall [USER]
#                                  remove the socket settings, and USER from the group (the group
#                                  itself and any other member stay)
#
# What it writes:
#   /etc/systemd/system/podman.socket.d/suckerpot.conf   SocketGroup=<group>, SocketMode=0660
#   /etc/tmpfiles.d/00-suckerpot-podman.conf             D! /run/podman 0750 root <group>
#   /etc/containers/containers.conf.d/50-suckerpot.conf  [network] firewall_driver = "nftables"
#     (netavark's driver no longer depends on the distribution's default; the boot unit checks
#     that the table "inet netavark" exists after each start)
# Podman's own tmpfiles rule keeps /run/podman at 0700 root, so the socket's group alone is not
# enough. systemd-tmpfiles applies the first file (in name order) that names a path, so this rule
# wins over the packaged one, and the packaged file's other lines still apply.
#
# The new group only counts in a new login session (log out and in, or `newgrp suckerpot-podman`).
# Needs root: it re-runs itself through sudo. SUCKERPOT_UNIT_ROOT (tests only) prefixes the paths.
#
# Exit codes: 0 done; 2 bad arguments; 3 a command is missing; 5 a step failed.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=${SUCKERPOT_UNIT_ROOT:-}
group=suckerpot-podman
dropin=$root/etc/systemd/system/podman.socket.d/suckerpot.conf
tmpfiles=$root/etc/tmpfiles.d/00-suckerpot-podman.conf
containers_conf=$root/etc/containers/containers.conf.d/50-suckerpot.conf
rundir=${SUCKERPOT_PODMAN_RUNDIR:-/run/podman}

fail() {
  local code=$1
  shift
  echo "podman-socket: $*" >&2
  exit "$code"
}

case ${1:-} in
  -h | --help)
    sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
    exit 0
    ;;
  "") fail 2 "usage: podman-socket.sh USER | --uninstall" ;;
esac
if [ "$1" = --uninstall ]; then
  [ "$#" -le 2 ] || fail 2 "usage: podman-socket.sh USER | --uninstall [USER]"
else
  [ "$#" -eq 1 ] || fail 2 "usage: podman-socket.sh USER | --uninstall [USER]"
fi

if [ "$(id -u)" -ne 0 ]; then
  command -v sudo > /dev/null 2>&1 || fail 3 "run it as root (sudo is not installed)"
  exec sudo -- "$here/podman-socket.sh" "$@"
fi
command -v systemctl > /dev/null 2>&1 || fail 3 "systemctl not found: Podman nodes need systemd"

if [ "$1" = --uninstall ]; then
  rm -f "$dropin" "$tmpfiles" "$containers_conf"
  if [ -n "${2:-}" ] && getent group "$group" > /dev/null 2>&1; then
    [[ $2 =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || fail 2 "'$2' is not a plain user name"
    gpasswd -d "$2" "$group" > /dev/null 2>&1 || true
    echo "podman-socket: $2 is no longer in group $group (from its next login)"
  fi
  systemctl daemon-reload
  systemctl restart podman.socket > /dev/null 2>&1 || true
  members=$(getent group "$group" 2> /dev/null | cut -d: -f4)
  echo "podman-socket: removed; the socket is root-only again (group $group kept; members: ${members:-none})"
  exit 0
fi

user=$1
[[ $user =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || fail 2 "'$user' is not a plain user name"
id -u "$user" > /dev/null 2>&1 || fail 2 "no such user: $user"
[ "$user" != root ] || fail 2 "root reaches the socket already"

if getent group "$group" > /dev/null 2>&1; then
  # Every member can act as root through the socket: say who already is one.
  members=$(getent group "$group" | cut -d: -f4)
  echo "podman-socket: group $group already exists; members: ${members:-none} (each one is root-equivalent)"
else
  groupadd --system "$group" || fail 5 "groupadd $group failed"
fi
usermod -aG "$group" "$user" || fail 5 "usermod -aG $group $user failed"

mkdir -p "$(dirname "$dropin")" "$(dirname "$tmpfiles")" "$(dirname "$containers_conf")"
printf '%s\n' "# Installed by scripts/host/podman-socket.sh: group $group may use the root Podman socket." \
  "[Socket]" "SocketGroup=$group" "SocketMode=0660" > "$dropin"
printf '%s\n' "# Installed by scripts/host/podman-socket.sh: group $group may enter /run/podman." \
  "D! /run/podman 0750 root $group" > "$tmpfiles"
printf '%s\n' "# Installed by scripts/host/podman-socket.sh: SuckerPot's host firewall and checks expect it." \
  "[network]" 'firewall_driver = "nftables"' > "$containers_conf"
chmod 0644 "$dropin" "$tmpfiles" "$containers_conf"

# Now, not only at the next boot. --create never empties the folder (only --remove and boot do).
systemd-tmpfiles --create "$tmpfiles" > /dev/null 2>&1 || true
if [ -d "$rundir" ]; then
  { chgrp "$group" "$rundir" && chmod 0750 "$rundir"; } || fail 5 "could not open $rundir to $group"
fi
systemctl daemon-reload
systemctl enable podman.socket > /dev/null 2>&1 || fail 5 "systemctl enable podman.socket failed"
systemctl restart podman.socket || fail 5 "systemctl restart podman.socket failed"
echo "podman-socket: $user may use the root Podman socket through group $group (root-equivalent)."
echo "  The group counts from the next login: log out and in, or run: newgrp $group"
