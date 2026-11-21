#!/usr/bin/env bash
# Installs the boot unit of a Podman node, suckerpot-stack.service (docs/dev/design/podman.md,
# section 5.7). Docker nodes do not need it: the Docker daemon restarts the containers itself.
#
#   install-stack-unit.sh USER CHECKOUT                fill in the unit, install and enable it
#   install-stack-unit.sh --no-firewall USER CHECKOUT  the same, without requiring the firewall unit
#   install-stack-unit.sh --uninstall                  disable and remove the unit
#
# USER is the installing user (it runs docker-compose; it reaches the root Podman socket through
# the socket's group). CHECKOUT is the absolute path of the SuckerPot checkout. The unit requires
# suckerpot-firewall.service and starts after it, so no container starts at boot before the host
# firewall is loaded; the firewall unit must be installed first (scripts/host/install-firewall.sh).
# --no-firewall is for an owner who filters elsewhere and said so (installer flag --no-firewall):
# the containers then start without the firewall.
#
# The unit is enabled, not started: the installer starts the stack itself.
# Needs root: it re-runs itself through sudo when started as another user.
#
# Exit codes: 0 done; 2 bad arguments; 3 systemctl or docker-compose missing; 4 the firewall unit
# is not installed; 5 systemctl failed.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# SUCKERPOT_UNIT_ROOT (tests only) prefixes the system paths. sudo resets the environment, so only
# a caller that is already root can set it.
root=${SUCKERPOT_UNIT_ROOT:-}
unit=suckerpot-stack.service
unit_path=$root/etc/systemd/system/$unit
fw_unit_path=$root/etc/systemd/system/suckerpot-firewall.service
# podman-restart.service (off by default) starts containers at boot by their restart policy; on
# Podman 5.6 and later that includes unless-stopped. If an owner turns it on, it must still wait
# for the firewall: this drop-in orders it after the firewall unit.
restart_dropin=$root/etc/systemd/system/podman-restart.service.d/suckerpot-firewall.conf

usage() {
  echo "usage: install-stack-unit.sh [--no-firewall] USER CHECKOUT | --uninstall" >&2
  exit 2
}
fail() {
  local code=$1
  shift
  echo "install-stack-unit: $*" >&2
  exit "$code"
}

case ${1:-} in -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;; esac
no_fw=0
if [ "${1:-}" = --no-firewall ]; then
  no_fw=1
  shift
fi
if [ "${1:-}" = --uninstall ]; then
  [ "$#" -eq 1 ] && [ "$no_fw" = 0 ] || usage
else
  [ "$#" -eq 2 ] || usage
fi

if [ "$(id -u)" -ne 0 ]; then
  command -v sudo > /dev/null 2>&1 || fail 3 "run it as root (sudo is not installed)"
  args=()
  [ "$no_fw" = 0 ] || args+=(--no-firewall)
  exec sudo -- "$here/install-stack-unit.sh" "${args[@]}" "$@"
fi

command -v systemctl > /dev/null 2>&1 || fail 3 "systemctl not found: Podman nodes need systemd"

if [ "$1" = --uninstall ]; then
  systemctl disable "$unit" > /dev/null 2>&1 || true
  rm -f "$unit_path" "$restart_dropin"
  systemctl daemon-reload
  echo "install-stack-unit: removed $unit; the stack no longer starts at boot"
  exit 0
fi

user=$1
checkout=$2
# Plain values only: they go into a unit file, where spaces and specials change the meaning.
[[ $user =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || fail 2 "'$user' is not a plain user name"
id -u "$user" > /dev/null 2>&1 || fail 2 "no such user: $user"
[ "$user" != root ] || fail 2 "run the stack as the installing user, not root"
[[ $checkout =~ ^/[A-Za-z0-9._/-]+$ ]] && [[ $checkout != *..* ]] ||
  fail 2 "'$checkout' must be an absolute path of letters, digits, '.', '_', '-' and '/'"
{ [ -f "$checkout/docker-compose.yml" ] && [ -f "$checkout/scripts/ensure-networks.sh" ]; } ||
  fail 2 "$checkout is not a SuckerPot checkout"
compose=$(command -v docker-compose || true)
[ -n "$compose" ] || fail 3 "docker-compose not found: install it first (2.26 or newer)"

fw_line=suckerpot-firewall.service
if [ "$no_fw" = 1 ]; then
  fw_line=""
  echo "install-stack-unit: WARNING: --no-firewall: the stack starts at boot without the host firewall. On Podman, sensors then reach the internet and each other unless you filter elsewhere." >&2
else
  [ -f "$fw_unit_path" ] ||
    fail 4 "suckerpot-firewall.service is not installed: install the host firewall first (scripts/host/install-firewall.sh), or pass --no-firewall"
fi

tmp=$(umask 022 && mktemp "$(dirname "$unit_path")/.suckerpot-stack.XXXXXX") ||
  fail 5 "cannot create a temporary file next to $unit_path"
trap 'rm -f "$tmp"' EXIT
nft=$(command -v nft || echo /usr/sbin/nft)
nofw_sed=()
if [ -z "$fw_line" ]; then
  # No firewall: drop every line that ties the stack to it, and tell ensure-networks.sh.
  nofw_sed=(-e '/^BindsTo=suckerpot-firewall\.service$/d' -e '/^PartOf=suckerpot-firewall\.service$/d'
    -e '/^ExecStartPre=+.* list table /d' -e 's/ suckerpot-firewall\.service$//'
    -e 's/^Environment=DOCKER_HOST=\(.*\)$/Environment=DOCKER_HOST=\1 SUCKERPOT_NO_FIREWALL=1/')
fi
sed -e "s|@USER@|$user|g" -e "s|@CHECKOUT@|$checkout|g" -e "s|@COMPOSE@|$compose|g" \
  -e "s|@NFT@|$nft|g" "${nofw_sed[@]}" "$here/$unit" > "$tmp"
if grep -q '@[A-Z_]*@' "$tmp"; then
  fail 5 "a placeholder is left in the unit (template changed?)"
fi
chmod 0644 "$tmp"
mv -f "$tmp" "$unit_path"
trap - EXIT
if [ -n "$fw_line" ]; then
  mkdir -p "$(dirname "$restart_dropin")"
  printf '%s\n' "# Installed by scripts/host/install-stack-unit.sh: no container starts before the host firewall." \
    "[Unit]" "Requires=suckerpot-firewall.service" "After=suckerpot-firewall.service" > "$restart_dropin"
  chmod 0644 "$restart_dropin"
else
  rm -f "$restart_dropin"
fi
systemctl daemon-reload
systemctl enable "$unit" > /dev/null 2>&1 || fail 5 "systemctl enable $unit failed"
echo "install-stack-unit: installed and enabled $unit; the stack starts at every boot${fw_line:+, after the host firewall}."
