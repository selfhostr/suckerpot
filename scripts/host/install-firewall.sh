#!/usr/bin/env bash
# Installs a rendered SuckerPot host firewall (render-firewall.sh) so that it loads now and after
# every reboot, through its own systemd unit (never the stock nftables service, whose
# /etc/nftables.conf starts with "flush ruleset" and would wipe Docker's rules).
#
#   install-firewall.sh FILE          check FILE, install it, enable and (re)load the unit
#   install-firewall.sh --uninstall   unload the table, disable and remove the unit and the file
#
# Needs root: it re-runs itself through sudo when started as another user. It only touches
# /etc/suckerpot-firewall.nft, /etc/systemd/system/suckerpot-firewall.service and the nftables
# table "inet suckerpot_host" (on Podman also "bridge suckerpot_bridge"); the engine's own tables
# are left alone.
#
# Exit codes: 0 done; 2 bad arguments; 3 nft or systemctl missing; 4 FILE refused (placeholder
# left, or `nft -c` failed); 5 loading or verifying failed (the previous table, if any, stays);
# 6 --uninstall refused: SuckerPot containers run on Podman (SUCKERPOT_NO_FIREWALL=1 overrides).
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# SUCKERPOT_FW_ROOT (tests only) prefixes the two system paths. sudo resets the environment, so
# only a caller that is already root can set it.
fw_root=${SUCKERPOT_FW_ROOT:-}
target=$fw_root/etc/suckerpot-firewall.nft
unit=suckerpot-firewall.service
unit_path=$fw_root/etc/systemd/system/$unit

usage() {
  echo "usage: install-firewall.sh FILE | --uninstall" >&2
  exit 2
}
fail() {
  local code=$1
  shift
  echo "install-firewall: $*" >&2
  exit "$code"
}

[ "$#" -eq 1 ] || usage
case $1 in -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;; esac

if [ "$(id -u)" -ne 0 ]; then
  command -v sudo > /dev/null 2>&1 || fail 3 "run it as root (sudo is not installed)"
  arg=$1
  [ "$arg" = --uninstall ] || arg=$(cd "$(dirname "$arg")" && pwd)/$(basename "$arg")
  # sudo resets the environment: keep the owner's opt-out for --uninstall (see below).
  if [ "$arg" = --uninstall ] && [ "${SUCKERPOT_NO_FIREWALL:-}" = 1 ]; then
    exec sudo -- env SUCKERPOT_NO_FIREWALL=1 "$here/install-firewall.sh" "$arg"
  fi
  exec sudo -- "$here/install-firewall.sh" "$arg"
fi

command -v nft > /dev/null 2>&1 || fail 3 "nft not found: install the nftables package first"
command -v systemctl > /dev/null 2>&1 || fail 3 "systemctl not found: load it by hand with nft -f (scripts/host/README.md)"

if [ "$1" = --uninstall ]; then
  # On Podman the firewall carries the isolation of the sensors (design D5): never remove it under
  # running SuckerPot containers, unless the owner says they filter elsewhere.
  if [ "${SUCKERPOT_NO_FIREWALL:-}" != 1 ] && command -v podman > /dev/null 2>&1 &&
    [ -n "$(podman ps -q --filter label=com.docker.compose.project 2> /dev/null || true)" ]; then
    fail 6 "Podman containers of a compose project are running: on Podman they must not run without this firewall. Stop the stack first (docker-compose down), or set SUCKERPOT_NO_FIREWALL=1 if you filter elsewhere."
  fi
  systemctl disable --now "$unit" > /dev/null 2>&1 || true
  nft delete table inet suckerpot_host > /dev/null 2>&1 || true
  nft delete table bridge suckerpot_bridge > /dev/null 2>&1 || true
  rm -f "$unit_path" "$target"
  systemctl daemon-reload
  echo "install-firewall: removed; the host firewall table is no longer loaded"
  exit 0
fi

src=$1
{ [ -f "$src" ] && [ -r "$src" ]; } || fail 2 "cannot read $src"

# From here on, work on a root-owned private copy: the user's file could change between the
# checks and the install. The copy sits next to the target, so the final rename is atomic.
tmp=$(umask 077 && mktemp "$(dirname "$target")/.suckerpot-firewall.XXXXXX") ||
  fail 5 "cannot create a temporary file next to $target"
trap 'rm -f "$tmp"' EXIT
cat -- "$src" > "$tmp"
chown root:root "$tmp"
chmod 0600 "$tmp"

if grep -q 'CHANGE_ME\|@[A-Z_]*@' "$tmp"; then
  fail 4 "$src still holds a placeholder: render it with scripts/host/render-firewall.sh"
fi
grep -q '^table inet suckerpot_host' "$tmp" || fail 4 "$src is not a SuckerPot host firewall"
nft -c -f "$tmp" || fail 4 "nft -c refused $src (nothing was changed)"

mv -f "$tmp" "$target"
trap - EXIT
install -m 0644 -o root -g root "$here/suckerpot-firewall.service" "$unit_path"
systemctl daemon-reload
systemctl enable "$unit" > /dev/null 2>&1 || fail 5 "systemctl enable $unit failed"
# Active: reload, which loads the new file in one transaction and never stops what is bound to the
# unit (on Podman, the stack). Not active: start.
if systemctl is-active --quiet "$unit"; then
  systemctl reload "$unit" || fail 5 "the unit failed to load the new file: journalctl -u $unit"
else
  systemctl start "$unit" || fail 5 "the unit failed to load the table: journalctl -u $unit"
fi
nft list table inet suckerpot_host > /dev/null 2>&1 || fail 5 "table inet suckerpot_host is not loaded"
# A Podman rendering also holds the bridge table (sensor-to-sensor drops).
if grep -q '^table bridge suckerpot_bridge' "$target"; then
  nft list table bridge suckerpot_bridge > /dev/null 2>&1 || fail 5 "table bridge suckerpot_bridge is not loaded"
fi

cat << EOF
install-firewall: loaded table inet suckerpot_host; it is reloaded after every reboot ($unit).
  See the rules and counters: sudo nft list table inet suckerpot_host
  Undo for this boot only:    sudo systemctl stop $unit   (on Podman this also stops the stack)
  Undo for good:              sudo $here/install-firewall.sh --uninstall
EOF
