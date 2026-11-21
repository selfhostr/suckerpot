# shellcheck shell=bash
# Is the host firewall (scripts/host/) in force right now? Read-only checks, sourced by
# egress-check.sh, status.sh, ensure-networks.sh and compose-fresh.sh. Needs scripts/lib/engine.sh
# (ENGINE_ID). A unit that is active is not enough: `nft flush ruleset`, a restart of the stock
# nftables service or `nft delete table` remove the rules and leave the unit active.

FW_UNIT=suckerpot-firewall.service

# fw_installed: the unit file is there (readable without root). SUCKERPOT_FW_ROOT: tests only.
fw_installed() { [ -f "${SUCKERPOT_FW_ROOT:-}/etc/systemd/system/$FW_UNIT" ]; }

# fw_tables_needed: the nftables tables the firewall of this engine loads, one per line.
fw_tables_needed() {
  echo "inet suckerpot_host"
  [ "${ENGINE_ID:-docker}" != podman ] || echo "bridge suckerpot_bridge"
}

# fw_nft_tables: `nft list tables`, as root or through sudo without a password. Returns 2 when
# neither is possible (listing tables needs root).
fw_nft_tables() {
  if [ "$(id -u)" = 0 ]; then
    command -v nft > /dev/null 2>&1 || return 2
    nft list tables 2> /dev/null || return 2
    return 0
  fi
  command -v sudo > /dev/null 2>&1 || return 2
  sudo -n nft list tables 2> /dev/null || return 2
}

# fw_state: prints one word.
#   loaded      the unit is active and every table is there
#   inactive    the unit is not active (stopped, failed, or not installed)
#   missing:T   the unit is active but table(s) T are gone
#   unknown     the unit is active, but the tables cannot be read (no root, no sudo -n)
#   nosystemd   no systemctl: nothing can be said
fw_state() {
  local tables t miss=""
  command -v systemctl > /dev/null 2>&1 || {
    echo nosystemd
    return 0
  }
  if ! systemctl is-active --quiet "$FW_UNIT" 2> /dev/null; then
    echo inactive
    return 0
  fi
  if ! tables=$(fw_nft_tables); then
    echo unknown
    return 0
  fi
  while read -r t; do
    grep -qx "table $t" <<< "$tables" || miss+="${miss:+,}$t"
  done < <(fw_tables_needed)
  if [ -z "$miss" ]; then echo loaded; else echo "missing:$miss"; fi
}

# fw_no_firewall: the owner opted out (SUCKERPOT_NO_FIREWALL=1 in the environment or in .env).
fw_no_firewall() {
  local v=${SUCKERPOT_NO_FIREWALL:-}
  [ -n "$v" ] || v=$(sed -n 's/^SUCKERPOT_NO_FIREWALL=//p' "${ENV_FILE:-.env}" 2> /dev/null | tail -n 1 | tr -d "\"' \r")
  [ "$v" = 1 ]
}

# fw_guard: Podman only. Succeeds when the stack may start: the firewall unit is active and its
# tables are loaded, or the owner opted out. When the tables cannot be read (no root and no
# passwordless sudo, as in the automatic updater), an active unit is accepted with a note; the boot
# unit checks the tables as root. Docker: always succeeds (the firewall is optional there).
fw_guard() {
  local state
  [ "${ENGINE_ID:-docker}" = podman ] || return 0
  if fw_no_firewall; then
    echo "note: SUCKERPOT_NO_FIREWALL=1: starting without the host firewall check" >&2
    return 0
  fi
  state=$(fw_state)
  case $state in
    loaded) return 0 ;;
    unknown)
      echo "note: $FW_UNIT is active; its tables were not read (needs root or sudo without a password)" >&2
      return 0
      ;;
    inactive) echo "the host firewall ($FW_UNIT) is not active. On Podman the stack does not start without it: sudo systemctl start $FW_UNIT (or install it: scripts/host/install-firewall.sh)" >&2 ;;
    missing:*) echo "the host firewall unit is active but its table(s) ${state#missing:} are not loaded (flushed?). Load them again: sudo systemctl reload $FW_UNIT" >&2 ;;
    *) echo "the host firewall cannot be checked ($state). On Podman the stack does not start without it." >&2 ;;
  esac
  return 1
}
