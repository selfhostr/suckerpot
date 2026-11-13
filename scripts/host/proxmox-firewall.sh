#!/usr/bin/env bash
# Manages the Proxmox VE firewall of the VM that runs SuckerPot: /etc/pve/firewall/<vmid>.fw.
# Run it as root on the Proxmox node. It is the hypervisor layer; the nftables table of
# install-firewall.sh (inside the VM) is still needed.
#
#   proxmox-firewall.sh --vmid N --gateway ADDR --admin-port N --admin-from CIDR [options]
#                       dry run: print the file and its difference, change nothing
#   proxmox-firewall.sh ... --apply [--replace] [--set-nic-firewall]
#   proxmox-firewall.sh --undo --vmid N
#
# Required:
#   --vmid N           the VM (digits, 100 and up)
#   --gateway ADDR     the LAN gateway and DNS the VM needs (IPv4 or IPv6 address)
#   --admin-port N     the port of the VM's admin SSH: the port you chose with
#                      scripts/move-admin-ssh.sh. There is no default
#   --admin-from CIDR  who may reach the admin port (an address or a CIDR, never /0)
# Options:
#   --gateway-all      let the VM reach EVERY port of the gateway. Without it the gateway
#                      answers DNS only (53/udp and 53/tcp): the router's admin page, UPnP and
#                      the like stay out of reach. Routing through the gateway is unaffected
#   --dns ADDR         another resolver the VM uses, DNS only (53/udp and 53/tcp): an IPv4 or
#                      IPv6 address, such as the box's IPv6 link-local or ULA resolver (repeat it).
#                      Check what the VM uses with `resolvectl dns` on the VM
#   --allow-out ADDR   another LAN host the VM may reach on every port (address or CIDR, repeat
#                      it). Placed before the private-range drops
#   --vm-addr ADDR     an address the VM uses (IPv4 or IPv6, or a CIDR no broader than a /24 or
#                      a /64, such as the IPv6 /64 when the VM rotates temporary addresses;
#                      repeat it). Writes the set ipfilter-<NIC>, which filters that NIC: the VM
#                      may then only send with these source addresses. List EVERY address the VM
#                      uses on that NIC, IPv6 included, or it loses that traffic
#   --vm-nic NAME      the NIC of --vm-addr, as in `qm config` (default net0)
#   --private-port N  a port that only some hosts may reach, such as the dashboard port or a hub
#                      port (repeat it). Needs --private-from or --private-from-admin
#   --private-from ADDR
#                      who may reach the private ports: the host of the reverse tunnel, for
#                      example a cloudflared VM (address or CIDR, repeat it)
#   --private-from-admin
#                      the admin network may reach the private ports too
#   --apply            write the file (needs root on a Proxmox node). Default is a dry run
#   --replace          with --apply: also drop rules and options this script did not generate
#   --set-nic-firewall with --apply: run `qm set` to put firewall=1 on the VM's NICs that lack
#                      it (briefly reconnects a running VM's NIC). Without it, the command is
#                      only printed
#   --undo             go back one step: put the most recent backup of this VM back and drop it
#                      from the stack of backups (run it again to go back another step)
#   -h, --help         show this help
#
# What it writes (Proxmox evaluates top to bottom, the first match wins):
#   [OPTIONS]  enable: 1, policy_in: ACCEPT (the sensors must accept the internet on many ports),
#              policy_out: ACCEPT, macfilter: 1. There is no `ipfilter` option: it would give
#              every NIC an empty set, which drops all of that NIC's IPv4 traffic (a NIC that
#              later gets firewall=1 would be cut off). The set of --vm-addr alone filters its
#              NIC
#   [RULES]    1. OUT DROP of udp to port 68 and 546: no rogue DHCP server replies from the VM
#              2. OUT ACCEPT of DNS (53/udp, 53/tcp) to the gateway, or of everything with
#                 --gateway-all, then of DNS to each --dns, then of everything to each
#                 --allow-out
#              3. OUT DROP to the private ranges: the three of RFC 1918 (10/8, 172.16/12,
#                 192.168/16), 100.64/10 (CGNAT), 169.254/16 (link-local) and, for IPv6,
#                 fc00::/7. Then OUT DROP of tcp and udp to fe80::/10: without it the VM could
#                 find every IPv6 host of the LAN (ping ff02::1) and reach its services over
#                 link-local. ICMPv6 is left alone: neighbour discovery is ICMPv6, and Proxmox
#                 accepts it (option ndp) before these rules. A LAN that is also reachable by
#                 global IPv6 addresses cannot be blocked here
#              4. IN ACCEPT admin-from to the admin port, then IN DROP of the admin port
#              5. for each --private-port: IN ACCEPT from the tunnel host(s) (and the admin
#                 network with --private-from-admin), then IN DROP of that port
#   [IPSET ipfilter-<nic>]  with --vm-addr: the addresses of the VM; it filters that NIC
#
# Safety: a dry run changes nothing. --apply backs the current file up to
# /root/suckerpot-firewall-backups/<vmid>-<UTC timestamp>.fw (0600), checks the copy, writes the
# new file atomically (a temp file in /etc/pve/firewall, then a rename), runs `pve-firewall
# compile` and puts the backup back when that fails. A failed apply leaves no backup behind. It
# refuses (exit 4) when the current file holds rules or options it did not generate, unless
# --replace. It never touches the datacenter firewall (cluster.fw) or the node firewall: it only
# reads whether the datacenter firewall is on and warns. It checks `qm config` for firewall=1 on
# the NICs and only changes it with --set-nic-firewall. A rule it wrote carries a "# SuckerPot:"
# comment: those are replaced without --replace. It warns about a source wider than a /16
# (IPv4) or a /48 (IPv6) and about an --allow-out that covers a whole private range. It refuses a
# --vm-addr broader than a /24 (IPv4) or a /64 (IPv6).
#
# Keep the Proxmox console open the first time: a wrong --admin-from cuts your SSH to the VM,
# and a wrong --vm-addr cuts the VM off (--undo, run on the node, brings it back).
#
# Exit codes: 0 done, or the dry run worked; 2 bad arguments; 3 not a Proxmox node, or a tool is
# missing; 4 refused (not root, VM not found, foreign rules without --replace, nothing to
# undo); 5 the change failed (nothing was changed when /etc/pve is read-only or the backup
# failed; a failed check was rolled back; a failed `qm set` leaves the written file in place).
#
# SUCKERPOT_PVE_ROOT is for the tests only: it prefixes /etc/pve and /root. Never set it (it is
# refused for root).
set -euo pipefail

# The sensors' default host ports (.env.example, *_HOST_PORT). A private port or the admin port
# on one of them would block a sensor or expose the admin SSH, so they are refused.
SENSOR_PORTS="22 23 80 443 445 1433 2375 3306 3389 5000 5001 5060 5555 6379"
MARK="SuckerPot:"
# What the VM may not reach, whatever the protocol: RFC 1918, CGNAT, link-local, IPv6 unique
# local. IPv6 link-local (fe80::/10) is dropped for tcp and udp only (see build).
PRIVATE_RANGES="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 fc00::/7" # gitleaks:allow (private ranges are the point of the rule)

root=${SUCKERPOT_PVE_ROOT:-}
pve=$root/etc/pve
fwdir=$pve/firewall
bakdir=$root/root/suckerpot-firewall-backups

# Admin tools live in sbin, which a plain `su` shell may not have. Appended last: PATH wins.
PATH="$PATH:/usr/sbin:/sbin"

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'; }
note() { echo "proxmox-firewall: $*" >&2; }
warn() { echo "proxmox-firewall: warning: $*" >&2; }
die() {
  local code=$1
  shift
  echo "proxmox-firewall: $*" >&2
  exit "$code"
}
bad() { die 2 "$* (see --help)"; }

# ---------------------------------------------------------------- validation
valid_port() { [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$1 <= 65535)); }
valid_vmid() { [[ $1 =~ ^[1-9][0-9]{2,8}$ ]]; }

valid_ipv4() {
  local IFS=. octet
  [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  # shellcheck disable=SC2086 # split on dots on purpose
  for octet in $1; do
    [[ $octet =~ ^(0|[1-9][0-9]*)$ ]] && ((octet <= 255)) || return 1
  done
}

# Number of 16-bit groups in one side of an IPv6 address (an empty side has 0), or fails. The
# last side may end with a dotted IPv4 address, which counts as two groups.
v6_groups() {
  local s=$1 allow4=$2 colons n extra=0
  [ -n "$s" ] || {
    echo 0
    return 0
  }
  if [ "$allow4" = 1 ] && [[ $s == *.* ]]; then
    valid_ipv4 "${s##*:}" || return 1
    extra=2
    if [[ $s == *:* ]]; then
      s=${s%:*}
    else
      echo 2
      return 0
    fi
  fi
  [[ $s =~ ^[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4})*$ ]] || return 1
  colons=${s//[^:]/}
  n=$((${#colons} + 1 + extra))
  echo "$n"
}

valid_ipv6() {
  local a=$1 head tail nh nt
  [[ $a =~ ^[0-9a-fA-F:.]+$ ]] || return 1
  [[ $a == *:::* ]] && return 1
  if [[ $a == *::* ]]; then
    head=${a%%::*}
    tail=${a#*::}
    [[ $tail == *::* ]] && return 1
    nh=$(v6_groups "$head" 0) || return 1
    nt=$(v6_groups "$tail" 1) || return 1
    ((nh + nt <= 7))
  else
    nh=$(v6_groups "$a" 1) || return 1
    ((nh == 8))
  fi
}

valid_addr() { valid_ipv4 "$1" || valid_ipv6 "$1"; }

# An address, or ADDR/LENGTH. Prints nothing; a /0 is refused by the caller (net_is_everyone).
valid_net() {
  local addr=${1%%/*} len=""
  [[ $1 == */* ]] && len=${1#*/}
  [[ $1 != */*/* ]] || return 1
  if [[ $1 == */* ]]; then
    [[ $len =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
  fi
  if valid_ipv4 "$addr"; then
    [ -z "$len" ] || ((len <= 32))
  elif valid_ipv6 "$addr"; then
    [ -z "$len" ] || ((len <= 128))
  else
    return 1
  fi
}

net_is_everyone() { [[ $1 == */0 ]]; }

# A second opinion from python3's ipaddress module when it exists (it is on Proxmox). It can only
# refuse more: an answer other than "bad", or a missing or broken python3, changes nothing.
py_agrees() {
  local res
  command -v python3 > /dev/null 2>&1 || return 0
  res=$(python3 -I -c '
import ipaddress, sys
try:
    if sys.argv[1] == "addr":
        ipaddress.ip_address(sys.argv[2])
    else:
        ipaddress.ip_network(sys.argv[2], strict=False)
    print("ok")
except ValueError:
    print("bad")
' "$1" "$2" 2> /dev/null) || return 0
  [ "$res" != bad ]
}

check_addr() { # option value
  if ! valid_addr "$2" || ! py_agrees addr "$2"; then
    bad "$1: '$2' is not an IPv4 or IPv6 address"
  fi
}
check_source() { # option value: an address or a CIDR that is not "everyone"
  if ! valid_net "$2" || ! py_agrees net "$2"; then
    bad "$1: '$2' is not an IPv4 or IPv6 address or CIDR"
  fi
  ! net_is_everyone "$2" || bad "$1: '$2' means every address, which defeats the rule"
}

in_list() { [[ " $2 " == *" $1 "* ]]; }

ipv4_int() {
  local IFS=. a b c d
  read -r a b c d <<< "$1"
  echo $(((a << 24) + (b << 16) + (c << 8) + d))
}

# Prefix length of an address or CIDR (a bare address is a host: 32 or 128).
net_len() {
  if [[ $1 == */* ]]; then
    echo "${1#*/}"
  elif valid_ipv4 "$1"; then
    echo 32
  else
    echo 128
  fi
}

# Warns about a source broader than a /16 (IPv4) or a /48 (IPv6).
warn_wide() { # option value
  local addr=${2%%/*} len
  len=$(net_len "$2")
  if valid_ipv4 "$addr"; then
    ((len >= 16)) || warn "$1 $2 is wider than a /16: every host in it is trusted"
  else
    ((len >= 48)) || warn "$1 $2 is wider than a /48: every host in it is trusted"
  fi
}

# --vm-addr: an address, or a CIDR no broader than a /24 (IPv4) or a /64 (IPv6). The VM may send
# from every address in it, so a wider one would hardly filter anything. A /64 is what a VM that
# rotates temporary IPv6 addresses needs.
check_vm_addr() { # value
  local addr=${1%%/*} len
  if ! valid_net "$1" || ! py_agrees net "$1"; then
    bad "--vm-addr: '$1' is not an IPv4 or IPv6 address or CIDR"
  fi
  len=$(net_len "$1")
  if valid_ipv4 "$addr"; then
    ((len >= 24)) || bad "--vm-addr $1 is broader than a /24: the VM could send from too many addresses; list the addresses it uses, or a narrower range"
  else
    ((len >= 64)) || bad "--vm-addr $1 is broader than a /64: the VM could send from too many addresses; use the /64 it lives in, or list its addresses"
  fi
}

# Prints the private range (IPv4) that the address or CIDR $1 covers whole, and fails if none.
covers_private() {
  local addr=${1%%/*} len a r rl mask
  valid_ipv4 "$addr" || return 1
  len=$(net_len "$1")
  a=$(ipv4_int "$addr")
  for r in $PRIVATE_RANGES; do
    [[ $r != *:* ]] || continue
    rl=${r#*/}
    ((len <= rl)) || continue
    mask=$(((0xFFFFFFFF << (32 - len)) & 0xFFFFFFFF))
    if ((($(ipv4_int "${r%/*}") & mask) == (a & mask))); then
      echo "$r"
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------- arguments
vmid=""
gateway=""
gateway_all=0
admin_port=""
admin_from=""
allow_out=()
dns_hosts=()
vm_addrs=()
vm_nic=""
private_ports=()
private_from=()
private_from_admin=0
apply=0
replace=0
set_nic=0
undo=0

need_value() { { [ "$#" -ge 2 ] && [ -n "$2" ]; } || bad "$1 needs a value"; }
once() { [ -z "$2" ] || bad "$1 was given twice"; }

while [ "$#" -gt 0 ]; do
  case $1 in
    --vmid | --gateway | --admin-port | --admin-from | --allow-out | --private-port | --private-from | --vm-addr | --vm-nic | --dns)
      need_value "$@"
      case $1 in
        --vmid) once "$1" "$vmid" && vmid=$2 ;;
        --gateway) once "$1" "$gateway" && gateway=$2 ;;
        --admin-port) once "$1" "$admin_port" && admin_port=$2 ;;
        --admin-from) once "$1" "$admin_from" && admin_from=$2 ;;
        --vm-nic) once "$1" "$vm_nic" && vm_nic=$2 ;;
        --allow-out) allow_out+=("$2") ;;
        --dns) dns_hosts+=("$2") ;;
        --vm-addr) vm_addrs+=("$2") ;;
        --private-port) private_ports+=("$2") ;;
        --private-from) private_from+=("$2") ;;
      esac
      shift 2
      ;;
    --private-from-admin)
      private_from_admin=1
      shift
      ;;
    --gateway-all)
      gateway_all=1
      shift
      ;;
    --apply)
      apply=1
      shift
      ;;
    --replace)
      replace=1
      shift
      ;;
    --set-nic-firewall)
      set_nic=1
      shift
      ;;
    --undo)
      undo=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) bad "unknown argument: $1" ;;
  esac
done

# The test root moves /etc/pve and /root: for root it would send a real run to the wrong place.
if [ -n "${SUCKERPOT_PVE_ROOT:-}" ] && [ "$EUID" -eq 0 ]; then
  die 2 "SUCKERPOT_PVE_ROOT is for the tests only and is refused for root: unset it"
fi

[ -n "$vmid" ] || bad "--vmid is required"
valid_vmid "$vmid" || bad "--vmid must be a whole number, 100 or more"

if [ "$undo" = 1 ]; then
  { [ -z "$gateway$admin_port$admin_from$vm_nic" ] && [ "${#allow_out[@]}" -eq 0 ] &&
    [ "${#dns_hosts[@]}" -eq 0 ] &&
    [ "${#vm_addrs[@]}" -eq 0 ] && [ "${#private_ports[@]}" -eq 0 ] &&
    [ "${#private_from[@]}" -eq 0 ] &&
    [ "$private_from_admin$gateway_all$apply$replace$set_nic" = 00000 ]; } ||
    bad "--undo takes only --vmid"
else
  [ -n "$gateway" ] || bad "--gateway is required (the LAN gateway and DNS the VM needs)"
  [ -n "$admin_port" ] || bad "--admin-port is required (the port you chose with scripts/move-admin-ssh.sh)"
  [ -n "$admin_from" ] || bad "--admin-from is required (an address or CIDR that may reach the admin port)"
  check_addr --gateway "$gateway"
  valid_port "$admin_port" || bad "--admin-port must be a whole number from 1 to 65535"
  in_list "$admin_port" "$SENSOR_PORTS" && bad "--admin-port $admin_port is a sensor port ($SENSOR_PORTS)"
  check_source --admin-from "$admin_from"
  warn_wide --admin-from "$admin_from"
  for a in ${allow_out[@]+"${allow_out[@]}"}; do
    check_source --allow-out "$a"
    if covered=$(covers_private "$a"); then
      warn "--allow-out $a covers the whole private range $covered: the VM could reach every host in it, which defeats the drop of that range"
    else
      warn_wide --allow-out "$a"
    fi
  done
  for a in ${private_from[@]+"${private_from[@]}"}; do
    check_source --private-from "$a"
    warn_wide --private-from "$a"
  done
  for a in ${dns_hosts[@]+"${dns_hosts[@]}"}; do check_addr --dns "$a"; done
  for a in ${vm_addrs[@]+"${vm_addrs[@]}"}; do check_vm_addr "$a"; done
  if [ "${#vm_addrs[@]}" -gt 0 ]; then
    vm_nic=${vm_nic:-net0}
    [[ $vm_nic =~ ^net[0-9]{1,2}$ ]] || bad "--vm-nic must be a NIC of the VM such as net0"
  elif [ -n "$vm_nic" ]; then
    bad "--vm-nic needs --vm-addr"
  fi
  for p in ${private_ports[@]+"${private_ports[@]}"}; do
    valid_port "$p" || bad "--private-port '$p' is not a whole number from 1 to 65535"
    [ "$p" != "$admin_port" ] || bad "--private-port $p is the admin port: they must differ"
    in_list "$p" "$SENSOR_PORTS" && bad "--private-port $p is a sensor port ($SENSOR_PORTS): dropping it would block that sensor"
  done
  if [ "${#private_ports[@]}" -gt 0 ]; then
    [ "${#private_from[@]}" -gt 0 ] || [ "$private_from_admin" = 1 ] ||
      bad "--private-port needs --private-from (the tunnel host) or --private-from-admin: otherwise nobody could reach the port"
  elif [ "${#private_from[@]}" -gt 0 ] || [ "$private_from_admin" = 1 ]; then
    bad "--private-from and --private-from-admin need a --private-port"
  fi
  [ "$set_nic" = 0 ] || [ "$apply" = 1 ] || bad "--set-nic-firewall needs --apply"
fi

for t in diff cmp awk sort timeout; do
  command -v "$t" > /dev/null 2>&1 || die 3 "'$t' not found"
done

target=$fwdir/$vmid.fw
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# ---------------------------------------------------------------- Proxmox
need_node() {
  local missing=() t
  for t in pve-firewall qm pvesh; do
    command -v "$t" > /dev/null 2>&1 || missing+=("$t")
  done
  [ "${#missing[@]}" -eq 0 ] ||
    die 3 "this is not a Proxmox node (missing: ${missing[*]}): run it as root on the node that hosts VM $vmid"
  [ -e "$pve/.version" ] || die 3 "/etc/pve is not mounted (is pve-cluster running?)"
  [ "$(id -u)" -eq 0 ] || die 4 "--apply and --undo must run as root"
}

# Whether a file can be created in the firewall folder. /etc/pve is read-only when the cluster
# has lost its quorum or pve-cluster is down: then nothing can change, and nothing has.
probe_write() {
  local tmp=$fwdir/$vmid.fw.tmp.$$
  mkdir -p "$fwdir" 2> /dev/null || true
  if (: > "$tmp") 2> /dev/null; then
    rm -f "$tmp"
    return 0
  fi
  return 1
}
no_write() {
  die 5 "cannot write in $fwdir: /etc/pve is read-only, usually because the cluster has no quorum (see pvecm status) or pve-cluster is not running. Nothing was changed"
}

# Atomic write of $1 as the VM file: a temp file in the same folder, then a rename. When it
# fails, the VM file is as it was.
install_file() {
  local tmp=$fwdir/$vmid.fw.tmp.$$
  mkdir -p "$fwdir" || return 1
  rm -f "$tmp"
  if ! cat -- "$1" > "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  mv -f -- "$tmp" "$target" || {
    rm -f "$tmp"
    return 1
  }
}

# Copies $1 to $2 (mode 0600) and checks the copy: same size, same bytes. A bad copy is removed.
copy_checked() {
  if ! (umask 077 && cat -- "$1" > "$2") 2> /dev/null; then
    rm -f -- "$2"
    return 1
  fi
  if [ "$(wc -c < "$1")" != "$(wc -c < "$2")" ] || ! cmp -s -- "$1" "$2"; then
    rm -f -- "$2"
    return 1
  fi
  chmod 0600 "$2"
}

# State of the VM file before a change: "file" (copied to $work/prev) or "absent".
prev_kind=absent
save_prev() {
  if [ -e "$target" ]; then
    copy_checked "$target" "$work/prev" || return 1
    prev_kind="file"
  else
    prev_kind=absent
  fi
}

restore_prev() {
  if [ "$prev_kind" = file ]; then
    install_file "$work/prev"
  else
    rm -f -- "$target"
  fi
}

# An apply pushes a backup on the stack; a failure of that apply takes it off again.
backup_path=""
drop_backup=0
abandon() {
  [ "$drop_backup" = 0 ] || rm -f -- "$backup_path"
}

# Puts the previous state back, loudly when even that fails.
rollback() {
  if restore_prev; then
    note "the previous $vmid.fw is back in place"
    abandon
  else
    echo "proxmox-firewall: RESTORE FAILED: put the backup back by hand: ${backup_path:-the copy in $work} -> $target" >&2
    return 1
  fi
}

# Dies with exit 5 after a failed check, saying only what is true about the file.
rolled_back_die() { # message
  if rollback; then die 5 "$1 and was rolled back"; fi
  die 5 "$1, and the previous file could NOT be put back (see above)"
}

on_signal() {
  trap - INT TERM HUP
  note "interrupted: restoring the previous file"
  rollback || true
  exit 5
}

# `pve-firewall compile` parses every rule file and prints the iptables rules; it applies
# nothing. It fails on a bad file, or reports this VM's file by its path on stderr. The name must
# match whole: a complaint about the file of VM 1<vmid> is not about this one.
check_compile() {
  local rc=0 err=$work/compile.err
  timeout 120 pve-firewall compile > /dev/null 2> "$err" || rc=$?
  if [ "$rc" -ne 0 ]; then
    note "pve-firewall compile failed (exit $rc)"
    sed 's/^/  /' "$err" >&2
    return 1
  fi
  if grep -Eq "(^|[/[:space:]])${vmid}\\.fw([^A-Za-z0-9_.-]|\$)" "$err"; then
    note "pve-firewall compile complains about $vmid.fw"
    sed 's/^/  /' "$err" >&2
    return 1
  fi
  return 0
}

show_status() {
  echo "== pve-firewall status =="
  pve-firewall status 2>&1 || true
}

# A new backup path for kind $1 (fw or absent), never an existing one. Timestamps sort, so the
# newest backup is the last name.
new_backup() {
  local ts f n=0 taken
  while :; do
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    taken=0
    for f in "$bakdir/$vmid-$ts".*; do [ ! -e "$f" ] || taken=1; done
    if [ "$taken" = 0 ]; then
      backup_path=$bakdir/$vmid-$ts.$1
      return 0
    fi
    n=$((n + 1))
    [ "$n" -lt 5 ] || return 1
    sleep 1
  done
}

# Pushes the current state on the stack of backups: a checked copy of the file, or an empty
# ".absent" marker when there is no file. Fails without leaving a partial backup.
make_backup() {
  { mkdir -p "$bakdir" && chmod 0700 "$bakdir"; } 2> /dev/null || return 1
  if [ "$prev_kind" = file ]; then
    new_backup fw || return 1
    copy_checked "$target" "$backup_path" || return 1
  else
    new_backup absent || return 1
    (umask 077 && : > "$backup_path") 2> /dev/null || return 1
  fi
}

# ---------------------------------------------------------------- undo
# One step back per call: the newest backup is restored and then taken off the stack.
if [ "$undo" = 1 ]; then
  need_node
  found=()
  for f in "$bakdir/$vmid-"*; do
    [[ ${f##*/} =~ ^${vmid}-[0-9]{8}T[0-9]{6}Z\.(fw|absent)$ ]] && found+=("$f")
  done
  [ "${#found[@]}" -gt 0 ] || die 4 "no backup for VM $vmid in $bakdir: nothing to undo"
  latest=$(printf '%s\n' "${found[@]}" | sort | tail -n 1)
  probe_write || no_write
  save_prev || die 5 "could not read $target: nothing was changed"
  if [ "$prev_kind" = absent ] && [ "${latest##*.}" = absent ]; then
    rm -f -- "$latest"
    note "VM $vmid has no firewall file, as before that apply: nothing to write; the backup is taken off"
    exit 0
  fi
  if [ "$prev_kind" = file ]; then
    # Kept apart from the numbered backups, so that it is never taken for a step to go back to.
    keep=$bakdir/$vmid-$(date -u +%Y%m%dT%H%M%SZ)-before-undo.fw
    copy_checked "$target" "$keep" || die 5 "could not keep a copy of $target in $bakdir: nothing was changed"
  fi
  backup_path=$latest
  trap on_signal INT TERM HUP
  if [ "${latest##*.}" = fw ]; then
    install_file "$latest" || die 5 "could not write $target: nothing was changed"
  else
    rm -f -- "$target" || die 5 "could not remove $target: nothing was changed"
  fi
  if ! check_compile; then
    rolled_back_die "the undo failed its check (the backup is kept)"
  fi
  trap - INT TERM HUP
  rm -f -- "$latest"
  note "restored $latest; $((${#found[@]} - 1)) older backup(s) left"
  show_status
  exit 0
fi

# ---------------------------------------------------------------- the generated file
rule() { # "OUT ACCEPT -dest ADDR" "comment"
  printf '%s # %s %s\n' "$1" "$MARK" "$2"
}

build() {
  local r p s why seen
  printf '[OPTIONS]\n\n'
  # No `ipfilter` option: the set of --vm-addr alone filters its NIC, while the option would give
  # every NIC an empty set (and cut off a NIC that later gets firewall=1).
  printf 'enable: 1\npolicy_in: ACCEPT\npolicy_out: ACCEPT\nmacfilter: 1\n'
  printf '\n[RULES]\n\n'
  # First, so that no later accept can let a DHCP server's replies out: the VM is a DHCP client
  # (it sends to port 67 and 547), never a server (replies go to port 68 and 546).
  rule "OUT DROP -p udp -dport 68" "no DHCP server replies from the VM (rogue DHCP server)"
  rule "OUT DROP -p udp -dport 546" "no DHCPv6 server replies from the VM (rogue DHCP server)"
  if [ "$gateway_all" = 1 ]; then
    rule "OUT ACCEPT -dest $gateway" "LAN gateway, every port (--gateway-all)"
  else
    rule "OUT ACCEPT -dest $gateway -p udp -dport 53" "DNS to the LAN gateway"
    rule "OUT ACCEPT -dest $gateway -p tcp -dport 53" "DNS over TCP to the LAN gateway"
  fi
  seen=" $gateway "
  for r in ${dns_hosts[@]+"${dns_hosts[@]}"}; do
    [[ $seen != *" $r "* ]] || continue
    seen="$seen$r "
    rule "OUT ACCEPT -dest $r -p udp -dport 53" "DNS to a resolver of the VM"
    rule "OUT ACCEPT -dest $r -p tcp -dport 53" "DNS over TCP to a resolver of the VM"
  done
  for r in ${allow_out[@]+"${allow_out[@]}"}; do
    rule "OUT ACCEPT -dest $r" "extra LAN host the VM may reach, every port"
  done
  for r in $PRIVATE_RANGES; do
    case $r in
      100.64.*) why="shared address space (CGNAT)" ;;
      169.254.*) why="link-local addresses" ;;
      fc00:*) why="IPv6 unique local addresses" ;;
      *) why="private range (RFC 1918)" ;;
    esac
    rule "OUT DROP -dest $r" "no traffic to $why"
  done
  # IPv6 link-local: tcp and udp only. ICMPv6 (neighbour discovery) stays, and Proxmox accepts it
  # before these rules anyway; without these two, the VM could reach every service of every
  # IPv6 host of the LAN, the Proxmox node included, over fe80::.
  rule "OUT DROP -dest fe80::/10 -p tcp" "no TCP to IPv6 link-local addresses (ICMPv6 is not affected)"
  rule "OUT DROP -dest fe80::/10 -p udp" "no UDP to IPv6 link-local addresses (ICMPv6 is not affected)"
  rule "IN ACCEPT -source $admin_from -p tcp -dport $admin_port" "admin SSH from the management network"
  rule "IN DROP -p tcp -dport $admin_port" "admin SSH from nowhere else"
  seen=" "
  for p in ${private_ports[@]+"${private_ports[@]}"}; do
    [[ $seen != *" $p "* ]] || continue
    seen="$seen$p "
    local srcs=" "
    for s in ${private_from[@]+"${private_from[@]}"}; do
      [[ $srcs != *" $s "* ]] || continue
      srcs="$srcs$s "
      rule "IN ACCEPT -source $s -p tcp -dport $p" "port $p from the tunnel host"
    done
    if [ "$private_from_admin" = 1 ] && [[ $srcs != *" $admin_from "* ]]; then
      rule "IN ACCEPT -source $admin_from -p tcp -dport $p" "port $p from the admin network"
    fi
    rule "IN DROP -p tcp -dport $p" "port $p from nowhere else"
  done
  if [ "${#vm_addrs[@]}" -gt 0 ]; then
    # The IP filter of the NIC: the addresses (or CIDRs) the VM may send from.
    printf '\n[IPSET ipfilter-%s]\n\n' "$vm_nic"
    seen=" "
    for s in "${vm_addrs[@]}"; do
      [[ $seen != *" $s "* ]] || continue
      seen="$seen$s "
      printf '%s # %s address or range of the VM\n' "$s" "$MARK"
    done
  fi
}

build > "$work/new.fw"

# Lines of the current file that this script did not generate: not in the new file, and not a
# rule it wrote earlier (its comment starts with "# SuckerPot:"). Any other section counts.
# shellcheck disable=SC2016 # an awk program: nothing in it is for the shell to expand
FOREIGN_AWK='
function trim(s) { sub(/^[ \t\r]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
function parse(raw,    line, idx, k, v) {
  line = trim(raw)
  kind = ""
  comment = ""
  if (line == "" || line ~ /^#/) return
  if (line ~ /^\[[^]]*\]/) {
    idx = index(line, "]")
    section = trim(toupper(substr(line, 2, idx - 2)))
    gsub(/[ \t]+/, " ", section)
    kind = "header"
    return
  }
  body = line
  if (section == "RULES" || section ~ /^IPSET /) {
    idx = index(line, "#")
    if (idx > 0) { comment = substr(line, idx); body = trim(substr(line, 1, idx - 1)) }
  }
  gsub(/[ \t]+/, " ", body)
  if (section == "OPTIONS" && match(body, /^[A-Za-z_]+:/)) {
    k = tolower(substr(body, 1, RLENGTH - 1)); v = trim(substr(body, RLENGTH + 1))
    body = k ": " v
  }
  kind = "line"
}
FNR == 1 { section = "" }
FILENAME == gen { parse($0); if (kind == "line") known[section SUBSEP body] = 1; next }
{
  parse($0)
  if (kind != "line") next
  if ((section SUBSEP body) in known) next
  if ((section == "RULES" || section ~ /^IPSET /) && comment ~ /^#[ \t]*SuckerPot:/) next
  print "[" section "] " trim($0)
}
'

if [ "$apply" = 1 ]; then need_node; fi

cur_state=absent
if [ -e "$target" ]; then
  if [ -r "$target" ] && [ -f "$target" ]; then cur_state="file"; else cur_state=unreadable; fi
fi

foreign=""
if [ "$cur_state" = file ]; then
  foreign=$(awk -v gen="$work/new.fw" "$FOREIGN_AWK" "$work/new.fw" "$target")
fi

# ---------------------------------------------------------------- checks that only warn
dc_state=skipped
if command -v pvesh > /dev/null 2>&1; then
  if dc_out=$(pvesh get /cluster/firewall/options --output-format json 2> /dev/null); then
    if grep -Eq '"enable"[[:space:]]*:[[:space:]]*("?1"?|true)' <<< "$dc_out"; then
      dc_state=enabled
    else
      dc_state=disabled
    fi
  else
    dc_state=unknown
  fi
fi

nic_cmds=()
nic_names=()
nic_values=()
all_nics=()
nic_state=skipped
if command -v qm > /dev/null 2>&1; then
  if qm_out=$(qm config "$vmid" 2> /dev/null); then
    nic_state=ok
    while IFS= read -r line; do
      [[ $line =~ ^(net[0-9]+):[[:space:]]*(.*)$ ]] || continue
      nic=${BASH_REMATCH[1]}
      val=${BASH_REMATCH[2]}
      all_nics+=("$nic")
      [[ ,$val, != *,firewall=1,* ]] || continue
      IFS=, read -ra opts <<< "$val"
      newval=""
      for o in "${opts[@]}"; do
        [[ $o == firewall=* ]] || newval=${newval:+$newval,}$o
      done
      newval=$newval,firewall=1
      nic_names+=("$nic")
      nic_values+=("$newval")
      nic_cmds+=("qm set $vmid --$nic $newval")
    done <<< "$qm_out"
  else
    nic_state=missing
  fi
fi

# The set of --vm-addr is named after a NIC: it must be one the VM has, or it filters nothing.
ipf_problem=""
if [ "${#vm_addrs[@]}" -gt 0 ] && [ "$nic_state" = ok ]; then
  if ! in_list "$vm_nic" "${all_nics[*]:-}"; then
    ipf_problem="the VM has no $vm_nic (qm config lists: ${all_nics[*]:-no NIC})"
  fi
fi

report_checks() {
  [ -e "$pve/.version" ] || warn "this is not a Proxmox node (/etc/pve is not mounted): the difference above is against a missing file"
  case $dc_state in
    disabled)
      warn "the datacenter firewall is disabled: the rules of VM $vmid do nothing until it is on.
  Enable it in the web UI (Datacenter > Firewall > Options > Firewall) or with:
    pvesh set /cluster/firewall/options --enable 1
  Read this first: enabling it applies the datacenter policy_in (DROP by default) to the node
  itself. Unless rules allow the web UI (8006/tcp) and SSH from your management network, you can
  lose access to the node. Proxmox adds rules for the local network, but check that they cover
  your admin machine, and keep the console at hand. This script never changes it."
      ;;
    unknown) warn "could not read the datacenter firewall setting (pvesh failed, run it as root): check that it is enabled" ;;
    skipped) warn "pvesh not found: cannot check that the datacenter firewall is enabled" ;;
  esac
  case $nic_state in
    missing) warn "VM $vmid not found on this node (qm config failed): the NIC check was skipped" ;;
    skipped) warn "qm not found: cannot check firewall=1 on the VM's NICs" ;;
  esac
  if [ "${#nic_cmds[@]}" -gt 0 ]; then
    warn "the VM's NIC needs firewall=1 or its rules do nothing: ${nic_names[*]}
  Run it (a running VM's NIC reconnects briefly), or pass --set-nic-firewall with --apply:"
    printf '    %s\n' "${nic_cmds[@]}" >&2
  fi
  [ -z "$ipf_problem" ] || warn "$ipf_problem"
  if [ "${#vm_addrs[@]}" -gt 0 ]; then
    warn "the set ipfilter-$vm_nic filters $vm_nic: the VM can only send from ${vm_addrs[*]}. Any other address it uses, IPv6 included, loses its traffic: keep the console open"
  fi
}

# ---------------------------------------------------------------- show
echo "== Generated $target ($([ "$apply" = 1 ] && echo apply || echo "dry run: nothing is changed")) =="
cat "$work/new.fw"
echo
echo "== Difference against the current file =="
case $cur_state in
  absent) echo "new file: $target does not exist yet" ;;
  unreadable) echo "cannot read $target: run it as root on the node for a difference" ;;
  file)
    if cmp -s "$work/new.fw" "$target"; then
      echo "no difference: the file already matches"
    else
      diff -u --label "$target (current)" --label "$target (generated)" "$target" "$work/new.fw" || true
    fi
    ;;
esac
if [ -n "$foreign" ]; then
  echo
  echo "== In the current file, not generated by this script =="
  echo "$foreign"
  if [ "$replace" = 1 ]; then
    echo "(--replace drops them)"
  else
    echo "(--apply refuses to run until you pass --replace, which drops them)"
  fi
fi
if [ "$cur_state" = unreadable ] && [ "$apply" = 0 ]; then
  warn "could not read $target: rules or options that this script did not generate would go unnoticed"
fi
echo
report_checks

if [ "$apply" = 0 ]; then
  note "dry run: nothing was changed. Re-run with --apply to write it."
  exit 0
fi

# ---------------------------------------------------------------- apply
[ "$nic_state" = ok ] || die 4 "VM $vmid not found on this node (qm config $vmid failed): run it on the node that hosts the VM"
[ -z "$ipf_problem" ] || die 4 "refused: $ipf_problem"
[ "$cur_state" != unreadable ] || die 4 "$target exists but is not a readable regular file"
if [ -n "$foreign" ] && [ "$replace" = 0 ]; then
  die 4 "refused: $target holds rules or options this script did not generate (listed above). Pass --replace to drop them; the backup keeps them"
fi

changed=1
if [ "$cur_state" = file ] && cmp -s "$work/new.fw" "$target"; then
  changed=0
  note "$target already matches: nothing to write"
fi

if [ "$changed" = 1 ]; then
  probe_write || no_write
  save_prev || die 5 "could not read $target: nothing was changed"
  make_backup || die 5 "could not make a checked backup in $bakdir: nothing was changed"
  drop_backup=1
  note "backup: $([ "$prev_kind" = file ] && echo "$backup_path" || echo "none, the file did not exist ($backup_path marks that)")"
  trap on_signal INT TERM HUP
  if ! install_file "$work/new.fw"; then
    trap - INT TERM HUP
    abandon
    die 5 "could not write $target: nothing was changed"
  fi
  if ! check_compile; then
    rolled_back_die "the new file failed its check"
  fi
  trap - INT TERM HUP
  note "wrote $target"
fi

if [ "$set_nic" = 1 ] && [ "${#nic_names[@]}" -gt 0 ]; then
  for i in "${!nic_names[@]}"; do
    note "qm set $vmid --${nic_names[$i]} ${nic_values[$i]}"
    qm set "$vmid" "--${nic_names[$i]}" "${nic_values[$i]}" ||
      die 5 "qm set failed for ${nic_names[$i]}: the rules are written but do nothing until the NIC has firewall=1"
  done
fi

show_status
cat << EOF

Next: check that your admin SSH to the VM still works, and that the VM cannot
open a connection to another machine on your LAN. Undo with:
  $0 --undo --vmid $vmid
EOF
