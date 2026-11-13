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
#   --allow-out ADDR   another LAN host the VM may reach, such as a local DNS server (address or
#                      CIDR, repeat it). Placed before the private-range drops
#   --private-port N   a port that only some hosts may reach, such as the dashboard port or a hub
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
#   --undo             put back the most recent backup of this VM
#   -h, --help         show this help
#
# What it writes (Proxmox evaluates top to bottom, the first match wins):
#   [OPTIONS]  enable: 1, policy_in: ACCEPT (the sensors must accept the internet on many ports),
#              policy_out: ACCEPT, macfilter: 1. ipfilter is NOT set: on a VM an empty ipfilter
#              set drops all of the VM's IPv4 traffic, and the script cannot know the VM's
#              addresses. It would cut the VM off.
#   [RULES]    1. OUT ACCEPT to the gateway, then to each --allow-out
#              2. OUT DROP to the private ranges: the three of RFC 1918 (10/8, 172.16/12,
#                 192.168/16), 100.64/10 (CGNAT), 169.254/16 (link-local) and, for IPv6,
#                 fc00::/7. fe80::/10 stays open: neighbour discovery needs it. A LAN that is
#                 also reachable by global IPv6 addresses cannot be blocked here
#              3. IN ACCEPT admin-from to the admin port, then IN DROP of the admin port
#              4. for each --private-port: IN ACCEPT from the tunnel host(s) (and the admin
#                 network with --private-from-admin), then IN DROP of that port
#
# Safety: a dry run changes nothing. --apply backs the current file up to
# /root/suckerpot-firewall-backups/<vmid>-<UTC timestamp>.fw (0600), writes the new file
# atomically (a temp file in /etc/pve/firewall, then a rename), runs `pve-firewall compile` and
# puts the backup back when that fails. It refuses (exit 4) when the current file holds rules or
# options it did not generate, unless --replace. It never touches the datacenter firewall
# (cluster.fw) or the node firewall: it only reads whether the datacenter firewall is on and
# warns. It checks `qm config` for firewall=1 on the NICs and only changes it with
# --set-nic-firewall. A rule it wrote carries a "# SuckerPot:" comment: those are replaced
# without --replace.
#
# Keep the Proxmox console open the first time: a wrong --admin-from cuts your SSH to the VM
# (--undo, run on the node, brings it back).
#
# Exit codes: 0 done, or the dry run worked; 2 bad arguments; 3 not a Proxmox node, or a tool is
# missing; 4 refused (not root, VM not found, foreign rules without --replace, nothing to
# undo); 5 the change failed (a failed check was rolled back; a failed `qm set` leaves the
# written file in place).
#
# SUCKERPOT_PVE_ROOT is for the tests only: it prefixes /etc/pve and /root. Never set it.
set -euo pipefail

# The sensors' default host ports (.env.example, *_HOST_PORT). A private port or the admin port
# on one of them would block a sensor or expose the admin SSH, so they are refused.
SENSOR_PORTS="22 23 80 443 445 1433 2375 3306 3389 5000 5001 5060 5555 6379"
MARK="SuckerPot:"
# What the VM may not reach: RFC 1918, CGNAT, link-local, IPv6 unique local. Not fe80::/10: IPv6
# neighbour discovery needs it.
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

# ---------------------------------------------------------------- arguments
vmid=""
gateway=""
admin_port=""
admin_from=""
allow_out=()
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
    --vmid | --gateway | --admin-port | --admin-from | --allow-out | --private-port | --private-from)
      need_value "$@"
      case $1 in
        --vmid) once "$1" "$vmid" && vmid=$2 ;;
        --gateway) once "$1" "$gateway" && gateway=$2 ;;
        --admin-port) once "$1" "$admin_port" && admin_port=$2 ;;
        --admin-from) once "$1" "$admin_from" && admin_from=$2 ;;
        --allow-out) allow_out+=("$2") ;;
        --private-port) private_ports+=("$2") ;;
        --private-from) private_from+=("$2") ;;
      esac
      shift 2
      ;;
    --private-from-admin)
      private_from_admin=1
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

[ -n "$vmid" ] || bad "--vmid is required"
valid_vmid "$vmid" || bad "--vmid must be a whole number, 100 or more"

if [ "$undo" = 1 ]; then
  { [ -z "$gateway$admin_port$admin_from" ] && [ "${#allow_out[@]}" -eq 0 ] &&
    [ "${#private_ports[@]}" -eq 0 ] && [ "${#private_from[@]}" -eq 0 ] &&
    [ "$private_from_admin$apply$replace$set_nic" = 0000 ]; } ||
    bad "--undo takes only --vmid"
else
  [ -n "$gateway" ] || bad "--gateway is required (the LAN gateway and DNS the VM needs)"
  [ -n "$admin_port" ] || bad "--admin-port is required (the port you chose with scripts/move-admin-ssh.sh)"
  [ -n "$admin_from" ] || bad "--admin-from is required (an address or CIDR that may reach the admin port)"
  check_addr --gateway "$gateway"
  valid_port "$admin_port" || bad "--admin-port must be a whole number from 1 to 65535"
  in_list "$admin_port" "$SENSOR_PORTS" && bad "--admin-port $admin_port is a sensor port ($SENSOR_PORTS)"
  check_source --admin-from "$admin_from"
  for a in ${allow_out[@]+"${allow_out[@]}"}; do check_source --allow-out "$a"; done
  for a in ${private_from[@]+"${private_from[@]}"}; do check_source --private-from "$a"; done
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

# Atomic write of $1 as the VM file: a temp file in the same folder, then a rename.
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

# State of the VM file before a change: "file" (copied to $work/prev) or "absent".
prev_kind=absent
save_prev() {
  if [ -e "$target" ]; then
    cat -- "$target" > "$work/prev"
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

# Puts the previous state back, loudly when even that fails.
rollback() {
  if restore_prev; then
    note "the previous $vmid.fw is back in place"
  else
    echo "proxmox-firewall: RESTORE FAILED: put the backup back by hand: $backup_path -> $target" >&2
  fi
}

on_signal() {
  trap - INT TERM HUP
  note "interrupted: restoring the previous file"
  rollback
  exit 5
}

# `pve-firewall compile` parses every rule file and prints the iptables rules; it applies
# nothing. It fails on a bad file, or reports the file by name on stderr.
check_compile() {
  local rc=0 err=$work/compile.err
  timeout 120 pve-firewall compile > /dev/null 2> "$err" || rc=$?
  if [ "$rc" -ne 0 ]; then
    note "pve-firewall compile failed (exit $rc)"
    sed 's/^/  /' "$err" >&2
    return 1
  fi
  if grep -qF -- "$vmid.fw" "$err"; then
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

# A new backup path for kind $1 (fw or absent), never an existing one. Timestamps sort.
backup_path=""
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

make_backup() {
  mkdir -p "$bakdir" || return 1
  chmod 0700 "$bakdir"
  new_backup "$([ "$prev_kind" = file ] && echo fw || echo absent)" || return 1
  (
    umask 077
    if [ "$prev_kind" = file ]; then cat -- "$work/prev" > "$backup_path"; else : > "$backup_path"; fi
  )
  chmod 0600 "$backup_path"
}

# ---------------------------------------------------------------- undo
if [ "$undo" = 1 ]; then
  need_node
  found=()
  for f in "$bakdir/$vmid-"*; do
    [[ ${f##*/} =~ ^${vmid}-[0-9]{8}T[0-9]{6}Z\.(fw|absent)$ ]] && found+=("$f")
  done
  [ "${#found[@]}" -gt 0 ] || die 4 "no backup for VM $vmid in $bakdir: nothing to undo"
  latest=$(printf '%s\n' "${found[@]}" | sort | tail -n 1)
  save_prev
  if [ "$prev_kind" = file ] && [ "${latest##*.}" = fw ] && cmp -s "$latest" "$target"; then
    note "$target already matches $latest: nothing to do"
    show_status
    exit 0
  fi
  if [ "$prev_kind" = absent ] && [ "${latest##*.}" = absent ]; then
    note "VM $vmid has no firewall file, like before the first --apply: nothing to do"
    exit 0
  fi
  if [ "$prev_kind" = file ]; then
    # Kept apart from the numbered backups, so that a second --undo does not undo the undo.
    mkdir -p "$bakdir"
    chmod 0700 "$bakdir"
    keep=$bakdir/$vmid-$(date -u +%Y%m%dT%H%M%SZ)-before-undo.fw
    (umask 077 && cat -- "$work/prev" > "$keep")
    chmod 0600 "$keep"
  fi
  backup_path=$latest
  trap on_signal INT TERM HUP
  if [ "${latest##*.}" = fw ]; then
    install_file "$latest" || die 5 "could not write $target"
  else
    rm -f -- "$target" || die 5 "could not remove $target"
  fi
  if ! check_compile; then
    rollback
    die 5 "the undo failed its check and was rolled back"
  fi
  trap - INT TERM HUP
  note "restored $latest"
  show_status
  exit 0
fi

# ---------------------------------------------------------------- the generated file
rule() { # "OUT ACCEPT -dest ADDR" "comment"
  printf '%s # %s %s\n' "$1" "$MARK" "$2"
}

build() {
  local r p s why
  printf '[OPTIONS]\n\n'
  printf 'enable: 1\npolicy_in: ACCEPT\npolicy_out: ACCEPT\nmacfilter: 1\n\n'
  printf '[RULES]\n\n'
  rule "OUT ACCEPT -dest $gateway" "LAN gateway and DNS"
  for r in ${allow_out[@]+"${allow_out[@]}"}; do
    rule "OUT ACCEPT -dest $r" "extra LAN host the VM may reach"
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
  rule "IN ACCEPT -source $admin_from -p tcp -dport $admin_port" "admin SSH from the management network"
  rule "IN DROP -p tcp -dport $admin_port" "admin SSH from nowhere else"
  local seen=" "
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
  if (line ~ /^\[.*\]$/) {
    section = toupper(substr(line, 2, length(line) - 2))
    section = trim(section)
    kind = "header"
    return
  }
  body = line
  if (section == "RULES") {
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
  if ((section == "OPTIONS" || section == "RULES") && ((section SUBSEP body) in known)) next
  if (section == "RULES" && comment ~ /^#[ \t]*SuckerPot:/) next
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
nic_state=skipped
if command -v qm > /dev/null 2>&1; then
  if qm_out=$(qm config "$vmid" 2> /dev/null); then
    nic_state=ok
    while IFS= read -r line; do
      [[ $line =~ ^(net[0-9]+):[[:space:]]*(.*)$ ]] || continue
      nic=${BASH_REMATCH[1]}
      val=${BASH_REMATCH[2]}
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
  save_prev
  make_backup || die 5 "could not write the backup in $bakdir (nothing was changed)"
  note "backup: $([ "$prev_kind" = file ] && echo "$backup_path" || echo "none, the file did not exist ($backup_path marks that)")"
  trap on_signal INT TERM HUP
  if ! install_file "$work/new.fw"; then
    rollback
    die 5 "could not write $target (rolled back)"
  fi
  if ! check_compile; then
    rollback
    die 5 "the new file failed its check and was rolled back"
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
