#!/usr/bin/env bash
# Renders the SuckerPot host firewall (nftables) with every value filled in. Pure: no root, no
# change to the system; it only reads the resolver configuration and writes the ruleset.
#
#   render-firewall.sh --participant --admin-ssh-port N [--out FILE]
#   render-firewall.sh --full --admin-ssh-port N [--dashboard-port N] [--vpn-endpoint IP:PORT]
#                      [--out FILE]
#
# Common options:
#   --dns IP           an upstream resolver for hubproxy's DNS (repeat it); replaces the ones read
#                      from the resolver configuration. Use it when /etc/docker/daemon.json sets
#                      "dns".
#   --resolv-conf F    read F instead of /etc/resolv.conf
#   --systemd-resolv-conf F
#                      the systemd-resolved upstream list (default /run/systemd/resolve/resolv.conf)
#   --vpn-endpoint IP:PORT
#                      participant with a VPN, or full mode with the egress profile: the one
#                      WireGuard endpoint sp-vpn may reach. Without it, sp-vpn may open nothing.
#   --allow-bridge NAME
#                      accept a bridge that is not Docker's but matches br-* or sp-* (repeat it);
#                      see "Bridges" below. Only when you know what that bridge carries.
#   --engine docker|podman
#                      the container engine the rules are for (default: SUCKERPOT_ENGINE of this
#                      checkout, else docker). Podman adds the "#podman: " lines of the templates:
#                      DNS to aardvark-dns, the podman* bridges and the bridge-family table that
#                      blocks traffic between sensors. On Docker those lines are removed.
#
# Bridges: the rules match Docker bridges by name with the wildcards "br-*" and "sp-*" (nft only
# has trailing wildcards, so Docker's own br-<12 hex> pattern cannot be written exactly). A host
# bridge of yours with such a name (a VM or LAN bridge called br-lan, say) would get the same
# drops, and if your admin SSH reaches the host through it you would be locked out. So the
# renderer lists the host's bridges (`ip -o link show type bridge`, or /sys/class/net) and the
# ones Docker owns (`docker network ls` / `docker network inspect`), and refuses (exit 2) when a
# matching bridge is not Docker's. When Docker cannot be asked, a bridge counts as Docker's only
# if it is named br-<12 hex digits> or is one of SuckerPot's fixed sp-* names.
#
# The ruleset goes to stdout, or to --out FILE (mode 0600; the admin port is private). When nft is
# installed and allowed to (root), the result is syntax-checked with `nft -c -f`; otherwise the
# check is skipped with a note (install-firewall.sh always checks before loading).
#
# Exit codes: 0 rendered; 1 the rendered ruleset failed `nft -c`; 2 bad arguments.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# The engine of this checkout (its .env, whatever the current folder). Read-only: an unknown
# value falls back to docker with a warning.
ENV_FILE="$here/../../.env" ENGINE_LENIENT=1
# shellcheck source=scripts/lib/engine.sh
. "$here/../lib/engine.sh"
unset ENV_FILE

die() {
  echo "render-firewall: $*" >&2
  exit 2
}
note() { echo "render-firewall: $*" >&2; }

valid_port() {
  [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$1 <= 65535))
}

valid_ipv4() {
  local IFS=. octet
  [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  # shellcheck disable=SC2086 # split on dots on purpose
  for octet in $1; do
    [[ $octet =~ ^(0|[1-9][0-9]*)$ ]] && ((octet <= 255)) || return 1
  done
}

mode=""
admin_port=""
dashboard_port=8443
vpn_endpoint=""
out=""
resolv_conf=/etc/resolv.conf
systemd_resolv_conf=/run/systemd/resolve/resolv.conf
dns=()
allow_bridges=()
engine=$ENGINE_ID
# SuckerPot's fixed bridge names (docker-compose.yml; scripts/guardrails checks they match).
SP_BRIDGES="sp-ingress sp-dashboard sp-vpn sp-hubgate sp-egress sp-hubproxy sp-samples sp-backend sp-tools sp-s-ssh sp-s-rdp sp-s-telnet sp-s-web sp-s-redis sp-s-docker sp-s-mysql sp-s-mssql sp-s-adb sp-s-smb sp-s-sip sp-s-synology"

need_value() { { [ "$#" -ge 2 ] && [ -n "$2" ]; } || die "$1 needs a value"; }

while [ "$#" -gt 0 ]; do
  case $1 in
    --participant | --full)
      [ -z "$mode" ] || die "choose one of --participant and --full"
      mode=${1#--}
      shift
      ;;
    --admin-ssh-port | --dashboard-port | --vpn-endpoint | --out | --dns | --resolv-conf | --systemd-resolv-conf | --allow-bridge | --engine)
      need_value "$@"
      case $1 in
        --allow-bridge) allow_bridges+=("$2") ;;
        --engine) engine=$2 ;;
        --admin-ssh-port) admin_port=$2 ;;
        --dashboard-port) dashboard_port=$2 ;;
        --vpn-endpoint) vpn_endpoint=$2 ;;
        --out) out=$2 ;;
        --dns) dns+=("$2") ;;
        --resolv-conf) resolv_conf=$2 ;;
        --systemd-resolv-conf) systemd_resolv_conf=$2 ;;
      esac
      shift 2
      ;;
    -h | --help)
      sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

[ -n "$mode" ] || die "choose --participant or --full"
case $engine in docker | podman) ;; *) die "--engine must be docker or podman" ;; esac
# ctr and the bridge listing below follow the engine the rules are for.
[ "$engine" = "$ENGINE_ID" ] || engine_use "$engine"
[ -n "$admin_port" ] || die "--admin-ssh-port is required (the port of this host's admin SSH daemon)"
valid_port "$admin_port" || die "--admin-ssh-port must be a whole number from 1 to 65535"
valid_port "$dashboard_port" || die "--dashboard-port must be a whole number from 1 to 65535"
[ "$mode" = full ] || [ "$dashboard_port" = 8443 ] || die "--dashboard-port is only for --full"
[ "$admin_port" != "$dashboard_port" ] || [ "$mode" = participant ] ||
  die "the admin SSH port and the dashboard port must differ"

vpn_ip=127.0.0.1
vpn_port=51820
if [ -n "$vpn_endpoint" ]; then
  vpn_ip=${vpn_endpoint%:*}
  vpn_port=${vpn_endpoint##*:}
  [ "$vpn_ip" != "$vpn_endpoint" ] || die "--vpn-endpoint must be IP:PORT"
  valid_ipv4 "$vpn_ip" || die "--vpn-endpoint: '$vpn_ip' is not an IPv4 address"
  valid_port "$vpn_port" || die "--vpn-endpoint: '$vpn_port' is not a port"
fi

# --- Bridges: refuse to match a host bridge that is not Docker's --------------------------------

# The host's bridge interfaces, one per line (no root needed).
host_bridges() {
  local dir
  if command -v ip > /dev/null 2>&1; then
    ip -o link show type bridge 2> /dev/null | awk -F': ' '{ sub(/@.*/, "", $2); print $2 }'
    return 0
  fi
  for dir in "${SUCKERPOT_SYS_CLASS_NET:-/sys/class/net}"/*/bridge; do
    [ -d "$dir" ] && basename "$(dirname "$dir")"
  done
  return 0
}

# The engine's bridge interfaces, one per line; fails when the engine cannot be asked.
docker_bridges() {
  local ids id name
  command -v "${ENGINE_CTR[0]}" > /dev/null 2>&1 || return 1
  if [ "$engine" = podman ]; then
    # Podman names the bridge itself: no options to read.
    ctr network ls --format '{{.NetworkInterface}}' 2> /dev/null || return 1
    return 0
  fi
  ids=$(ctr network ls --filter driver=bridge --no-trunc -q 2> /dev/null) || return 1
  [ -n "$ids" ] || return 0
  # shellcheck disable=SC2086 # one argument per network id
  ctr network inspect --format '{{.Id}} {{index .Options "com.docker.network.bridge.name"}}' \
    $ids 2> /dev/null | while read -r id name; do
    if [ -n "$name" ] && [ "$name" != "<no value>" ]; then echo "$name"; else echo "br-${id:0:12}"; fi
  done
}

mapfile -t bridges < <(host_bridges)
docker_known=()
docker_ok=1
if out_docker=$(docker_bridges); then
  mapfile -t docker_known <<< "$out_docker"
else
  docker_ok=0
fi
foreign=()
for b in "${bridges[@]}"; do
  case $b in br-* | sp-*) ;; podman*) [ "$engine" = podman ] || continue ;; *) continue ;; esac
  for a in "${allow_bridges[@]}"; do [ "$a" != "$b" ] || continue 2; done
  if [ "$docker_ok" = 1 ]; then
    for k in "${docker_known[@]}"; do [ "$k" != "$b" ] || continue 2; done
  else
    [[ $b =~ ^br-[0-9a-f]{12}$ ]] && continue
    [ "$engine" = podman ] && [[ $b =~ ^podman[0-9]+$ ]] && continue
    for k in $SP_BRIDGES; do [ "$k" != "$b" ] || continue 2; done
  fi
  foreign+=("$b")
done
if [ "${#foreign[@]}" -gt 0 ]; then
  [ "$docker_ok" = 1 ] || note "$(engine_name) could not be asked which bridges it owns; judged by name only"
  wild="br-* or sp-*"
  [ "$engine" = docker ] || wild="br-*, sp-* or podman*"
  die "host bridge(s) ${foreign[*]} match the firewall's $wild wildcard but are not $(engine_name)'s.
  The rules would drop their traffic to the host, and if your admin SSH arrives through one of
  them you would lock yourself out. Rename the bridge, or, if you are sure nothing you need
  crosses it towards this host, pass --allow-bridge NAME for each."
fi

# Nameservers of a resolv.conf file, in order.
nameservers() {
  [ -r "$1" ] || return 0
  awk '$1 == "nameserver" && NF >= 2 { print $2 }' "$1"
}

# The upstream resolvers Docker's embedded resolver forwards to from the container namespace,
# which is what crosses sp-hubgate: Docker reads /etc/resolv.conf, or the systemd-resolved
# upstream list when /etc/resolv.conf only names the stub 127.0.0.53. Loopback upstreams are
# queried from the host namespace (never through the bridge), and the bridge has no IPv6.
# On Podman none: aardvark-dns forwards from the host's namespace, so no query crosses sp-hubgate
# (hubproxy reaches aardvark-dns through the "#podman: " input rule instead).
resolvers=()
if [ "$engine" = podman ]; then
  [ "${#dns[@]}" -eq 0 ] || note "--dns is ignored on Podman: aardvark-dns asks the upstream resolvers from the host itself"
elif [ "${#dns[@]}" -gt 0 ]; then
  for ip in "${dns[@]}"; do
    valid_ipv4 "$ip" || die "--dns: '$ip' is not an IPv4 address"
    resolvers+=("$ip")
  done
else
  mapfile -t found < <(nameservers "$resolv_conf")
  if [ "${found[*]:-}" = 127.0.0.53 ] && [ -r "$systemd_resolv_conf" ]; then
    mapfile -t found < <(nameservers "$systemd_resolv_conf")
  fi
  for ip in "${found[@]}"; do
    ip=${ip%%%*}
    valid_ipv4 "$ip" || continue # IPv6: no IPv6 on sp-hubgate
    case $ip in 127.* | 0.*) continue ;; esac
    resolvers+=("$ip")
  done
  if grep -qs '"dns"' /etc/docker/daemon.json 2> /dev/null; then
    note "/etc/docker/daemon.json sets \"dns\": pass those servers with --dns"
  fi
fi
# Unique, order kept.
declare -A seen=()
uniq=()
for ip in "${resolvers[@]}"; do
  [ -n "${seen[$ip]:-}" ] || uniq+=("$ip")
  seen[$ip]=1
done
if [ "${#uniq[@]}" -eq 0 ]; then
  hubgate_dns="{ 127.0.0.1 }"
  [ "$mode" = full ] || [ "$engine" = podman ] ||
    note "no non-loopback IPv4 resolver found: hubproxy's DNS goes through the host namespace, sp-hubgate gets no DNS rule"
else
  joined=$(
    IFS=,
    echo "${uniq[*]}"
  )
  hubgate_dns="{ ${joined//,/, } }"
fi

if [ "$mode" = participant ]; then
  template=$here/firewall-participant.nft
else
  template=$here/firewall.nft
fi
[ -r "$template" ] || die "template not found: $template"

rendered=$(
  awk -v admin="$admin_port" -v dash="$dashboard_port" -v vip="$vpn_ip" -v vport="$vpn_port" \
    -v dnsset="$hubgate_dns" -v vpn="$vpn_endpoint" -v engine="$engine" '
    /^#podman:/ {
      if (engine != "podman") next
      sub(/^#podman: ?/, "")
    }
    /^define ADMIN_SSH_PORT = /    { print "define ADMIN_SSH_PORT = " admin; next }
    /^define DASHBOARD_PORT = /    { print "define DASHBOARD_PORT = " dash; next }
    /^define VPN_ENDPOINT_IP = /   { print "define VPN_ENDPOINT_IP = " vip; next }
    /^define VPN_ENDPOINT_PORT = / { print "define VPN_ENDPOINT_PORT = " vport; next }
    /^define HUBGATE_DNS = /       { print "define HUBGATE_DNS = " dnsset; next }
    /^ *# @VPN_ACCEPT@$/ {
      if (vpn != "") {
        sub(/# @VPN_ACCEPT@/, "iifname \"sp-vpn\" ct state new ip daddr " vip " udp dport " vport " counter accept")
      } else {
        sub(/# @VPN_ACCEPT@/, "# (no --vpn-endpoint: sp-vpn may open nothing)")
      }
      print; next
    }
    { print }
  ' "$template"
)
header="# Rendered by scripts/host/render-firewall.sh --$mode on $(date -u +%Y-%m-%dT%H:%M:%SZ)."
[ "$engine" = docker ] || header="# Rendered by scripts/host/render-firewall.sh --$mode --engine $engine on $(date -u +%Y-%m-%dT%H:%M:%SZ)."
rendered="$header"$'\n'"$rendered"

if grep -q 'CHANGE_ME\|@[A-Z_]*@' <<< "$rendered"; then
  echo "render-firewall: a placeholder is left in the rendered ruleset (template changed?)" >&2
  exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
chmod 600 "$tmp"
printf '%s\n' "$rendered" > "$tmp"

# Syntax check when this user may run it. nft talks to the kernel even with -c, so it needs root.
if command -v nft > /dev/null 2>&1; then
  if check=$(nft -c -f "$tmp" 2>&1); then
    note "nft -c: ruleset is valid"
  elif grep -qi 'not permitted\|permission denied' <<< "$check"; then
    note "nft -c skipped (needs root); install-firewall.sh checks it before loading"
  else
    echo "render-firewall: nft -c refused the ruleset:" >&2
    echo "$check" >&2
    exit 1
  fi
else
  note "nft not installed: syntax check skipped"
fi

if [ -n "$out" ]; then
  # Same directory as the target, so the final rename is atomic.
  final=$(mktemp "$(dirname "$out")/.render-firewall.XXXXXX")
  chmod 600 "$final"
  cat "$tmp" > "$final"
  mv -f "$final" "$out"
  note "wrote $out"
else
  cat "$tmp"
fi
