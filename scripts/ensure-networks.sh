#!/usr/bin/env bash
# Creates the SuckerPot networks on Podman (docs/dev/design/podman.md, section 5.2). Docker needs
# nothing: there, compose creates the networks from docker-compose.yml.
#
#   scripts/ensure-networks.sh           create the missing networks, recreate the wrong ones
#   scripts/ensure-networks.sh --check   only compare; print each problem, exit 1 on any
#
# Why: Podman's Docker-compatible API ignores the network options SuckerPot relies on
# (enable_ip_masquerade, enable_icc, gateway_mode_ipv4). So on Podman SuckerPot creates every
# sp-* network itself, with netavark's own options, and docker-compose.podman.yml marks them
# external:
#   - isolate=strict on every network: no traffic between two SuckerPot bridges, nor with any
#     other Podman network;
#   - --internal where docker-compose.yml says internal: true (no default route, no forwarding);
#   - --disable-dns on sp-ingress, sp-dashboard and sp-vpn: no member needs a name there, and
#     aardvark-dns would forward outside names from the host's namespace (section 5.3);
#   - no IPv6.
# The host firewall (scripts/host/, mandatory on Podman) adds what netavark cannot do: no
# outbound route from sp-ingress and sp-dashboard, no traffic between two members of one bridge.
#
# A network is only removed when no container uses it. When a network in use must change, the
# script stops with exit 3: stop the stack (docker-compose down), then run it again.
# compose_up_recreating (scripts/lib/env.sh) does exactly that.
#
# Exit codes: 0 done (or nothing to do on Docker); 1 error or (--check) a problem found;
# 2 bad arguments; 3 a network in use must be recreated.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/engine.sh
. scripts/lib/engine.sh

check=0
case ${1:-} in
  "") ;;
  --check) check=1 ;;
  -h | --help)
    sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "ensure-networks: unknown argument: $1 (see --help)" >&2
    exit 2
    ;;
esac

if [ "$ENGINE_ID" != podman ]; then
  [ "$check" = 1 ] || echo "ensure-networks: nothing to do on $(engine_name) (compose creates the networks)"
  exit 0
fi

# Without the Podman overlay, compose would create its own networks through the compat API, with
# none of the options below. Refuse, so that nothing starts on those.
compose_file=${COMPOSE_FILE:-$(sed -n 's/^COMPOSE_FILE=//p' "${ENV_FILE:-.env}" 2> /dev/null | tail -n 1 | tr -d "\"'\r")}
case ":$compose_file:" in
  *:docker-compose.podman.yml:*) ;;
  *)
    echo "ensure-networks: COMPOSE_FILE does not list docker-compose.podman.yml (it is '${compose_file:-unset}'). On Podman it must, or the stack would run on networks without isolation." >&2
    exit 1
    ;;
esac

# Bump when a network's options change: networks with an older value are recreated.
NETSPEC=1

# name internal dns, one network per line. The names are the bridge names of docker-compose.yml
# (scripts/guardrails checks both lists match).
SPECS="sp-ingress 0 0
sp-dashboard 0 0
sp-vpn 0 0
sp-hubgate 0 1
sp-egress 1 1
sp-hubproxy 1 1
sp-samples 1 1
sp-backend 1 1
sp-tools 1 1
sp-s-ssh 1 1
sp-s-rdp 1 1
sp-s-telnet 1 1
sp-s-web 1 1
sp-s-redis 1 1
sp-s-docker 1 1
sp-s-mysql 1 1
sp-s-mssql 1 1
sp-s-adb 1 1
sp-s-smb 1 1
sp-s-sip 1 1
sp-s-synology 1 1"

# What `podman network inspect` must print for a network made by this script.
want_line() {
  local name=$1 internal=$2 dns=$3 int=false dnson=false
  [ "$internal" = 1 ] && int=true
  [ "$dns" = 1 ] && dnson=true
  echo "bridge $name $int $dnson false strict $NETSPEC"
}

have_line() {
  ctr network inspect --format '{{.Driver}} {{.NetworkInterface}} {{.Internal}} {{.DNSEnabled}} {{.IPv6Enabled}} {{index .Options "isolate"}} {{index .Labels "io.suckerpot.netspec"}}' "$1" 2> /dev/null
}

# Containers (any state) attached to network $1.
users() { ctr ps -a -q --filter "network=$1" 2> /dev/null || true; }

# Other networks whose bridge is called $1 (a network made by compose through the compat API,
# for example). Their interface name would clash.
clashing() {
  ctr network ls --format '{{.Name}} {{.NetworkInterface}}' 2> /dev/null |
    awk -v want="$1" '$2 == want && $1 != want { print $1 }'
}

create() {
  local name=$1 internal=$2 dns=$3 args=()
  args=(network create --driver bridge --interface-name "$name" --opt isolate=strict
    --label io.suckerpot.managed=1 --label "io.suckerpot.netspec=$NETSPEC")
  [ "$internal" = 1 ] && args+=(--internal)
  [ "$dns" = 1 ] || args+=(--disable-dns)
  ctr "${args[@]}" "$name" > /dev/null
}

# remove NAME WHY: removes an unused network; returns 3 when containers use it.
remove() {
  local name=$1 why=$2 used
  used=$(users "$name")
  if [ -n "$used" ]; then
    echo "ensure-networks: network $name must be recreated ($why), but containers use it. Stop the stack (docker-compose down), then run this again." >&2
    return 3
  fi
  echo "ensure-networks: recreating network $name ($why)"
  ctr network rm "$name" > /dev/null
}

problems=0
rc=0
while read -r name internal dns; do
  want=$(want_line "$name" "$internal" "$dns")
  have=$(have_line "$name" || true)
  others=$(clashing "$name")
  if [ "$check" = 1 ]; then
    if [ -z "$have" ]; then
      echo "ensure-networks: network $name is missing" >&2
      problems=$((problems + 1))
    elif [ "$have" != "$want" ]; then
      echo "ensure-networks: network $name differs: have '$have', want '$want' (driver interface internal dns ipv6 isolate netspec)" >&2
      problems=$((problems + 1))
    fi
    if [ -n "$others" ]; then
      echo "ensure-networks: other network(s) on bridge $name: $others" >&2
      problems=$((problems + 1))
    fi
    continue
  fi
  for other in $others; do
    remove "$other" "it uses the bridge name $name" || {
      rc=$?
      continue 2
    }
  done
  if [ -n "$have" ] && [ "$have" != "$want" ]; then
    remove "$name" "have '$have', want '$want'" || {
      rc=$?
      continue
    }
    have=""
  fi
  if [ -z "$have" ]; then
    create "$name" "$internal" "$dns"
    have=$(have_line "$name" || true)
    if [ "$have" != "$want" ]; then
      echo "ensure-networks: network $name was created but reads '$have', not '$want'" >&2
      exit 1
    fi
  fi
done <<< "$SPECS"

if [ "$check" = 1 ]; then
  [ "$problems" = 0 ] || exit 1
  exit 0
fi
exit "$rc"
