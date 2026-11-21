#!/bin/bash
# shellcheck disable=SC2016 # dc exec ... sh -c '...': expanded by the shell inside the container
# Live check of the anonymous egress (M21). Run it on the machine with the stack up and
# COMPOSE_PROFILES=egress. Prints PASS or FAIL per line, exits non-zero on any FAIL.
# It never prints the VPN exit address.
#
#   scripts/egress-check.sh           everything, including the kill-switch tests
#                                     (briefly takes the tunnel down, then stops/starts vpn)
#   scripts/egress-check.sh --quick   read-only checks only
#
# With COMPOSE_PROFILES=direct (participant stack, M32) it checks the direct mode instead:
# hubproxy is the only way out, and only to the allowed names. The VPN checks below are
# then skipped; no kill-switch test applies (there is no tunnel).
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/engine.sh
. scripts/lib/engine.sh || exit 1

quick=0
[ "${1:-}" = "--quick" ] && quick=1

fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
# check "label" cmd...   (PASS when the command succeeds)
check() { local label=$1; shift; if "$@" >/dev/null 2>&1; then pass "$label"; else fail "$label"; fi; }
# check_not "label" cmd... (PASS when the command fails)
check_not() { local label=$1; shift; if "$@" >/dev/null 2>&1; then fail "$label"; else pass "$label"; fi; }

selftest() { local svc=$1; shift; dc exec -T "$svc" python -m suckerpot_egress.selftest "$@"; }

# Direct mode (M32): ingest has no route and no DNS; hubproxy tunnels to the allowed names only.
env_value() { local v=${!1:-}; [ -n "$v" ] || v=$(sed -n "s/^$1=//p" .env 2>/dev/null | tail -n 1); printf '%s' "$v"; }
direct=0
case ",$(env_value COMPOSE_PROFILES)," in *,direct,*) direct=1 ;; esac
if [ "$direct" -eq 1 ]; then
  for svc in hubproxy ingest; do
    state=$(dc ps --format '{{.State}}' "$svc" 2>/dev/null | head -n 1)
    [ "$state" = "running" ] && pass "$svc is running" || fail "$svc is running (state: ${state:-none})"
  done
  hub_url=$(env_value NETWORK_HUB_URL)
  hub_host=${hub_url#*://}; hub_host=${hub_host%%[/:]*}
  hub_host=${hub_host:-suckerpot-hub.selfhostr.io}
  for svc in vpn collector analyzer; do
    state=$(dc ps --format '{{.State}}' "$svc" 2>/dev/null | head -n 1)
    [ "$state" = "running" ] && fail "$svc must not run in direct mode" || pass "$svc is not running"
  done
  check "ingest: no direct route, no external DNS" selftest ingest --direct
  check "ingest: egress gate open (hubproxy allows only the scope)" selftest ingest --gate
  check "ingest: hubproxy refuses CONNECT example.org:443" selftest ingest --refuse "example.org:443"
  check "ingest: hubproxy refuses CONNECT to an IP literal" selftest ingest --refuse "1.1.1.1:443"
  check "ingest: hubproxy refuses CONNECT to the hub on another port" \
    selftest ingest --refuse "$hub_host:80"
  check "ingest: hubproxy accepts CONNECT to the hub" selftest ingest --accept "$hub_host:443"
  for svc in redis db; do
    check_not "$svc: no direct route out" dc exec -T "$svc" sh -c 'exec 3<>/dev/tcp/1.1.1.1/443' 
  done
  if [ "$fails" -gt 0 ]; then
    echo "egress-check: $fails check(s) failed" >&2
    exit 1
  fi
  echo "egress-check: all checks passed (direct mode)"
  exit 0
fi

case ",${COMPOSE_PROFILES:-}," in
  *,egress,*) ;;
  *) if ! grep -qs '^COMPOSE_PROFILES=.*egress' .env; then
       echo "egress-check: COMPOSE_PROFILES does not include egress" >&2; exit 2; fi ;;
esac

for svc in vpn ingest collector analyzer; do
  state=$(dc ps --format '{{.State}}' "$svc" 2>/dev/null | head -n 1)
  [ "$state" = "running" ] && pass "$svc is running" || fail "$svc is running (state: ${state:-none})"
done

# Addresses learned from Docker, used only as probe targets and never printed.
vpn_cid=$(dc ps -q vpn 2>/dev/null | head -n 1)
gateway=""
vpn_ip=""
if [ -n "$vpn_cid" ]; then
  gateway=$(ctr inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{if eq $k "sp-vpn"}}{{$v.Gateway}}{{end}}{{end}}' "$vpn_cid")
  vpn_ip=$(ctr inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{if ne $k "sp-vpn"}}{{$v.IPAddress}}{{end}}{{end}}' "$vpn_cid")
fi
proxy_gw=""
if [ -n "$vpn_cid" ]; then
  proxy_gw=$(ctr inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{if ne $k "sp-vpn"}}{{$v.Gateway}}{{end}}{{end}}' "$vpn_cid")
fi
if [ -z "$proxy_gw" ] && [ -n "$vpn_cid" ]; then
  pass "egress-proxy bridge has no gateway address (isolated): the host is not reachable through it"
fi
dash_port=${DASHBOARD_PORT:-$(sed -n 's/^DASHBOARD_PORT=//p' .env 2>/dev/null | tail -n 1)}
dash_port=${dash_port:-8443}

# Direct connections, external DNS and name resolution must fail; then the gate must be open.
for svc in ingest collector; do
  check "$svc: no direct route, no external DNS" selftest "$svc" --direct
  check "$svc: egress gate open, exit address in the allow-list" selftest "$svc" --gate
  [ -n "$gateway" ] && check "$svc: proxy refuses the sp-vpn gateway on the dashboard port" \
    selftest "$svc" --refuse "$gateway:$dash_port"
  [ -n "$gateway" ] && check "$svc: proxy refuses the sp-vpn gateway (the host) on a sensor port" \
    selftest "$svc" --refuse "$gateway:22"
  if [ -n "$proxy_gw" ]; then
    check "$svc: proxy refuses the egress-proxy gateway (the host) on a sensor port" \
      selftest "$svc" --refuse "$proxy_gw:22"
  fi
  # The proxy runs inside vpn, so a CONNECT to vpn's own address is a local connection
  # that gluetun's firewall cannot filter. Covered instead by the collector's validator
  # (private literals refused) and the control server's deny-by-default auth.
  if [ -n "$vpn_ip" ]; then
    if selftest "$svc" --refuse "$vpn_ip:8000" >/dev/null 2>&1; then
      pass "$svc: proxy refuses the vpn control port by private literal"
    else
      printf 'NOTE  %s\n' "$svc: proxy reaches vpn's own control port (local; validator and control auth cover it)"
    fi
  fi
  check "$svc: proxy refuses a name that resolves to loopback" \
    selftest "$svc" --refuse "localtest.me:80"
done

# The uploaded VPN settings (M23) are visible to vpn (read-only) and api only.
for svc in ingest collector analyzer; do
  check_not "$svc: /vpn-config is not mounted" dc exec -T "$svc" test -e /vpn-config
done
check "vpn: /vpn-config is read-only" dc exec -T vpn sh -c '! touch /vpn-config/.w 2>/dev/null'

# The analyzer has no way out at all.
check "analyzer: no direct route, no proxy" selftest analyzer --direct --no-connect vpn:8888

if [ "$quick" -eq 0 ]; then
  echo "-- kill switch (the tunnel goes down for a short while)"
  dc exec -T vpn ip link set wg0 down >/dev/null 2>&1
  sleep 1
  check "tunnel down: nothing leaves through the proxy" selftest ingest --echo-fails
  check_not "tunnel down: the gate closes" selftest ingest --gate
  restored=0
  for _ in $(seq 1 15); do
    if selftest ingest --gate >/dev/null 2>&1; then restored=1; break; fi
    sleep 4
  done
  [ "$restored" -eq 1 ] && pass "tunnel restored: gate open again" || fail "tunnel restored: gate open again"

  echo "-- vpn container stopped"
  dc stop vpn >/dev/null 2>&1
  check "vpn stopped: gate reports no_vpn" selftest ingest --gate --expect no_vpn
  state=$(dc ps --format '{{.Health}}' ingest 2>/dev/null | head -n 1)
  [ "$state" = "healthy" ] && pass "vpn stopped: ingest stays healthy" || fail "vpn stopped: ingest stays healthy (${state:-unknown})"
  dc start vpn >/dev/null 2>&1
  for _ in $(seq 1 15); do
    [ "$(dc ps --format '{{.Health}}' vpn 2>/dev/null | head -n 1)" = "healthy" ] && break
    sleep 4
  done
  [ "$(dc ps --format '{{.Health}}' vpn 2>/dev/null | head -n 1)" = "healthy" ] && pass "vpn started again and healthy" || fail "vpn started again and healthy"
fi

if [ "$fails" -gt 0 ]; then
  echo "egress-check: $fails check(s) failed" >&2
  exit 1
fi
echo "egress-check: all checks passed"
