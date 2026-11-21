#!/bin/bash
# shellcheck disable=SC2016 # dc exec ... sh -c '...': expanded by the shell inside the container
# Live check of the anonymous egress (M21). Run it on the machine with the stack up and
# COMPOSE_PROFILES=egress. Prints PASS or FAIL per line, exits non-zero on any FAIL.
# It never prints the VPN exit address.
#
#   scripts/egress-check.sh           everything, including the kill-switch tests
#                                     (briefly takes the tunnel down, then stops/starts vpn)
#   scripts/egress-check.sh --quick   read-only checks only
#   scripts/egress-check.sh --isolation   only the sensor isolation checks (any profile, also a
#                                     full install without the VPN)
#
# With COMPOSE_PROFILES=direct (participant stack, M32) it checks the direct mode instead:
# hubproxy is the only way out, and only to the allowed names. The VPN checks below are
# then skipped; no kill-switch test applies (there is no tunnel).
#
# Both modes also check the isolation of the sensors (no outside DNS, no way out, no other sensor,
# no host port), on Docker and on Podman. On Podman they also check the sp-* networks, the host
# firewall and the boot unit, which carry guarantees that Docker gives by itself.
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh || exit 1
# shellcheck source=scripts/lib/firewall.sh
. scripts/lib/firewall.sh
# shellcheck source=scripts/lib/fwcheck.sh
. scripts/lib/fwcheck.sh

quick=0
isolation_only=0
case ${1:-} in
  --quick) quick=1 ;;
  --isolation) isolation_only=1 ;;
esac

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

# --- Isolation of the sensors (both engines; docs/dev/design/podman.md, section 7 and D10) -------
# From inside each running sensor: service names resolve, outside names do not, no connection to
# the internet, to another sensor, or to the host's SSH and dashboard ports. One python process per
# sensor runs every probe at once; it prints "probe yes" or "probe no" (did it succeed).
SENSOR_PROBE='
import socket, sys, threading
res = {}
def run(item):
    kind, _, target = item.partition(":")
    try:
        if kind == "resolve":
            socket.getaddrinfo(target, None)
        else:
            host, _, port = target.rpartition(":")
            socket.create_connection((host, int(port)), timeout=3).close()
        res[item] = "yes"
    except Exception:
        res[item] = "no"
threads = [threading.Thread(target=run, args=(i,), daemon=True) for i in sys.argv[1:]]
for t in threads:
    t.start()
for t in threads:
    t.join(10)
for i in sys.argv[1:]:
    print(i, res.get(i, "no"))
'
# A public address and name for the "no way out" probes (never contacted when isolation holds).
PROBE_IP=1.1.1.1
PROBE_NAME=example.com

# note "label": printed, never counted as a failure.
note() { printf 'NOTE  %s\n' "$1"; }
# probe_ok PROBE: the probe succeeded in the last sensor run ($out).
probe_ok() { grep -qx "$1 yes" <<< "$out"; }

isolation_checks() {
  local sensors=() probes=() reached=() host_ports=() s cid gws addrs next i p g a host_strict=0 admin admin_src dash target_ports published fwst
  echo "-- sensor isolation ($(engine_name))"
  if [ "$ENGINE_ID" = podman ]; then
    check "podman: every sp-* network has its options (isolate=strict, internal, no DNS on sp-ingress, sp-dashboard, sp-vpn)" \
      bash scripts/ensure-networks.sh --check
    if systemctl show -p BindsTo --value suckerpot-stack.service 2>/dev/null | grep -qw suckerpot-firewall.service; then
      pass "podman: the boot unit is bound to the host firewall (starts after it, stops with it)"
    else
      fail "podman: the boot unit is bound to the host firewall (suckerpot-stack.service missing or without BindsTo=suckerpot-firewall.service)"
    fi
  fi
  # The host firewall must be in force, not only its unit active: a flush or an nftables restart
  # removes the tables and leaves the unit active. Listing tables needs root (or sudo -n).
  # On Docker the firewall is optional: not installed is fine, installed but not loaded is a FAIL.
  # On Podman it is required. A reachable host port is then a FAIL; on Docker without the
  # firewall, a NOTE.
  fwst=$(fw_state)
  case $fwst in
    loaded)
      pass "host firewall loaded (unit active, tables $(fw_tables_needed | tr '\n' ' ' | sed 's/ $//'))"
      host_strict=1
      ;;
    missing:*)
      fail "host firewall loaded (the unit is active but table(s) ${fwst#missing:} are gone: sudo systemctl reload $FW_UNIT)"
      host_strict=1
      ;;
    unknown)
      if [ "$ENGINE_ID" = podman ]; then
        fail "host firewall loaded (unit active; its tables cannot be read: run this check with sudo)"
      else
        note "host firewall unit active; its tables were not read (run this check with sudo to see them)"
      fi
      host_strict=1
      ;;
    *)
      if [ "$ENGINE_ID" = podman ]; then
        fail "host firewall loaded ($FW_UNIT is not active)"
      elif fw_installed; then
        fail "host firewall loaded ($FW_UNIT is installed but not active: sudo systemctl start $FW_UNIT)"
        host_strict=1
      fi
      ;;
  esac
  [ "$ENGINE_ID" != podman ] || host_strict=1
  dash=$(env_value DASHBOARD_PORT)
  mapfile -t sensors < <(dc ps --status running --format '{{.Service}}' 2>/dev/null | grep '^sensor-' | sort -u)
  if [ "${#sensors[@]}" -eq 0 ]; then
    fail "at least one sensor is running (none is: sensor isolation not checked)"
    return 0
  fi
  # The host ports to probe: the admin SSH port (ADMIN_SSH_PORT, else what sshd is configured
  # with, else 22) and the dashboard port. When the port is only the default 22 and a sensor
  # publishes it, it is skipped: a probe there would only reach that sensor (and add a fake event
  # to its data), not the host's sshd.
  read -r admin admin_src <<< "$(fw_admin_port)"
  published=" "
  for s in "${sensors[@]}"; do
    cid=$(dc ps -q "$s" 2>/dev/null | head -n 1)
    [ -n "$cid" ] || continue
    published+=$(ctr inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{.HostPort}} {{end}}{{end}}' "$cid" 2>/dev/null)" "
  done
  host_ports=()
  if [ "$admin_src" != default ]; then
    host_ports+=("$admin")
  else
    case "$published" in *" $admin "*) note "the admin SSH port is unknown (set ADMIN_SSH_PORT in .env) and 22 is a sensor's: host SSH not probed" ;; *) host_ports+=("$admin") ;; esac
  fi
  case " ${host_ports[*]} $published" in *" ${dash:-8443} "*) ;; *) host_ports+=("${dash:-8443}") ;; esac
  for i in "${!sensors[@]}"; do
    s=${sensors[$i]}
    cid=$(dc ps -q "$s" 2>/dev/null | head -n 1)
    [ -n "$cid" ] || continue
    gws=$(ctr inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}' "$cid" 2>/dev/null)
    # The next sensor in the list: its addresses and listening ports are the targets.
    next=${sensors[$(( (i + 1) % ${#sensors[@]} ))]}
    addrs=""
    target_ports=""
    if [ "$next" != "$s" ]; then
      a=$(dc ps -q "$next" 2>/dev/null | head -n 1)
      if [ -n "$a" ]; then
        addrs=$(ctr inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$a" 2>/dev/null)
        target_ports=$(ctr inspect -f '{{range $p, $c := .NetworkSettings.Ports}}{{$p}} {{end}}' "$a" 2>/dev/null |
          tr ' ' '\n' | sed -n 's|/tcp$||p')
      fi
    fi
    probes=("resolve:redis" "resolve:$PROBE_NAME" "connect:$PROBE_IP:443")
    for g in $gws; do
      for p in "${host_ports[@]}"; do probes+=("connect:$g:$p"); done
    done
    for a in $addrs; do
      for p in $target_ports; do probes+=("connect:$a:$p"); done
    done
    out=$(timeout 30 "${ENGINE_DC[@]}" exec -T "$s" python -c "$SENSOR_PROBE" "${probes[@]}" 2>/dev/null)
    if [ -z "$out" ]; then
      fail "$s: isolation probe did not run"
      continue
    fi
    if probe_ok "resolve:redis"; then pass "$s: resolves service names (redis)"; else fail "$s: resolves service names (redis)"; fi
    if probe_ok "resolve:$PROBE_NAME"; then fail "$s: cannot resolve outside names"; else pass "$s: cannot resolve outside names"; fi
    if probe_ok "connect:$PROBE_IP:443"; then fail "$s: no connection to the internet"; else pass "$s: no connection to the internet"; fi
    reached=()
    for g in $gws; do
      for p in "${host_ports[@]}"; do probe_ok "connect:$g:$p" && reached+=("$p"); done
    done
    [ "${#reached[@]}" -eq 0 ] || mapfile -t reached < <(printf '%s\n' "${reached[@]}" | sort -un)
    if [ -z "$gws" ]; then
      pass "$s: no host address on its networks"
    elif [ "${#reached[@]}" -eq 0 ]; then
      pass "$s: cannot reach the host's SSH or dashboard port"
    elif [ "$host_strict" = 1 ]; then
      fail "$s: cannot reach the host's SSH or dashboard port (reached port(s) ${reached[*]})"
    else
      note "$s: reaches the host on port(s) ${reached[*]}; install the host firewall (scripts/host/README.md) to close that"
    fi
    if [ -z "$addrs" ] || [ -z "$target_ports" ]; then
      [ "$next" = "$s" ] || note "$s: no address or port of $next to probe"
    else
      reached=()
      for a in $addrs; do
        for p in $target_ports; do probe_ok "connect:$a:$p" && reached+=("$a:$p"); done
      done
      if [ "${#reached[@]}" -eq 0 ]; then
        pass "$s: cannot reach another sensor ($next)"
      else
        fail "$s: cannot reach another sensor ($next; reached ${#reached[@]} address and port pair(s))"
      fi
    fi
  done
}
if [ "$isolation_only" -eq 1 ]; then
  isolation_checks
  if [ "$fails" -gt 0 ]; then
    echo "egress-check: $fails check(s) failed" >&2
    exit 1
  fi
  echo "egress-check: all isolation checks passed"
  exit 0
fi

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
  isolation_checks
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

isolation_checks

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
