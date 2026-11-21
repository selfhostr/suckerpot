#!/usr/bin/env bash
# End-to-end test of the participant install (docs/dev/design/m32.md section 11.3).
#
#   scripts/e2e/participant.sh [--keep]
#
# Builds the images from source, starts a throwaway test hub (hub/docker-compose.test.yml, TLS from
# Caddy's internal CA), runs the REAL scripts/install.sh --participant --yes in a temporary copy of
# this repository, and checks the result: the participant services, the containment of the
# ingest container, the hubproxy allow-list, enrolment at the test hub, an accepted batch,
# status.sh, participant.sh leave, and the switch to full mode (data kept).
#
# Hermetic by construction:
#   - the compose project is sp-it-participant-<random>; the test installer mode
#     (SELFHOSTR_TEST_INSTALL=1) accepts only that shape of name, and appends
#     docker-compose.participant-it.yml (local images, local volumes, no published sensor port,
#     internal networks only). The machine's own .env is never read or written;
#   - the test hub is reached under the name suckerpot-hub.selfhostr.io through a network alias on a
#     throwaway INTERNAL Docker network (no gateway, no route). The name never reaches a real
#     resolver, and the real hub is never contacted;
#   - the only traffic to the internet is what Docker itself does (image pulls, base image
#     downloads while building). Nothing that this script starts has a route out;
#   - nothing of a running live stack is touched: every Docker object has the unique project name.
#
# --keep leaves the stack running at the end (for debugging; remove it with the printed commands).
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
keep=0
[ "${1:-}" != --keep ] || keep=1

# Nothing from the caller's environment may steer compose (just loads .env into its recipes).
while IFS= read -r v; do unset "$v"; done < <(compgen -e | grep -E '^(COMPOSE_|SUCKERPOT_|NETWORK_|EGRESS_|HUBPROXY_|REDIS_|POSTGRES_|SENSOR_|ADMIN_|DASHBOARD_|API_|SELF_|E2E_|AUTO_UPDATE|COLLECTOR_|VPN_)' || true)
# dc and ctr (scripts/lib/engine.sh). Docker: the caller's .env is not read, and the variable is gone.
# shellcheck source=scripts/lib/engine.sh
ENV_FILE=/dev/null . "$repo/scripts/lib/engine.sh"

rand=$( (set +o pipefail; LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c 8) )
PROJ="sp-it-participant-$rand"
HUBPROJ="sp-it-hub-$rand"
UPLINK="$PROJ-hubgate"
export E2E_UPLINK_NET="$UPLINK" E2E_HUB_IP=11.251.77.10 SELFHOSTR_TEST_INSTALL=1
# A public-looking subnet on an internal network: hubproxy (rightly) refuses private addresses.
# Nothing is routed there; the bridge only exists while the test runs.
UPLINK_SUBNET=11.251.77.0/24
HUB_IP=11.251.77.10
[[ $PROJ =~ ^sp-it-participant-[a-z0-9]{8}$ ]] || { echo "e2e: bad project name" >&2; exit 2; }

work=""
shim=""
t0=$(date +%s)
passed=0
failed=0

log() { printf '[%4ss] %s\n' "$(($(date +%s) - t0))" "$*"; }
ok() { passed=$((passed + 1)); echo "  ok    $*"; }
bad() { failed=$((failed + 1)); echo "  FAIL  $*"; }
fatal() { echo "e2e: $*" >&2; exit 1; }

# Runs a command and records the result.
check() {
  local desc=$1
  shift
  if "$@" > /dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}

dc() { (cd "$work" && "${ENGINE_DC[@]}" "$@"); }
hubdc() {
  (cd "$work" && E2E_UPLINK_NET=$UPLINK E2E_HUB_IP=$HUB_IP \
    "${ENGINE_DC[@]}" -f hub/docker-compose.test.yml -p "$HUBPROJ" --profile participant-e2e "$@")
}
# The same, with the host-side port probe stubbed (see below) and the test mode on.
inst() {
  (cd "$work" && PATH="$shim:$PATH" SELFHOSTR_TEST_INSTALL=1 E2E_UPLINK_NET=$UPLINK "$@")
}
envget() { sed -n "s/^$1=//p" "$work/.env" | tail -n 1 | tr -d "\"' \r"; }
psql_node() {
  dc exec -T -e PGPASSWORD="$(envget POSTGRES_PASSWORD)" db psql -X -q -t -A -U suckerpot -d suckerpot "$@"
}
psql_hub() {
  hubdc exec -T -e PGPASSWORD=hubtest-owner-password-0001 hub-db psql -X -q -t -A -U hub -d hub "$@"
}
py_ingest() { dc exec -T ingest python -I -c "$1"; }
# Top-level "state" of the network status (nested objects have their own "state" keys).
node_state() {
  dc exec -T ingest sh -c 'python -m ingest.network.cli status --json 2> /dev/null | python -I -c "import json, sys; print(json.load(sys.stdin).get(\"state\", \"\"))"' 2> /dev/null | tr -d '\r\n'
}

# What to look at when something failed (throwaway data only).
diagnose() {
  echo "---- diagnostics ----"
  [ -z "$work" ] || [ ! -f "$work/.env" ] || {
    dc ps -a --format '{{.Service}} {{.State}} {{.Health}}'
    dc logs --no-color --tail 40 ingest hubproxy 2>&1 | sed 's/^/ingest+hubproxy| /'
  }
  [ -z "$work" ] || [ ! -d "$work/hub" ] || hubdc logs --no-color --tail 15 hub-api hub-edge 2>&1 | sed 's/^/hub| /'
  echo "---- end diagnostics ----"
}

cleanup() {
  local rc=$?
  set +e
  if [ "$rc" != 0 ] || [ "$failed" != 0 ]; then diagnose; fi
  if [ "$keep" = 1 ] && [ "$rc" = 0 ] && [ "$failed" = 0 ]; then
    echo "e2e: --keep: the stack stays up. Remove it with:"
    echo "  (cd $work && ${ENGINE_DC[*]} --profile '*' down -v --remove-orphans)"
    echo "  ${ENGINE_DC[*]} -f $work/hub/docker-compose.test.yml -p $HUBPROJ --profile participant-e2e down -v"
    echo "  ${ENGINE_CTR[*]} network rm $UPLINK"
    return
  fi
  log "teardown"
  if [ -n "$work" ] && [ -f "$work/.env" ]; then
    (cd "$work" && SELFHOSTR_TEST_INSTALL=1 E2E_UPLINK_NET=$UPLINK timeout 180 "${ENGINE_DC[@]}" --profile '*' down -v --remove-orphans -t 5) > /dev/null 2>&1
  fi
  if [ -n "$work" ] && [ -d "$work/hub" ]; then
    hubdc down -v --remove-orphans -t 5 > /dev/null 2>&1
  fi
  # Whatever is left of the two unique projects, by label. The names are random and unique.
  for p in "$PROJ" "$HUBPROJ"; do
    ctr ps -aq --filter "label=com.docker.compose.project=$p" | xargs -r "${ENGINE_CTR[@]}" rm -f > /dev/null 2>&1
    ctr volume ls -q --filter "label=com.docker.compose.project=$p" | xargs -r "${ENGINE_CTR[@]}" volume rm -f > /dev/null 2>&1
    ctr network ls -q --filter "label=com.docker.compose.project=$p" | xargs -r "${ENGINE_CTR[@]}" network rm > /dev/null 2>&1
  done
  ctr volume ls -q --filter "name=^test-${PROJ}_" | xargs -r "${ENGINE_CTR[@]}" volume rm -f > /dev/null 2>&1
  ctr network rm "$UPLINK" > /dev/null 2>&1
  ctr image ls -q --filter "reference=local/${PROJ}-*" | sort -u | xargs -r "${ENGINE_CTR[@]}" rmi -f > /dev/null 2>&1
  ctr image ls -q --filter "reference=${HUBPROJ}-*" | sort -u | xargs -r "${ENGINE_CTR[@]}" rmi -f > /dev/null 2>&1
  [ -z "$work" ] || rm -rf "$work"
  log "teardown done"
}
trap cleanup EXIT

command -v "${ENGINE_CTR[0]}" > /dev/null || fatal "$(engine_name) is not installed"
dc version > /dev/null || fatal "Docker Compose v2 is required"
ctr network inspect "$UPLINK" > /dev/null 2>&1 && fatal "network $UPLINK exists"
if ip -4 route 2> /dev/null | grep -q "^11\.251\.77\."; then fatal "the test subnet $UPLINK_SUBNET is in use on this machine"; fi

# ---------------------------------------------------------------- 1. a clean copy of the sources
log "copying the sources (tracked and new files, no .env, no git history)"
work=$(mktemp -d "${TMPDIR:-/tmp}/selfhostr-e2e.XXXXXX")
(cd "$repo" && git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf -) | tar -C "$work" -xf -
[ -f "$work/scripts/participant.sh" ] || fatal "the copy is incomplete"
rm -f "$work/.env"
shim=$(mktemp -d "${TMPDIR:-/tmp}/selfhostr-e2e-shim.XXXXXX")
# The installer asks `ss` which host ports are busy. The overlay publishes no sensor port, so the
# answer must not depend on what else runs on this machine: pretend that nothing listens.
printf '#!/bin/sh\nexit 0\n' > "$shim/ss"
chmod +x "$shim/ss"
export COMPOSE_PARALLEL_LIMIT=2
export DOCKER_BUILDKIT=1

# ---------------------------------------------------------------- 2. the test hub
log "creating the internal hub gate network $UPLINK ($UPLINK_SUBNET)"
ctr network create --internal --subnet "$UPLINK_SUBNET" --label "e2e.project=$PROJ" "$UPLINK" > /dev/null
log "building and starting the test hub (project $HUBPROJ)"
timeout 900 bash -c "cd '$work' && E2E_UPLINK_NET='$UPLINK' E2E_HUB_IP='$HUB_IP' ${ENGINE_DC[*]} -f hub/docker-compose.test.yml -p '$HUBPROJ' --profile participant-e2e up -d --build --wait --wait-timeout 300 hub-edge" \
  || fatal "the test hub did not start"
hub_key=$(hubdc exec -T hub-api python -m hub.admin show-public-key | sed -n 's/^hub_key=//p' | tr -d '\r\n ')
[ -n "$hub_key" ] || fatal "no hub key"
ca=""
for _ in $(seq 1 30); do
  ca=$(hubdc exec -T hub-edge cat /data/caddy/pki/authorities/local/root.crt 2> /dev/null || true)
  case $ca in *BEGIN\ CERTIFICATE*) break ;; esac
  sleep 2
done
case $ca in *BEGIN\ CERTIFICATE*) ;; *) fatal "no test CA from the hub edge" ;; esac
# Replaces certifi's bundle in the ingest container only (see the overlay): the test CA alone is
# enough, because in participant mode ingest talks to the hub and to nothing else.
printf '%s\n' "$ca" > "$work/e2e-ca-bundle.pem"
log "test hub up; its name is an alias on $UPLINK"

# ---------------------------------------------------------------- 3. the real installer
log "running scripts/install.sh --participant --yes (builds the images: this takes a while)"
free_port() {
  local p
  while :; do
    p=$((20000 + RANDOM % 10000))
    ss -Hltn 2> /dev/null | grep -q ":$p " || { echo "$p"; return; }
  done
}
dash_port=$(free_port)
inst timeout 2400 "$work/scripts/install.sh" --participant --yes --source --project "$PROJ" --prefix "$PROJ" \
  --sensors ssh,telnet --lowmem on --self-address 203.0.113.9 --no-auto-update > "$work/install.out" 2>&1 \
  || { tail -n 40 "$work/install.out" >&2; fatal "the installer failed"; }
tail -n 14 "$work/install.out" | sed 's/^/    | /'
t_install=$(($(date +%s) - t0))
[ "$(envget COMPOSE_PROJECT_NAME)" = "$PROJ" ] || fatal ".env names another project"
case $(envget COMPOSE_FILE) in *docker-compose.participant-it.yml) ;; *) fatal "the test overlay is not in COMPOSE_FILE" ;; esac
log "installed"

# The hub address in the defaults is the real name with a placeholder key. The test injects the
# key through .env, explicitly: the committed defaults are not edited.
{
  echo "NETWORK_HUB_URL=https://suckerpot-hub.selfhostr.io"
  echo "NETWORK_HUB_KEY=$hub_key"
  echo "NETWORK_INTERVAL_S=30"
} >> "$work/.env"
dc up -d --no-build --no-deps --wait --wait-timeout 120 ingest > /dev/null 2>&1 || fatal "ingest did not restart with the test hub settings"

# ---------------------------------------------------------------- 4. the participant stack
log "checking the participant stack"
ps=$(dc ps --format '{{.Service}} {{.State}} {{.Health}}')
echo "$ps" | sed 's/^/    | /'
for svc in redis db ingest hubproxy backup sensor-ssh sensor-telnet; do
  line=$(echo "$ps" | grep "^$svc " || true)
  case $line in
    *"running healthy"*) ok "$svc is running and healthy" ;;
    *) bad "$svc is not running and healthy ($line)" ;;
  esac
done
extra=$(echo "$ps" | awk '$2 == "running" {print $1}' | grep -Ev '^(redis|db|ingest|hubproxy|backup|sensor-ssh|sensor-telnet)$' || true)
[ -z "$extra" ] && ok "no other service runs" || bad "unexpected services run: $extra"
for svc in api web vpn collector analyzer; do
  echo "$ps" | grep -q "^$svc " && bad "$svc is present in participant mode" || ok "$svc is absent"
done
echo "$ps" | grep -Eq ' (unhealthy|starting)$' && bad "a service is unhealthy or still starting" || ok "no unhealthy service"
[ "$(envget SUCKERPOT_STACK_MODE)" = participant ] && ok ".env says participant" || bad ".env stack mode"

# ---------------------------------------------------------------- 5. containment
log "checking containment"
probe_net='
import socket
def fails(fn):
    try:
        fn()
    except OSError:
        return True
    return False
routes = open("/proc/net/route").read().splitlines()[1:]
print("default_route", any(r.split()[1] == "00000000" for r in routes))
s = socket.socket()
s.settimeout(3)
print("tcp_1.1.1.1_443_fails", fails(lambda: s.connect(("1.1.1.1", 443))))
print("dns_example.org_fails", fails(lambda: socket.getaddrinfo("example.org", 443)))
print("dns_hub_name_fails", fails(lambda: socket.getaddrinfo("suckerpot-hub.selfhostr.io", 443)))
print("dns_hubproxy_works", not fails(lambda: socket.getaddrinfo("hubproxy", 8888)))
'
net_out=$(py_ingest "$probe_net" 2> /dev/null || true)
echo "$net_out" | grep -qx 'default_route False' && ok "ingest has no default route" || bad "ingest has a default route ($net_out)"
echo "$net_out" | grep -qx 'tcp_1.1.1.1_443_fails True' && ok "ingest cannot open a TCP connection to 1.1.1.1:443" || bad "ingest reached 1.1.1.1:443"
echo "$net_out" | grep -qx 'dns_example.org_fails True' && ok "ingest cannot resolve example.org" || bad "ingest resolves example.org"
echo "$net_out" | grep -qx 'dns_hub_name_fails True' && ok "ingest cannot resolve the hub name itself" || bad "ingest resolves the hub name"
echo "$net_out" | grep -qx 'dns_hubproxy_works True' && ok "ingest resolves hubproxy" || bad "ingest cannot resolve hubproxy"

probe_proxy='
import base64, os, socket

def connect(target, method="CONNECT", auth=True):
    s = socket.create_connection(("hubproxy", 8888), timeout=10)
    head = f"{method} {target} HTTP/1.1\r\nHost: {target}\r\n"
    if auth:
        token = base64.b64encode(("egress:" + os.environ["EGRESS_PROXY_PASSWORD"]).encode()).decode()
        head += "Proxy-Authorization: Basic " + token + "\r\n"
    s.sendall((head + "\r\n").encode())
    line = s.recv(200).split(b"\r\n")[0].decode(errors="replace")
    s.close()
    return line.split(" ")[1] if line.count(" ") >= 1 else line

for label, args in (
    ("example.org:443", ("example.org:443",)),
    ("ip_literal_1.1.1.1:443", ("1.1.1.1:443",)),
    ("ip_literal_192.0.2.7:443", ("192.0.2.7:443",)),
    ("hub_port_80", ("suckerpot-hub.selfhostr.io:80",)),
    ("hub_port_22", ("suckerpot-hub.selfhostr.io:22",)),
    ("get_method", ("suckerpot-hub.selfhostr.io:443", "GET")),
    ("no_auth", ("suckerpot-hub.selfhostr.io:443", "CONNECT", False)),
    ("hub_443", ("suckerpot-hub.selfhostr.io:443",)),
):
    print(label, connect(*args))
'
proxy_out=$(py_ingest "$probe_proxy" 2> /dev/null || true)
want_code() { echo "$proxy_out" | grep -qx "$1 $2"; }
want_code example.org:443 403 && ok "hubproxy refuses example.org:443 (403)" || bad "hubproxy and example.org:443 ($proxy_out)"
want_code ip_literal_1.1.1.1:443 403 && ok "hubproxy refuses an IP literal (403)" || bad "hubproxy and an IP literal"
want_code ip_literal_192.0.2.7:443 403 && ok "hubproxy refuses a documentation IP literal (403)" || bad "hubproxy and a documentation IP"
want_code hub_port_80 403 && ok "hubproxy refuses the hub name on port 80 (403)" || bad "hubproxy and port 80"
want_code hub_port_22 403 && ok "hubproxy refuses the hub name on port 22 (403)" || bad "hubproxy and port 22"
want_code get_method 405 && ok "hubproxy refuses a plain GET (405)" || bad "hubproxy and GET"
want_code no_auth 407 && ok "hubproxy asks for credentials (407)" || bad "hubproxy without credentials"
want_code hub_443 200 && ok "hubproxy lets the hub name on 443 through (200)" || bad "hubproxy and the hub name"

sensor_out=$(dc exec -T sensor-ssh python -I -c '
import socket
try:
    socket.getaddrinfo("hubproxy", 8888)
    print("resolves")
except OSError:
    print("refused")
' 2> /dev/null || true)
[ "$sensor_out" = refused ] && ok "a sensor container cannot resolve hubproxy" || bad "a sensor resolves hubproxy ($sensor_out)"

# ---------------------------------------------------------------- 6. enrolment
log "waiting for the node to enrol at the test hub"
state=""
for _ in $(seq 1 40); do
  state=$(node_state || true)
  [ "$state" = member ] && break
  sleep 5
done
[ "$state" = member ] && ok "the node is a member (state: $state)" || bad "the node did not enrol (state: ${state:-unknown})"
hub_nodes=$(psql_hub -c 'SELECT count(*) FROM nodes' 2> /dev/null || echo "?")
[ "$hub_nodes" = 1 ] && ok "the test hub holds exactly one node" || bad "the hub holds $hub_nodes nodes"

# ---------------------------------------------------------------- 7. a batch is accepted
# Real timers: a day is sent after it closed plus 2 to 20 hours, and never before the enrolment
# day. The test creates yesterday's sessions with global-looking addresses (nothing is ever
# contacted) and moves the node's own bookkeeping back (enrolled_day, next_submit_at) in the
# throwaway database. The worker, the guards, the signatures and the hub are all the real ones.
log "giving the node a closed day of sessions and a due submission"
sessions_before=0
if [ "$state" = member ]; then
  psql_node -c "
    INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at, last_event_at,
                          event_count, login_attempts, commands, tags)
    SELECT 'e2e-' || g, 'ssh', ('11.250.0.' || (g + 10))::inet, 40000 + g, 22,
           (date_trunc('day', now() AT TIME ZONE 'utc') - interval '12 hours') AT TIME ZONE 'utc',
           (date_trunc('day', now() AT TIME ZONE 'utc') - interval '12 hours') AT TIME ZONE 'utc',
           3, 4, 0, '{}'
    FROM generate_series(1, 3) g;
    UPDATE network_membership
       SET enrolled_day = (now() AT TIME ZONE 'utc')::date - 3, next_submit_at = now() - interval '1 hour';" > /dev/null
  sessions_before=$(psql_node -c 'SELECT count(*) FROM sessions')
  sent=""
  for _ in $(seq 1 30); do
    sent=$(psql_node -c "SELECT status FROM network_submissions ORDER BY day DESC LIMIT 1" 2> /dev/null || true)
    [ "$sent" = sent ] && break
    sleep 5
  done
  [ "$sent" = sent ] && ok "a batch was sent and the hub accepted it" || bad "no batch was accepted (last status: ${sent:-none}; $(psql_node -c 'SELECT coalesce(last_error_code, '"'"'-'"'"') FROM network_membership' 2> /dev/null))"
  hub_batches=$(psql_hub -c 'SELECT count(*) FROM batches' 2> /dev/null || echo "?")
  [ "$hub_batches" -ge 1 ] 2> /dev/null && ok "the hub stored the batch" || bad "the hub holds no batch ($hub_batches)"
else
  bad "no batch test: the node is not a member"
fi

# ---------------------------------------------------------------- 8. status.sh
log "checking status.sh"
set +e
status_json=$(cd "$work" && ./scripts/status.sh --json 2> /dev/null)
status_rc=$?
set -e
[ "$status_rc" = 0 ] || [ "$status_rc" = 1 ] && ok "status.sh --json exits $status_rc" || bad "status.sh --json exits $status_rc"
printf '%s' "$status_json" | dc exec -T ingest python -I -c '
import json, sys
d = json.load(sys.stdin)
sys.exit(0 if d.get("stack") == "participant" and d.get("network", {}).get("state") == "member" else 1)
' > /dev/null 2>&1 && ok "status.sh --json shows the node as a member" || bad "status.sh --json does not show a member: $(printf '%s' "$status_json" | head -c 300)"
set +e
(cd "$work" && ./scripts/status.sh > "$work/status.txt" 2>&1)
text_rc=$?
set -e
{ [ "$text_rc" = 0 ] || [ "$text_rc" = 1 ]; } && ok "status.sh (text) exits $text_rc" || bad "status.sh (text) exits $text_rc"

# ---------------------------------------------------------------- 9. P7 question: remove-orphans
# Does `up --remove-orphans` stop a service of a profile that is no longer on? The installer and
# participant.sh assume it does NOT, and stop such services by name. Check, without changing .env.
log "does 'up --remove-orphans' remove a service of an inactive profile?"
(cd "$work" && COMPOSE_PROFILES=egress dc up -d --no-build --no-deps --remove-orphans redis > /dev/null 2>&1) || true
if [ -n "$(dc ps -q hubproxy 2> /dev/null)" ]; then
  ok "P7: --remove-orphans leaves hubproxy (profile direct, inactive) running: the explicit rm -sf is needed"
  REMOVE_ORPHANS_REMOVES=0
else
  ok "P7: --remove-orphans removed hubproxy by itself (the explicit rm -sf is redundant, harmless)"
  REMOVE_ORPHANS_REMOVES=1
  dc up -d --no-build --no-deps --wait hubproxy > /dev/null 2>&1 || bad "hubproxy did not come back"
fi

# ---------------------------------------------------------------- 10. leave
log "participant.sh leave"
(cd "$work" && PATH="$shim:$PATH" SELFHOSTR_TEST_INSTALL=1 E2E_UPLINK_NET=$UPLINK timeout 400 ./scripts/participant.sh leave) > "$work/leave.out" 2>&1 \
  && ok "participant.sh leave succeeded" || { bad "participant.sh leave failed"; tail -n 15 "$work/leave.out" | sed 's/^/    | /'; }
[ "$(envget NETWORK_ENABLED)" = false ] && ok ".env has NETWORK_ENABLED=false" || bad "NETWORK_ENABLED is not false"
hub_nodes=$(psql_hub -c 'SELECT count(*) FROM nodes' 2> /dev/null || echo "?")
if [ "$hub_nodes" = 0 ]; then
  ok "the hub deleted the node"
else
  bad "the hub still holds $hub_nodes node(s)"
  psql_node -c "SELECT desired, state, left_day, last_error_code FROM network_membership" | sed 's/^/    | membership: /'
  dc logs --no-color --tail 25 ingest hubproxy 2>&1 | sed 's/^/    | /'
fi
left=$(node_state || true)
case $left in off | left | not_joined) ok "the node reports state $left" ;; *) bad "the node reports state ${left:-unknown}" ;; esac

# ---------------------------------------------------------------- 11. switch to full mode
log "install.sh --full (switch; builds the api image)"
sessions_before=$(psql_node -c 'SELECT count(*) FROM sessions')
set +e
printf '%s\n' "e2e-admin-password-$rand" | inst timeout 2400 "$work/scripts/install.sh" --full --yes --admin-password-stdin \
  --dashboard-port "$dash_port" > "$work/switch.out" 2>&1
switch_rc=$?
set -e
[ "$switch_rc" = 0 ] && ok "install.sh --full succeeded" || { bad "install.sh --full failed ($switch_rc)"; tail -n 30 "$work/switch.out" | sed 's/^/    | /'; }
[ "$(envget SUCKERPOT_STACK_MODE)" = full ] && ok ".env says full" || bad ".env stack mode after the switch"
ps=$(dc ps --format '{{.Service}} {{.State}} {{.Health}}')
echo "$ps" | sed 's/^/    | /'
echo "$ps" | grep -q '^api running healthy' && ok "api is running and healthy" || bad "api is not healthy"
echo "$ps" | grep -q '^hubproxy ' && bad "hubproxy still exists after the switch" || ok "hubproxy is gone after the switch"
sessions_after=$(psql_node -c 'SELECT count(*) FROM sessions' 2> /dev/null || echo "?")
[ "$sessions_before" = "$sessions_after" ] && [ "$sessions_before" != "?" ] && ok "the database kept its data ($sessions_after sessions)" || bad "session count changed: $sessions_before -> $sessions_after"
curl -fsS --max-time 10 "http://127.0.0.1:$dash_port/healthz" > /dev/null 2>&1 && ok "the dashboard answers on 127.0.0.1:$dash_port" || bad "the dashboard does not answer"
[ -f "$work/.env.participant.bak" ] && ok ".env.participant.bak was kept" || bad "no .env.participant.bak"

# ---------------------------------------------------------------- result
log "done in $(($(date +%s) - t0)) s (install finished at ${t_install} s): $passed passed, $failed failed"
[ "$failed" = 0 ] || exit 1
