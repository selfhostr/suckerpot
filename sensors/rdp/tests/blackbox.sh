#!/bin/sh
# Black-box check with real clients (nmap NSE RDP scripts, FreeRDP) against the built container.
# Usage (repo root):  sg docker -c "sh sensors/rdp/tests/blackbox.sh"
# Needs docker and network access to pull redis, alpine and instrumentisto/nmap. A throwaway
# Redis (no auth) on a private network collects the events, which are printed at the end.
set -eu
cd "$(dirname "$0")/../../.."
NET=sp-rdp-bb; NAME=sp-rdp-bb; IMG=sp-rdp-bb:dev; REDIS=sp-rdp-bb-redis
cleanup() {
  docker rm -f "$NAME" "$REDIS" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$NAME-data" >/dev/null 2>&1 || true
}
trap cleanup EXIT; cleanup
docker build -q -f sensors/rdp/Dockerfile -t "$IMG" . >/dev/null
docker network create "$NET" >/dev/null
docker run -d --name "$REDIS" --network "$NET" valkey/valkey:9.1-alpine3.24 >/dev/null
docker run -d --name "$NAME" --network "$NET" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true --memory 128m --cpus 0.5 --pids-limit 128 \
  -v "$NAME-data:/data" -e REDIS_HOST="$REDIS" -e EVENTS_STREAM=events:rdp "$IMG" >/dev/null
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] && break
  sleep 2
done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] || { echo "not healthy"; exit 1; }
echo HEALTHY
echo "--- nmap -sV + rdp scripts"
docker run --rm --network "$NET" instrumentisto/nmap -Pn -sV -p 3389 \
  --script rdp-ntlm-info,rdp-enum-encryption,ssl-cert "$NAME" | sed -n '/^PORT/,/^Service detection/p'
echo "--- xfreerdp +auth-only"
docker run --rm --network "$NET" alpine:3.24 sh -c "apk add -q freerdp xvfb-run >/dev/null 2>&1; xfreerdp /version 2>&1 | grep -i 'version' | head -1; \
  timeout 30 xvfb-run -a xfreerdp /v:$NAME /u:administrator /p:Winter2026 /cert:ignore +auth-only; echo exit=\$?" 2>&1 | tail -8
echo "--- non-RDP traffic"
docker run --rm --network "$NET" alpine:3.24 sh -c "printf 'GET / HTTP/1.1\r\nHost: x\r\n\r\n' | nc -w 3 $NAME 3389 | od -c | head -2; echo http_done"
sleep 1
echo "--- events (type, username / kind, reason)"
docker exec "$REDIS" valkey-cli XRANGE events:rdp - + | grep '^{' | \
  sed -E 's/.*"type":"([a-z_]+)".*/\1/' | sort | uniq -c
docker exec "$REDIS" valkey-cli XRANGE events:rdp - + | grep -o '"username":"[^"]*"\|"reason":"[^"]*"\|"kind":"[^"]*"\|"negotiation":"[^"]*"' | sort | uniq -c
docker exec "$REDIS" valkey-cli XRANGE events:rdp - + | grep -c Winter2026 | sed 's/^/password_occurrences_in_events=/' || true
docker exec "$REDIS" valkey-cli XRANGE events:rdp - + | grep '"credssp_not_supported"' | tail -1 | cut -c1-1500
docker logs "$NAME" 2>&1 | grep -ci "honeypot\|suckerpot\|traceback" | sed 's/^/giveaway_or_traceback_lines_in_logs=/'
