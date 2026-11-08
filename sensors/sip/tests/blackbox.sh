#!/bin/sh
# Black-box check with real SIP clients (sipsak, SIPVicious svmap/svwar/svcrack, nmap -sU -sV)
# against the built container. Usage (repo root):  sg docker -c "sh sensors/sip/tests/blackbox.sh"
# Needs docker and network access (pulls python, redis and instrumentisto/nmap, and installs
# sipsak and SIPVicious in a throwaway client image). Everything runs on a private throwaway
# network with no published ports; a throwaway Redis collects the events. The sensor is started
# with SENSOR_SIP_ALLOW_PRIVATE=true because the clients live on a private Docker network (in
# production, private sources are never answered). Nothing here touches the live stack.
set -eu
cd "$(dirname "$0")/../../.."
NET=sp-sip-bb; NAME=sp-sip-bb; IMG=sp-sip-bb:dev; STREAM=sp-sip-bb-stream; TOOLS=sp-sip-bb-tools:dev
cleanup() {
  docker rm -f "$NAME" "$STREAM" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$NAME-data" >/dev/null 2>&1 || true
  [ "${KEEP_IMAGES:-0}" = 1 ] || docker rmi "$IMG" "$TOOLS" >/dev/null 2>&1 || true
}
trap cleanup EXIT; cleanup
docker build -q -f sensors/sip/Dockerfile -t "$IMG" . >/dev/null
docker build -q -t "$TOOLS" - >/dev/null <<'DOCKERFILE'
FROM python:3.15.2-slim-trixie
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends sipsak netcat-openbsd >/dev/null \
    && pip install -q --no-cache-dir sipvicious && rm -rf /var/lib/apt/lists/*
DOCKERFILE
docker network create "$NET" >/dev/null
docker run -d --name "$STREAM" --network "$NET" valkey/valkey:9.1-alpine3.24 >/dev/null
docker run -d --name "$NAME" --network "$NET" --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges:true --memory 128m --memory-swap 128m \
  --cpus 0.5 --pids-limit 128 -v "$NAME-data:/data" \
  -e REDIS_HOST="$STREAM" -e EVENTS_STREAM=events:sip \
  -e SENSOR_SIP_ALLOW_PRIVATE=true -e SENSOR_SIP_REPLY_PER_IP_RATE=50 -e SENSOR_SIP_REPLY_PER_IP_BURST=100 \
  "$IMG" >/dev/null
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] && break
  sleep 2
done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] || { echo "not healthy"; exit 1; }
echo HEALTHY
run() { docker run --rm -i --network "$NET" "$TOOLS" "$@"; }

echo "--- sipsak OPTIONS (-v shows the reply)"
run sipsak -vv -s "sip:100@$NAME" 2>&1 | sed -n '/reply received/,$p' | head -20
echo "--- sipsak REGISTER (expect 401), then with the weak password (expect 200)"
run sipsak -U -s "sip:100@$NAME" -u 100 -a wrongpass 2>&1 | grep -E "^SIP/2.0|failed|ok" | head -3
run sipsak -U -s "sip:100@$NAME" -u 100 -a 100 2>&1 | grep -E "^SIP/2.0|failed|ok" | head -3
echo "--- SIPVicious svmap (OPTIONS sweep)"
run sipvicious_svmap "$NAME" -p 5060 -m OPTIONS 2>&1 | tail -6
echo "--- SIPVicious svwar (extension enumeration)"
run sipvicious_svwar --force -e 100-103 -m REGISTER "$NAME" 2>&1 | tail -8
echo "--- SIPVicious svcrack (password guessing against extension 100)"
run sh -c "printf '1234\n100\nadmin\nsecret\n' > /tmp/pw.txt; sipvicious_svcrack -u 100 -d /tmp/pw.txt $NAME 2>&1 | tail -8"
echo "--- toll-fraud style INVITE"
run python - <<PY
import socket
msg = ("INVITE sip:0041791234567@$NAME SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.9:5060;branch=z9hG4bKx1\r\n"
       "From: <sip:100@$NAME>;tag=1\r\nTo: <sip:0041791234567@$NAME>\r\nCall-ID: t1@198.51.100.9\r\n"
       "CSeq: 1 INVITE\r\nContact: <sip:100@198.51.100.9:5060>\r\nMax-Forwards: 70\r\nUser-Agent: friendly-scanner\r\nContent-Length: 0\r\n\r\n")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(msg.encode(), ("$NAME", 5060)); print(s.recvfrom(2048)[0].decode().split("\r\n")[0])
PY

echo "--- nmap -sU -sV -p 5060"
docker run --rm --network "$NET" instrumentisto/nmap -Pn -sU -sV -p 5060 "$NAME" | sed -n '/^PORT/,/^Service detection/p'
echo "--- nmap -sV -p 5060 (TCP)"
docker run --rm --network "$NET" instrumentisto/nmap -Pn -sV -p 5060 "$NAME" | sed -n '/^PORT/,/^Service detection/p'
echo "--- TCP OPTIONS with nc"
run sh -c "printf 'OPTIONS sip:100@$NAME SIP/2.0\r\nVia: SIP/2.0/TCP 198.51.100.9;branch=z9hG4bK2\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:100@$NAME>\r\nCall-ID: tcp1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n' | nc -w 2 $NAME 5060 | head -3"

sleep 1
echo "--- stats line and logs"
docker logs "$NAME" 2>&1 | grep -ci "honeypot\|suckerpot\|traceback" | sed 's/^/giveaway_or_traceback_lines_in_logs=/' || true
docker stop -t 3 "$NAME" >/dev/null   # flushes the session summaries / disconnect events
sleep 1
echo "--- events by type"
docker exec "$STREAM" valkey-cli XRANGE events:sip - + | grep '^{' | \
  sed -E 's/.*"type":"([a-z_]+)".*/\1/' | sort | uniq -c
docker exec "$STREAM" valkey-cli XRANGE events:sip - + | grep -o '"flags":\[[^]]*\]' | sort | uniq -c | sort -rn | head
docker exec "$STREAM" valkey-cli XRANGE events:sip - + | grep '"login_attempt"' | head -3 | cut -c1-500
docker exec "$STREAM" valkey-cli XRANGE events:sip - + | grep '"toll_fraud"' | head -1 | cut -c1-500
docker exec "$STREAM" valkey-cli XRANGE events:sip - + | grep '"sip_summary"' | head -2 | cut -c1-500
