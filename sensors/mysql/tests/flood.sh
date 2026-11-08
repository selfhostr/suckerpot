#!/bin/sh
# Flood test: 20 source addresses (throwaway containers) abuse the sensor for ~75 s while the
# container's memory and CPU are sampled. Usage (repo root):
#   sg docker -c "sh sensors/mysql/tests/flood.sh"
set -eu
cd "$(dirname "$0")/../../.."
NET=sp-mysql-fl; NAME=sp-mysql-fl; IMG=sp-mysql-bb:dev; REDIS=sp-mysql-fl-redis; SECS=${SECS:-75}; PER=${PER:-5}
cleanup() {
  docker ps -aq --filter "label=sp-mysql-fl" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker rm -f "$NAME" "$REDIS" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$NAME-data" >/dev/null 2>&1 || true
}
trap cleanup EXIT; cleanup
docker build -q -f sensors/mysql/Dockerfile -t "$IMG" . >/dev/null
docker network create "$NET" >/dev/null
docker run -d --name "$REDIS" --network "$NET" valkey/valkey:9.1-alpine3.24 >/dev/null
docker run -d --name "$NAME" --network "$NET" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true --memory 256m --memory-swap 256m --cpus 0.5 --pids-limit 128 \
  -v "$NAME-data:/data" -e REDIS_HOST="$REDIS" -e EVENTS_STREAM=events:mysql \
  -e SENSOR_MAX_PER_IP=8 "$IMG" >/dev/null
sleep 6
for mode in stall noread slow brute; do
  for n in $(seq 1 "$PER"); do
    docker run -d --label sp-mysql-fl --name "sp-mysql-fl-$mode-$n" --network "$NET" \
      -v "$PWD/sensors/mysql/tests/flood.py:/flood.py:ro" python:3.15-slim-trixie \
      sh -c "pip install -q pymysql cryptography >/dev/null 2>&1; python /flood.py $NAME $mode $SECS" >/dev/null
  done
done
# Expensive statements: 3 more sources, 8 connections each, 50 full-scan statements per query.
for n in 1 2 3; do
  docker run -d --label sp-mysql-fl --name "sp-mysql-fl-scan-$n" --network "$NET" \
    -v "$PWD/sensors/mysql/tests/scanclient.py:/scanclient.py:ro" python:3.15-slim-trixie \
    python /scanclient.py "$NAME" 3306 0.0.0.0 8 "$SECS" >/dev/null
done
peak=0
i=0
while [ $i -lt $((SECS / 5 + 4)) ]; do
  sleep 5; i=$((i + 1))
  t0=$(date +%s%N); hc=ok; docker exec "$NAME" python -m mysql_sensor.healthcheck >/dev/null 2>&1 || hc=FAILED
  echo "healthcheck=$hc in $(( ($(date +%s%N) - t0) / 1000000 )) ms"
  line=$(docker stats --no-stream --format '{{.MemUsage}} {{.CPUPerc}} {{.PIDs}}' "$NAME")
  mem=$(echo "$line" | sed -E 's/^([0-9.]+)MiB.*/\1/')
  echo "t=$((i * 5))s $line conns=$(docker logs "$NAME" 2>&1 | grep -oE 'connections\\?": [0-9]+' | tail -1)"
  peak=$(echo "$peak $mem" | awk '{print ($2 > $1) ? $2 : $1}')
done
echo "peak_memory_mib=$peak (limit 256)"
docker inspect -f 'oom_killed={{.State.OOMKilled}} restarts={{.RestartCount}} health={{.State.Health.Status}}' "$NAME"
docker logs "$NAME" 2>&1 | grep -ci "traceback" | sed 's/^/traceback_lines=/' || true
docker logs "$NAME" 2>&1 | tail -2 | cut -c1-400
