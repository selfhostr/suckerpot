#!/usr/bin/env bash
# Tests the broker image (redis/) against persisted data written by other versions.
# Everything runs in throwaway containers, volumes and networks named sp-brokertest-<pid>-*,
# so it cannot touch a real install. Needs Docker and the network to pull the Redis image.
#
#   upgrade-rdb      Redis 8 volume with an RDB preamble (what v0.10.0 wrote): Valkey cannot read it,
#                    the broker must still come up healthy, with the old files moved aside.
#   upgrade-aof      Redis 8 volume written without a preamble (the new default, or after
#                    CONFIG SET aof-use-rdb-preamble no): streams, group and pending entries survive.
#   corrupt          Garbage in the AOF: healthy start, files moved aside.
#   corrupt-keeps-2  Three corruptions in a row: at most 2 copies are kept.
#   truncated        A torn last write is loadable: nothing is moved aside, nothing is lost.
#   other-failure    A healthy AOF and a server that exits 1 for another reason (invalid
#                    directive): nothing is moved aside and the container keeps failing.
#   stale-rdb        A healthy AOF next to a garbage dump.rdb: normal start, both kept.
#   unreadable-aof   A good AOF the server cannot read (root, mode 000): the container fails, files stay.
#   stop-time        A clean docker stop ends with exit 0 inside the grace period (no SIGKILL).
set -euo pipefail
cd "$(dirname "$0")/.."

REDIS8_IMAGE=${REDIS8_IMAGE:-redis:8.10.3-alpine3.23@sha256:71885d8cc6e42f2bc0aa2eb853bfc4be200b5108a46ac50e117ae1df0531fb80}
P=sp-brokertest-$$
IMG=$P-image
NET=$P-net
C=$P-c
fail=0

cleanup() {
  docker rm -f "$C" "$P-old" >/dev/null 2>&1 || true
  docker volume ls -q --filter "name=$P-" | xargs -r docker volume rm >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker image rm "$IMG" >/dev/null 2>&1 || true
}
trap cleanup EXIT

VARS="REDIS_PASSWORD REDIS_HEALTH_PASSWORD REDIS_INGEST_PASSWORD REDIS_SENSOR_SSH_PASSWORD REDIS_SENSOR_RDP_PASSWORD REDIS_SENSOR_TELNET_PASSWORD REDIS_SENSOR_WEB_PASSWORD REDIS_SENSOR_REDIS_PASSWORD REDIS_SENSOR_DOCKER_PASSWORD REDIS_SENSOR_MYSQL_PASSWORD REDIS_SENSOR_MSSQL_PASSWORD REDIS_SENSOR_ADB_PASSWORD REDIS_SENSOR_SMB_PASSWORD REDIS_SENSOR_SIP_PASSWORD REDIS_SENSOR_SYNOLOGY_PASSWORD REDIS_DEMO_PASSWORD"
pw() { echo "brokertest-$1-0123456789abcdef"; }
env_args=()
for v in $VARS; do env_args+=(-e "$v=$(pw "$v")"); done

docker build -q -t "$IMG" redis >/dev/null
docker network create --internal "$NET" >/dev/null

# Starts the broker image on volume $1 (optional command in $2...) with the same hardening as docker-compose.yml.
start_broker() {
  docker rm -f "$C" >/dev/null 2>&1 || true
  docker run -d --name "$C" --network "$NET" --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --user 999:999 \
    --memory 384m --memory-swap 384m --pids-limit 64 \
    --tmpfs /run/redis:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=999,gid=999 \
    -v "$1:/data" "${env_args[@]}" "$IMG" "${@:2}" >/dev/null
}

wait_healthy() {
  for _ in $(seq 1 90); do
    case "$(docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$C")" in
      "running healthy") return 0 ;;
      exited* | dead*) return 1 ;;
    esac
    sleep 1
  done
  return 1
}

bcli() { docker exec -i -e REDISCLI_AUTH="$(pw REDIS_PASSWORD)" "$C" valkey-cli --user admin "$@"; }
ocli() { docker exec -i "$P-old" redis-cli "$@"; }

# Starts the pinned Redis 8 server (no auth, internal network only) on volume $1.
start_old() {
  docker run -d --name "$P-old" --network "$NET" --user 999:999 -v "$1:/data" "$REDIS8_IMAGE" \
    redis-server --appendonly yes --appendfsync always --save "" "${@:2}" >/dev/null
  for _ in $(seq 1 30); do ocli ping 2>/dev/null | grep -q PONG && return 0; sleep 1; done
  return 1
}

# Streams like the sensors' (XADD MAXLEN ~), a group with some entries delivered and
# some acknowledged, so that pending and last-delivered-id are non-trivial.
seed() { # cli function
  local cli=$1 i
  for i in $(seq 1 600); do
    echo "XADD events:ssh MAXLEN ~ 10000 * type login_attempt n $i"
    echo "XADD events:web MAXLEN ~ 10000 * type http_request n $i"
  done | $cli >/dev/null
  $cli XGROUP CREATE events:ssh ingest 0 >/dev/null
  $cli XGROUP CREATE events:web ingest 0 >/dev/null
  $cli XREADGROUP GROUP ingest c1 COUNT 300 STREAMS events:ssh '>' >/dev/null
  $cli XREADGROUP GROUP ingest c1 COUNT 200 STREAMS events:web '>' >/dev/null
  # shellcheck disable=SC2046
  $cli XACK events:ssh ingest $($cli XRANGE events:ssh - + COUNT 100 | grep -E '^[0-9]+-[0-9]+$') >/dev/null
}

# One line summarising what the streams and the group look like.
summary() {
  local cli=$1 s out=""
  for s in ssh web; do
    out="$out $s:len=$($cli XLEN events:$s)"
    out="$out,pending=$($cli XPENDING events:$s ingest | head -1)"
    out="$out,last=$($cli XINFO GROUPS events:$s | grep -A1 '^last-delivered-id' | tail -1)"
  done
  echo "$out"
}

aside_count() { docker exec "$C" sh -c 'ls -1d /data/*.unreadable-* 2>/dev/null | wc -l' | tr -d ' '; }

checks=0
ok() { checks=$((checks + 1)); echo "ok   $1"; }
bad() { checks=$((checks + 1)); echo "FAIL $1"; fail=1; }
check() { # description command...
  local d=$1
  shift
  if "$@"; then ok "$d"; else bad "$d"; fi
}
eq() { [ "$1" = "$2" ] || { echo "     expected: $2"; echo "     got:      $1"; return 1; }; }

new_volume() { docker volume create "$P-$1" >/dev/null; echo "$P-$1"; }

# Replaces the incremental AOF file of volume $1's running-or-stopped broker (container stopped).
corrupt_aof() { # volume
  docker run --rm -v "$1:/data" --entrypoint sh "$IMG" -c \
    'for f in /data/appendonlydir/*.incr.aof; do echo "this is not an append only file" > "$f"; done'
}

scenario_upgrade_rdb() {
  local v before
  v=$(new_volume upgrade-rdb)
  start_old "$v" --aof-use-rdb-preamble yes
  seed ocli
  ocli BGREWRITEAOF >/dev/null
  sleep 2
  ocli XADD events:ssh '*' type login_attempt n after-rewrite >/dev/null
  before=$(summary ocli)
  echo "     redis 8 before: $before"
  docker stop -t 30 "$P-old" >/dev/null && docker rm "$P-old" >/dev/null
  start_broker "$v"
  check "upgrade-rdb: broker becomes healthy" wait_healthy
  check "upgrade-rdb: old files moved aside" eq "$(aside_count)" 1
  check "upgrade-rdb: logged once" bash -c "docker logs $C 2>&1 | grep -c 'persisted data could not be loaded' | grep -qx 1"
  check "upgrade-rdb: accepts writes" bash -c "[ -n \"\$(docker exec -e REDISCLI_AUTH=$(pw REDIS_SENSOR_SSH_PASSWORD) $C valkey-cli --user sensor-ssh XADD events:ssh '*' a b)\" ]"
  docker rm -f "$C" >/dev/null
}

scenario_upgrade_aof() {
  local v before after
  v=$(new_volume upgrade-aof)
  start_old "$v" --aof-use-rdb-preamble yes
  seed ocli
  ocli CONFIG SET aof-use-rdb-preamble no >/dev/null
  ocli BGREWRITEAOF >/dev/null
  sleep 2
  ocli XADD events:ssh '*' type login_attempt n after-rewrite >/dev/null
  before=$(summary ocli)
  echo "     redis 8 before: $before"
  docker stop -t 30 "$P-old" >/dev/null && docker rm "$P-old" >/dev/null
  start_broker "$v"
  check "upgrade-aof: broker becomes healthy" wait_healthy
  after=$(summary bcli)
  echo "     valkey after:  $after"
  check "upgrade-aof: streams, group and pending identical" eq "$after" "$before"
  check "upgrade-aof: nothing moved aside" eq "$(aside_count)" 0
  docker rm -f "$C" >/dev/null
}

scenario_corrupt() {
  local v
  v=$(new_volume corrupt)
  start_broker "$v"
  wait_healthy || bad "corrupt: first start"
  seed bcli
  docker stop -t 30 "$C" >/dev/null
  corrupt_aof "$v"
  start_broker "$v"
  check "corrupt: broker becomes healthy" wait_healthy
  check "corrupt: files moved aside" eq "$(aside_count)" 1
  check "corrupt: stream buffer is empty" eq "$(bcli XLEN events:ssh)" 0
  # Restart on the repaired (empty) volume: nothing more to move.
  docker stop -t 30 "$C" >/dev/null
  start_broker "$v"
  check "corrupt: restart is healthy" wait_healthy
  check "corrupt: still one copy" eq "$(aside_count)" 1
  docker rm -f "$C" >/dev/null
}

scenario_corrupt_keeps_2() {
  local v n
  v=$(new_volume keep2)
  for n in 1 2 3; do
    start_broker "$v"
    wait_healthy || bad "corrupt-keeps-2: start $n"
    bcli XADD events:ssh '*' type login_attempt n "$n" >/dev/null
    docker stop -t 30 "$C" >/dev/null
    corrupt_aof "$v"
    sleep 1 # distinct timestamps
  done
  start_broker "$v"
  check "corrupt-keeps-2: broker becomes healthy" wait_healthy
  check "corrupt-keeps-2: at most 2 copies of the AOF directory" \
    eq "$(docker exec "$C" sh -c 'ls -1d /data/appendonlydir.unreadable-* | wc -l' | tr -d ' ')" 2
  docker rm -f "$C" >/dev/null
}

scenario_truncated() {
  local v
  v=$(new_volume truncated)
  start_broker "$v"
  wait_healthy || bad "truncated: first start"
  seed bcli
  docker kill "$C" >/dev/null
  # A torn last write: the last few bytes of the incremental file are missing.
  docker run --rm -v "$v:/data" --entrypoint sh "$IMG" -c \
    'for f in /data/appendonlydir/*.incr.aof; do s=$(wc -c < "$f"); truncate -s $((s - 5)) "$f"; done'
  start_broker "$v"
  check "truncated: broker becomes healthy" wait_healthy
  check "truncated: nothing moved aside" eq "$(aside_count)" 0
  # Only the torn last write (an XACK) may be missing: both streams are complete.
  check "truncated: streams complete" eq "$(bcli XLEN events:ssh) $(bcli XLEN events:web)" "600 600"
  docker rm -f "$C" >/dev/null
}

scenario_other_failure() {
  local v
  v=$(new_volume other)
  start_broker "$v"
  wait_healthy || bad "other-failure: first start"
  seed bcli
  docker stop -t 30 "$C" >/dev/null
  start_broker "$v" valkey-server /etc/redis/redis.conf --not-a-directive 1
  for _ in $(seq 1 60); do
    [ "$(docker inspect -f '{{.State.Status}}' "$C")" = exited ] && break
    sleep 1
  done
  check "other-failure: container exits with 1" eq "$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$C")" "exited 1"
  check "other-failure: reports that the data was left untouched" bash -c "docker logs $C 2>&1 | grep -q 'persisted data was left untouched'"
  check "other-failure: nothing moved aside" eq "$(docker run --rm -v "$v:/data" --entrypoint sh "$IMG" -c 'ls -1d /data/*.unreadable-* 2>/dev/null | wc -l' | tr -d ' ')" 0
  start_broker "$v"
  check "other-failure: healthy afterwards" wait_healthy
  check "other-failure: streams intact" eq "$(bcli XLEN events:ssh) $(bcli XLEN events:web) $(bcli XPENDING events:ssh ingest | head -1)" "600 600 200"
  docker rm -f "$C" >/dev/null
}

scenario_stale_rdb() {
  local v
  v=$(new_volume stale)
  start_broker "$v"
  wait_healthy || bad "stale-rdb: first start"
  seed bcli
  docker stop -t 30 "$C" >/dev/null
  docker run --rm -v "$v:/data" --entrypoint sh "$IMG" -c 'echo "not an rdb file" > /data/dump.rdb && chmod 644 /data/dump.rdb'
  start_broker "$v"
  check "stale-rdb: broker becomes healthy" wait_healthy
  check "stale-rdb: nothing moved aside" eq "$(aside_count)" 0
  check "stale-rdb: dump.rdb kept" docker exec "$C" test -f /data/dump.rdb
  check "stale-rdb: streams intact" eq "$(bcli XLEN events:ssh) $(bcli XLEN events:web) $(bcli XPENDING events:ssh ingest | head -1)" "600 600 200"
  docker rm -f "$C" >/dev/null
}

scenario_stop_time() {
  local v t0 t
  v=$(new_volume stop)
  start_broker "$v"
  wait_healthy || bad "stop-time: first start"
  t0=$(date +%s)
  docker stop -t 30 "$C" >/dev/null
  t=$(($(date +%s) - t0))
  echo "     docker stop took ${t}s"
  # The elapsed time is informational (a busy Docker daemon adds seconds of its own): the check is
  # that the stop was a clean shutdown, not a SIGKILL after the grace period (that exits 137).
  check "stop-time: not killed after the grace period" test "$t" -lt 30
  check "stop-time: exit status 0" eq "$(docker inspect -f '{{.State.ExitCode}}' "$C")" 0
  docker rm -f "$C" >/dev/null
}

scenario_unreadable_aof() {
  local v
  v=$(new_volume unreadable)
  start_broker "$v"
  wait_healthy || bad "unreadable-aof: first start"
  seed bcli
  docker stop -t 30 "$C" >/dev/null
  # A good AOF that the server's user cannot read (restored as root, mode 000).
  # With appendonly yes a dump.rdb is never loaded, so the AOF is the file that matters.
  docker run --rm --user 0:0 -v "$v:/data" --entrypoint sh "$IMG" -c \
    'chown 0:0 /data/appendonlydir/*.incr.aof && chmod 000 /data/appendonlydir/*.incr.aof'
  start_broker "$v"
  for _ in $(seq 1 60); do
    [ "$(docker inspect -f '{{.State.Status}}' "$C")" = exited ] && break
    sleep 1
  done
  check "unreadable-aof: container fails" eq "$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$C")" "exited 1"
  check "unreadable-aof: says what to check" bash -c "docker logs $C 2>&1 | grep -q 'unreadable by this user'"
  check "unreadable-aof: files kept under their own name, no copy" \
    eq "$(docker run --rm -v "$v:/data" --entrypoint sh "$IMG" -c 'ls -A /data')" "appendonlydir"
  docker rm -f "$C" >/dev/null
}

selected=${1:-all}
for s in upgrade_rdb upgrade_aof corrupt corrupt_keeps_2 truncated other_failure stale_rdb unreadable_aof stop_time; do
  if [ "$selected" = all ] || [ "$selected" = "${s//_/-}" ]; then
    echo "== ${s//_/-}"
    "scenario_$s"
  fi
done

echo "$checks checks run"
min=1; [ "$selected" = all ] && min=30
if [ "$checks" -lt "$min" ]; then echo "FAIL: expected at least $min checks (unknown scenario name?)"; fail=1; fi
exit "$fail"
