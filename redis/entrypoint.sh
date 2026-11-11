#!/bin/sh
# Generates the Redis ACL file from environment variables, then execs the server.
# The file goes to a tmpfs (/run/redis), mode 0600, and stores SHA-256 hashes
# instead of clear-text passwords. Secrets are never put on a command line or logged.
set -eu
umask 077

ACL_FILE=/run/redis/users.acl

ALLOW_DEFAULT=${SUCKERPOT_ALLOW_DEFAULT_SECRETS:-0}

check() {
  name=$1
  eval "value=\${$name:-}"
  if [ -z "$value" ]; then
    echo "FATAL: $name is empty or unset" >&2
    exit 1
  fi
  if [ "$ALLOW_DEFAULT" != "1" ] && [ "${#value}" -lt 24 ]; then
    echo "FATAL: $name must be at least 24 characters (generate one with: openssl rand -base64 32)" >&2
    exit 1
  fi
}

distinct() {
  # Compares two secrets without printing them.
  if [ "$ALLOW_DEFAULT" != "1" ] && [ "$(eval "printf %s \"\$$1\"")" = "$(eval "printf %s \"\$$2\"")" ]; then
    echo "FATAL: $1 and $2 must be different" >&2
    exit 1
  fi
}

hash() {
  printf '%s' "$1" | sha256sum | cut -d' ' -f1
}

VARS="REDIS_PASSWORD REDIS_HEALTH_PASSWORD REDIS_INGEST_PASSWORD REDIS_SENSOR_SSH_PASSWORD REDIS_SENSOR_RDP_PASSWORD REDIS_SENSOR_TELNET_PASSWORD REDIS_SENSOR_WEB_PASSWORD REDIS_SENSOR_REDIS_PASSWORD REDIS_SENSOR_DOCKER_PASSWORD REDIS_SENSOR_MYSQL_PASSWORD REDIS_SENSOR_MSSQL_PASSWORD REDIS_SENSOR_ADB_PASSWORD REDIS_SENSOR_SMB_PASSWORD REDIS_SENSOR_SIP_PASSWORD REDIS_SENSOR_SYNOLOGY_PASSWORD REDIS_DEMO_PASSWORD"
for v in $VARS; do
  check "$v"
done
# Pairwise distinct (each pair is compared once).
for a in $VARS; do
  for b in $VARS; do
    if [ "$a" \< "$b" ]; then distinct "$a" "$b"; fi
  done
done

h() { hash "$(eval "printf %s \"\$$1\"")"; }

# One user per sensor: it may only append to its own stream.
cat > "$ACL_FILE" <<ACL
user default off
user admin on #$(h REDIS_PASSWORD) ~* &* +@all
user health on #$(h REDIS_HEALTH_PASSWORD) resetkeys -@all +ping +hello +auth
user sensor-ssh on #$(h REDIS_SENSOR_SSH_PASSWORD) resetkeys ~events:ssh -@all +xadd +hello +auth
user sensor-rdp on #$(h REDIS_SENSOR_RDP_PASSWORD) resetkeys ~events:rdp -@all +xadd +hello +auth
user sensor-telnet on #$(h REDIS_SENSOR_TELNET_PASSWORD) resetkeys ~events:telnet -@all +xadd +hello +auth
user sensor-web on #$(h REDIS_SENSOR_WEB_PASSWORD) resetkeys ~events:web -@all +xadd +hello +auth
user sensor-redis on #$(h REDIS_SENSOR_REDIS_PASSWORD) resetkeys ~events:redis -@all +xadd +hello +auth
user sensor-docker on #$(h REDIS_SENSOR_DOCKER_PASSWORD) resetkeys ~events:docker -@all +xadd +hello +auth
user sensor-mysql on #$(h REDIS_SENSOR_MYSQL_PASSWORD) resetkeys ~events:mysql -@all +xadd +hello +auth
user sensor-mssql on #$(h REDIS_SENSOR_MSSQL_PASSWORD) resetkeys ~events:mssql -@all +xadd +hello +auth
user sensor-adb on #$(h REDIS_SENSOR_ADB_PASSWORD) resetkeys ~events:adb -@all +xadd +hello +auth
user sensor-smb on #$(h REDIS_SENSOR_SMB_PASSWORD) resetkeys ~events:smb -@all +xadd +hello +auth
user sensor-sip on #$(h REDIS_SENSOR_SIP_PASSWORD) resetkeys ~events:sip -@all +xadd +hello +auth
user sensor-synology on #$(h REDIS_SENSOR_SYNOLOGY_PASSWORD) resetkeys ~events:synology -@all +xadd +hello +auth
user demo on #$(h REDIS_DEMO_PASSWORD) resetkeys ~events:* -@all +xadd +hello +auth
user ingest on #$(h REDIS_INGEST_PASSWORD) resetkeys ~events:* -@all +xreadgroup +xack +xgroup|create +xautoclaim +xtrim +hello +auth (~events:parked +xadd)
ACL
chmod 0600 "$ACL_FILE"

# Do not leak secrets to the server process environment beyond what it needs.
unset $VARS

# Memory cap (MiB). The low-memory overlay lowers it; command-line options win over redis.conf.
MAXMEMORY_MB=${REDIS_MAXMEMORY_MB:-192}
case $MAXMEMORY_MB in
  '' | *[!0-9]*) echo "FATAL: REDIS_MAXMEMORY_MB must be a whole number of MiB" >&2; exit 1 ;;
esac
if [ "$MAXMEMORY_MB" -lt 32 ] || [ "$MAXMEMORY_MB" -gt 4096 ]; then
  echo "FATAL: REDIS_MAXMEMORY_MB must be between 32 and 4096" >&2
  exit 1
fi

set -- "$@" --maxmemory "${MAXMEMORY_MB}mb"

# --- Start the server, with a safety net for unreadable persisted data ----------
# The stream is only a buffer in front of the database: losing the few seconds of
# events not yet consumed is far cheaper than a broker that crash-loops, because
# then every sensor drops every event for as long as it lasts. So when the server
# cannot load /data (for example an RDB written by a newer or different engine),
# the files are moved aside and the server starts empty.
#
# Conservative on purpose, data the server can load is never touched. All of
# these must hold: the server exited with status 1 within STARTUP_WINDOW seconds,
# it did so twice in a row (rules out a transient fault), its own output contains
# a data-load failure message (a config or ACL error never matches), and the
# bundled valkey-check-aof / valkey-check-rdb tool also rejects the files the
# server actually loads: the AOF directory when there is one (appendonly yes),
# dump.rdb only when there is no AOF directory at all.
DATA_DIR=/data
AOF_DIR=$DATA_DIR/appendonlydir
RDB_FILE=$DATA_DIR/dump.rdb
SERVER_LOG=/run/redis/server.log
SERVER_FIFO=/run/redis/server.fifo
LOG_LINES=300
STARTUP_WINDOW=30
KEEP_UNREADABLE=2

# Messages the server prints when it gives up loading persisted data:
#   Can't handle RDB format version N               RDB from a newer or different engine
#   Error reading the RDB base file                 the AOF base file is an unreadable RDB
#   Bad file format reading the append only file    garbage in the AOF
#   Unexpected end of file reading the append only file / Unrecoverable error reading
#   Wrong signature trying to load DB from file     dump.rdb is not an RDB
#   Short read or OOM loading DB / Fatal error loading the DB / Error loading the RDB
#   Invalid AOF manifest / Failed loading the AOF manifest   damaged manifest
LOAD_FAILURE='Can.t handle RDB format version|Error reading the RDB base file|Bad file format reading the append only file|Unexpected end of file reading the append only file|Unrecoverable error reading the append only file|Wrong signature trying to load DB from file|Short read or OOM loading DB|Fatal error loading the DB|Error loading the RDB|Invalid AOF manifest|Failed loading the AOF manifest'

log() { echo "suckerpot-redis: $*" >&2; }

pid=
stopping=
trap 'stopping=1; if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || true; fi' TERM INT

# Runs the server in the background (so that a signal reaches it through the trap)
# and sets rc to its exit status. Its output goes through a fifo to awk, which
# prints it unchanged and keeps the first LOG_LINES lines in SERVER_LOG (on the
# tmpfs, truncated at each start), so a long-running server cannot fill it.
run_server() {
  rc=0
  if [ -n "$stopping" ]; then return; fi
  rm -f "$SERVER_FIFO"
  mkfifo "$SERVER_FIFO"
  : > "$SERVER_LOG"
  awk -v f="$SERVER_LOG" -v max="$LOG_LINES" '{ print; fflush(); if (n < max) { n++; print > f; fflush(f) } }' < "$SERVER_FIFO" &
  logger_pid=$!
  "$@" > "$SERVER_FIFO" 2>&1 &
  pid=$!
  # A TERM that arrived before the pid was known was not forwarded.
  if [ -n "$stopping" ]; then kill -TERM "$pid" 2>/dev/null || true; fi
  wait "$pid" || rc=$?
  # A trapped signal interrupts wait before the server is gone: wait for the real status.
  while kill -0 "$pid" 2>/dev/null; do
    wait "$pid" || rc=$?
  done
  pid=
  wait "$logger_pid" 2>/dev/null || true
  rm -f "$SERVER_FIFO"
}

has_persisted_data() {
  [ -e "$AOF_DIR" ] || [ -e "$RDB_FILE" ]
}

# True when every file the server loads can be read by the current user: a good
# file that is merely unreadable (restored as root, an I/O error) must never be
# mistaken for a damaged one.
persisted_data_is_readable() {
  if [ -d "$AOF_DIR" ]; then
    [ -r "$AOF_DIR" ] && [ -x "$AOF_DIR" ] || return 1
    for file in "$AOF_DIR"/*; do
      if [ -e "$file" ] && [ ! -r "$file" ]; then return 1; fi
    done
  elif [ -e "$RDB_FILE" ]; then
    [ -r "$RDB_FILE" ] || return 1
  fi
  return 0
}

# Succeeds only when the server's output reports a load failure that is not a
# permission or I/O problem, the files are readable, and the check tool rejects
# the file set the server loads.
persisted_data_is_unreadable() {
  grep -Eq "$LOAD_FAILURE" "$SERVER_LOG" || return 1
  if grep -Eq 'Permission denied|Input/output error' "$SERVER_LOG"; then return 1; fi
  persisted_data_is_readable || return 1
  if [ -d "$AOF_DIR" ]; then
    ! valkey-check-aof "$AOF_DIR/appendonly.aof.manifest" >/dev/null 2>&1
  else
    ! valkey-check-rdb "$RDB_FILE" >/dev/null 2>&1
  fi
}

# Keeps only the newest KEEP_UNREADABLE copies of "$1.unreadable-*" (the UTC
# timestamp suffix makes the glob come out oldest first), so the volume cannot
# fill up. Only paths directly under the data directory are ever removed.
prune_unreadable() {
  total=0
  for old in "$1".unreadable-*; do
    if [ -e "$old" ]; then total=$((total + 1)); fi
  done
  excess=$((total - KEEP_UNREADABLE))
  for old in "$1".unreadable-*; do
    if [ "$excess" -le 0 ]; then break; fi
    case $old in
      "$DATA_DIR"/*.unreadable-*) rm -rf -- "$old"; excess=$((excess - 1)) ;;
    esac
  done
}

# Moves aside the file set the server loads (the AOF directory, else dump.rdb).
move_aside() {
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  if [ -d "$AOF_DIR" ]; then f=$AOF_DIR; else f=$RDB_FILE; fi
  mv "$f" "$f.unreadable-$stamp"
  prune_unreadable "$f"
  log "persisted data could not be loaded: moved to $(basename "$f").unreadable-$stamp in $DATA_DIR, starting with an empty stream buffer"
}

attempt=0
moved=
while :; do
  attempt=$((attempt + 1))
  started=$(date +%s)
  run_server "$@"
  if [ -n "$stopping" ]; then exit 0; fi
  elapsed=$(($(date +%s) - started))
  # Not a start-up failure (it ran for a while, or was killed): the restart policy decides.
  if [ "$rc" -ne 1 ] || [ "$elapsed" -ge "$STARTUP_WINDOW" ]; then exit "$rc"; fi
  if [ -n "$moved" ] || ! has_persisted_data; then exit "$rc"; fi
  if [ "$attempt" -lt 2 ]; then
    log "server failed to start, trying once more before touching the persisted data"
    continue
  fi
  if persisted_data_is_unreadable; then
    move_aside
    moved=1
    continue
  fi
  log "server failed to start and the persisted data was left untouched: either the failure is not a data-load error, or the data is unreadable by this user (check ownership and mode of the files in $DATA_DIR) or hit an I/O error"
  exit "$rc"
done
