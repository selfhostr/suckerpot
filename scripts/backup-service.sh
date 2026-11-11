#!/bin/sh
# Entry point of the `backup` compose service (runs inside the timescaledb image, as uid 70).
#
#   backup-service.sh          loop: dump when the newest dump is older than 24 h, check hourly
#   backup-service.sh now      dump once, right now, then exit (used by `just backup`)
#   backup-service.sh now preswitch
#                              same for the switch from participant to full mode (install.sh
#                              --full): suckerpot-preswitch-<ts>.dump, the newest PREKEEP are kept
#   backup-service.sh now preupdate
#                              same, but the file is named suckerpot-preupdate-<ts>.dump and is
#                              protected from the normal retention (the newest PREKEEP, default 2,
#                              are kept): `just update` takes it so `just rollback` always has it
#
# Dumps are custom-format pg_dump files (TimescaleDB data included) in /backups, mode 0600.
# Retention: the newest BACKUP_KEEP dumps (default 7), plus the newest dump of each of the last
# 4 weeks and 3 months. A dump that is smaller than half of the previous one is stored, but
# NOTHING is pruned and the service turns unhealthy (marker /backups/.shrunk) until you look at
# it and remove the marker. The owner credentials come from the environment and are never
# printed. A failed dump is logged and retried after 30 s, then 60 s, 120 s and so on (never more
# than an hour), so a database that is slow to start does not leave the service without a dump;
# after a success the check goes back to hourly. The healthcheck needs a dump younger than 26 hours.
set -eu

DIR=/backups
KEEP=${BACKUP_KEEP:-7}
WEEKS=4
MONTHS=3
LOCK=/tmp/backup.lock
PREKEEP=${BACKUP_PREUPDATE_KEEP:-2}
case $KEEP in '' | *[!0-9]* | 0) echo "backup: BACKUP_KEEP must be a positive number" >&2; exit 2 ;; esac
umask 077

# Regular dumps only (suckerpot-<digits>T<digits>Z.dump): the pre-update dumps follow their own rule.
list() { ls -1 "$DIR"/suckerpot-[0-9]*.dump 2>/dev/null | sort -r || true; }
list_pre() { ls -1 "$DIR"/suckerpot-"${1:-preupdate}"-*.dump 2>/dev/null | sort -r || true; }
prune_pre() {
  n=0
  for f in $(list_pre "${1:-preupdate}"); do
    n=$((n + 1))
    if [ "$n" -gt "$PREKEEP" ]; then
      rm -f -- "$f"
      echo "backup: removed old pre-update dump ${f##*/}"
    fi
  done
}
newest() { list | head -n 1; }
size() { stat -c %s "$1"; }

# Timestamp part of a dump name: suckerpot-20261101T020000Z.dump -> 20261101
day_of() { b=${1##*/}; b=${b#suckerpot-}; printf %s "${b%%T*}"; }
week_of() {
  d=$(day_of "$1")
  s=$(date -u -d "$(printf %s "$d" | cut -c1-4)-$(printf %s "$d" | cut -c5-6)-$(printf %s "$d" | cut -c7-8) 00:00:00" +%s)
  echo $((s / 604800))
}

# Deletes every dump outside the retention set. $1 = number of daily dumps to keep.
prune() {
  daily=$1
  n=0
  seen_weeks=" "
  seen_months=" "
  wcount=0
  mcount=0
  for f in $(list); do
    n=$((n + 1))
    if [ "$n" -le "$daily" ]; then continue; fi
    wk=$(week_of "$f")
    mon=$(day_of "$f" | cut -c1-6)
    keep=0
    case $seen_weeks in *" $wk "*) ;; *) if [ "$wcount" -lt "$WEEKS" ]; then keep=1; seen_weeks="$seen_weeks$wk "; wcount=$((wcount + 1)); fi ;; esac
    case $seen_months in *" $mon "*) ;; *) if [ "$mcount" -lt "$MONTHS" ]; then keep=1; seen_months="$seen_months$mon "; mcount=$((mcount + 1)); fi ;; esac
    if [ "$keep" -eq 0 ]; then
      rm -f -- "$f"
      echo "backup: removed old dump ${f##*/}"
    fi
  done
}

free_bytes() { echo $(($(df -Pk "$DIR" | awk 'NR==2 {print $4}') * 1024)); }

# Headroom: 2x the last dump plus 2 GiB. When tight, drop to KEEP-1 daily dumps first.
make_room() {
  last=$(newest)
  need=$((2 * 1024 * 1024 * 1024))
  if [ -n "$last" ]; then need=$((need + $(size "$last") * 2)); fi
  if [ "$(free_bytes)" -ge "$need" ]; then return 0; fi
  if [ "$KEEP" -gt 1 ]; then
    echo "backup: low disk space, pruning to $((KEEP - 1)) daily dumps" >&2
    prune $((KEEP - 1))
  fi
  if [ "$(free_bytes)" -lt "$need" ]; then
    echo "backup: not enough free space in $DIR (free $(free_bytes) bytes, need $need)" >&2
    return 1
  fi
}

dump() {
  kind=${1:-regular}
  if [ "$kind" = preupdate ] || [ "$kind" = preswitch ]; then
    name="suckerpot-$kind-$(date -u +%Y%m%dT%H%M%SZ).dump"
  else
    name="suckerpot-$(date -u +%Y%m%dT%H%M%SZ).dump"
  fi
  tmp="$DIR/.$name.partial"
  make_room || return 1
  if ! PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" \
    -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc > "$tmp"; then
    rm -f "$tmp"
    echo "backup: pg_dump failed" >&2
    return 1
  fi
  if [ ! -s "$tmp" ]; then
    rm -f "$tmp"
    echo "backup: the dump is empty" >&2
    return 1
  fi
  # Compare with the newest previous dump, not the largest kept one: after an intended shrink the
  # next dump matches the new size again, and old large dumps age out normally.
  previous=0
  last=$(newest)
  if [ -n "$last" ]; then previous=$(size "$last"); fi
  if ! mv "$tmp" "$DIR/$name"; then
    rm -f "$tmp"
    echo "backup: could not move the dump into place" >&2
    return 1
  fi
  new=$(size "$DIR/$name")
  echo "backup: wrote $name ($new bytes)"
  if [ "$kind" = preupdate ] || [ "$kind" = preswitch ]; then
    prune_pre "$kind"
    return 0
  fi
  if [ "$((new * 2))" -lt "$previous" ]; then
    : > "$DIR/.shrunk"
    echo "backup: WARNING the new dump is under half of the previous one ($previous bytes): nothing pruned, marker $DIR/.shrunk set (remove it once checked)" >&2
    return 0
  fi
  prune "$KEEP"
}

# One writer at a time (the loop and `just backup` share this container's /tmp).
locked() {
  if mkdir "$LOCK" 2> /dev/null; then
    echo $$ > "$LOCK/pid"
    return 0
  fi
  other=$(cat "$LOCK/pid" 2> /dev/null || true)
  if [ -n "$other" ] && kill -0 "$other" 2> /dev/null; then return 1; fi
  rm -rf "$LOCK"
  mkdir "$LOCK" 2> /dev/null || return 1
  echo $$ > "$LOCK/pid"
}
unlock() { rm -rf "$LOCK"; }

locked_dump() {
  if ! locked; then
    echo "backup: another backup is running" >&2
    return 1
  fi
  rc=0
  dump "${1:-regular}" || rc=$?
  unlock
  return "$rc"
}

if [ "${1:-}" = "now" ]; then
  case ${2:-} in '' | preupdate | preswitch) ;; *) echo "backup: unknown option ${2}" >&2; exit 2 ;; esac
  locked_dump "${2:-regular}"
  exit $?
fi

if locked; then
  rm -f "$DIR"/.suckerpot-*.partial
  unlock
fi

# Check hourly. After a failed dump retry sooner: 30 s, doubled each time, capped at the hour.
delay=30
while true; do
  pause=3600
  if [ -n "$(find "$DIR" -maxdepth 1 -name 'suckerpot-*.dump' -mmin -1440 2> /dev/null | head -n 1)" ]; then
    delay=30
  elif locked_dump; then
    delay=30
  else
    pause=$delay
    delay=$((delay * 2))
    if [ "$delay" -gt 3600 ]; then delay=3600; fi
  fi
  sleep "$pause"
done
