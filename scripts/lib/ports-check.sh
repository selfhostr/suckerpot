#!/usr/bin/env bash
# shellcheck disable=SC2016 # dc exec ... sh -c '...': expanded by the shell inside the container
# Port reachability check, sourced by scripts/participant.sh and scripts/install.sh. Defines
# functions and constants only; it runs nothing. Needs scripts/lib/env.sh (ports_table, env_get).
#
# It makes NO network connection of any kind: no port-check website, no address lookup, no
# request to the hub, no connection to this machine's own public address. The only evidence is
# local: sensor ports on the internet are scanned within minutes, so a session from a public
# source address that reached a sensor proves the router forwards that port. The DB is read
# with a read-only `docker compose exec -T db psql`, and the addresses are filtered inside the
# ingest container. Source addresses are never printed, only counts per sensor.

# Prints the SQL: one "sensor address" row per distinct source of the sessions started since $1
# (a validated timestamp). Which addresses are public is decided by ports_check_filter.py.
ports_check_sql() {
  printf "BEGIN READ ONLY;\nSELECT DISTINCT sensor, host(src_ip) FROM sessions WHERE started_at >= '%s'::timestamptz LIMIT 50000;\nCOMMIT;\n" "$1"
}

# True when $1 looks like an ISO timestamp (nothing else ever reaches the SQL).
ports_check_valid_ts() {
  [[ $1 =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}([T\ ][0-9]{2}:[0-9]{2}(:[0-9]{2}(\.[0-9]+)?)?)?(Z|[+-][0-9]{2}(:?[0-9]{2})?)?$ ]]
}

# Prints "sensor count" lines (count = distinct public source addresses) since $1. The database
# is read-only; the filter runs inside the ingest container (standard library only) and prints
# no address. Fails when the database or the filter cannot run.
ports_check_counts() {
  local src
  src=$(cat scripts/lib/ports_check_filter.py) || return 1
  # Read-only twice: the session default (PGOPTIONS, passed with -e: exec does not forward the
  # caller's environment) and an explicit READ ONLY transaction in the SQL itself.
  ports_check_sql "$1" | dc exec -T -e PGOPTIONS='-c default_transaction_read_only=on' db sh -c \
    'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -X -q -At -F " " -v ON_ERROR_STOP=1 -f -' 2> /dev/null \
    | dc exec -T ingest python -I -c "$src" 2> /dev/null
}

# Prints "HOSTPORT SENSOR" lines of the published sensor ports that nothing listens on here.
# Prints nothing when `ss` is not available. Only a warning: it never decides the verdict.
ports_check_not_listening() {
  local listening rp hp proto sname p
  command -v ss > /dev/null 2>&1 || return 0
  listening=$(ss -H -ltnu 2> /dev/null | awk '{ n = split($5, a, ":"); print tolower($1) " " a[n] }') || return 0
  while read -r rp hp proto sname; do
    [ -n "${hp:-}" ] || continue
    for p in $(printf %s "$proto" | tr 'A-Z/' 'a-z '); do
      printf '%s\n' "$listening" | grep -qx "$p $hp" || printf '%s %s\n' "$hp" "$sname"
    done
  done < <(ports_table) | sort -u
}

# ports_check_run WAIT SINCE: the whole check. Prints the report and returns 0 (the internet
# reached at least one sensor), 3 (nothing yet) or 2 (the database could not be read).
ports_check_run() {
  local wait=$1 since=$2 interval=${PORTS_CHECK_INTERVAL:-10} left rows="" rc=0
  [[ $interval =~ ^[0-9]{1,4}$ ]] && [ "$interval" -ge 1 ] || interval=10
  declare -A got=()
  local reached=0 bad rp hp proto sname count status

  bad=$(ports_check_not_listening)
  if [ -n "$bad" ]; then
    echo "These sensor ports are not listening on this machine (is the stack running? ./scripts/status.sh):"
    while read -r hp sname; do echo "  port $hp ($sname)"; done <<< "$bad"
    echo
  fi

  echo "Looking for connections from the internet since $since (no connection is made from here)."
  left=$wait
  while :; do
    if rows=$(ports_check_counts "$since"); then
      got=()
      reached=0
      while read -r sname count; do
        [ -n "${count:-}" ] || continue
        got[$sname]=$count
        reached=1
      done <<< "$rows"
    else
      echo "Could not read the database: is the stack running? (./scripts/status.sh)" >&2
      return 2
    fi
    [ "$reached" = 0 ] || break
    [ "$left" -gt 0 ] || break
    if [ -t 1 ]; then printf '\r  waiting for a first connection... %3ss left ' "$left"; fi
    sleep "$interval"
    left=$((left - interval))
  done
  if [ -t 1 ] && [ "$wait" -gt 0 ]; then printf '\r%60s\r' ''; fi

  printf '  %-12s  %-12s  %-9s  %-9s  %s\n' "Router port" "This machine" "Protocol" "Sensor" "Status"
  while read -r rp hp proto sname; do
    [ -n "${rp:-}" ] || continue
    if [ -n "${got[$sname]:-}" ]; then status="reached from the internet (${got[$sname]})"; else status="no traffic yet"; fi
    printf '  %-12s  %-12s  %-9s  %-9s  %s\n' "$rp" "$hp" "$proto" "$sname" "$status"
  done < <(ports_table)
  echo
  if [ "$reached" = 1 ]; then
    echo "Ports are open: the internet reaches this machine."
    echo "Services that bots rarely scan (for example SIP or MSSQL) can stay quiet for hours: that is normal."
  else
    echo "WARNING: No connection from the internet has reached your sensors yet."
    echo "Your router probably does not forward the ports yet (or you set up a DMZ that is not active)."
    echo "Forward the ports of the table above to this machine, then check again: ./scripts/participant.sh ports-check"
    rc=3
  fi
  return "$rc"
}

# ports_check_cli [--wait SECONDS] [--since ISO | --since-install]: the command itself.
# Usage errors go to stderr and return 64.
ports_check_cli() {
  local wait=180 since=""
  while [ $# -gt 0 ]; do
    case $1 in
      --wait)
        if [ $# -lt 2 ] || ! [[ $2 =~ ^[0-9]{1,5}$ ]]; then echo "ports-check: --wait needs a number of seconds" >&2; return 64; fi
        wait=$2
        shift
        ;;
      --since)
        if [ $# -lt 2 ] || ! ports_check_valid_ts "$2"; then echo "ports-check: --since needs an ISO date such as 2026-11-04T10:00:00Z" >&2; return 64; fi
        since=$2
        shift
        ;;
      --since-install)
        since=$(head -n 1 install.log 2> /dev/null | awk '{ print $1 }')
        ports_check_valid_ts "${since:-x}" || since=""
        if [ -z "$since" ]; then echo "ports-check: install time unknown, using the last 24 hours" >&2; fi
        ;;
      *) echo "usage: ports-check [--wait SECONDS] [--since ISO | --since-install]" >&2; return 64 ;;
    esac
    shift
  done
  [ -n "$since" ] || since=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)
  ports_check_run "$wait" "$since"
}
