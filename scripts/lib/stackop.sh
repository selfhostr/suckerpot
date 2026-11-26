#!/usr/bin/env bash
# Changes to the running stack that must survive a slow machine and a Ctrl-C (participant.sh,
# edit.sh, update.sh, install.sh). Sourced after scripts/lib/env.sh; defines functions only.
#
#   stack_slow                 true on a small machine (1 CPU, or less than 1.5 GiB of memory)
#   stack_wait_timeout         seconds a `compose up --wait` may take: SUCKERPOT_WAIT_TIMEOUT, else
#                              900 on a small machine and 300 elsewhere
#   stack_leftovers            names of the containers an interrupted recreate left behind
#                              (<12 hex>_<project>-<service>-<n>); stack_clean_leftovers removes
#                              the ones that are not running, and says so
#   stack_run DESC CMD...      runs CMD (a compose command) where Ctrl-C cannot cut it in half:
#                              in its own session, its output in .suckerpot-state/stack.log. On a
#                              terminal it shows DESC and the time it has taken, every few
#                              seconds; without one, one line a minute. Ctrl-C (or TERM) while it
#                              runs only says that the step finishes first; STACK_INTERRUPTED=1
#                              then stops the script once the step is over (or, with
#                              STACK_EXIT_ON_INTERRUPT=0, tells the caller). On failure it prints the
#                              last lines of the log. Returns the status of CMD.
#   stack_wait_healthy SECONDS SERVICE...
#                              waits until every SERVICE runs and is healthy (or has no
#                              healthcheck). An "unhealthy" on the way is not the end: a loaded
#                              node fails a check now and then; only the deadline is. Shows the
#                              time on a terminal. Returns 0 when healthy, 1 at the deadline.
#   stack_restart DESC [--recreate] SERVICE...
#                              `compose up -d --no-deps` of SERVICE (recreated with --recreate)
#                              through stack_run, WITHOUT --wait (compose gives up at the first
#                              unhealthy check), then stack_wait_healthy with stack_wait_timeout
#   ingest_wait_answer SECONDS waits until `ingest.network.cli status` answers (with a growing
#                              pause between tries, and the time shown); prints the state, or
#                              nothing when ingest is not running or did not answer in time
#
# Why the leftovers matter: compose recreates a container by renaming the old one to
# <id>_<name>, creating the new one, then removing the old. Cut in the middle, the renamed old
# container stays; it still carries the labels of the service, so the next `up --wait` counts it
# and fails on it ("has no healthcheck configured", or a dependency that never gets healthy).

STACK_LOG=${STACK_LOG:-.suckerpot-state/stack.log}
# shellcheck disable=SC2034 # read by the callers
STACK_INTERRUPTED=0

stack_slow() {
  local cpus kb
  cpus=$(nproc 2> /dev/null || echo 2)
  kb=$(awk '/^MemTotal:/ {print $2}' "${SELFHOSTR_MEMINFO:-/proc/meminfo}" 2> /dev/null || echo 0)
  [ "${cpus:-2}" -le 1 ] || [ "${kb:-0}" -lt 1572864 ]
}

stack_wait_timeout() {
  local t=${SUCKERPOT_WAIT_TIMEOUT:-}
  if [[ $t =~ ^[0-9]{2,5}$ ]]; then echo "$t"; elif stack_slow; then echo 900; else echo 300; fi
}

stack_leftovers() {
  local project
  project=$(env_get COMPOSE_PROJECT_NAME)
  [ -n "$project" ] || return 0
  ctr ps -a --filter "label=com.docker.compose.project=$project" --format '{{.Names}} {{.State}}' 2> /dev/null \
    | awk -v p="$project" '$1 ~ "^[0-9a-f]{12}_" p "-" { print }' || true
}

stack_clean_leftovers() {
  local name state n=0
  while read -r name state; do
    [ -n "${name:-}" ] || continue
    if [ "$state" = running ]; then
      echo "note: $name is left from an interrupted restart and still runs; compose replaces it" >&2
      continue
    fi
    if ctr rm -f "$name" > /dev/null 2>&1; then
      n=$((n + 1))
      printf '%s removed %s (left by an interrupted restart, %s)\n' "$(date -u +%FT%TZ)" "$name" "$state" >> "$STACK_LOG" 2> /dev/null || true
    fi
  done < <(stack_leftovers)
  [ "$n" = 0 ] || echo "  Removed $n container(s) left by an interrupted restart (see $STACK_LOG)."
  return 0
}

# _stack_tick DESC START: the progress line (a terminal) or a line a minute (no terminal).
_stack_tick() {
  local el=$(($(date +%s) - $2))
  if [ -t 1 ]; then
    printf '\r  %s %d:%02d ' "$1" $((el / 60)) $((el % 60))
  elif [ $((el % 60)) -lt 5 ] && [ "$el" -ge 60 ]; then
    printf '  %s still running (%d min)\n' "$1" $((el / 60))
  fi
}

stack_run() {
  local desc=$1 pid rc=0 t0 saw=0 off
  shift
  mkdir -p "$(dirname "$STACK_LOG")" 2> /dev/null || true
  off=$(wc -c < "$STACK_LOG" 2> /dev/null || echo 0)
  printf '\n%s %s: %s\n' "$(date -u +%FT%TZ)" "$desc" "$*" >> "$STACK_LOG" 2> /dev/null || true
  stack_clean_leftovers
  t0=$(date +%s)
  echo "  $desc (this can take a few minutes on a small machine; Ctrl-C does not cut it in half)."
  # Its own session: a Ctrl-C on the terminal reaches this script, never the compose command. A
  # shell function of the scripts (engine_stack_up...) runs in a new bash that loads them again.
  local run=("$@")
  if declare -F "$1" > /dev/null; then
    run=(bash -c 'set -o pipefail; cd "$1" && shift && . scripts/lib/env.sh && "$@"' stack_run "$PWD" "$@")
  fi
  if command -v setsid > /dev/null 2>&1; then
    setsid --wait "${run[@]}" >> "$STACK_LOG" 2>&1 < /dev/null &
  else
    "${run[@]}" >> "$STACK_LOG" 2>&1 < /dev/null &
  fi
  pid=$!
  local old_traps
  old_traps=$(trap -p INT TERM HUP)
  trap 'STACK_INTERRUPTED=1; saw=1' INT TERM HUP
  while kill -0 "$pid" 2> /dev/null; do
    if [ "$saw" = 1 ]; then
      [ -t 1 ] && printf '\r\033[K'
      echo "  Interrupted: the current step finishes first, so the stack is never left half restarted. Please wait."
      saw=2
    fi
    _stack_tick "$desc" "$t0"
    sleep 2 & wait $! 2> /dev/null || true
  done
  wait "$pid" || rc=$?
  trap - INT TERM HUP
  [ -z "$old_traps" ] || eval "$old_traps"
  [ ! -t 1 ] || printf '\r\033[K'
  # The scripts' own notes (indented by six spaces, as update.sh writes them) are shown, not
  # only logged: "a network must be recreated...", a warning of the step.
  tail -c +"$((off + 1))" "$STACK_LOG" 2> /dev/null | grep -E '^      [[:alnum:](]' >&2 || true
  if [ "$rc" = 0 ]; then
    echo "  $desc: done in $(( ($(date +%s) - t0) )) s."
  else
    echo "  $desc: failed (exit $rc) after $(( ($(date +%s) - t0) )) s. The last lines of $STACK_LOG:" >&2
    tail -n 12 "$STACK_LOG" 2> /dev/null | sed 's/^/    | /' >&2 || true
  fi
  # Interrupted: the step is complete, now the script stops (STACK_EXIT_ON_INTERRUPT=0 lets the
  # caller finish its own work first, as update.sh does to judge the health of what it started).
  # A caller with its own Ctrl-C handler (participant.sh) gets the signal again, now.
  if [ "$STACK_INTERRUPTED" = 1 ] && [ "${STACK_EXIT_ON_INTERRUPT:-1}" = 1 ]; then
    echo "  Stopped after that step, as asked." >&2
    if [ -n "$old_traps" ]; then kill -INT "$$"; sleep 1; fi
    exit 130
  fi
  return "$rc"
}

ingest_wait_answer() {
  local limit=${1:-120} t0 doc st pause=2 el
  t0=$(date +%s)
  while :; do
    doc=$(dc exec -T ingest python -m ingest.network.cli status --json 2> /dev/null) || doc=""
    st=$(printf '%s' "$doc" | json_top_string state)
    if [ -n "$st" ]; then
      [ ! -t 2 ] || [ "$(($(date +%s) - t0))" -lt 3 ] || printf '\r\033[K' >&2
      printf '%s\n' "$st"
      return 0
    fi
    # Not running at all: no point in waiting.
    [ -n "$(dc ps --status running -q ingest 2> /dev/null)" ] || return 0
    el=$(($(date +%s) - t0))
    [ "$el" -lt "$limit" ] || { [ ! -t 2 ] || printf '\r\033[K' >&2; return 0; }
    [ ! -t 2 ] || printf '\r  waiting for ingest to answer (it is starting or busy) %d:%02d ' $((el / 60)) $((el % 60)) >&2
    sleep "$pause"
    [ "$pause" -ge 15 ] || pause=$((pause * 2))
  done
}

stack_wait_healthy() {
  local limit=$1 t0 el svc line state health bad
  shift
  t0=$(date +%s)
  while :; do
    bad=""
    for svc in "$@"; do
      line=$(dc ps --format '{{.Service}} {{.State}} {{.Health}}' 2> /dev/null | awk -v s="$svc" '$1 == s { print; exit }')
      read -r _ state health <<< "${line:-x missing}"
      case "$state/${health:-}" in
        running/healthy | running/) ;;
        *) bad+="$svc(${health:-$state}) " ;;
      esac
    done
    if [ -z "$bad" ]; then
      [ ! -t 1 ] || printf '\r\033[K'
      return 0
    fi
    el=$(($(date +%s) - t0))
    if [ "$el" -ge "$limit" ]; then
      [ ! -t 1 ] || printf '\r\033[K'
      echo "  Not healthy after $el s: ${bad% }" >&2
      return 1
    fi
    [ ! -t 1 ] || printf '\r  waiting for %s to be healthy %d:%02d ' "${bad% }" $((el / 60)) $((el % 60))
    sleep 5 & wait $! 2> /dev/null || true
  done
}

stack_restart() {
  local desc=$1 recreate=()
  shift
  if [ "${1:-}" = --recreate ]; then recreate=(--force-recreate); shift; fi
  local up=(engine_stack_up -d --no-deps ${recreate[@]+"${recreate[@]}"})
  if [ "$(env_get SUCKERPOT_INSTALL_MODE source)" = images ]; then up+=(--no-build --pull never); else up+=(--build); fi
  stack_run "$desc" "${up[@]}" "$@" || return 1
  stack_wait_healthy "$(stack_wait_timeout)" "$@"
}
