#!/usr/bin/env bash
# Display of the host scripts: a step list with one progress bar on a terminal, plain lines
# everywhere else (docs/dev/design/installer-ux.md). Pure bash and coreutils; sourced, never run.
#
# Two modes:
#   rich   stdout and stderr are terminals and TERM is set and not "dumb". A fixed list of steps
#          and one bar are redrawn in place (cursor up, erase, rewrite: no alternate screen, no
#          terminal query). The script's own stdout and stderr go to the log; the display, the
#          questions and the final screen go to the terminal through UI_OUT and UI_ERR.
#          NO_COLOR keeps this display without colour.
#   plain  anything else, or --plain (ui_init's second argument), or SUCKERPOT_UI=plain. Nothing
#          changes on screen: the caller prints what it printed before, and ui_run tees the output
#          of commands into the log. No escape sequence, no carriage return.
#   SUCKERPOT_UI=rich forces the rich mode (tests).
#
# API (the caller keeps its own wording; see scripts/install.sh):
#   ui_init LOGFILE PLAIN          LOGFILE "" = no log (dry run); PLAIN 1 = --plain
#   ui_header CONTEXT              the header (rich only)
#   ui_plan "id|Title|weight" ...  the fixed list of steps (rich only)
#   ui_begin ID                    start a step; the running one before it is marked done
#   ui_detail TEXT                 the short result shown on the right of the current step
#   ui_done [TEXT] / ui_skip [TEXT] / ui_failed [TEXT]   end the current step
#   ui_run [--count REGEX N] [--expect SECONDS] -- CMD ARGS...
#                                  run a command with its output in the log (rich: a spinner and a
#                                  moving bar; plain: the output is also shown, as before)
#   ui_pause                       take the list off the screen before printing or asking
#   ui_warn TEXT                   a warning above the list (rich)
#   ui_end                         the final frame: no more redraws, cursor shown
#   ui_fail MESSAGE                the failure screen (rich) or "PREFIX: MESSAGE" (plain); exit 1
#   ui_exit                        exit trap: cursor back, terminal restored
#
# Nothing secret may go through ui_run's arguments or output: both are written to the log.

UI_MODE=plain
UI_PREFIX=${UI_PREFIX:-ui}
UI_LOG=""
UI_SINK=/dev/null
UI_LOG_OFF=0
UI_OUT=1
UI_ERR=2
UI_COLS=80
UI_LINES=24
UI_UTF8=0
UI_NLINES=0
UI_WIDTHS=""
UI_STATE_FILE=""
UI_CUR=-1
UI_PART=0
UI_SPIN_PID=""
UI_T0=0
UI_ENDED=0
UI_IDS=()
UI_TITLES=()
UI_WEIGHTS=()
UI_STATES=()
UI_DETAILS=()

# ---------------------------------------------------------------- setup

# ui_init LOGFILE PLAIN
ui_init() {
  local log=${1:-} plain=${2:-0}
  case ${SUCKERPOT_UI:-} in
    rich) UI_MODE=rich ;;
    plain) UI_MODE=plain ;;
    *)
      if [ "$plain" != 1 ] && [ -t 1 ] && [ -t 2 ] && [ -n "${TERM:-}" ] && [ "$TERM" != dumb ]; then
        UI_MODE=rich
      else
        UI_MODE=plain
      fi
      ;;
  esac
  [ "$plain" = 1 ] && [ "${SUCKERPOT_UI:-}" != rich ] && UI_MODE=plain
  case ${LC_ALL:-${LC_CTYPE:-${LANG:-}}} in *[Uu][Tt][Ff]-8* | *[Uu][Tt][Ff]8*) UI_UTF8=1 ;; *) UI_UTF8=0 ;; esac
  printf -v UI_T0 '%(%s)T' -1

  if [ -n "$log" ]; then
    UI_LOG=$log
    # The log is private: it holds the full output of every command.
    (umask 077 && : >> "$UI_LOG") 2> /dev/null || true
    chmod 600 "$UI_LOG" 2> /dev/null || true
    UI_LOG_OFF=$(wc -c < "$UI_LOG" 2> /dev/null || echo 0)
    UI_SINK=$UI_LOG
  fi

  if [ "$UI_MODE" = rich ]; then
    exec {UI_OUT}>&1 {UI_ERR}>&2
    UI_STATE_FILE=$(mktemp 2> /dev/null || true)
    # From here, anything the script prints by itself lands in the log, never in the display.
    exec >> "$UI_SINK" 2>&1
    _ui_colors
    _ui_size
    trap '_ui_resized=1' WINCH
    trap '_ui_signal 130' INT
    trap '_ui_quit 143' TERM
    trap '_ui_quit 129' HUP
  fi
  trap ui_exit EXIT
}

# shellcheck disable=SC2034 # the colour variables are used by the scripts that source this file
_ui_colors() {
  local tier=8
  if [ -n "${NO_COLOR:-}" ]; then
    tier=0
  elif [ "${COLORTERM:-}" = truecolor ] || [ "${COLORTERM:-}" = 24bit ]; then
    tier=24
  else
    case ${TERM:-} in *256color*) tier=256 ;; esac
  fi
  local e=$'\033['
  UI_B="${e}1m" UI_D="${e}2m" UI_R="${e}0m"
  case $tier in
    24)
      UI_ACC="${e}38;2;167;139;250m" UI_OK="${e}38;2;111;211;181m" UI_WARN="${e}38;2;245;163;92m"
      UI_BAD="${e}38;2;242;85;90m" UI_PR="${e}38;2;143;188;243m" UI_DIM="${e}38;2;139;143;153m"
      ;;
    256)
      UI_ACC="${e}38;5;141m" UI_OK="${e}38;5;79m" UI_WARN="${e}38;5;215m"
      UI_BAD="${e}38;5;203m" UI_PR="${e}38;5;111m" UI_DIM="${e}38;5;246m"
      ;;
    8)
      UI_ACC="${e}35m" UI_OK="${e}32m" UI_WARN="${e}33m" UI_BAD="${e}31m" UI_PR="${e}34m" UI_DIM="${e}2m"
      ;;
    *)
      UI_ACC="" UI_OK="" UI_WARN="" UI_BAD="" UI_PR="" UI_DIM=$UI_D
      ;;
  esac
  if [ "$UI_UTF8" = 1 ]; then
    UI_G_OK="✓" UI_G_BAD="✗" UI_G_TODO="·" UI_G_SKIP="–" UI_G_WARN="!"
    UI_SPIN=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    UI_BAR_FULL="━" UI_BAR_HEAD="╸" UI_BAR_EMPTY="━" UI_V="│"
  else
    UI_G_OK="+" UI_G_BAD="x" UI_G_TODO="." UI_G_SKIP="-" UI_G_WARN="!"
    UI_SPIN=("|" "/" "-" "\\")
    UI_BAR_FULL="#" UI_BAR_HEAD="#" UI_BAR_EMPTY="-" UI_V="|"
  fi
}

# Terminal size from the display's own descriptor (works without a controlling terminal too).
_ui_size() {
  local s r c
  s=$(stty size <&"$UI_OUT" 2> /dev/null || true)
  read -r r c <<< "$s"
  [[ ${c:-} =~ ^[0-9]+$ ]] && [ "$c" -gt 0 ] || c=${COLUMNS:-80}
  [[ ${r:-} =~ ^[0-9]+$ ]] && [ "$r" -gt 0 ] || r=${LINES:-24}
  [[ $c =~ ^[0-9]+$ ]] || c=80
  [[ $r =~ ^[0-9]+$ ]] || r=24
  UI_COLS=$c UI_LINES=$r
  _ui_resized=0
}

# ui_plan "id|Title|weight" ...
ui_plan() {
  local spec id title weight
  UI_IDS=() UI_TITLES=() UI_WEIGHTS=() UI_STATES=() UI_DETAILS=()
  for spec in "$@"; do
    IFS='|' read -r id title weight <<< "$spec"
    UI_IDS+=("$id")
    UI_TITLES+=("$title")
    UI_WEIGHTS+=("${weight:-1}")
    UI_STATES+=(todo)
    UI_DETAILS+=("")
  done
  UI_CUR=-1
}

# ui_header CONTEXT: the logo (the website's violet drop) and the wordmark.
ui_header() {
  [ "$UI_MODE" = rich ] || return 0
  local ctx=$1 logline=""
  [ -z "$UI_LOG" ] || logline="log: $(_ui_abs "$UI_LOG")"
  if [ "$UI_UTF8" = 1 ] && [ "$UI_COLS" -ge 40 ]; then
    printf '\n%s    ▄%s     %sSuckerPot%s\n%s   ███%s    %s\n%s  ██%s%s●%s%s██%s   %s%s%s\n%s   ▀▀▀%s\n\n' \
      "$UI_ACC" "$UI_R" "$UI_B" "$UI_R" \
      "$UI_ACC" "$UI_R" "$(_ui_cut "$ctx" $((UI_COLS - 11)))" \
      "$UI_ACC" "$UI_R" "$UI_B" "$UI_R" "$UI_ACC" "$UI_R" "$UI_DIM" "$(_ui_cut "$logline" $((UI_COLS - 11)))" "$UI_R" \
      "$UI_ACC" "$UI_R" 1>&"$UI_OUT" || true
  else
    printf '\n%sSuckerPot%s  %s\n' "$UI_B" "$UI_R" "$(_ui_cut "$ctx" $((UI_COLS - 12)))" 1>&"$UI_OUT" || true
    [ -z "$logline" ] || printf '%s%s%s\n' "$UI_DIM" "$(_ui_cut "$logline" $((UI_COLS - 1)))" "$UI_R" 1>&"$UI_OUT" || true
    printf '\n' 1>&"$UI_OUT" || true
  fi
}

_ui_abs() { case $1 in /*) printf %s "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }

# _ui_cut TEXT WIDTH: TEXT cut to WIDTH characters (an ellipsis marks the cut).
_ui_cut() {
  local t=$1 w=$2
  [ "$w" -gt 0 ] || { printf ''; return; }
  if [ "${#t}" -le "$w" ]; then printf %s "$t"; return; fi
  if [ "$w" -le 1 ]; then printf %s "${t:0:$w}"; return; fi
  if [ "$UI_UTF8" = 1 ]; then printf '%s…' "${t:0:$((w - 1))}"; else printf %s "${t:0:$w}"; fi
}

# ---------------------------------------------------------------- steps

_ui_index() {
  local i
  for i in "${!UI_IDS[@]}"; do
    [ "${UI_IDS[$i]}" = "$1" ] && { echo "$i"; return 0; }
  done
  return 1
}

ui_begin() {
  [ "$UI_MODE" = rich ] || return 0
  local i
  i=$(_ui_index "$1") || return 0
  [ "$i" != "$UI_CUR" ] || return 0
  if [ "$UI_CUR" -ge 0 ] && [ "${UI_STATES[$UI_CUR]}" = run ]; then UI_STATES[UI_CUR]=ok; fi
  UI_CUR=$i
  UI_STATES[i]=run
  UI_PART=0
  _ui_draw
}

ui_detail() {
  [ "$UI_MODE" = rich ] && [ "$UI_CUR" -ge 0 ] || return 0
  UI_DETAILS[UI_CUR]=$1
  _ui_draw
}

_ui_close() {
  [ "$UI_MODE" = rich ] && [ "$UI_CUR" -ge 0 ] || return 0
  UI_STATES[UI_CUR]=$1
  [ -z "${2:-}" ] || UI_DETAILS[UI_CUR]=$2
  UI_PART=0
  _ui_draw
}
ui_done() { _ui_close ok "${1:-}"; }
ui_skip() { _ui_close skip "${1:-}"; }
ui_failed() { _ui_close bad "${1:-}"; }

# ui_skip_rest TEXT: every step not started yet is marked skipped.
ui_skip_rest() {
  [ "$UI_MODE" = rich ] || return 0
  local i
  for i in "${!UI_STATES[@]}"; do
    if [ "${UI_STATES[$i]}" = todo ]; then UI_STATES[i]=skip; UI_DETAILS[i]=${1:-}; fi
  done
}

# Progress in thousandths: the weight of the finished steps plus a part of the running one.
_ui_progress() {
  local i total=0 done=0
  for i in "${!UI_WEIGHTS[@]}"; do
    total=$((total + UI_WEIGHTS[i]))
    case ${UI_STATES[$i]} in
      ok | skip) done=$((done + UI_WEIGHTS[i] * 1000)) ;;
      run) done=$((done + UI_WEIGHTS[i] * UI_PART)) ;;
    esac
  done
  [ "$total" -gt 0 ] || { echo 0; return; }
  echo $((done / total))
}

# _ui_frame SPINFRAME: the list and the bar as one string (one write, so a frame is never cut).
_ui_frame() {
  local f=${1:-0} i g col title detail tw=0 line out="" n=0 compact=0 cols=$UI_COLS widths=""
  for i in "${!UI_TITLES[@]}"; do [ "${#UI_TITLES[$i]}" -le "$tw" ] || tw=${#UI_TITLES[$i]}; done
  tw=$((tw + 3))
  if [ "$cols" -lt 40 ] || [ "$UI_LINES" -lt $((${#UI_IDS[@]} + 6)) ]; then compact=1; fi
  # While the spinner runs, the number of lines must not change (the main shell erases that many).
  [ -z "${UI_LOCK_COMPACT:-}" ] || compact=$UI_LOCK_COMPACT
  UI_COMPACT=$compact
  for i in "${!UI_IDS[@]}"; do
    if [ "$compact" = 1 ] && [ "$i" != "$UI_CUR" ]; then continue; fi
    case ${UI_STATES[$i]} in
      ok) g=$UI_G_OK col=$UI_OK ;;
      bad) g=$UI_G_BAD col=$UI_BAD ;;
      skip) g=$UI_G_SKIP col=$UI_DIM ;;
      run) g=${UI_SPIN[$((f % ${#UI_SPIN[@]}))]} col=$UI_ACC ;;
      *) g=$UI_G_TODO col=$UI_DIM ;;
    esac
    title=$(_ui_cut "${UI_TITLES[$i]}" $((cols - 5)))
    detail=""
    if [ "$cols" -ge 60 ] && [ -n "${UI_DETAILS[$i]}" ]; then
      detail=$(_ui_cut "${UI_DETAILS[$i]}" $((cols - 5 - tw)))
      printf -v title "%-${tw}s" "$title"
    fi
    if [ "${UI_STATES[$i]}" = todo ]; then
      line="  ${col}${g} ${title}${UI_R}"
    elif [ "${UI_STATES[$i]}" = run ]; then
      line="  ${col}${g}${UI_R} ${UI_B}${title}${UI_R}${UI_DIM}${detail}${UI_R}"
    else
      line="  ${col}${g}${UI_R} ${title}${UI_DIM}${detail}${UI_R}"
    fi
    out+="${line}"$'\n'
    widths+="$((4 + ${#title} + ${#detail})) "
    n=$((n + 1))
  done
  # The bar: width minus the margins, the percentage and the time.
  local p bw full el m s tail
  p=$(_ui_progress)
  printf -v el '%(%s)T' -1
  el=$((el - UI_T0))
  m=$((el / 60)) s=$((el % 60))
  printf -v tail ' %3d%%  %d:%02d' $((p / 10)) "$m" "$s"
  bw=$((cols - 3 - ${#tail}))
  [ "$bw" -le 60 ] || bw=60
  local bar_done="" bar_rest="" k
  if [ "$bw" -ge 10 ]; then
    full=$((bw * p / 1000))
    for ((k = 0; k < full; k++)); do bar_done+=$UI_BAR_FULL; done
    if [ "$full" -lt "$bw" ]; then
      bar_rest=$UI_BAR_HEAD
      for ((k = full + 1; k < bw; k++)); do bar_rest+=$UI_BAR_EMPTY; done
    fi
  fi
  if [ "$compact" = 0 ]; then out+=$'\n'; widths+="0 "; n=$((n + 1)); fi
  tail=$(_ui_cut "$tail" $((cols - 3)))
  out+="  ${UI_ACC}${bar_done}${UI_R}${UI_DIM}${bar_rest}${UI_R}${tail}"$'\n'
  [ "$bw" -ge 10 ] || bw=0
  widths+="$((2 + bw + ${#tail}))"
  n=$((n + 1))
  UI_FRAME_TEXT=$out
  UI_FRAME_LINES=$n
  UI_FRAME_WIDTHS=$widths
}

# Erases the list, which ends just above the cursor.
_ui_clear() {
  [ "$UI_NLINES" -gt 0 ] || return 0
  [ "${_ui_resized:-0}" = 0 ] || _ui_size
  _ui_height
  printf '\033[%dA\r\033[J' "$UI_H" 1>&"$UI_OUT" 2> /dev/null || true
  UI_NLINES=0
}

# _ui_height: how many terminal rows the list on screen takes now. A terminal that was made
# narrower wraps the old lines, so the height is counted with the current width.
_ui_height() {
  local w c=$UI_COLS
  [ "$c" -gt 0 ] || c=80
  UI_H=0
  for w in ${UI_WIDTHS:-}; do
    if [ "$w" -le 0 ]; then UI_H=$((UI_H + 1)); else UI_H=$((UI_H + (w + c - 1) / c)); fi
  done
}

_ui_draw() {
  [ "$UI_MODE" = rich ] && [ "$UI_ENDED" = 0 ] && [ "${#UI_IDS[@]}" -gt 0 ] || return 0
  [ "${_ui_resized:-0}" = 0 ] || _ui_size
  _ui_frame 0
  _ui_clear
  printf '\033[?25l%s' "$UI_FRAME_TEXT" 1>&"$UI_OUT" 2> /dev/null || true
  UI_NLINES=$UI_FRAME_LINES
  UI_WIDTHS=$UI_FRAME_WIDTHS
}

# ui_pause: the list leaves the screen and the cursor comes back, so a question or a block of
# text can be printed. The next change of state draws the list again, below that text.
ui_pause() {
  [ "$UI_MODE" = rich ] || return 0
  _ui_clear
  printf '\033[?25h' 1>&"$UI_OUT" 2> /dev/null || true
}

ui_warn() {
  [ "$UI_MODE" = rich ] || return 0
  ui_pause
  local l first=1
  while IFS= read -r l; do
    if [ "$first" = 1 ]; then
      printf '  %s%s %s%s\n' "$UI_WARN" "$UI_G_WARN" "$l" "$UI_R"
    else
      printf '    %s%s%s\n' "$UI_WARN" "$l" "$UI_R"
    fi
    first=0
  done < <(printf '%s\n' "$1" | fold -s -w $((UI_COLS > 20 ? UI_COLS - 5 : 60))) 1>&"$UI_OUT" 2> /dev/null || true
  _ui_draw
}

ui_end() {
  [ "$UI_MODE" = rich ] || return 0
  [ "$UI_ENDED" = 0 ] || return 0
  if [ "$UI_CUR" -ge 0 ] && [ "${UI_STATES[$UI_CUR]}" = run ]; then UI_STATES[UI_CUR]=ok; fi
  ui_skip_rest ""
  _ui_draw
  UI_NLINES=0
  UI_ENDED=1
  printf '\033[?25h' 1>&"$UI_OUT" 2> /dev/null || true
}

# ---------------------------------------------------------------- commands

_ui_log_count() {
  [ -n "$UI_LOG" ] && [ -f "$UI_LOG" ] || { echo 0; return; }
  tail -c +"$(($2 + 1))" "$UI_LOG" 2> /dev/null | grep -cE -- "$1" || true
}

# The spinner runs in the background while the command runs in the foreground, so Ctrl-C reaches
# the command as usual. It only redraws; the main shell draws nothing while it runs.
_ui_spinner() {
  local re=$1 n=$2 expect=$3 off=$4 f=0 c el now
  UI_LOCK_COMPACT=${UI_COMPACT:-0}
  # On TERM it leaves the widths of its last frame to the main shell, which erases that frame.
  trap '[ -z "$UI_STATE_FILE" ] || printf "%s" "$UI_WIDTHS" > "$UI_STATE_FILE"; exit 0' TERM
  trap '_ui_resized=1' WINCH
  trap '' INT
  local tick
  exec {tick}<> <(:)
  while :; do
    if [ -n "$re" ] && [ "$n" -gt 0 ]; then
      c=$(_ui_log_count "$re" "$off")
      UI_PART=$((c * 1000 / n))
    elif [ "$expect" -gt 0 ]; then
      printf -v now '%(%s)T' -1
      el=$((now - _ui_run_t0))
      UI_PART=$((el * 1000 / expect))
    fi
    [ "$UI_PART" -le 950 ] || UI_PART=950
    [ "${_ui_resized:-0}" = 0 ] || _ui_size
    _ui_frame "$f"
    _ui_height
    printf '\033[%dA\r\033[J%s' "$UI_H" "$UI_FRAME_TEXT" 1>&"$UI_OUT" 2> /dev/null || exit 0
    UI_NLINES=$UI_FRAME_LINES
    UI_WIDTHS=$UI_FRAME_WIDTHS
    f=$((f + 1))
    read -r -t 0.12 -u "$tick" _ 2> /dev/null || true
  done
}

# ui_run [--count REGEX N] [--expect SECONDS] -- CMD ARGS...: returns the command's status.
ui_run() {
  local re="" n=0 expect=0 rc=0 off
  while [ $# -gt 0 ]; do
    case $1 in
      --count) re=$2 n=$3; shift 3 ;;
      --expect) expect=$2; shift 2 ;;
      --) shift; break ;;
      *) break ;;
    esac
  done
  [ -z "$UI_LOG" ] || printf '+ %s\n' "$*" >> "$UI_LOG"
  if [ "$UI_MODE" = plain ]; then
    if [ -z "$UI_LOG" ]; then
      "$@" || rc=$?
    elif "$@" 2>&1 | tee -a "$UI_LOG"; then
      rc=0
    else
      rc=${PIPESTATUS[0]}
      [ "$rc" != 0 ] || rc=1
    fi
    return "$rc"
  fi
  off=$(wc -c < "$UI_SINK" 2> /dev/null || echo 0)
  [[ $off =~ ^[0-9]+$ ]] || off=0
  _ui_draw
  printf -v _ui_run_t0 '%(%s)T' -1
  _ui_in_run=1
  if [ "$UI_ENDED" = 0 ] && [ "$UI_NLINES" -gt 0 ]; then
    [ -z "$UI_STATE_FILE" ] || : > "$UI_STATE_FILE"
    _ui_spinner "$re" "$n" "$expect" "$off" &
    UI_SPIN_PID=$!
  fi
  "$@" >> "$UI_SINK" 2>&1 < /dev/null || rc=$?
  _ui_stop_spinner
  _ui_in_run=0
  if [ -n "${_ui_sig:-}" ]; then _ui_interrupt "$_ui_sig"; fi
  # shellcheck disable=SC2034 # read by the caller
  if [ -n "$re" ]; then UI_COUNT=$(_ui_log_count "$re" "$off"); fi
  _ui_draw
  return "$rc"
}

_ui_stop_spinner() {
  [ -n "$UI_SPIN_PID" ] || return 0
  kill -TERM "$UI_SPIN_PID" 2> /dev/null || true
  wait "$UI_SPIN_PID" 2> /dev/null || true
  UI_SPIN_PID=""
  local w=""
  [ -z "$UI_STATE_FILE" ] || w=$(cat "$UI_STATE_FILE" 2> /dev/null || true)
  [ -z "$w" ] || UI_WIDTHS=$w
  [ "${_ui_resized:-0}" = 0 ] || _ui_size
}

# ---------------------------------------------------------------- the end

# ui_fail MESSAGE [FIX]: the failure screen, then exit 1. FIX is a command shown under "Fix"
# (rich only). UI_FAIL_LOGLINE, when set, is appended to the log after the screen has read it.
ui_fail() {
  local msg=$1 fix=${2:-}
  if [ "$UI_MODE" != rich ]; then
    echo "$UI_PREFIX: $msg" 1>&"$UI_ERR"
    if [ -n "$UI_LOG" ] && [ -f "$UI_LOG" ]; then echo "      log: $(_ui_abs "$UI_LOG")" 1>&"$UI_ERR"; fi
    _ui_fail_log
    exit 1
  fi
  _ui_stop_spinner
  if [ "$UI_ENDED" = 0 ]; then
    if [ "$UI_CUR" -ge 0 ]; then
      UI_STATES[UI_CUR]=bad
      UI_DETAILS[UI_CUR]="failed"
    fi
    _ui_draw
    UI_NLINES=0
    UI_ENDED=1
  fi
  {
    printf '\033[?25h\n  %s%s %s%s\n' "$UI_BAD" "$UI_G_BAD" "$msg" "$UI_R"
    if [ -n "$UI_LOG" ] && [ -f "$UI_LOG" ]; then
      local lines l
      lines=$(tail -c +"$((UI_LOG_OFF + 1))" "$UI_LOG" 2> /dev/null | grep -v '^[[:space:]]*$' | tail -n 15 || true)
      if [ -n "$lines" ]; then
        printf '\n'
        while IFS= read -r l; do
          printf '    %s%s %s%s\n' "$UI_DIM" "$UI_V" "$(_ui_cut "$l" $((UI_COLS - 7)))" "$UI_R"
        done <<< "$lines"
      fi
      printf '\n'
      [ -z "$fix" ] || printf '  %sFix%s   %s%s%s\n' "$UI_B" "$UI_R" "$UI_PR" "$fix" "$UI_R"
      printf '  %sLog%s   %s\n' "$UI_B" "$UI_R" "$(_ui_abs "$UI_LOG")"
    fi
  } 1>&"$UI_OUT" 2> /dev/null || true
  _ui_fail_log
  exit 1
}

_ui_fail_log() {
  if [ -n "${UI_FAIL_LOGLINE:-}" ] && [ -n "$UI_LOG" ]; then printf '%s\n' "$UI_FAIL_LOGLINE" >> "$UI_LOG"; fi
}

# Signals. Bash may stop a trap handler that waits for a command substitution after a Ctrl-C, so
# the handlers run no command substitution. During ui_run, Ctrl-C has reached the command too:
# the handler only notes it, and ui_run draws the interrupted step once the command has ended.
_ui_signal() {
  if [ "${_ui_in_run:-0}" = 1 ]; then _ui_sig=$1; return 0; fi
  _ui_quit "$1"
}

# _ui_quit CODE: leave at once (a question, shell code, or TERM and HUP).
_ui_quit() {
  local p=$UI_LOG
  trap '' INT TERM HUP
  [ -z "$UI_SPIN_PID" ] || kill -TERM "$UI_SPIN_PID" 2> /dev/null || true
  UI_SPIN_PID=""
  case $p in "" | /*) ;; *) p=$PWD/$p ;; esac
  {
    printf '\033[?25h\n  %s%s Interrupted.%s' "$UI_BAD" "$UI_G_BAD" "$UI_R"
    [ -z "$p" ] || printf ' Log: %s' "$p"
    printf '\n'
  } 1>&"$UI_OUT" 2> /dev/null || true
  exit "$1"
}

_ui_interrupt() {
  local code=$1
  trap '' INT TERM HUP
  _ui_stop_spinner
  if [ "$UI_ENDED" = 0 ] && [ "${#UI_IDS[@]}" -gt 0 ]; then
    if [ "$UI_CUR" -ge 0 ]; then UI_STATES[UI_CUR]=bad; UI_DETAILS[UI_CUR]="interrupted"; fi
    _ui_draw
    UI_NLINES=0
    UI_ENDED=1
  fi
  {
    printf '\033[?25h\n  %s%s Interrupted.%s' "$UI_BAD" "$UI_G_BAD" "$UI_R"
    [ -z "$UI_LOG" ] || printf ' Log: %s' "$(_ui_abs "$UI_LOG")"
    printf '\n'
  } 1>&"$UI_OUT" 2> /dev/null || true
  exit "$code"
}

# ui_exit: the exit trap. Callers with their own exit work call it at the end of their trap.
ui_exit() {
  [ "$UI_MODE" = rich ] || return 0
  _ui_stop_spinner
  [ -z "$UI_STATE_FILE" ] || rm -f "$UI_STATE_FILE"
  printf '\033[?25h' 1>&"$UI_OUT" 2> /dev/null || true
  stty echo <&"$UI_OUT" 2> /dev/null || true
}
