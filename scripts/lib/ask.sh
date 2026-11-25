#!/usr/bin/env bash
# Questions and menus of the host scripts (install.sh, edit.sh, uninstall.sh, suckerpot.sh).
# Pure bash; sourced, never run. Works over SSH, in 80x24, in tmux, without colour.
#
# Answers come from fd 3: the terminal (/dev/tty), or SELFHOSTR_TTY (a file of answers, used by
# the tests). The questions go to ASK_OUT (default fd 2), so stdout stays free for the caller. An
# answer file that runs out (end of file) takes the default of every question that is left, so an
# older answer file still works when a question is added.
#
#   ask_open [--non-interactive]  open fd 3 on the terminal; ASK_TTY=1 when there is one
#   ask_text VAR PROMPT DEFAULT [CHECK]
#                                 one line; CHECK is a function that prints why a value is wrong
#                                 and fails; the question is asked again (at most 5 times)
#   ask_yn PROMPT y|n             yes or no; returns 0 for yes
#   ask_menu VAR DEFAULT TITLE "key|Label|hint" ...
#                                 one choice. On a real terminal: arrow keys (or j/k), Enter, or
#                                 the key of an item. Elsewhere: a numbered list and one line.
#   ask_pause [TEXT]              "Press Enter" on a terminal; nothing without one
#
# ASK_EOF=1 once the answers ran out (a menu loop then stops instead of choosing for ever).
#
# ASK_PLAIN=1 (the --plain display) keeps the numbered list on a terminal too.
#
# The key menu redraws itself with cursor-up and erase-below only (the sequences of ui.sh), never
# the alternate screen. NO_COLOR, TERM=dumb or no terminal: no colour (reverse video is not a
# colour, but NO_COLOR also drops it; the current line keeps its ">" mark).

# shellcheck disable=SC2034 # ASK_EOF is read by the callers
true
ASK_IN=3
ASK_OUT=${ASK_OUT:-2}
ASK_TTY=0
ASK_IND=${ASK_IND:-"  "}

# ask_open [--non-interactive]: fd 3 on the terminal or on SELFHOSTR_TTY.
ask_open() {
  ASK_TTY=0
  [ "${1:-}" != --non-interactive ] || return 0
  local tty=${SELFHOSTR_TTY:-/dev/tty}
  if [ -r "$tty" ] && (: < "$tty") 2> /dev/null; then
    exec 3< "$tty"
    ASK_TTY=1
  fi
  return 0
}

# _ask_style: colours only when the questions go to a terminal and NO_COLOR is not set.
_ask_style() {
  ASK_B="" ASK_R="" ASK_D="" ASK_ACC="" ASK_REV="" ASK_WARN="" ASK_OK=""
  [ -t "$ASK_OUT" ] && [ -n "${TERM:-}" ] && [ "$TERM" != dumb ] || return 0
  [ -z "${NO_COLOR:-}" ] || return 0
  local e=$'\033['
  ASK_B="${e}1m" ASK_R="${e}0m" ASK_D="${e}2m" ASK_REV="${e}7m"
  case ${TERM:-} in
    *256color*) ASK_ACC="${e}38;5;141m" ASK_WARN="${e}38;5;215m" ASK_OK="${e}38;5;79m" ;;
    *) ASK_ACC="${e}35m" ASK_WARN="${e}33m" ASK_OK="${e}32m" ;;
  esac
}

# ask_keys: true when the menu can read single keys (a real terminal on fd 3 and on the output).
ask_keys() {
  [ "$ASK_TTY" = 1 ] && [ -t "$ASK_IN" ] && [ -t "$ASK_OUT" ] || return 1
  [ -n "${TERM:-}" ] && [ "$TERM" != dumb ] || return 1
  case ${SUCKERPOT_UI:-} in plain) return 1 ;; esac
  [ "${ASK_PLAIN:-0}" = 0 ] || return 1
  return 0
}

# _ask_read VAR: one line from fd 3. Fails at the end of the answers (ASK_EOF=1 then).
ASK_EOF=0
_ask_read() {
  local _line="" _rc
  [ "$ASK_TTY" = 1 ] || { ASK_EOF=1; return 1; }
  while :; do
    _rc=0
    IFS= read -r _line <&"$ASK_IN" || _rc=$?
    # A trapped signal (a window resize under the install display) is not the end of the answers.
    [ "$_rc" -gt 128 ] || break
  done
  if [ "$_rc" = 0 ]; then
    printf -v "$1" '%s' "$_line"
    # An answer from a file is not echoed by a terminal: end the prompt's line here.
    [ -t "$ASK_IN" ] || printf '\n' 1>&"$ASK_OUT"
    return 0
  fi
  [ -t "$ASK_IN" ] || printf '\n' 1>&"$ASK_OUT"
  ASK_EOF=1
  return 1
}

# ask_text VAR PROMPT DEFAULT [CHECK]
ask_text() {
  local _var=$1 _prompt=$2 _def=${3:-} _check=${4:-} _a _why _try=0 _shown
  _ask_style
  while [ "$_try" -lt 5 ]; do
    _try=$((_try + 1))
    _shown=""
    [ -z "$_def" ] || _shown=" [$_def]"
    printf '%s%s%s: ' "$ASK_IND" "$_prompt" "$_shown" 1>&"$ASK_OUT"
    if ! _ask_read _a; then _a=$_def; _try=5; fi
    # Surrounding blanks never count.
    _a="${_a#"${_a%%[![:space:]]*}"}"
    _a="${_a%"${_a##*[![:space:]]}"}"
    [ -n "$_a" ] || _a=$_def
    if [ -z "$_check" ] || _why=$("$_check" "$_a" 2>&1); then
      printf -v "$_var" '%s' "$_a"
      return 0
    fi
    printf '%s  %s%s%s\n' "$ASK_IND" "$ASK_WARN" "${_why:-not a valid answer}" "$ASK_R" 1>&"$ASK_OUT"
  done
  return 1
}

# ask_yn PROMPT y|n
ask_yn() {
  local _prompt=$1 _def=${2:-n} _a _hint
  if [ "$_def" = y ]; then _hint="[Y/n]"; else _hint="[y/N]"; fi
  while :; do
    printf '%s%s %s ' "$ASK_IND" "$_prompt" "$_hint" 1>&"$ASK_OUT"
    _ask_read _a || _a=""
    case ${_a:-$_def} in
      y | Y | yes | YES | Yes) return 0 ;;
      n | N | no | NO | No) return 1 ;;
      *) printf '%s  answer y or n\n' "$ASK_IND" 1>&"$ASK_OUT" ;;
    esac
  done
}

ask_pause() {
  local _a
  [ "$ASK_TTY" = 1 ] && [ -t "$ASK_IN" ] || return 0
  printf '%s%s%s' "$ASK_IND" "${1:-Press Enter to go back to the menu.}" " " 1>&"$ASK_OUT"
  IFS= read -r _a <&"$ASK_IN" || true
}

# _ask_cols: the width of the terminal the menu is drawn on.
_ask_cols() {
  local s r c
  s=$(stty size <&"$ASK_IN" 2> /dev/null || true)
  read -r r c <<< "$s"
  [[ ${c:-} =~ ^[1-9][0-9]*$ ]] || c=${COLUMNS:-80}
  [[ $c =~ ^[1-9][0-9]*$ ]] || c=80
  ASK_COLS=$c
}

# _ask_fit TEXT WIDTH: TEXT cut to WIDTH characters.
_ask_fit() {
  local t=$1 w=$2
  [ "$w" -gt 1 ] || { printf ''; return 0; }
  if [ "${#t}" -le "$w" ]; then printf '%s' "$t"; else printf '%s' "${t:0:$((w - 1))}~"; fi
}

# _ask_items "key|Label|hint" ...: fills _K, _L, _H and the label width _LW.
_ask_items() {
  local spec k l h
  _K=() _L=() _H=() _LW=0
  for spec in "$@"; do
    IFS='|' read -r k l h <<< "$spec"
    _K+=("$k") _L+=("$l") _H+=("${h:-}")
    [ "${#l}" -le "$_LW" ] || _LW=${#l}
  done
}

# _ask_menu_lines CURRENT: the menu text in _MENU (one line per item, then the help line).
_ask_menu_lines() {
  local cur=$1 i line mark pre post w
  _MENU=""
  _ask_cols
  w=$((ASK_COLS - 1))
  for i in "${!_K[@]}"; do
    printf -v line '%-3s %-*s  %s' "${_K[$i]}" "$_LW" "${_L[$i]}" "${_H[$i]}"
    line=$(_ask_fit "$line" $((w - ${#ASK_IND} - 2)))
    line="${line%"${line##*[! ]}"}"
    if [ "$i" = "$cur" ]; then
      mark="> " pre="${ASK_REV}${ASK_B}" post=$ASK_R
    else
      mark="  " pre="" post=""
    fi
    _MENU+="${ASK_IND}${ASK_ACC}${mark}${ASK_R}${pre}${line}${post}"$'\n'
  done
  _MENU+=$'\n'"${ASK_IND}${ASK_D}$(_ask_fit "Up/Down to move, Enter to choose, or press a key" $((w - ${#ASK_IND})))${ASK_R}"$'\n'
  _MENU_N=$((${#_K[@]} + 2))
}

# ask_menu VAR DEFAULT TITLE ITEM...
ask_menu() {
  local _var=$1 _def=$2 _title=$3 _cur=0 _i _k _rest _a _try=0 _rc
  shift 3
  _ask_style
  _ask_items "$@"
  for _i in "${!_K[@]}"; do [ "${_K[$_i]}" != "$_def" ] || _cur=$_i; done
  [ -z "$_title" ] || printf '%s%s%s%s\n\n' "$ASK_IND" "$ASK_B" "$_title" "$ASK_R" 1>&"$ASK_OUT"
  if ask_keys; then
    _ask_menu_lines "$_cur"
    printf '\033[?25l%s' "$_MENU" 1>&"$ASK_OUT"
    while :; do
      _k="" _rc=0
      IFS= read -rsn1 -u "$ASK_IN" _k || _rc=$?
      # A trapped signal (a window resize) only redraws; anything else is the end of the input.
      if [ "$_rc" -gt 128 ]; then _k=redraw; elif [ "$_rc" != 0 ]; then ASK_EOF=1; break; fi
      case $_k in
        $'\033')
          _rest=""
          IFS= read -rsn2 -t 0.05 -u "$ASK_IN" _rest || true
          case $_rest in
            "[A" | OA) _k=up ;;
            "[B" | OB) _k=down ;;
            "") _k=esc ;;
            *) _k="" ;;
          esac
          ;;
        "") _k=enter ;;
      esac
      case $_k in
        up | k) [ "$_cur" -le 0 ] && _cur=$((${#_K[@]} - 1)) || _cur=$((_cur - 1)) ;;
        down | j) [ "$_cur" -ge $((${#_K[@]} - 1)) ] && _cur=0 || _cur=$((_cur + 1)) ;;
        enter) break ;;
        redraw) ;;
        esc)
          # Escape leaves through the q item (quit or back), when the menu has one.
          for _i in "${!_K[@]}"; do [ "${_K[$_i]}" != q ] && [ "${_K[$_i]}" != b ] || { _cur=$_i; break 2; }; done
          ;;
        *)
          for _i in "${!_K[@]}"; do
            if [ "${_K[$_i],,}" = "${_k,,}" ]; then _cur=$_i; break 2; fi
          done
          continue
          ;;
      esac
      printf '\033[%dA\r\033[J' "$_MENU_N" 1>&"$ASK_OUT"
      _ask_menu_lines "$_cur"
      printf '%s' "$_MENU" 1>&"$ASK_OUT"
    done
    # The final frame shows the choice, then the cursor comes back.
    printf '\033[%dA\r\033[J' "$_MENU_N" 1>&"$ASK_OUT"
    _ask_menu_lines "$_cur"
    printf '%s\033[?25h\n' "$_MENU" 1>&"$ASK_OUT"
    printf -v "$_var" '%s' "${_K[$_cur]}"
    return 0
  fi
  # A numbered list and one line (no terminal, TERM=dumb, an answers file).
  for _i in "${!_K[@]}"; do
    printf '%s  %-3s %-*s  %s\n' "$ASK_IND" "${_K[$_i]}" "$_LW" "${_L[$_i]}" "${_H[$_i]}" 1>&"$ASK_OUT"
  done
  printf '\n' 1>&"$ASK_OUT"
  while :; do
    printf '%sChoose [%s]: ' "$ASK_IND" "$_def" 1>&"$ASK_OUT"
    if ! _ask_read _a; then
      printf -v "$_var" '%s' "$_def"
      return 0
    fi
    _a="${_a//[[:space:]]/}"
    [ -n "$_a" ] || _a=$_def
    for _i in "${!_K[@]}"; do
      if [ "${_K[$_i],,}" = "${_a,,}" ]; then printf -v "$_var" '%s' "${_K[$_i]}"; return 0; fi
    done
    _try=$((_try + 1))
    printf '%s  answer one of: %s\n' "$ASK_IND" "${_K[*]}" 1>&"$ASK_OUT"
    # An answers file with a wrong answer must not loop for ever.
    if [ "$_try" -ge 5 ]; then printf -v "$_var" '%s' "$_def"; return 0; fi
  done
}
