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
# Text for a terminal is wrapped at its width minus 4, at word boundaries (a line never breaks in
# the middle of a word). Without a terminal it is printed as given, so plain and CI output stay
# the same:
#   text_wrap [--join] WIDTH      stdin to stdout; long lines wrap under their own indent (under
#                                 the text of a "- " or "! " item). --join first joins the lines
#                                 of a paragraph that were broken by hand (a line that ends in the
#                                 middle of a sentence, and the indented lines of an item).
#   text_width FD                 TEXT_W = the width to wrap at for FD: 0 when FD is not a
#                                 terminal (it sets a variable: in $(...) fd 1 is a pipe)
#   text_out FD [--join]          stdin to FD, wrapped when FD is a terminal
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
    if [ -n "$_shown" ]; then _ask_prompt "$_prompt" "${_shown# }:"; else _ask_prompt "$_prompt:" ""; fi
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
    _ask_prompt "$_prompt" "$_hint"
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

text_wrap() {
  local join=0
  [ "${1:-}" != --join ] || { join=1; shift; }
  awk -v W="${1:-0}" -v J="$join" '
    function lead(s) { match(s, /^ */); return RLENGTH }
    # Prints TEXT word-wrapped: the first line after P1, the next ones after P2.
    function out(text, p1, p2,   n, w, i, line, pre) {
      if (W <= 0 || length(p1 text) <= W) { print p1 text; return }
      n = split(text, w, / +/); line = ""; pre = p1
      for (i = 1; i <= n; i++) {
        if (w[i] == "") continue
        if (line != "" && length(pre line " " w[i]) > W) { print pre line; line = w[i]; pre = p2 }
        else line = (line == "") ? w[i] : line " " w[i]
      }
      print pre line
    }
    function flush() { if (have) out(buf, p1, p2); have = 0; buf = "" }
    function start(s,   i, rest) {
      i = lead(s); rest = substr(s, i + 1)
      p1 = sprintf("%" i "s", ""); p2 = p1; ind = i
      if (rest ~ /^[-!] /) { p1 = p1 substr(rest, 1, 2); rest = substr(rest, 3); p2 = sprintf("%" (i + 2) "s", ""); cont = i + 2 }
      else cont = i
      buf = rest; have = 1
    }
    {
      # Width 0 (no terminal): the text as given, nothing joined.
      if (W <= 0) { print; next }
      sub(/\r$/, "")
      if ($0 ~ /^ *$/) { flush(); print ""; next }
      if (!J) { start($0); flush(); next }
      i = lead($0); rest = substr($0, i + 1)
      if (have && rest !~ /^[-!] / && i == cont && (cont > ind || buf ~ /[A-Za-z0-9,]$/)) {
        buf = buf " " rest; next
      }
      flush(); start($0)
    }
    END { flush() }'
}

text_width() {
  local s r c fd=${1:-1}
  TEXT_W=0
  [ -t "$fd" ] && [ -n "${TERM:-}" ] && [ "$TERM" != dumb ] || return 0
  [ "${ASK_PLAIN:-0}" = 0 ] || return 0
  s=$(stty size <&"$fd" 2> /dev/null || true)
  read -r r c <<< "$s"
  [[ ${c:-} =~ ^[1-9][0-9]*$ ]] || c=${COLUMNS:-80}
  [[ $c =~ ^[1-9][0-9]*$ ]] || c=80
  [ "$c" -gt 24 ] || c=24
  TEXT_W=$((c - 4))
}

text_out() {
  local fd=${1:-1} join=()
  [ "${2:-}" != --join ] || join=(--join)
  text_width "$fd"
  text_wrap ${join[@]+"${join[@]}"} "$TEXT_W" 1>&"$fd"
}

# ask_lines STYLE TEXT...: one paragraph per TEXT, after ASK_IND, in STYLE (an SGR string or ""),
# wrapped at the width of a terminal (as given without one).
ask_lines() {
  local st=$1 w l
  shift
  text_width "$ASK_OUT"
  w=$TEXT_W
  [ "$w" = 0 ] || w=$((w - ${#ASK_IND}))
  [ "$w" -ge 0 ] || w=20
  _ask_style
  while IFS= read -r l; do
    if [ -n "$l" ]; then printf '%s%s%s%s\n' "$ASK_IND" "$st" "$l" "${st:+$ASK_R}"; else printf '\n'; fi
  done < <(printf '%s\n' "$@" | text_wrap "$w") 1>&"$ASK_OUT"
}

# _ask_prompt TEXT HINT: the question, wrapped on a terminal; the cursor stays after HINT.
_ask_prompt() {
  local text="$ASK_IND$1" hint=$2 w body last
  text_width "$ASK_OUT"
  w=$TEXT_W
  if [ "$w" -gt 0 ] && [ $((${#text} + ${#hint} + 1)) -gt "$w" ]; then
    body=$(printf '%s%s\n' "$text" "${hint:+ $hint}" | text_wrap "$w")
    last=${body##*$'\n'}
    [ "$last" = "$body" ] || printf '%s\n' "${body%$'\n'*}" 1>&"$ASK_OUT"
    printf '%s ' "$last" 1>&"$ASK_OUT"
  elif [ -n "$hint" ]; then
    printf '%s %s ' "$text" "$hint" 1>&"$ASK_OUT"
  else
    printf '%s ' "$text" 1>&"$ASK_OUT"
  fi
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
