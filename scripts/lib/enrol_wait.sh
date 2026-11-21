#!/usr/bin/env bash
# Waits for the network worker to finish a join (participant installs). Source this file after
# scripts/lib/engine.sh; it defines functions only.
#
#   json_top_string KEY      prints the top-level string KEY of a JSON document on stdin
#   enrol_wait [SECONDS]     prints "<state> <error_code>" once the join is decided, or
#                            "enrolling -" when SECONDS (default SUCKERPOT_ENROL_WAIT or 300) ran out
#
# The proof of work of an enrolment can take minutes on a small machine. Nothing here prints a
# secret: the network status holds none.

# A grep over the whole document is wrong: the nested verifier, consent and membership objects
# have their own "state" keys.
json_top_string() {
  awk -v key="$1" 'BEGIN { RS = "\001" }
  {
    n = length($0); depth = 0; instr = 0; esc = 0; tok = ""; want = 0
    for (i = 1; i <= n; i++) {
      c = substr($0, i, 1)
      if (instr) {
        if (esc) { esc = 0; tok = tok c }
        else if (c == "\\") esc = 1
        else if (c == "\"") {
          instr = 0
          if (depth == 1) {
            if (want) { print tok; exit }
            j = i + 1
            while (substr($0, j, 1) == " ") j++
            if (substr($0, j, 1) == ":" && tok == key) want = 1
          }
        } else tok = tok c
      } else if (c == "\"") { instr = 1; tok = "" }
      else if (want && depth == 1 && c == "n") { exit }
      else if (c == "{" || c == "[") depth++
      else if (c == "}" || c == "]") depth--
    }
  }'
}

enrol_wait() {
  local limit=${1:-${SUCKERPOT_ENROL_WAIT:-300}} waited=0 doc st code
  while :; do
    doc=$(dc exec -T ingest python -m ingest.network.cli status --json 2> /dev/null) || doc=""
    st=$(printf '%s' "$doc" | json_top_string state)
    code=$(printf '%s' "$doc" | json_top_string error_code)
    case $st in
      "") echo "unknown -"; return 0 ;;  # ingest did not answer: say nothing about the join
      not_joined | off | enrolling) ;;
      *) echo "$st ${code:--}"; return 0 ;;
    esac
    if [ "$waited" -ge "$limit" ]; then
      echo "enrolling ${code:--}"
      return 0
    fi
    sleep 5
    waited=$((waited + 5))
  done
}
