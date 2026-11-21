#!/usr/bin/env bash
# Pseudonyms of network participants (M32). Source this file; it defines functions only.
#
#   pseudonym_valid NAME     succeeds when NAME follows the hub's rules (docs/network-protocol.md)
#   pseudonym_random         prints "adjective-noun-NN" built from the shipped word lists
#
# The hub checks the same rules again; checking here only gives a fast, clear error before the
# install starts. The words come from netproto/suckerpot_netproto/data/pseudonym_words.txt
# ([adjectives] and [nouns] sections, one lowercase word per line).

PSEUDONYM_WORDS=${PSEUDONYM_WORDS:-netproto/suckerpot_netproto/data/pseudonym_words.txt}

# Succeeds for a pseudonym the hub accepts. On failure prints the reason on stderr.
pseudonym_valid() {
  local name=$1 norm word
  if ! [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9\ _.-]{1,22}[A-Za-z0-9]$ ]]; then
    echo "a pseudonym has 3 to 24 characters: letters, digits, space, _ . -, starting and ending with a letter or digit" >&2
    return 1
  fi
  if [[ $name == *"  "* ]]; then
    echo "a pseudonym must not have two spaces in a row" >&2
    return 1
  fi
  if [[ $name =~ [0-9]{4} ]]; then
    echo "a pseudonym must not contain a run of four digits" >&2
    return 1
  fi
  norm=$(printf %s "$name" | tr '[:upper:]' '[:lower:]' | tr -d ' _.-')
  for word in admin administrator root hub official moderator staff support system network node; do
    if [ "$norm" = "$word" ]; then
      echo "'$name' is a reserved word" >&2
      return 1
    fi
  done
  case $norm in
    *suckerpot* | *selfhostr* | *honeypot*)
      echo "a pseudonym must not contain the project name or 'honeypot'" >&2
      return 1
      ;;
  esac
  return 0
}

# Prints the words of one section ("adjectives" or "nouns").
_pseudonym_section() {
  awk -v want="[$1]" '
    /^#/ || /^[[:space:]]*$/ { next }
    /^\[/ { on = ($0 == want); next }
    on { print }
  ' "$PSEUDONYM_WORDS"
}

# A random integer in 0..$1-1 from the kernel's random source.
_pseudonym_rand() {
  local n
  n=$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')
  printf '%s' "$((n % $1))"
}

# Prints a random valid pseudonym, for example "amber-falcon-42".
pseudonym_random() {
  local -a adj noun
  local a n tries=0 name
  [ -r "$PSEUDONYM_WORDS" ] || { echo "word list not found: $PSEUDONYM_WORDS" >&2; return 1; }
  mapfile -t adj < <(_pseudonym_section adjectives)
  mapfile -t noun < <(_pseudonym_section nouns)
  [ "${#adj[@]}" -gt 0 ] && [ "${#noun[@]}" -gt 0 ] || { echo "word list is empty" >&2; return 1; }
  while [ "$tries" -lt 20 ]; do
    a=${adj[$(_pseudonym_rand "${#adj[@]}")]}
    n=${noun[$(_pseudonym_rand "${#noun[@]}")]}
    name=$(printf '%s-%s-%02d' "$a" "$n" "$((10 + $(_pseudonym_rand 90)))")
    if pseudonym_valid "$name" 2> /dev/null; then
      printf '%s' "$name"
      return 0
    fi
    tries=$((tries + 1))
  done
  echo "could not build a valid pseudonym from the word lists" >&2
  return 1
}

# Prints NAME with a short random suffix ("bignoe3" -> "bignoe3-42"), for a name the hub refused
# as taken. The base is shortened so the result still has at most 24 characters.
pseudonym_suggest() {
  local base=$1 tries=0 name
  base=${base:0:21}
  base=${base%[ _.-]}
  while [ "$tries" -lt 20 ]; do
    name=$(printf '%s-%02d' "$base" "$((10 + $(_pseudonym_rand 90)))")
    if pseudonym_valid "$name" 2> /dev/null; then
      printf '%s' "$name"
      return 0
    fi
    tries=$((tries + 1))
  done
  pseudonym_random
}
