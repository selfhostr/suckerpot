#!/usr/bin/env bash
# Packs the node bundle of a release: the files of config/node-bundle.list, plus .suckerpot-bundle
# (what they are), in a reproducible tar.gz (sorted names, fixed times and owners, no gzip name or
# time). The release workflow runs it on the tag and signs its SHA-256 in the release manifest;
# scripts/get.sh and the update of a bundle install check that hash before they unpack anything.
#
#   scripts/make-bundle.sh VERSION OUT.tar.gz
#
# SOURCE_DATE_EPOCH, when set, is the time of every entry (else the commit time, else 0).
# BUNDLE_COMMIT names the commit (else git rev-parse HEAD; the tests set it).
set -euo pipefail

caller=$PWD
cd "$(dirname "$0")/.."
die() { echo "make-bundle: $*" >&2; exit 1; }
[ $# -eq 2 ] || die "usage: make-bundle.sh VERSION OUT.tar.gz"
version=$1 out=$2
[[ $version =~ ^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || die "VERSION must look like v1.2.3"
case $out in /*) ;; *) out="$caller/$out" ;; esac

files=()
shopt -s nullglob
while IFS= read -r line; do
  case $line in "" | \#*) continue ;; esac
  # shellcheck disable=SC2206 # the line is a glob on purpose
  matches=($line)
  [ "${#matches[@]}" -gt 0 ] || die "nothing matches '$line' (config/node-bundle.list)"
  for f in "${matches[@]}"; do
    [ -f "$f" ] && [ ! -L "$f" ] || die "'$f' is not a plain file"
    files+=("$f")
  done
done < config/node-bundle.list
shopt -u nullglob

commit=${BUNDLE_COMMIT:-$(git rev-parse HEAD 2> /dev/null || echo unknown)}
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2> /dev/null || echo 0)}
[[ $epoch =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be a number"

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
umask 022
for f in "${files[@]}"; do
  mkdir -p "$stage/$(dirname "$f")"
  cp -p "$f" "$stage/$f"
  chmod u+rw,go+r,go-w "$stage/$f"
done
printf 'version=%s\nref=%s\ncommit=%s\nsigned=1\nlatest=%s\n' "$version" "$version" "$commit" "$version" > "$stage/.suckerpot-bundle"
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner --format=gnu \
  -C "$stage" -cf - . | gzip -9n > "$out"
echo "make-bundle: $out: $(( ${#files[@]} + 1 )) files, sha256 $(sha256sum "$out" | cut -d' ' -f1)"
