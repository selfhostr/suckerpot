#!/bin/sh
# SuckerPot: fetch a node, check it, and start its menu. No git and no clone needed.
#
#   curl -fsSLO https://github.com/selfhostr/suckerpot/releases/latest/download/get.sh
#   sh get.sh [--dir DIR] [--version vX.Y.Z] [--yes] [--no-menu]
#
# What it does, in this order, and nothing else (it says so before it starts):
#   1. finds the newest release (or takes --version) on GitHub;
#   2. downloads three files of that release: the node bundle (suckerpot-node-vX.Y.Z.tar.gz: the
#      compose files, scripts and settings a node needs, not the sources), the signed release
#      manifest and its Sigstore signature;
#   3. checks the signature with cosign (a pinned release of cosign, itself checked against its
#      SHA-256): the manifest must be signed by the release workflow of this repository for that
#      very tag; then the bundle's SHA-256 must be the one in the manifest. Anything else stops
#      here, and nothing is written outside a temporary folder;
#   4. creates DIR (default ~/suckerpot; it must not exist, or be empty), unpacks the bundle there
#      (only plain files and folders, every path inside DIR);
#   5. starts DIR/suckerpot.sh, the menu (unless --no-menu, or without a terminal).
# It never calls sudo. Run it as your user (the installer asks for sudo itself, only where it needs
# it), or as root: started with sudo, the folder goes to the home of the user who called sudo and
# belongs to them, and the menu then runs as root without asking for any password again.
#
# Testing a branch before a release (NOT SIGNED: only HTTPS protects the download):
#   sh get.sh --ref dev [--dir DIR]
# fetches the branch as GitHub archives it and keeps only the files of the bundle. The install
# then runs the scripts of that branch with the signed images of the newest release.
set -eu

REPO=${SUCKERPOT_REPO:-selfhostr/suckerpot}
GH=https://github.com
CODELOAD=https://codeload.github.com
# The tests point these at local files (only with SELFHOSTR_TEST_INSTALL=1).
if [ "${SELFHOSTR_TEST_INSTALL:-}" = 1 ]; then
  GH=${SELFHOSTR_GET_GH:-$GH}
  CODELOAD=${SELFHOSTR_GET_CODELOAD:-$CODELOAD}
fi
COSIGN_VERSION=v3.1.4
COSIGN_SHA256_AMD64=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
COSIGN_SHA256_ARM64=ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2
ISSUER=https://token.actions.githubusercontent.com

# On a terminal the long lines wrap at word boundaries (78 columns); otherwise as they are.
say() { if [ -t 1 ]; then printf '%s\n' "$*" | fold -s -w 78; else printf '%s\n' "$*"; fi; }
die() { printf 'get: %s\n' "$*" >&2; exit 1; }

owner=""
uid=${SELFHOSTR_EUID:-$(id -u)}
if [ "$uid" = 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] \
  && printf '%s' "$SUDO_USER" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$'; then
  owner=$SUDO_USER
fi
home=${HOME:-}
if [ -n "$owner" ]; then
  home=$(getent passwd "$owner" 2> /dev/null | cut -d: -f6 || true)
  [ -n "$home" ] || home=${HOME:-}
fi
dir="$home/suckerpot"
version=""
ref=""
yes=0
menu=1
while [ $# -gt 0 ]; do
  case $1 in
    --dir) [ $# -ge 2 ] || die "--dir needs a folder"; dir=$2; shift ;;
    --version) [ $# -ge 2 ] || die "--version needs vX.Y.Z"; version=$2; shift ;;
    --ref | --branch) [ $# -ge 2 ] || die "--ref needs a branch name"; ref=$2; shift ;;
    --yes | -y) yes=1 ;;
    --no-menu) menu=0 ;;
    -h | --help) sed -n '2,/^set -eu/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (sh get.sh --help)" ;;
  esac
  shift
done
[ -z "$version" ] || [ -z "$ref" ] || die "--version and --ref exclude each other"
if [ -n "$version" ]; then
  printf '%s' "$version" | grep -Eq '^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || die "--version must look like v1.2.3"
fi
if [ -n "$ref" ]; then
  printf '%s' "$ref" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$' || die "bad --ref name"
  case $ref in *..*) die "bad --ref name" ;; esac
fi
case $dir in /*) ;; "") die "no home folder: pass --dir /path" ;; *) dir="$PWD/$dir" ;; esac

for tool in curl tar gzip sha256sum uname mktemp; do
  command -v "$tool" > /dev/null 2>&1 || die "$tool is needed (install it with your package manager)"
done
command -v bash > /dev/null 2>&1 || die "bash is needed by the node's scripts (install bash)"
if [ -e "$dir" ] && [ -n "$(ls -A "$dir" 2> /dev/null)" ]; then
  if [ -f "$dir/.env" ] || [ -f "$dir/.suckerpot-bundle" ]; then
    die "$dir already holds a SuckerPot node: run $dir/suckerpot.sh (its menu updates, edits and removes it)"
  fi
  die "$dir exists and is not empty: pass --dir with a new folder"
fi

tty=0
if [ -r /dev/tty ] && (: < /dev/tty) 2> /dev/null; then tty=1; fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

get() { curl -fsSL --proto '=https' --tlsv1.2 --retry 2 --max-time "${3:-120}" -o "$2" "$1"; }

if [ -z "$ref" ] && [ -z "$version" ]; then
  url=$(curl -fsSLI --proto '=https' --tlsv1.2 --max-time 30 -o /dev/null -w '%{url_effective}' "$GH/$REPO/releases/latest") \
    || die "could not ask GitHub for the newest release (no network?)"
  version=${url##*/}
  printf '%s' "$version" | grep -Eq '^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || die "GitHub named no release ('$version')"
fi

say ""
say "SuckerPot node setup"
say ""
if [ -n "$ref" ]; then
  say "  !! TESTING BUILD, NOT SIGNED: the files come from the branch '$ref' of github.com/$REPO."
  say "  !! Only HTTPS protects the download; no release signature is checked. Use it to test."
  say ""
  say "  This will:"
  say "    - download $CODELOAD/$REPO/tar.gz/refs/heads/$ref"
  say "    - keep only the files of a node (config/node-bundle.list), in $dir"
else
  say "  This will:"
  say "    - download the node bundle of $version and its signed release manifest from"
  say "      $GH/$REPO/releases/tag/$version"
  say "    - download cosign $COSIGN_VERSION (checked against its pinned SHA-256) and check that the"
  say "      manifest is signed by the release workflow of $REPO for $version, and that the"
  say "      bundle is the one the manifest names (anything else: stop, nothing written)"
  say "    - create $dir and unpack the bundle there"
fi
[ "$menu" = 0 ] || say "    - start $dir/suckerpot.sh (the menu: install, status, edit, update, remove)"
me=$(id -un 2> /dev/null || true)
if [ -n "$owner" ]; then
  say "  It runs as root (started with sudo) and calls no sudo; $dir will belong to $owner."
else
  say "  It runs as ${me:-your user} and calls no sudo."
fi
say ""
if [ "$yes" = 0 ]; then
  [ "$tty" = 1 ] || die "no terminal to ask on: add --yes to go ahead"
  if [ -n "$ref" ]; then printf '  Type yes to install this unsigned testing build: '; else printf '  Go ahead? [Y/n] '; fi
  IFS= read -r a < /dev/tty || a=n
  if [ -n "$ref" ]; then
    [ "$a" = yes ] || die "nothing was done"
  else
    case $a in "" | y | Y | yes) ;; *) die "nothing was done" ;; esac
  fi
fi

# safe_tar FILE: every entry is a plain file or folder, its path relative and inside.
safe_tar() {
  tar -tvzf "$1" > "$work/list.v" 2> /dev/null || die "the archive is damaged"
  if awk '{ t = substr($1, 1, 1); if (t != "-" && t != "d") bad = 1 } END { exit !bad }' "$work/list.v"; then
    die "the archive holds links or special files: refused"
  fi
  tar -tzf "$1" > "$work/list" 2> /dev/null || die "the archive is damaged"
  if grep -Eq '(^/|(^|/)\.\.(/|$))' "$work/list"; then die "the archive has a path outside its folder: refused"; fi
}

stage=$work/stage
mkdir -p "$stage"
umask 022
if [ -n "$ref" ]; then
  say "Downloading the branch $ref..."
  get "$CODELOAD/$REPO/tar.gz/refs/heads/$ref" "$work/branch.tar.gz" 300 || die "could not download the branch $ref"
  safe_tar "$work/branch.tar.gz"
  top=$(head -n 1 "$work/list" | cut -d/ -f1)
  [ -n "$top" ] || die "the archive is empty"
  tar -xzf "$work/branch.tar.gz" -C "$work" "$top/config/node-bundle.list" 2> /dev/null \
    || die "the branch $ref has no config/node-bundle.list: it cannot be installed this way"
  # The commit GitHub archived (git archive writes it into the archive's comment).
  commit=$(gzip -dc "$work/branch.tar.gz" | head -c 1024 | tr -c 'a-f0-9' '\n' | grep -E '^[0-9a-f]{40}$' | head -n 1 || true)
  : > "$work/want"
  while IFS= read -r line; do
    case $line in "" | \#*) continue ;; esac
    grep -E "^$top/$(printf '%s' "$line" | sed 's/[.]/\\./g; s/[*]/[^\/]*/g')\$" "$work/list" >> "$work/want" || true
  done < "$work/$top/config/node-bundle.list"
  # Files only: a folder in the list would bring all of it (and the file names a second time).
  grep -v '/$' "$work/want" | sort -u > "$work/want.u" || true
  [ -s "$work/want.u" ] || die "no file of the bundle list was found in the branch"
  tar -xzf "$work/branch.tar.gz" -C "$work" -T "$work/want.u"
  (cd "$work/$top" && tar -cf - .) | (cd "$stage" && tar -xf -)
  latest=$(curl -fsSLI --proto '=https' --tlsv1.2 --max-time 30 -o /dev/null -w '%{url_effective}' "$GH/$REPO/releases/latest" 2> /dev/null || true)
  latest=${latest##*/}
  printf '%s' "$latest" | grep -Eq '^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || latest=""
  printf 'version=%s\nref=%s\ncommit=%s\nsigned=0\nlatest=%s\n' "${latest:-unknown}" "$ref" "${commit:-unknown}" "$latest" > "$stage/.suckerpot-bundle"
else
  base="$GH/$REPO/releases/download/$version"
  bundle="suckerpot-node-$version.tar.gz"
  say "Downloading the node bundle of $version..."
  get "$base/release-manifest.json" "$work/release-manifest.json" 30 || die "$version has no signed release manifest"
  get "$base/release-manifest.json.sigstore.json" "$work/release-manifest.json.sigstore.json" 30 || die "the manifest of $version has no signature"
  get "$base/$bundle" "$work/$bundle" 300 || die "$version has no node bundle (it predates them: use a newer release, or --ref to test)"
  case $(uname -m) in
    x86_64 | amd64) arch=amd64 sum=$COSIGN_SHA256_AMD64 ;;
    aarch64 | arm64) arch=arm64 sum=$COSIGN_SHA256_ARM64 ;;
    *) die "no pinned cosign for $(uname -m)" ;;
  esac
  cosign=$work/cosign
  if [ "${SELFHOSTR_TEST_INSTALL:-}" = 1 ] && [ -n "${SELFHOSTR_GET_COSIGN:-}" ]; then
    cp "$SELFHOSTR_GET_COSIGN" "$cosign"
    sum=$(sha256sum "$cosign" | cut -d' ' -f1)
  else
    say "Downloading cosign $COSIGN_VERSION to check the signature..."
    get "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-$arch" "$cosign" 120 \
      || die "could not download cosign"
  fi
  printf '%s  %s\n' "$sum" "$cosign" | sha256sum -c - > /dev/null 2>&1 || die "cosign does not have its pinned SHA-256: refused"
  chmod 700 "$cosign"
  tag_re=$(printf '%s' "$version" | sed 's/[.]/\\./g')
  repo_re=$(printf '%s' "$REPO" | sed 's/[.]/\\./g')
  if ! "$cosign" verify-blob --bundle "$work/release-manifest.json.sigstore.json" \
    --certificate-identity-regexp "(?i)^https://github\.com/$repo_re/\.github/workflows/release\.yml@refs/tags/$tag_re\$" \
    --certificate-oidc-issuer "$ISSUER" "$work/release-manifest.json" > "$work/cosign.out" 2>&1; then
    tail -n 3 "$work/cosign.out" | sed 's/^/    /' >&2
    die "the release manifest of $version is NOT signed by the release workflow: refused, nothing was installed"
  fi
  flat=$(tr -d '\n\r' < "$work/release-manifest.json")
  m_version=$(printf '%s' "$flat" | sed -n 's/.*"version" *: *"\([^"]*\)".*/\1/p')
  m_bundle=$(printf '%s' "$flat" | sed -n 's/.*"node_bundle_sha256" *: *"\([0-9a-f]\{64\}\)".*/\1/p')
  m_commit=$(printf '%s' "$flat" | sed -n 's/.*"commit" *: *"\([0-9a-f]\{40\}\)".*/\1/p')
  [ "$m_version" = "$version" ] || die "the signed manifest is for '$m_version', not $version: refused"
  [ -n "$m_bundle" ] || die "the signed manifest of $version names no node bundle: refused"
  have=$(sha256sum "$work/$bundle" | cut -d' ' -f1)
  [ "$have" = "$m_bundle" ] || die "the node bundle does not have the SHA-256 of the signed manifest: refused, nothing was installed"
  say "  The manifest is signed by the release workflow of $REPO for $version; the bundle matches it."
  safe_tar "$work/$bundle"
  tar -xzf "$work/$bundle" -C "$stage"
  grep -q "^commit=$m_commit\$" "$stage/.suckerpot-bundle" 2> /dev/null || die "the bundle names another commit than the signed manifest: refused"
fi
[ -f "$stage/suckerpot.sh" ] && [ -f "$stage/scripts/install.sh" ] || die "the bundle has no suckerpot.sh or scripts/install.sh: refused"

mkdir -p "$dir"
(cd "$stage" && tar -cf - .) | (cd "$dir" && tar -xf -)
chmod 755 "$dir"
if [ -n "$owner" ]; then
  chown -R "$owner:" "$dir" 2> /dev/null || say "  warning: could not give $dir to $owner (chown -R $owner: $dir)"
fi
say ""
say "SuckerPot is in $dir ($(cd "$dir" && find . -type f | wc -l | tr -d ' ') files$( [ -n "$ref" ] && printf ', testing build of %s, NOT signed' "$ref" || printf ', %s, signed' "$version"))."
say "Everything else happens from there:  cd $dir && ./suckerpot.sh"
if [ "$menu" = 1 ] && [ "$tty" = 1 ]; then
  cd "$dir"
  exec bash ./suckerpot.sh < /dev/tty
fi
