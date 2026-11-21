#!/usr/bin/env bash
# Verifies the cosign signature of every published image of a release (M28), against the identity of
# this project's release workflow. Nothing is pulled or started: cosign only reads signatures.
#
#   scripts/verify-images.sh [--pull] [--only "api ingest"] [vX.Y.Z]
#
# --pull makes the check the gate for what runs: for each image, cosign verifies the tag and
# reports the digest it verified; the image is then pulled BY THAT DIGEST and the local
# <prefix>-<image>:<version> tag is pointed at it. Nothing the registry serves later under the
# same tag can slip in between the check and the start. Any failure stops with a non-zero exit.
# --expect FILE compares each verified digest with the signed release manifest: FILE holds the
# `image.<name>=sha256:...` lines printed by verify-release.sh. An image that differs, or that the
# manifest does not list, is refused (exit 7) before anything is pulled.
# --only restricts the check (and the pull) to the listed image names, e.g. "api".
#
# The version comes from the argument, then SUCKERPOT_VERSION (environment or .env). The registry
# prefix comes from SUCKERPOT_IMAGE_PREFIX (same lookup, default ghcr.io/selfhostr/suckerpot); the
# GitHub repository whose workflow must have signed the images is taken from that prefix
# (ghcr.io/<owner>/<repo>), so a fork verifies its own releases.
#
# cosign runs in a pinned container (host traffic: it contacts the registry and the Sigstore
# transparency log from this machine, like `docker pull` does; it uses the host network, so it
# resolves names with the host's own DNS, such as a Tailscale or VPN resolver that a container on
# the default bridge cannot reach). It never sees a secret, unless you
# have a registry login in ~/.docker/config.json: that file is then mounted read-only so private
# packages can be read. Set VERIFY_IMAGES_NO_AUTH=1 to skip it.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/engine.sh
. scripts/lib/engine.sh

COSIGN_IMAGE="ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d"
ISSUER="https://token.actions.githubusercontent.com"
IMAGES="redis migrate ingest api collector hubproxy demo sensor-ssh sensor-rdp sensor-telnet sensor-web sensor-redis sensor-docker sensor-mysql sensor-mssql sensor-adb sensor-smb sensor-sip sensor-synology"

die() { echo "verify-images: $*" >&2; exit 1; }

# Reads VAR from the environment or from .env (last assignment wins; quotes removed).
get() {
  eval "val=\${$1:-}"
  if [ -z "$val" ] && [ -f .env ]; then
    val=$(sed -n "s/^$1=//p" .env | tail -n 1 | tr -d "\"' \r")
  fi
  printf '%s' "${val:-$2}"
}

pull=0
only=""
expect_file=""
while [ $# -gt 0 ]; do
  case $1 in
    --pull) pull=1; shift ;;
    --expect) [ $# -ge 2 ] || die "--expect needs a file"; expect_file=$2; shift 2 ;;
    --only) [ $# -ge 2 ] || die "--only needs a list of image names"; only=$2; shift 2 ;;
    --*) die "unknown option: $1" ;;
    *) break ;;
  esac
done
if [ -n "$only" ]; then
  for name in $only; do
    case " $IMAGES " in *" $name "*) ;; *) die "unknown image name: $name" ;; esac
  done
  IMAGES=$only
fi

version=${1:-$(get SUCKERPOT_VERSION '')}
[ -n "$version" ] || die "no version: pass vX.Y.Z or set SUCKERPOT_VERSION"
printf '%s' "$version" | grep -Eq '^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' \
  || die "'$version' is not a release version (vX.Y.Z); a source build has nothing to verify"

# hubproxy exists from M32 on (v0.6.0). An older release does not have the image, so it is neither
# verified nor pulled for it: that keeps a rollback to a pre-M32 release working. The signal is the
# release tree (hubproxy/Dockerfile in the tag); a tag this checkout does not know falls back to
# the version number. A participant install cannot run without hubproxy, so it refuses such a target.
ships_hubproxy=0
if git rev-parse -q --verify "refs/tags/$version" > /dev/null 2>&1; then
  if git cat-file -e "$version:hubproxy/Dockerfile" > /dev/null 2>&1; then ships_hubproxy=1; fi
elif [ "$(printf '%s\n%s\n' "${version#v}" 0.6.0 | sort -V | head -n 1)" = 0.6.0 ]; then
  ships_hubproxy=1
fi
if [ "$ships_hubproxy" = 0 ]; then
  if [ "$(get SUCKERPOT_STACK_MODE full)" = participant ]; then
    die "$version has no hubproxy image; a participant install needs a release from v0.6.0 on"
  fi
  case " $IMAGES " in
    *" hubproxy "*)
      if [ "$only" = hubproxy ]; then die "$version has no hubproxy image"; fi
      IMAGES=$(printf '%s\n' "$IMAGES" | sed 's/ hubproxy / /; s/^hubproxy //; s/ hubproxy$//')
      ;;
  esac
fi

prefix=$(get SUCKERPOT_IMAGE_PREFIX ghcr.io/selfhostr/suckerpot)
printf '%s' "$prefix" | grep -Eq '^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$' \
  || die "SUCKERPOT_IMAGE_PREFIX must look like ghcr.io/<owner>/<name>"
repo=${prefix#ghcr.io/}
# Dots in the repository path are literal in the identity pattern; the owner part is matched
# case-insensitively because GHCR names are lower case and GitHub account names are not.
escaped=$(printf '%s' "$repo" | sed 's/\./\\./g')
identity="^https://github\\.com/$escaped/\\.github/workflows/release\\.yml@refs/tags/$(printf '%s' "$version" | sed 's/\./\\./g')\$"

auth=()
if [ "${VERIFY_IMAGES_NO_AUTH:-0}" != 1 ] && [ -f "$HOME/.docker/config.json" ]; then
  auth=(-v "$HOME/.docker/config.json:/home/nonroot/.docker/config.json:ro")
fi
errlog=$(mktemp)
outlog=$(mktemp)
trap 'rm -f "$errlog" "$outlog"' EXIT

echo "verify-images: $version, signer github.com/$repo release workflow"
fail=0
mismatch=0
for image in $IMAGES; do
  ref="$prefix-$image:$version"
  if ctr run --rm --network host --user 65532:65532 --read-only --cap-drop ALL \
      --security-opt no-new-privileges:true --tmpfs /tmp:rw,noexec,nosuid,size=32m,uid=65532,gid=65532 \
      -e HOME=/tmp -e TUF_ROOT=/tmp/tuf ${auth[@]+"${auth[@]}"} \
      -e DOCKER_CONFIG=/home/nonroot/.docker \
      "$COSIGN_IMAGE" verify \
      --certificate-identity-regexp "(?i)$identity" \
      --certificate-oidc-issuer "$ISSUER" \
      "$ref" >"$outlog" 2>"$errlog"; then
    # The digest cosign verified (exactly one distinct value, or the image is refused).
    digests=$(grep -o '"docker-manifest-digest" *: *"sha256:[0-9a-f]\{64\}"' "$outlog" | grep -o 'sha256:[0-9a-f]\{64\}' | sort -u || true)
    if [ "$(printf '%s\n' "$digests" | grep -c .)" -ne 1 ]; then
      echo "  FAILED  $image (no single verified digest in the cosign output)" >&2
      fail=1
      continue
    fi
    if [ -n "$expect_file" ]; then
      signed=$(sed -n "s/^image\\.$image=//p" "$expect_file" | head -n 1)
      if [ "$signed" != "$digests" ]; then
        echo "  REFUSED $image (verified $digests, the signed manifest says ${signed:-nothing})" >&2
        mismatch=1
        continue
      fi
    fi
    if [ "$pull" = 1 ]; then
      if ctr pull --quiet "$prefix-$image@$digests" >/dev/null 2>"$errlog" \
        && ctr tag "$prefix-$image@$digests" "$ref"; then
        echo "  ok      $image ($digests)"
      else
        echo "  FAILED  $image (could not pull the verified digest)" >&2
        sed 's/^/          /' "$errlog" | tail -n 3 >&2
        fail=1
      fi
    else
      echo "  ok      $image ($digests)"
    fi
  else
    echo "  FAILED  $image" >&2
    sed 's/^/          /' "$errlog" | tail -n 3 >&2
    fail=1
  fi
done

if [ "$mismatch" -ne 0 ]; then
  echo "verify-images: an image digest differs from the signed release manifest: do not run this version" >&2
  exit 7
fi
if [ "$fail" -ne 0 ]; then
  die "at least one image did not verify: do not run this version"
fi
echo "verify-images: all $(echo "$IMAGES" | wc -w | tr -d ' ') images carry a valid signature"
[ "$pull" = 0 ] || echo "verify-images: pulled by verified digest and tagged $version"
