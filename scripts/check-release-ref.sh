#!/usr/bin/env bash
# Refuses a release that does not come from reviewed code on main.
#
# Usage: scripts/check-release-ref.sh TAG COMMIT [MAIN_REF]
#
#   TAG       the pushed tag, which must be exactly vMAJOR.MINOR.PATCH
#   COMMIT    the commit the tag points at (GITHUB_SHA in the release workflow)
#   MAIN_REF  the ref that holds the reviewed history (default: origin/main)
#
# Fails, with one line per failed condition on stderr, unless:
#   1. TAG looks like v1.2.3 (digits only, no suffix);
#   2. COMMIT is an ancestor of MAIN_REF (or MAIN_REF itself).
# There is no second version file to compare with: the version of a release is the tag, and the
# build stamps it into the images (see docs/updates.md). Run it from a clone with enough history.
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 TAG COMMIT [MAIN_REF]" >&2
  exit 2
fi
tag=$1
commit=$2
main_ref=${3:-origin/main}
failed=0

if [[ ! $tag =~ ^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "FAIL: the tag must look like vMAJOR.MINOR.PATCH (for example v1.2.3)." >&2
  failed=1
fi

if ! git rev-parse --verify --quiet "${commit}^{commit}" > /dev/null; then
  echo "FAIL: the commit is not in this clone." >&2
  failed=1
elif ! git rev-parse --verify --quiet "${main_ref}^{commit}" > /dev/null; then
  echo "FAIL: ${main_ref} is not available: fetch it first." >&2
  failed=1
elif ! git merge-base --is-ancestor "$commit" "$main_ref"; then
  echo "FAIL: commit ${commit} is not part of ${main_ref}: a release must be built from reviewed code merged to main." >&2
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "OK: ${tag} points at ${commit}, which is on ${main_ref}."
