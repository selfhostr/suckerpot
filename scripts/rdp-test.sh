#!/usr/bin/env bash
# End-to-end check of the RDP sensor: send a real X.224 Connection Request from a
# throwaway container, then wait until the session is visible through the API.
# Used by `just rdp-test` and by CI.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/engine.sh
. scripts/lib/engine.sh
RDP_PORT=${RDP_HOST_PORT:-3389}
API_URL=${API_URL:-http://127.0.0.1:${DASHBOARD_PORT:-8443}}

echo "== RDP connection request against 127.0.0.1:${RDP_PORT}"
ctr run --rm --network host -v "$PWD/scripts:/s:ro" docker.io/library/python:3.15.2-slim-trixie \
  python -I /s/rdp-test.py 127.0.0.1 "${RDP_PORT}" ci-user

echo "== waiting for the events to reach the API (max 60 s)"
for _ in $(seq 1 30); do
  if curl -fsS "${API_URL}/api/v1/sessions?sensor=rdp&limit=5" 2>/dev/null | grep -q '"sensor":"rdp"'; then
    echo "OK: an RDP session is visible through the API."
    exit 0
  fi
  sleep 2
done
echo "FAIL: no RDP session appeared in the API within 60 s." >&2
exit 1
