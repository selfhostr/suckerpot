#!/usr/bin/env bash
# End-to-end check of the Telnet sensor: log in like a Mirai-style bot from a
# throwaway container, run a few commands (one is a fake download), then wait until
# the session is visible through the API. Used by `just telnet-test` and by CI.
# The API must be reachable without a login (API_AUTH_DISABLED=true in .env).
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/engine.sh
. scripts/lib/engine.sh
TELNET_PORT=${TELNET_HOST_PORT:-23}
API_URL=${API_URL:-http://127.0.0.1:${DASHBOARD_PORT:-8443}}

echo "== Telnet login against 127.0.0.1:${TELNET_PORT}"
ctr run --rm --network host -v "$PWD/scripts:/s:ro" docker.io/library/python:3.15.2-slim-trixie \
  python -I /s/telnet-test.py 127.0.0.1 "${TELNET_PORT}"

echo "== waiting for the events to reach the API (max 60 s)"
for _ in $(seq 1 30); do
  if curl -fsS "${API_URL}/api/v1/sessions?sensor=telnet&limit=20" 2>/dev/null | grep -q '"downloads":[1-9]'; then
    echo "OK: a Telnet session with a recorded download is visible through the API."
    exit 0
  fi
  sleep 2
done
echo "FAIL: no Telnet session with a download appeared in the API within 60 s." >&2
exit 1
