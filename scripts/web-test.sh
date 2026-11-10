#!/usr/bin/env bash
# End-to-end check of the web sensor: from a throwaway container, post credentials to
# the fake WordPress login and send a PHP upload-progress multipart request carrying PHP code (the
# PHP2Shell trigger), then wait until the session shows up in the API tagged php2shell.
# Used by `just http-test` and by CI. The API must be reachable without a login
# (docker-compose.ci.yml).
set -euo pipefail

cd "$(dirname "$0")/.."
HTTP_PORT=${HTTP_HOST_PORT:-80}
API_URL=${API_URL:-http://127.0.0.1:${DASHBOARD_PORT:-8443}}

echo "== HTTP requests against 127.0.0.1:${HTTP_PORT}"
docker run --rm --network host --entrypoint sh curlimages/curl:8.11.1 -c "
  set -e
  base=http://127.0.0.1:${HTTP_PORT}
  curl -sS -o /dev/null -w 'wp-login: %{http_code}\n' -A 'Mozilla/5.0 ci-test' \
    -d 'log=admin&pwd=ci-password-1&wp-submit=Log+In' \$base/wp-login.php
  curl -sS -o /dev/null -w 'upload-progress: %{http_code}\n' -A 'Mozilla/5.0 ci-test' \
    -H 'Cookie: PHPSESSID=cisession1' \
    --form-string 'PHP_SESSION_UPLOAD_PROGRESS=<?php echo 1; ?>' \
    --form-string 'file=hello;filename=a.txt;type=text/plain' \$base/index.php
"

echo "== waiting for a php2shell-tagged web session in the API (max 60 s)"
for _ in $(seq 1 30); do
  if curl -fsS "${API_URL}/api/v1/sessions?sensor=web&tag=php2shell&limit=5" 2>/dev/null | grep -q '"sensor":"web"'; then
    echo "OK: a web session tagged php2shell is visible through the API."
    exit 0
  fi
  sleep 2
done
echo "FAIL: no php2shell web session appeared in the API within 60 s." >&2
exit 1
