#!/usr/bin/env bash
# Black-box run of real scanners against a built image. Run from the repository root:
#   sensors/web/tests/blackbox.sh
# Needs docker (all containers are throwaway, networks and the image are removed at the end).
set -euo pipefail
NET=sp-web-bb
docker network create $NET >/dev/null
docker run -d --rm --name sp-web-bb-redis --network $NET valkey/valkey:9.1-alpine3.24 >/dev/null
docker build -q -f sensors/web/Dockerfile -t sp-web-bb:dev . >/dev/null
docker run -d --rm --name sp-web-bb --network $NET -e REDIS_HOST=sp-web-bb-redis \
  -e EVENTS_STREAM=events:web -e WEB_CONN_RATE=200 -e WEB_CONN_BURST=400 -e WEB_MAX_PER_IP=50 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001 \
  --cap-drop ALL --security-opt no-new-privileges:true sp-web-bb:dev >/dev/null
trap 'docker rm -f sp-web-bb sp-web-bb-redis >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; docker rmi sp-web-bb:dev >/dev/null 2>&1' EXIT
sleep 5
docker run --rm --network $NET instrumentisto/nmap -sV -p 8080,8443 \
  --script http-headers,http-title,ssl-cert,http-methods,http-generator sp-web-bb
docker run --rm --network $NET ghcr.io/sullo/nikto -h http://sp-web-bb:8080 -maxtime 150s -nointeractive
docker run --rm --network $NET --entrypoint sh projectdiscovery/nuclei -c \
  'nuclei -ut -nc >/dev/null 2>&1; timeout 240 nuclei -u http://sp-web-bb:8080 -tags wordpress,phpmyadmin,phpinfo,apache,php,exposure -rl 150 -c 20 -nc -silent'
