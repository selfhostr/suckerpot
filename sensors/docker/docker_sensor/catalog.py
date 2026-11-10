"""Catalogue of plausible applications and base images a small Docker host runs.

A deployment draws its own subset (see profile.py), so the container list is never the same
on two installs. Tags are real, current ones.
"""

from __future__ import annotations

# Application images a small host runs: (repo, current tags, size, command, ports, service names).
# A port is (private, published choices), 0 meaning not published. Each install draws its own
# few of these, so the container list differs from one install to the next.
_Port = tuple[int, tuple[int, ...]]
_App = tuple[str, tuple[str, ...], int, str, tuple[_Port, ...], tuple[str, ...]]
APPS: list[_App] = [
    ("nginx", ("1.27.2", "1.27.1", "1.26.2", "1.27-alpine", "stable-alpine"), 192_000_000,
     "nginx -g 'daemon off;'", ((80, (80, 8080, 8081)),),
     ("web", "proxy", "nginx", "edge-proxy", "frontend", "gateway")),
    ("postgres", ("16.4", "16.3", "15.8", "17.0", "16-alpine", "15-alpine"), 432_000_000,
     "docker-entrypoint.sh postgres", ((5432, (0, 0, 5432)),),
     ("db", "postgres", "database", "pg", "app-db")),
    ("redis", ("7.4.1", "7.2.6", "7.0.15", "7.4-alpine", "6.2-alpine"), 117_000_000,
     "docker-entrypoint.sh redis-server", ((6379, (0, 0, 6379)),),
     ("cache", "redis", "app-cache", "sessions", "kv")),
    ("mysql", ("8.0.39", "8.4.2", "8.0.37", "8.0"), 573_000_000,
     "docker-entrypoint.sh mysqld", ((3306, (0, 0, 3306)),),
     ("db", "mysql", "database", "sql")),
    ("mariadb", ("11.4.3", "10.11.9", "11.2", "10.6"), 405_000_000,
     "docker-entrypoint.sh mariadbd", ((3306, (0, 3306)),), ("db", "mariadb", "database")),
    ("mongo", ("7.0.14", "6.0.18", "8.0.1", "7.0"), 756_000_000,
     "docker-entrypoint.sh mongod", ((27017, (0, 0, 27017)),), ("mongo", "db", "docstore")),
    ("grafana/grafana", ("11.2.0", "11.1.5", "10.4.8", "11.2.2"), 466_000_000,
     "/run.sh", ((3000, (3000, 3001)),), ("grafana", "metrics", "dashboards")),
    ("prom/prometheus", ("v2.54.1", "v2.53.2", "v2.55.0"), 270_000_000,
     "/bin/prometheus --config.file=/etc/prometheus/prometheus.yml", ((9090, (9090, 0)),),
     ("prometheus", "metrics", "monitor")),
    ("traefik", ("v3.1.4", "v3.1", "v2.11.10", "v3.2"), 183_000_000,
     "/entrypoint.sh traefik", ((80, (80,)), (443, (443,))),
     ("traefik", "proxy", "router", "ingress")),
    ("caddy", ("2.8.4", "2.8", "2.7.6-alpine"), 49_000_000,
     "caddy run --config /etc/caddy/Caddyfile --adapter caddyfile",
     ((80, (80, 8080)), (443, (443, 4443))), ("caddy", "proxy", "web")),
    ("rabbitmq", ("3.13.7-management", "3.12-management", "3.13-alpine"), 253_000_000,
     "docker-entrypoint.sh rabbitmq-server", ((5672, (0, 5672)),),
     ("rabbit", "queue", "mq", "broker")),
    ("memcached", ("1.6.31", "1.6.29-alpine", "1.6.32"), 85_000_000,
     "docker-entrypoint.sh memcached", ((11211, (0,)),), ("memcached", "cache", "mc")),
    ("vaultwarden/server", ("1.32.0", "1.31.0-alpine", "1.32.1"), 105_000_000,
     "/start.sh", ((80, (8200, 8081, 8080)),), ("vault", "vaultwarden", "passwords")),
    ("louislam/uptime-kuma", ("1.23.15", "1.23.13", "1"), 410_000_000,
     "extra/entrypoint.sh node server/server.js", ((3001, (3001, 8082)),),
     ("uptime", "kuma", "status")),
    ("gitea/gitea", ("1.22.2", "1.22.1", "1.21.11"), 190_000_000,
     "/usr/bin/entrypoint /usr/bin/s6-svscan /etc/s6", ((3000, (3000, 3002)), (22, (2222,))),
     ("git", "gitea", "scm")),
    ("wordpress", ("6.6.2-apache", "6.6.1-php8.3-apache", "6.5.5-apache"), 700_000_000,
     "docker-entrypoint.sh apache2-foreground", ((80, (8000, 8088, 80)),),
     ("wordpress", "blog", "site", "cms")),
    ("nextcloud", ("29.0.7-apache", "29.0.6", "28.0.10-apache"), 1_050_000_000,
     "/entrypoint.sh apache2-foreground", ((80, (8080, 8090)),), ("nextcloud", "cloud", "files")),
    ("minio/minio", ("RELEASE.2024-09-22T00-33-43Z", "RELEASE.2024-08-26T15-33-07Z"), 190_000_000,
     "/usr/bin/docker-entrypoint.sh server /data", ((9000, (9000, 0)),),
     ("minio", "s3", "storage")),
    ("portainer/portainer-ce", ("2.21.0", "2.20.3", "2.21.2"), 290_000_000,
     "/portainer", ((9000, (9000, 9443)),), ("portainer", "admin", "docker-ui")),
    ("httpd", ("2.4.62", "2.4.61-alpine", "2.4"), 148_000_000,
     "httpd-foreground", ((80, (80, 8080, 8888)),), ("apache", "web", "httpd", "intranet")),
    ("node", ("20-alpine", "20.17-slim", "22-alpine", "18.20-alpine"), 135_000_000,
     "docker-entrypoint.sh node server.js", ((3000, (3000, 0, 8000)),),
     ("api", "app", "backend", "worker")),
    ("python", ("3.12-slim", "3.11-slim", "3.12.6-alpine"), 125_000_000,
     "gunicorn -b 0.0.0.0:8000 app:app", ((8000, (8000, 0)),), ("api", "app", "backend", "web")),
    ("ghost", ("5.94-alpine", "5.96.0", "5-alpine"), 310_000_000,
     "docker-entrypoint.sh node current/index.js", ((2368, (2368, 8083)),),
     ("ghost", "blog", "cms")),
    ("elasticsearch", ("8.15.1", "8.14.3", "7.17.24"), 1_250_000_000,
     "/bin/tini -- /usr/local/bin/docker-entrypoint.sh eswrapper", ((9200, (0, 9200)),),
     ("elastic", "search", "es")),
    ("adminer", ("4.8.1", "4.8.1-standalone", "latest"), 90_000_000,
     "entrypoint.sh docker-php-entrypoint php -S [::]:8080 -t /var/www/html",
     ((8080, (8081, 8888)),), ("adminer", "dbadmin", "pma")),
]  # fmt: skip
PROJECTS = [
    "shop", "blog", "portal", "crm", "wiki", "billing", "intranet", "stack", "web", "app",
    "mail", "docs", "erp", "forum", "site", "media", "tools", "lab", "dev", "staging",
]  # fmt: skip
# Images a typical host already has (bots create from these without pulling), then a few more
# of which a per-deployment subset is present.
BASE_IMAGES = [
    ("alpine:latest", 8_400_000),
    ("ubuntu:latest", 78_100_000),
    ("ubuntu:22.04", 77_900_000),
    ("busybox:latest", 4_300_000),
    ("debian:bookworm", 117_000_000),
    ("nginx:latest", 192_000_000),
]
EXTRA_BASE = [
    ("alpine:3.20", 8_300_000),
    ("alpine:3.19", 7_700_000),
    ("ubuntu:24.04", 78_800_000),
    ("debian:bookworm-slim", 74_800_000),
    ("debian:12", 117_000_000),
    ("python:3.12-slim", 125_000_000),
    ("hello-world:latest", 13_300),
    ("node:20-alpine", 135_000_000),
]
