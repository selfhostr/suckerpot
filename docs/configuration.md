# Configuration

SuckerPot is configured with environment variables. You set them in `.env`, which Docker Compose reads. The template is `.env.example`. Copy it, then replace every placeholder.

```bash
cp .env.example .env
chmod 600 .env
```

Never commit `.env`. It holds passwords. The `.gitignore` already excludes it.

This page lists every variable the code reads today. "In `.env`" means Compose passes it through from your `.env`. "Fixed by Compose" means Compose sets it, and you should not change it. A variable that the code reads but Compose does not pass through can only be changed by editing `docker-compose.yml` (an override file is the clean way).

## Secrets

Compose refuses to start until the required secrets are set. Each secret must be at least 24 characters long, and no two may be equal. The Redis and migration containers check this at start-up and refuse to run otherwise. The message names the variable, never its value.

```bash
openssl rand -base64 32
```

| Secret | Used by | Purpose |
| --- | --- | --- |
| `POSTGRES_PASSWORD` | `db`, `migrate` | Database owner. Schema changes only. |
| `POSTGRES_INGEST_PASSWORD` | `migrate`, `ingest` | Role `suckerpot_ingest` |
| `POSTGRES_API_PASSWORD` | `migrate`, `api` | Role `suckerpot_api` (read-only) |
| `REDIS_PASSWORD` | `redis` | Redis `admin` user (operators only) |
| `REDIS_HEALTH_PASSWORD` | `redis` | Redis `health` user. It can only run `PING`. |
| `REDIS_INGEST_PASSWORD` | `redis`, `ingest` | Redis `ingest` user. It reads and acknowledges the event streams. |
| `REDIS_SENSOR_SSH_PASSWORD` | `redis`, `sensor-ssh` | Redis `sensor-ssh` user. It can only `XADD` to `events:ssh`. |
| `REDIS_SENSOR_RDP_PASSWORD` | `redis`, `sensor-rdp` | Redis `sensor-rdp` user. It can only `XADD` to `events:rdp`. |
| `REDIS_SENSOR_TELNET_PASSWORD` | `redis`, `sensor-telnet` | Redis `sensor-telnet` user. It can only `XADD` to `events:telnet`. |
| `REDIS_SENSOR_WEB_PASSWORD` | `redis`, `sensor-web` | Redis `sensor-web` user. It can only `XADD` to `events:web`. |
| `REDIS_SENSOR_REDIS_PASSWORD` | `redis`, `sensor-redis` | Redis `sensor-redis` user. It can only `XADD` to `events:redis`. |
| `REDIS_SENSOR_DOCKER_PASSWORD` | `redis`, `sensor-docker` | Redis `sensor-docker` user. It can only `XADD` to `events:docker`. |
| `REDIS_SENSOR_MYSQL_PASSWORD` | `redis`, `sensor-mysql` | Redis `sensor-mysql` user. It can only `XADD` to `events:mysql`. |
| `REDIS_SENSOR_MSSQL_PASSWORD` | `redis`, `sensor-mssql` | Redis `sensor-mssql` user. It can only `XADD` to `events:mssql`. |
| `REDIS_SENSOR_ADB_PASSWORD` | `redis`, `sensor-adb` | Redis `sensor-adb` user. It can only `XADD` to `events:adb`. |
| `REDIS_SENSOR_SMB_PASSWORD` | `redis`, `sensor-smb` | Redis `sensor-smb` user. It can only `XADD` to `events:smb`. |
| `REDIS_SENSOR_SIP_PASSWORD` | `redis`, `sensor-sip` | Redis `sensor-sip` user. It can only `XADD` to `events:sip`. |
| `REDIS_SENSOR_SYNOLOGY_PASSWORD` | `redis`, `sensor-synology` | Redis `sensor-synology` user. It can only `XADD` to `events:synology`. |
| `REDIS_DEMO_PASSWORD` | `redis`, `demo` | Redis `demo` user. It can only `XADD` to `events:*`. |
| `SESSION_SECRET` | `api` | Signs the dashboard session cookie (at least 32 bytes). See [Dashboard authentication](#dashboard-authentication). |
| `ADMIN_PASSWORD_HASH` | `api` | Argon2 hash of the dashboard password. A hash, not a password, but treat it as a secret. |
| `SETTINGS_ENCRYPTION_KEY` | `api`, `ingest` | Optional. Encrypts the enrichment API keys you enter on the Settings page. Make it with `openssl rand -base64 32` (at least 32 random bytes). See [Enrichment keys in Settings](#enrichment-keys-in-settings). |

Each of the twelve sensors has its own Redis secret, `REDIS_SENSOR_<NAME>_PASSWORD`, for SSH, Telnet, RDP, web, Redis, Docker, MySQL, MSSQL, ADB, SMB, SIP and Synology. To rotate secrets, see [Deployment](deployment.md#rotating-secrets).

```{warning}
The template uses `change-me` as a placeholder. It is too short for the policy, so the stack refuses to start until you replace it. `SUCKERPOT_ALLOW_DEFAULT_SECRETS=1` turns the check off. Set it only in CI or throwaway tests.
```

## Compose and host

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `COMPOSE_PROJECT_NAME` | `suckerpot` | `.env` | Prefix for container, network and volume names |
| `DASHBOARD_BIND` | `127.0.0.1` | `.env` | Host address the dashboard port binds to. Keep `127.0.0.1` unless a tunnel on another machine must reach it, and then [filter the port upstream](deployment.md#dashboard-bind-and-upstream-filtering). |
| `DASHBOARD_PORT` | `8443` | `.env` | Host port for the dashboard. Never 22, 23, 80, 443, 3389 or the admin SSH port. |
| `ADMIN_SSH_PORT` | empty | `.env` | Optional. The port of the host's own admin SSH daemon. Read only by `scripts/check-ports.sh`, to refuse a collision. |
| `SSH_HOST_PORT` | `22` | `.env` | Host port of the SSH sensor (IPv4 only) |
| `TELNET_HOST_PORT` | `23` | `.env` | Host port of the Telnet sensor |
| `HTTP_HOST_PORT` | `80` | `.env` | Host port of the web sensor (IPv4 only) |
| `HTTPS_HOST_PORT` | `443` | `.env` | Host port of the web sensor's TLS listener (IPv4 only) |
| `RDP_HOST_PORT` | `3389` | `.env` | Host port of the RDP sensor |
| `REDIS_HOST_PORT` | `6379` | `.env` | Host port of the Redis sensor (IPv4 only) |
| `DOCKER_HOST_PORT` | `2375` | `.env` | Host port of the Docker API sensor (IPv4 only) |
| `MYSQL_HOST_PORT` | `3306` | `.env` | Host port of the MySQL sensor (IPv4 only) |
| `MSSQL_HOST_PORT` | `1433` | `.env` | Host port of the MSSQL sensor (IPv4 only) |
| `ADB_HOST_PORT` | `5555` | `.env` | Host port of the ADB sensor (IPv4 only) |
| `SMB_HOST_PORT` | `445` | `.env` | Host port of the SMB sensor (IPv4 only). The sensor listens on container port 4450. |
| `SIP_HOST_PORT` | `5060` | `.env` | Host port of the SIP sensor, for both UDP and TCP (IPv4 only) |
| `SYNOLOGY_HTTP_HOST_PORT` | `5000` | `.env` | Host port of the Synology sensor's HTTP listener (IPv4 only) |
| `SYNOLOGY_HTTPS_HOST_PORT` | `5001` | `.env` | Host port of the Synology sensor's HTTPS listener (IPv4 only) |
| `SUCKERPOT_ALLOW_DEFAULT_SECRETS` | `0` | `.env` | `1` turns off the secret length and uniqueness checks. CI and throwaway tests only. |

## Install, updates and sensor switches (M28)

These variables are written by the installer, or changed by the update and sensor commands. The install guide explains them in context: [Install SuckerPot](install.md) and [Updates and rollback](updates.md).

### Sensor switches

Each sensor has a switch. `1` turns it on, `0` turns it off. A sensor that is off is not started and publishes no port. Change them with `just sensors`, or by editing `.env` and running `just up`. The default is `1`, so an older `.env` without these lines keeps every sensor.

| Variable | Sensor | Default | Standard port |
| --- | --- | --- | --- |
| `SENSOR_SSH` | SSH | `1` | 22 |
| `SENSOR_TELNET` | Telnet | `1` | 23 |
| `SENSOR_WEB` | Web (HTTP and HTTPS) | `1` | 80, 443 |
| `SENSOR_RDP` | RDP | `1` | 3389 |
| `SENSOR_REDIS` | Redis | `1` | 6379 |
| `SENSOR_DOCKER` | Docker API | `1` | 2375 |
| `SENSOR_MYSQL` | MySQL | `1` | 3306 |
| `SENSOR_MSSQL` | MSSQL | `1` | 1433 |
| `SENSOR_ADB` | ADB | `1` | 5555 |
| `SENSOR_SMB` | SMB | `1` | 445 |
| `SENSOR_SIP` | SIP | `1` | 5060 (UDP and TCP) |
| `SENSOR_SYNOLOGY` | Synology DSM | `1` | 5000, 5001 |

The port guard (`scripts/check-ports.sh`) accepts only `0` or `1`. Host ports are in [Ports to forward](install.md#ports-to-forward).

### Install mode and images

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `SUCKERPOT_INSTALL_MODE` | `source` | `.env`, written by the installer | `images` runs the signed release images. `source` builds them from the checkout. `just up` and the update scripts read it. |
| `SUCKERPOT_IMAGE_PREFIX` | unset | `.env`, written in images mode | Registry and name prefix of the release images, `ghcr.io/<owner>/suckerpot`. Unset, the images are built locally and named `local/<project>-<service>`. The installer uses the project registry unless you set this variable before you run it. The owner in this name is also the repository whose release signatures are checked. |
| `SUCKERPOT_VERSION` | `dev` | `.env`, written by the installer and by `just update` | Release tag of the images to run, such as `vX.Y.Z`. Every image name ends with it. |
| `SUCKERPOT_VOLUME_PREFIX` | none, required | `.env`, written by the installer | Prefix of the external data volumes, such as `suckerpot_db-data`. Compose refuses to start without it. |
| `SUCKERPOT_BUILD_VERSION` | `dev` | Set by `just up` and `just update` | Version baked into images built from the checkout. Leave it unset for a plain build. |
| `SUCKERPOT_BUILD_COMMIT` | `unknown` | Set by `just up` and `just update` | Commit baked into images built from the checkout. |

### Updates

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `UPDATE_CHECK_ENABLED` | `false` | `.env`, or `just set UPDATE_CHECK_ENABLED=true` | Once a day, ask GitHub for the latest release, through the VPN only. Never installs anything. See [the update check](updates.md#the-optional-update-check). |
| `UPDATE_CHECK_REPO` | the project repository, `owner/name` | `.env` | The repository the check reads. A fork sets its own. Any value that is not `owner/name` falls back to the default. `just set` does not accept this variable. |

### Low memory and Redis

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `COMPOSE_FILE` | unset | `.env`, written by the installer for low memory | Set to `docker-compose.yml:docker-compose.lowmem.yml` to use the lower memory limits. See [low-memory hosts](install.md#low-memory-hosts). `just set` does not change it. |
| `REDIS_MAXMEMORY_MB` | `192` (`96` in low-memory mode) | `.env` | Memory ceiling of Redis in MiB, from 32 to 4096. |
| `COMPOSE_PROFILES` | unset (the installer writes `egress`) | `.env` | `egress` runs `vpn`, `collector` and `analyzer`. The installer always sets it. Without a VPN configuration, `vpn` waits in idle mode. See [the VPN before a WireGuard file is uploaded](install.md#the-vpn-before-a-wireguard-file-is-uploaded). |

## Database

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `POSTGRES_DB` | `suckerpot` | `.env` | Database name |
| `POSTGRES_USER` | `suckerpot` | `.env` | Owner account. Used by `db` and `migrate` only. |
| `POSTGRES_PASSWORD` | none | `.env`, required | Owner password |
| `POSTGRES_INGEST_USER` | `suckerpot_ingest` | `.env` | Role name used by ingest |
| `POSTGRES_INGEST_PASSWORD` | none | `.env`, required | Password of the ingest role |
| `POSTGRES_API_USER` | `suckerpot_api` | `.env` | Role name used by the API |
| `POSTGRES_API_PASSWORD` | none | `.env`, required | Password of the API role |
| `POSTGRES_HOST` | `db` | Fixed by Compose | Database host on the `backend` network |
| `POSTGRES_PORT` | `5432` | Fixed by Compose | Database port |

Inside `ingest` and `api`, Compose sets `POSTGRES_USER` and `POSTGRES_PASSWORD` to that service's own role, not to the owner.

## Redis

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `REDIS_PASSWORD` and the other `REDIS_*_PASSWORD` secrets | none | `.env`, required | See [Secrets](#secrets) |
| `EVENTS_MAXLEN` | `10000` | `.env` | Approximate maximum length of each sensor's stream (`XADD MAXLEN ~`) for SSH, Telnet, Web and RDP |
| `EVENTS_MAXLEN_LOW` | `3000` | `.env` | The same cap for the seven M9 sensors (Redis, Docker, MySQL, MSSQL, ADB, SMB and SIP) and the Synology sensor. Kept short so a burst on seven more streams cannot fill Redis memory. Ingest drains the streams, and a sensor drops an event when `XADD` fails. |
| `DEMO_EVENTS_MAXLEN` | `100000` | `.env` | The same cap, for the demo generator only. Keep it above the number of events per sensor in a backfill, or entries ingest has not read yet are trimmed. |
| `EVENTS_MAX_BYTES_PER_SEC` | `200000` | Code default | Publisher backstop for **every** sensor: a token bucket on serialized event bytes per second. Beyond it the publisher drops events and counts them. |
| `EVENTS_MAX_BYTES_BURST` | `2000000` | Code default | Burst of that bucket, in bytes |
| `REDIS_HOST` | `redis` | Fixed by Compose | Redis host |
| `REDIS_PORT` | `6379` | Fixed by Compose | Redis port |
| `REDIS_USER` | per service | Fixed by Compose | `ingest`, `demo`, and one `sensor-<name>` user per sensor |
| `EVENTS_STREAM` | per service | Fixed by Compose | Stream a sensor writes to (`events:ssh`). The code default is `events`. |

Inside each service, Compose sets `REDIS_PASSWORD` to the password of that service's own Redis user.

## API

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `API_ENABLE_DOCS` | `false` | `.env` | Serve `/docs`, `/redoc` and `/openapi.json`. Keep `false` unless you are developing. |
| `API_ALLOWED_ORIGINS` | empty | `.env` | Extra browser origins for the live WebSocket, comma-separated, full origins such as `https://dash.example.com`. Needed behind a TLS-terminating tunnel. Same-host origins are always allowed. |
| `WEB_DIST_DIR` | `/app/web` | Code default | Folder with the built web UI. Served only when it contains an `index.html`. |

## Dashboard authentication

```{admonition} Status
:class: note

Built in M8, security review passed. Compose passes all of these variables to the `api` service from your `.env`. `ADMIN_PASSWORD_HASH` and `SESSION_SECRET` are required: `docker compose up` and `just up` refuse to start, with a message that names the variable, until both are set. `API_AUTH_DISABLED` and `SUCKERPOT_DEMO` are set only by `docker-compose.ci.yml`.
```

The owner account lives in `.env`: it is always an administrator and works even when the database is down. Colleagues get their own accounts, with the role `admin` or `viewer`, from **Settings > Users** (see [Users and roles](#users-and-roles)). See [API](api.md#authentication) for how sign-in works.

| Variable | Default | Description |
| --- | --- | --- |
| `ADMIN_USERNAME` | `admin` | Name of the owner account. A user created in Settings cannot take this name. |
| `ADMIN_PASSWORD_HASH` | none, **required** | Argon2 hash of the admin password. Make it with `docker compose run --rm api python -m api.hashpw`. Put it in `.env` in **single quotes**, because it contains `$`. |
| `SESSION_SECRET` | none, **required** | Signs the session and CSRF cookies. At least 32 bytes. Generate it with `openssl rand -base64 48`. Different from every other secret. |
| `SESSION_TTL_HOURS` | `12` | How long a login lasts |
| `COOKIE_SECURE` | `true` | Cookies are `Secure` and named `__Host-sp_session` and `__Host-sp_csrf`. Keep `true`, also behind a TLS-terminating tunnel (the browser talks HTTPS to the tunnel). `false` gives the plain names `sp_session` and `sp_csrf` without `Secure`: local development over HTTP only. |
| `LOGIN_RATE` | `5` | Login attempts per client address per minute (every attempt counts) |
| `LOGIN_RATE_GLOBAL` | `30` | **Wrong passwords** per minute for the whole server. Over this budget, each wrong answer keeps its password-check slot one more second, which caps guessing across all addresses. It never refuses a sign-in, so anonymous traffic cannot lock the owner out. Successful sign-ins do not count |
| `LOGIN_VERIFY_CONCURRENCY` | `2` | Password checks (argon2, about 64 MiB each) running at once, from 1 to 4 (other values are clamped and logged). Extra attempts queue, up to 20 in all; beyond that login answers `429` at once. While the server-wide wrong-password budget is spent, a wrong answer keeps its slot one more second |
| `LOGIN_VERIFY_WAIT` | `5` | Seconds an attempt may queue for a free check slot before it gets `429` with `Retry-After`. Minimum 0.5 |
| `LOGIN_RATE_USER` | `10` | Wrong passwords per minute for one username (any letter case), from any address. Not applied to the owner's name. |
| `AUTH_TRUSTED_PROXIES` | empty | Comma-separated CIDR list of proxy addresses (such as `203.0.113.0/24`). Only from those peers does the API read `CF-Connecting-IP`, or the rightmost non-proxy `X-Forwarded-For` entry, as the client address. Empty means the headers are never trusted. Replaces the old `AUTH_TRUST_PROXY_HEADERS`. |
| `API_ALLOWED_HOSTS` | empty | Comma-separated host names the API answers to. If empty, the hosts of `API_ALLOWED_ORIGINS` are used. `localhost` and `127.0.0.1` are always allowed. If both are empty, any host is allowed and the API logs a warning: set one in production, for example the tunnel's host name. |
| `API_AUTH_DISABLED` | `false` | Turns authentication **off**. It takes effect only together with `SUCKERPOT_DEMO=1`, and Compose sets both only through `docker-compose.ci.yml` (`just up-test`). The base `docker-compose.yml` never does. Never use it in production. |
| `API_ALLOWED_ORIGINS` | empty | Also used by login: when set, the **full origin** of a login request (scheme, host, port) must be listed. When empty, only the host is compared with the `Host` header. Set it behind a tunnel. |

The API refuses to start when the hash or the secret is missing or weak. `SUCKERPOT_ALLOW_DEFAULT_SECRETS=1` accepts a weak setup for CI only.

### Users and roles

Added in M14. There is nothing to configure in `.env` for it (apart from `LOGIN_RATE_USER` above): users are created and managed in **Settings > Users**, by an administrator.

| | Owner | Administrator | Viewer |
| --- | --- | --- | --- |
| Where it lives | `.env` | database | database |
| Look at every page, export data, watch Live | yes | yes | yes |
| Change settings and provider keys | yes | yes | no |
| Manage users, read the audit log | yes | yes | no |
| Password changed | in `.env` only | by the user | by the user |
| Can be disabled, demoted or deleted | no | yes, by another administrator | yes |

- A new account gets a strong temporary password that the administrator sees **once**. The person must choose their own password at the first sign-in; until then nothing else works.
- Passwords have 12 to 256 characters, are not one of about a thousand very common passwords (the list is `api/api/data/common-passwords.txt`) and must not contain the username.
- Five wrong passwords from one address lock that address for that account for a minute (longer on repeats, up to 15 minutes); 50 in total lock the account for 15 minutes, but only for addresses the user never signed in from. An administrator can unlock at once.
- Every change to a user asks the administrator for their own password again, and is written to the audit log (kept for one year).
- Changing a password, disabling an account, changing its role, deleting it or choosing "Sign out everywhere" ends all of that user's sessions immediately.
- Optional two-factor sign-in is not built yet.

**Losing the owner password:** make a new hash with `docker compose run --rm api python -m api.hashpw`, put it in `.env` as `ADMIN_PASSWORD_HASH` and restart the API. The owner account never depends on the database, so this works even when users cannot sign in.

## Site (Live map home)

| Variable | Default | Description |
| --- | --- | --- |
| `SITE_HOME_LAT`, `SITE_HOME_LON` | `46.8`, `8.2` | Where attack arcs land on the Live map. Rounded to one decimal. Use a country-level point, never your real address. |
| `SITE_HOME_LABEL` | `Switzerland` | Name shown next to the home point on the Live map (64 characters at most) |

## Ingest

Defaults are set in code. Compose passes `INGEST_STREAMS` through from `.env`. The others can only be changed with an override file.

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `INGEST_STREAMS` | `events:ssh,events:telnet,events:web,events:rdp,events:redis,events:docker,events:mysql,events:mssql,events:adb,events:smb,events:sip,events:synology` | `.env` | Streams to read, comma-separated. Leave it unset: an override must list every sensor, and ingest logs a warning for a built-in stream it leaves out. Letters, digits and `_ . : -`, up to 64 characters each. The suffix after the last `:` must be the sensor name: events whose `sensor` differs are dropped. |
| `INGEST_BATCH_SIZE` | `100` | Code default | Events per database write, 1 to 500 |
| `INGEST_BLOCK_MS` | `1000` | Code default | How long one stream read waits for new entries, in milliseconds |
| `INGEST_CLAIM_IDLE_MS` | `60000` | Code default | Pending entries idle for longer than this are reclaimed |
| `INGEST_RECLAIM_INTERVAL_S` | `60` | Code default | How often ingest looks for stale pending entries |
| `INGEST_GROUP` | `ingest` | Code default | Consumer group name |
| `INGEST_CONSUMER` | `ingest-1` | Code default | Consumer name inside the group. Keep it stable: a stable name makes restarts take over their own pending entries. |
| `INGEST_HEARTBEAT_PATH` | `/tmp/ingest-heartbeat` | Code default | File touched on each healthy loop. The health check reads it. |

## Enrichment and tagging

```{admonition} Status
:class: note

Built (M4). Compose passes these variables to `ingest` and mounts the `geoip-data` volume at `/data/geoip`. Every variable has a safe default. Without keys, GeoIP uses the key-less DB-IP Lite database and reputation lookups stay off.
```

The geolocation data has a licence that requires credit. See [Data sources and attribution](#data-sources-and-attribution).

| Variable | Default | Description |
| --- | --- | --- |
| `GEOIP_PROVIDER` | `auto` | `auto` (MaxMind if both MaxMind variables are set, else DB-IP), `maxmind`, `dbip` or `off` |
| `GEOIP_DIR` | `/data/geoip` | Folder for the downloaded MMDB files |
| `GEOIP_REFRESH_DAYS` | `30` | Re-download a database when it is older than this (at least 1) |
| `GEOIP_FAKE_FOR_PRIVATE` | `false` | Give private and documentation addresses a fake country. For demo screenshots only. |
| `SETTINGS_ENCRYPTION_KEY` | empty | Enables entering the keys below on the Settings page. See [Enrichment keys in Settings](#enrichment-keys-in-settings). |
| `MAXMIND_ACCOUNT_ID` | empty | MaxMind account ID for GeoLite2 downloads |
| `MAXMIND_LICENSE_KEY` | empty | MaxMind licence key. Optional. |
| `ABUSEIPDB_API_KEY` | empty | AbuseIPDB key. Without it, no lookups. |
| `ABUSEIPDB_DAILY_QUOTA` | `1000` | Maximum AbuseIPDB checks per day. Enforced, and persisted in the database. |
| `GREYNOISE_API_KEY` | empty | GreyNoise Community key. Without it, no lookups. |
| `GREYNOISE_DAILY_QUOTA` | `7` | Maximum GreyNoise checks per day. The free Community API allows about 50 per week, so 7 a day (49 a week) stays inside it |
| `CVE_WATCH_ENABLED` | `true` | Daily job that mirrors CISA KEV, NVD CVEs from the last 60 days and GitHub advisories. The feeds are read in chunks. See [Architecture](ARCHITECTURE.md). |
| `NVD_API_KEY` | empty | NVD key. Optional: raises the rate limit from 5 to 50 requests per 30 s |
| `GITHUB_ADVISORY_TOKEN` | empty | Token for the public GitHub advisories API. Optional: raises the limit from 60 requests per hour. Use a fine-grained token for public repositories only, read-only, with no permissions. Never your push token |
| `CVE_NVD_DAILY_QUOTA` | `200` | Maximum NVD requests per day. Enforced, and persisted in the database |
| `CVE_GITHUB_DAILY_QUOTA` | `100` | Maximum GitHub advisory requests per day |
| `REPUTATION_MIN_EVENTS` | `10` | An address is looked up only after this many events |
| `REPUTATION_INTERVAL_S` | `30` | Seconds between reputation cycles (at least 5) |
| `ABUSECH_AUTH_KEY` | empty | abuse.ch Auth-Key (free) for URLhaus and ThreatFox. Without it, no indicator lookups there. |
| `ABUSECH_DAILY_QUOTA` | `1000` | Maximum abuse.ch requests per day (URLhaus and ThreatFox share it). Enforced, and persisted. |
| `VIRUSTOTAL_API_KEY` | empty | VirusTotal key. Used for file hashes only. |
| `VIRUSTOTAL_DAILY_QUOTA` | `400` | Maximum VirusTotal requests per day (the free tier allows 500). Requests are also spaced 16 s apart. |
| `INTEL_INTERVAL_S` | `30` | Seconds between threat-intel cycles (at least 5) |
| `INDICATORS_ENABLED` | `true` | Extract indicators from recorded events |
| `INDICATORS_IGNORE` | empty | Comma-separated host names, addresses and CIDR blocks never recorded as indicators: **set it to your public IP and domains before going live**. A name also covers its subdomains. The hosts in `API_ALLOWED_HOSTS` and `API_ALLOWED_ORIGINS` are added automatically. |
| `INDICATORS_KEEP_DOCUMENTATION` | `false` | Keep documentation addresses and example domains as indicators. Demo events do not need it (they carry `demo: true`). They are never sent to an intel service either way. |
| `INDICATORS_MAX_ROWS` | `500000` | Most indicator rows kept (1,000 to 50 million). Read by `migrate`. The hourly job drops the least sighted, oldest single-source ones first. |
| `INDICATORS_LINK_CAP` | `500` | Most sessions linked to one indicator. Its counters stay exact beyond that. |
| `RULES_DIR` | `ingest/rules` (`/app/rules` in the image) | Folder with the tagging rules (`*.yaml`) |

### Enrichment keys in Settings

You can enter, replace and remove the AbuseIPDB, GreyNoise, MaxMind, abuse.ch and VirusTotal keys on the Settings page, with no restart.

1. Generate an encryption key and add it to `.env`: `SETTINGS_ENCRYPTION_KEY=$(openssl rand -base64 32)`. Then run `docker compose up -d` so `api` and `ingest` see it. Without it, the Settings page shows the keys as read-only and says why.
2. On the Settings page, choose **Set key** (or **Replace**) for a provider, paste the key and type the admin password to confirm. The key is encrypted before it is stored and is never shown again, only its last four characters.
3. Ingest checks for changes every 30 seconds, so a new key is used within a minute. A new MaxMind key also starts a database download.
4. **Test key** makes one real call to the provider and counts it against the daily quota. The result appears on the page.

A key set in Settings overrides the same key in `.env`. Remove it and the `.env` key is used again. The page shows where each key comes from. If you change or lose `SETTINGS_ENCRYPTION_KEY`, the saved keys cannot be decrypted: the page says so, and the `.env` keys keep working until you enter the keys again. See [Security](SECURITY.md) for the threat model.

## SSH sensor

The variables in the first group are passed through from `.env`. The second group is read by the sensor but not passed through by Compose. See [SSH sensor](sensors/ssh.md).

| Variable | Default | Description |
| --- | --- | --- |
| `SSH_HOSTNAME` | `srv-web01` | Host name shown to clients |
| `SSH_BANNER` | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14` | SSH version string. Keep it consistent with `SSH_OS_VERSION`. |
| `SSH_ACCEPT_CREDENTIALS` | `root:root,root:123456,root:password,admin:admin,ubuntu:ubuntu,pi:raspberry,user:user` | Comma-separated `user:password` pairs that log in. Weak on purpose. |
| `SSH_ACCEPT_RANDOM_PROB` | `0.0` | Probability (0 to 1) of accepting any non-empty password |
| `SSH_MAX_AUTH_ATTEMPTS` | `6` | Failed attempts per connection |
| `SSH_MAX_CONNECTIONS` | `200` | Simultaneous connections, in total |
| `SSH_MAX_PER_IP` | `5` | Simultaneous connections per source address |
| `SSH_PORT` | `2222` | Port inside the container (fixed by Compose) |
| `SSH_PUBLIC_PORT` | `22` | Port recorded as `dst_port` (set from `SSH_HOST_PORT`) |
| `SSH_HOSTKEY_DIR` | `/data/host_keys` | Host key folder, on a volume (fixed by Compose) |
| `SSH_LOGIN_TIMEOUT`, `SSH_IDLE_TIMEOUT`, `SSH_MAX_SESSION` | `30`, `300`, `1800` | Seconds: to log in, idle, whole session |
| `SSH_MAX_LINE` | `4096` | Longest accepted input line |
| `SSH_EVENTS_PER_SEC` | `20` | `connect` events per source address per second |
| `SSH_GLOBAL_EVENTS_PER_SEC` | `200` | Sensor-wide event cap |
| `SSH_CONN_RATE_PER_IP`, `SSH_CONN_BURST_PER_IP` | `1`, `10` | New connections per source address per second, and the burst |
| `SSH_SUMMARY_INTERVAL` | `60` | Seconds between summaries of suppressed events (at least 5) |
| `SSH_LINE_BUDGET` | `0.15` | CPU seconds allowed per command line |
| `SSH_MEMORY_BUDGET_MB` | `48` | Memory budget over all sessions |
| `SSH_MEMORY_SHARE_PER_IP` | `0.25` | Share of the memory budget one source address may hold (0.01 to 1) |
| `SSH_MEMORY_LIMIT_MB` | `256` | Memory limit the guard compares against when the cgroup limit cannot be read. Keep it equal to the container limit. |
| `SSH_MEMORY_PRESSURE` | `0.70` | Fraction of the limit above which new connections are refused and the biggest connections stop being read |
| `SSH_MEMORY_CRITICAL` | `0.85` | Fraction above which the biggest connections are closed |
| `SSH_CHANNEL_WINDOW_KB` | `32` | Flow-control window of a session channel, in KiB (8 to 1024). A session with more than four windows of unread input is closed. |
| `SSH_INBOUND_CONN_KB_PER_SEC` | `32` | Inbound data one connection may send per second, in KiB (metered before decryption). Also caps `scp` uploads. |
| `SSH_INBOUND_KB_PER_SEC` | `256` | The same, for all connections together |
| `SSH_SHELL_CPU_SHARE` | `0.3` | CPU-seconds of shell time per second for all sessions together (0.05 to 0.9), shared fairly between source addresses |
| `SSH_SHELL_CPU_BURST` | `0.2` | Burst of that budget, in CPU-seconds |
| `SSH_IP_EVENT_BYTES_PER_SEC`, `SSH_IP_EVENT_BYTES_BURST` | `20000`, `1000000` | Event bytes per source address per second, and the burst |
| `SSH_GLOBAL_EVENT_BYTES_PER_SEC`, `SSH_GLOBAL_EVENT_BYTES_BURST` | `200000`, `2000000` | Event bytes per second for the whole sensor, and the burst. Over budget, an event first loses its bulk (`output_omitted`, `replay_omitted`), then is dropped. |
| `SSH_STATS_INTERVAL` | `60` | Seconds between the sensor's own statistics log lines (at least 5) |
| `SSH_MAX_COMMANDS` | `5000` | Commands per session |
| `SSH_FAKE_IP` | derived | Private address shown by `ifconfig` and `ip a` |
| `SSH_OS_VERSION`, `SSH_KERNEL`, `SSH_KERNEL_BUILD` | `24.04.4`, `6.8.0-100-generic`, matching build | Fake OS and kernel versions |

## Web sensor

```{admonition} Status
:class: note

Built (M6) and wired into `docker-compose.yml`. It is still under security review. Compose sets the ports, the hostname and the Redis settings. The other variables use the defaults below unless you add them with an override file.
```

| Variable | Default | Description |
| --- | --- | --- |
| `WEB_HOSTNAME` | `srv-web01` | Host name (a plain label) |
| `WEB_HTTP_PORT`, `WEB_HTTPS_PORT` | `8080`, `8443` | Ports inside the container |
| `WEB_HTTP_PUBLIC_PORT`, `WEB_HTTPS_PUBLIC_PORT` | `80`, `443` | Ports recorded as `dst_port` and shown in error pages |
| `WEB_DATA_DIR` | `/data` | Folder for the generated profile and TLS certificate (a volume) |
| `WEB_SERVER_TOKEN` | `Apache/2.4.58 (Ubuntu)` | `Server` header. Must look like `Apache/2.4.N (Ubuntu)`. |
| `WEB_PHP_VERSION` | `8.3.6` | PHP version shown. Must be `8.3.N` with N below 36, the PHP2Shell-vulnerable range. |
| `WEB_EXPOSE_PHP` | `true` | Send `X-Powered-By` on PHP responses |
| `WEB_WP_VERSION`, `WEB_PMA_VERSION` | `6.8.1`, `5.2.1` | WordPress and phpMyAdmin versions shown |
| `WEB_UPLOAD_PROGRESS_NAME` | `PHP_SESSION_UPLOAD_PROGRESS` | Name of the upload-progress field the detector watches |
| `WEB_MAX_CONNECTIONS`, `WEB_MAX_PER_IP` | `200`, `10` | Connection caps |
| `WEB_MEMORY_BUDGET_MB` | `48` | Memory budget over all requests |
| `WEB_EVENTS_PER_SEC`, `WEB_GLOBAL_EVENTS_PER_SEC` | `20`, `200` | Event caps per source address and for the sensor |

## RDP sensor

```{admonition} Status
:class: note

Built. Compose sets the ports, `RDP_HOSTNAME`, the caps, and the NLA mode and decoy accounts. The rest use the defaults below unless you add them with an override file.
```

Set these in `.env`. Compose passes them to the sensor under the `SENSOR_RDP_` names shown in the first column. The `.env` names are in the second column, and `.env.example` lists them with comments.

| Variable | Default | Description |
| --- | --- | --- |
| `SENSOR_RDP_NLA_MODE` (`.env`: `RDP_NLA_MODE`) | `required` | `required` accepts NLA clients only. `optional` also accepts TLS-only clients and records the cleartext password they send. This is an owner opt-in, see [Security](SECURITY.md#credentials-the-sensors-record). Any other value stops the sensor at start-up. |
| `SENSOR_RDP_ACCOUNTS` (`.env`: `RDP_ACCOUNTS`) | `administrator:P@ssw0rd,administrator:123456,admin:admin` | Decoy `user:password` pairs, comma separated. Only these pairs are checked, and the pairs are public by design. |
| `RDP_PORT` | `3389` | Port inside the container |
| `RDP_PUBLIC_PORT` | `3389` | Port recorded as `dst_port` |
| `RDP_HOSTNAME` | derived | NetBIOS name in the certificate, 1 to 15 characters |
| `RDP_DATA_DIR` | `/data` | Profile secret, certificate and key (a volume) |
| `RDP_ENABLE_TLS` | `true` | Complete the TLS handshake after selecting CredSSP |
| `RDP_MAX_CONNECTIONS`, `RDP_MAX_PER_IP` | `200`, `8` | Connection caps |
| `RDP_MAX_TLS_PER_IP` | `4` | TLS handshakes allowed from one source at the same time (`.env` uses the same name) |
| `RDP_FIRST_DATA_TIMEOUT` | `8` | Seconds to wait for the first bytes |
| `RDP_HANDSHAKE_TIMEOUT` | `10` | Seconds per PDU and for the TLS handshake |
| `RDP_CREDSSP_TIMEOUT` | `10` | Seconds to wait for the first `TSRequest` |
| `RDP_MAX_SESSION` | `60` | Hard cap on one connection, in seconds |
| `RDP_SESSIONS_PER_SEC_PER_IP` | `2` | Recorded connections per source per second (burst 15 times that) |
| `RDP_GLOBAL_SESSIONS_PER_SEC` | `50` | Recorded connections per second overall (burst 2 times that) |
| `RDP_GLOBAL_EVENTS_PER_SEC` | `200` | Global event cap (all types except `disconnect`) |
| `RDP_DISCONNECT_EVENTS_PER_SEC` | `60` | Global cap on `disconnect` events |
| `RDP_TLS_PER_SEC_PER_IP`, `RDP_TLS_BURST_PER_IP` | `5`, `20` | TLS handshakes started per source |
| `RDP_MAX_TLS_HANDSHAKES` | `32` | TLS handshakes in progress at the same time |

## Telnet sensor

```{admonition} Status
:class: note

Built. Compose sets `TELNET_PUBLIC_PORT` (from `TELNET_HOST_PORT`) and the Redis settings. The other variables use the defaults below unless you add them with an override file. See [Telnet sensor](sensors/telnet.md).
```

| Variable | Default | Description |
| --- | --- | --- |
| `TELNET_PORT` | `2323` | Port inside the container |
| `TELNET_PUBLIC_PORT` | `23` | Port recorded as `dst_port` |
| `TELNET_PERSONALITY` | `dvr` | `dvr` or `router` |
| `TELNET_HOSTNAME` | derived | Host name (a plain label) |
| `TELNET_LOGIN_PROMPT` | `{hostname} login: ` | Login prompt. `\r` and `\n` are turned into line breaks. |
| `TELNET_PRELOGIN_BANNER`, `TELNET_MOTD` | empty | Texts before the login and after it. Empty means the personality's own text. At most 2048 characters. |
| `TELNET_DATA_DIR` | `/data` | Folder for the generated profile secret (a volume) |
| `TELNET_ACCEPT_CREDENTIALS` | trimmed Mirai list | Comma-separated `user:password` pairs that log in |
| `TELNET_ACCEPT_RANDOM_PROB` | `0.0` | Probability (0 to 1) of accepting any login |
| `TELNET_MAX_AUTH_ATTEMPTS` | `6` | Failed attempts per connection |
| `TELNET_MAX_CONNECTIONS`, `TELNET_MAX_PER_IP` | `200`, `8` | Connection caps |
| `TELNET_LOGIN_TIMEOUT`, `TELNET_IDLE_TIMEOUT`, `TELNET_MAX_SESSION` | `60`, `300`, `1800` | Seconds |
| `TELNET_MAX_LINE`, `TELNET_MAX_COMMANDS` | `4096`, `2000` | Longest input line, commands per session |
| `TELNET_LINE_BUDGET` | `0.15` | CPU seconds per command line |
| `TELNET_MEMORY_BUDGET_MB` | `48` | Memory budget over all sessions |
| `TELNET_EVENTS_PER_SEC`, `TELNET_GLOBAL_EVENTS_PER_SEC` | `20`, `200` | Event caps per source address and for the sensor |
| `TELNET_CONN_RATE_PER_IP`, `TELNET_CONN_BURST_PER_IP` | `1`, `10` | New connections per second per source address, and the burst |
| `TELNET_SUMMARY_INTERVAL` | `60` | Seconds between summaries of unrecorded connections (at least 5) |

## Sensors added in M9

Seven sensors were added in M9: Redis, Docker, MySQL, MSSQL, ADB, SMB and SIP. Compose wires each one with its own Redis user, stream and network. It sets the public port, the connection caps and the memory limit. The table lists the variables you can set in `.env`. The sensor's own tunables (timeouts, budgets, rate limits) keep their defaults unless you add them with an override file. Each sensor page lists them, and the sensor README has the full table.

| Variable | Default | Sensor | Description |
| --- | --- | --- | --- |
| `REDIS_MAX_CONNECTIONS`, `REDIS_MAX_PER_IP` | `200`, `8` | Redis | Connection caps, in total and per source address |
| `DOCKER_MAX_CONNECTIONS`, `DOCKER_MAX_PER_IP` | `200`, `8` | Docker | Connection caps |
| `MYSQL_MAX_CONNECTIONS`, `MYSQL_MAX_PER_IP` | `200`, `8` | MySQL | Connection caps |
| `MYSQL_ACCOUNTS` | `root:,root:root,admin:admin,mysql:mysql` | MySQL | Comma-separated `user:password` pairs that log in. Weak on purpose. |
| `MSSQL_MAX_CONNECTIONS`, `MSSQL_MAX_PER_IP` | `200`, `8` | MSSQL | Connection caps |
| `ADB_MAX_CONNECTIONS`, `ADB_MAX_PER_IP` | `200`, `8` | ADB | Connection caps |
| `SMB_MAX_CONNECTIONS`, `SMB_MAX_PER_IP` | `200`, `10` | SMB | Connection caps |
| `SMB_HOSTNAME`, `SMB_DOMAIN` | empty (derived) | SMB | NetBIOS computer name (1 to 15 characters) and domain or workgroup. Empty means a realistic name derived from the sensor's secret. |
| `SMB_SMB1_MODE` | `steer` | SMB | `steer` switches SMB1 clients to SMB2 and records them. `reset` records and drops them. |
| `SIP_MAX_CONNECTIONS`, `SIP_MAX_PER_IP` | `200`, `8` | SIP | TCP connection caps |
| `SIP_OWN_IPS` | empty | SIP | Comma-separated addresses of this host. The sensor never answers them, so it cannot be made to talk to itself. |

```{note}
For ADB, Docker and SIP, the connection caps that Compose sets (200 and 8) are higher than the defaults in the sensor README. When you run the stack, the Compose values apply.
```

Each of these sensors needs its own Redis password in `.env` (`REDIS_SENSOR_<NAME>_PASSWORD`). See [Secrets](#secrets). Each host port must differ from the others and from `DASHBOARD_PORT`. The [port guard](deployment.md#port-guard) checks this.

## Sensors added in M20

The Synology sensor (M20) has its own Redis user, stream and network, like the others. Compose sets its public ports, its connection caps and its memory limit. The ports are in [Compose and host](#compose-and-host). The table lists the variables you can set in `.env`. The sensor README has the full list of tunables.

| Variable | Default | Description |
| --- | --- | --- |
| `SYNOLOGY_MAX_CONNECTIONS`, `SYNOLOGY_MAX_PER_IP` | `200`, `8` | Connection caps, in total and per source address |
| `SYNOLOGY_CONN_RATE`, `SYNOLOGY_CONN_BURST` | `5`, `20` | New connections per second per source address, and the burst |
| `SYNOLOGY_MEMORY_BUDGET_MB` | `80` | Memory for connections and request bodies in flight. Compose sets `SYNOLOGY_MEMORY_LIMIT_MB` to 160, the container limit. |
| `SYNOLOGY_EVENTS_PER_SEC`, `SYNOLOGY_GLOBAL_EVENTS_PER_SEC` | `20`, `200` | Event caps per source address and for the sensor |
| `SYNOLOGY_HTTP_REDIRECT` | `false` | Redirect the HTTP login page to HTTPS, as a DSM with forced HTTPS does. Off by default: DSM serves the UI on port 5000. |

The Redis password is `REDIS_SENSOR_SYNOLOGY_PASSWORD`. See [Secrets](#secrets). The [sensor page](sensors/synology.md) describes what the sensor emulates and records.

## Demo data

| Variable | Default | Source | Description |
| --- | --- | --- | --- |
| `DEMO_DAYS` | `30` | `.env` | Number of days the demo data covers |
| `DEMO_SESSIONS` | `3000` | `.env` | Number of sessions the backfill creates |
| `DEMO_SEED` | `42` | `.env` | Random seed. The same seed gives the same data. |

See [Demo data](demo-data.md) for the command-line options that override these.

## Retention and disk guard

| Variable | Default | Description |
| --- | --- | --- |
| `RETENTION_DAYS` | `90` | Days to keep raw events (7 to 3650). Aggregates are kept forever. Read by the `migrate` service, which re-applies the policies on every run. See [Data retention](retention.md). |
| `DB_MAX_SIZE_GB` | `10` | Size ceiling of the database (at least 1). Above 90% the disk guard drops the oldest raw chunks down to 80%. Above 95% ingest keeps only payload previews. Read by `migrate` and `ingest`. |

## Blocklists and feeds (M16)

Details in [Defend](defend.md). Ingest scores indicators into blocklists when `BLOCKLIST_ENABLED=true`; the API serves a token-protected feed when `FEEDS_ENABLED=true`. Both are off by default.

| Variable | Default | Description |
| --- | --- | --- |
| `BLOCKLIST_ENABLED` | `false` | Score addresses, hosts, URLs and hashes into the blocklists (ingest, every 15 minutes) |
| `BLOCKLIST_WINDOW_DAYS` | `30` | How many days of sessions and indicators to score (1 to 365) |
| `BLOCKLIST_MAX_ROWS` | `20000` | Most entries kept, best score first (100 to 1,000,000) |
| `CONTACTS_SHARED_ASNS` | Google, Cloudflare, Microsoft, Akamai, Fastly, Meta, Apple | Comma-separated AS numbers whose addresses are dropped from VirusTotal-sourced probable-C2 contacts (read from the local ASN database, no lookup). Replaces the default list. ThreatFox C2 entries are never filtered by network. Pass it to the `ingest` service in `docker-compose.yml` to use it. |
| `BLOCKLIST_NEVER` | empty | Addresses, networks and names never listed (also read: `AUTH_TRUSTED_PROXIES`, `API_ALLOWED_HOSTS`, `INDICATORS_IGNORE`) |
| `FEEDS_ENABLED` | `false` | Serve `/feeds/*` with bearer tokens made in Settings. The only part of the API outside the dashboard login |

## Campaigns and ATT&CK (M15)

Details in [Architecture](ARCHITECTURE.md#analysis-workers-m15-to-m19). Both switches are off by default. Compose passes these variables to `ingest` and `api`.

| Variable | Default | Description |
| --- | --- | --- |
| `ATTACK_ENABLED` | `false` | Sync the MITRE ATT&CK catalogue every hour and label sessions with techniques |
| `CAMPAIGNS_ENABLED` | `false` | Cluster finished sessions into campaigns, every 5 minutes |
| `CAMPAIGN_MIN_SOURCES` | `2` | Distinct sources a shared key needs before it makes a campaign (2 to 100) |
| `CAMPAIGN_LINK_CAP` | `500` | Most sessions linked to one campaign (10 to 10,000) |
| `CAMPAIGNS_MAX_ROWS` | `50000` | Row ceiling of the campaign tables. The oldest, least seen rows go first (1,000 to 50 million) |

## Script library and LLM explainer (M17)

Details in [Architecture](ARCHITECTURE.md#analysis-workers-m15-to-m19). The explainer is off by default. When it is on, it sends the **normalised** command text of one script (addresses, host names and URLs are replaced by placeholders) to the Anthropic API, and nothing else. Set the key with `ANTHROPIC_API_KEY`. The API also accepts it as provider `anthropic` (`PUT /api/v1/settings/providers/anthropic`), which overrides the variable, but the Settings page does not show a card for it yet.

| Variable | Default | Description |
| --- | --- | --- |
| `SCRIPTS_ENABLED` | `false` | Fingerprint sessions with two or more commands into the script library, every 5 minutes |
| `SCRIPTS_MAX_ROWS` | `100000` | Row ceiling of the script tables (1,000 to 50 million) |
| `LLM_ENABLED` | `false` | Allow the optional LLM explanation. An administrator still has to ask for each one ("Explain now"). |
| `LLM_DAILY_QUOTA` | `50` | Calls to the model per UTC day, 0 to 10,000. Kept in the database, so a restart does not reset it. |
| `LLM_MONTHLY_TOKEN_CAP` | `2000000` | Tokens per UTC month, 0 to 1 billion. Kept in the database. |
| `LLM_MODEL` | `claude-haiku-5-5` | Model name: lower-case letters, digits, `-`, `.` and `_`, at most 64 characters |
| `ANTHROPIC_API_KEY` | empty | API key for the explainer. Needed only when `LLM_ENABLED=true`. |

## Alerts and weekly report (M18)

Details in [Architecture](ARCHITECTURE.md#analysis-workers-m15-to-m19). Alerts and the report are off by default. Discord and Teams targets are not set here. You add them in the dashboard (Alerts), where they are checked and stored encrypted. Every rule starts off, and you switch on each one yourself.

| Variable | Default | Description |
| --- | --- | --- |
| `ALERTS_ENABLED` | `false` | Evaluate the alert rules and deliver messages |
| `REPORTS_ENABLED` | `false` | Build the weekly report after each Monday 06:00 (site time) |
| `ALERTS_DASHBOARD_URL` | empty | Public `https` address of the dashboard, with no query string. Alert messages link to the matching page. Without it, messages have no links. |
| `SITE_TIMEZONE` | `UTC` | IANA time zone (for example `Europe/Zurich`) that decides when the week starts for the report |
| `SMTP_HOST` | empty | SMTP server for e-mail alerts. E-mail needs `SMTP_HOST` and `SMTP_FROM`. |
| `SMTP_PORT` | `587`, or `465` with `SMTP_SECURITY=ssl` | SMTP port (1 to 65535) |
| `SMTP_SECURITY` | `starttls` | `starttls` (usually port 587) or `ssl` (usually port 465). Plain text is not offered. The certificate is always checked. |
| `SMTP_USER` | empty | Login name. Leave empty for a server that needs no login. |
| `SMTP_FROM` | empty | Sender address of the alerts (a plain e-mail address) |
| `SMTP_PASSWORD` | empty | Login password. It can also be set in Settings, under provider `smtp`. |

Discord and Teams webhooks need no variable. They are stored as channels in the database. The outbound hosts are listed in [Architecture](ARCHITECTURE.md#outbound-hosts).

## Today and search (M19)

Today, global search, the glossary and the research-scanner switch need no variable. Research scanners are labelled by the network that owns them, and they are left out of lists unless a page asks for them (`include_benign`). The list of scanners is in `ingest/rules/scanners.yaml`.

## Anonymous egress and payload collection (M21)

Details in [Architecture](ARCHITECTURE.md#anonymous-egress-m21) and [Deployment](deployment.md#anonymous-egress-vpn). Every outbound request of the stack goes through a WireGuard tunnel in the `vpn` service. There is no direct mode: without a tunnel, the outbound features stay idle.

| Variable | Default | Description |
| --- | --- | --- |
| `COMPOSE_PROFILES` | unset | Add `egress` to run `vpn`, `collector` and `analyzer`. Without it the stack is healthy but has no outbound traffic. |
| `VPN_WG_PRIVATE_KEY` | empty | Interface private key from your provider's WireGuard config. A secret. |
| `VPN_WG_PEER_PUBLIC_KEY` | empty | Public key of the provider's server |
| `VPN_WG_ADDRESSES` | empty | Interface addresses, comma-separated. IPv6 entries are ignored. |
| `VPN_WG_DNS` | empty | The provider's DNS address (informational: names resolve through the tunnel) |
| `VPN_WG_ENDPOINT_IP` | empty | Server address, without the port (a public IPv4 address) |
| `VPN_WG_ENDPOINT_PORT` | empty | Server UDP port |
| `EGRESS_PROXY_PASSWORD` | empty | Password of the `vpn` HTTP proxy. At least 24 characters, required with the profile. A secret. |
| `EGRESS_PROXY_URL` | `http://vpn:8888` | Proxy used by ingest and collector |
| `EGRESS_CONTROL_URL` | `http://vpn:8000` | Control server (read-only status routes) |
| `EGRESS_ECHO_URLS` | `https://api.ipify.org,https://icanhazip.com` | Services that answer with the caller's public address. At least two must agree. |
| `EGRESS_ALLOWED_CIDRS` | empty | Networks the VPN exit address must belong to, comma-separated. Empty means the /24 of `VPN_WG_ENDPOINT_IP`. Set it when your provider exits elsewhere. |
| `EGRESS_CHECK_INTERVAL_S` | `300` | Seconds between egress self-checks |
| `POSTGRES_COLLECTOR_PASSWORD`, `POSTGRES_ANALYZER_PASSWORD` | empty | Passwords of the collector and analyzer database roles. At least 24 characters, all different from each other and from the other secrets. Required with the profile. Secrets. |
| `POSTGRES_COLLECTOR_USER`, `POSTGRES_ANALYZER_USER` | `suckerpot_collector`, `suckerpot_analyzer` | Role names |
| `COLLECTOR_ENABLED` | `false` | Fetch captured download URLs and analyse the files. Off by default. |
| `COLLECTOR_POLL_S` | `15` | Seconds between two looks for new URLs |
| `COLLECTOR_MAX_BYTES` | `16777216` | Largest file kept (16 MiB) |
| `COLLECTOR_TIMEOUT_S` | `60` | Total time for one fetch |
| `COLLECTOR_CONNECT_TIMEOUT_S` | `10` | Connect time for one fetch |
| `COLLECTOR_MAX_REDIRECTS` | `3` | Redirects followed, each one validated |
| `COLLECTOR_CONCURRENCY` | `2` | Fetches in flight (one per host) |
| `COLLECTOR_HOST_INTERVAL_S` | `10` | Seconds between two requests to the same host |
| `COLLECTOR_HOURLY_QUOTA`, `COLLECTOR_DAILY_QUOTA` | `60`, `500` | Fetches per hour and per day |
| `COLLECTOR_REFETCH_HOURS` | `24` | Minimum age before a URL that was seen again is fetched again |
| `COLLECTOR_MAX_DEPTH` | `2` | How many levels of next-stage URLs found inside fetched scripts are followed |
| `COLLECTOR_DENY_CIDRS` | empty | Extra networks the collector must never contact (your own ranges), comma-separated |
| `QUARANTINE_MAX_MB` | `2048` | Size cap of the quarantine volume. At the cap, fetching stops. |
| `QUARANTINE_RETENTION_DAYS` | `90` | Days to keep a file after it was last seen. Its row and analysis stay. |
| `ANALYZER_TIMEOUT_S` | `60` | Wall-clock limit for analysing one file |
| `ANALYZER_MEMORY_MB` | `384` | Memory cap of the parser child process |

`scripts/check-vpn-env.sh` (run by `just up` and `just config`) checks these settings and prints variable names only, never values. It refuses a missing endpoint, a private endpoint address, a proxy password under 24 characters, and missing or repeated database passwords.

`FETCH_PAYLOADS`, `PAYLOAD_MAX_BYTES` and `PAYLOAD_TIMEOUT_SECONDS` no longer exist. `COLLECTOR_ENABLED`, `COLLECTOR_MAX_BYTES` and `COLLECTOR_TIMEOUT_S` replace them.

## Anonymous reporting (M22)

Details in [Architecture](ARCHITECTURE.md#anonymous-reporting-m22), [Deployment](deployment.md#anonymous-reporting) and [Security](SECURITY.md#anonymous-reporting-m22). The worker is off by default. It only prepares drafts; it sends nothing unless you set up SMTP sending in Settings > Reporting (off by default, [M25 design](design/m25.md)). RDAP lookups go through the VPN egress gate, so the `egress` profile must be on.

| Variable | Default | Description |
| --- | --- | --- |
| `ABUSE_REPORTS_ENABLED` | `false` | Run the abuse worker in `ingest` |
| `ABUSE_BUILD_INTERVAL_S` | `3600` | Seconds between two draft builds (60 to 86400) |
| `ABUSE_MIN_LOGIN_ATTEMPTS` | `50` | Failed logins that select a source. A login followed by commands, a download attempt or a severe tag also selects it. |
| `ABUSE_SEVERE_TAGS` | built-in list | Tags that select a source: `malware-drop`, `mirai`, `crypto-miner`, `php2shell`, `exploit` and any `cve-*` tag. Empty means the built-in list. |
| `ABUSE_LOOKBACK_DAYS` | `7` | Days of evidence in a report |
| `ABUSE_SETTLE_MIN` | `30` | Minutes a source must be quiet before it is drafted |
| `ABUSE_RESEND_DAYS` | `14` | Days before the same source can be reported again to the same recipient |
| `ABUSE_MAX_SUBJECTS` | `100` | Subjects per report (maximum 100) |
| `ABUSE_MAX_OPEN_DRAFTS` | `200` | Drafts open at once |
| `ABUSE_RDAP_DAILY_QUOTA`, `ABUSE_RDAP_HOURLY_QUOTA` | `1000`, `200` | Hard RDAP request quotas. Each redirect and fallback counts. |
| `ABUSE_REPORTS_INCLUDE_DEMO` | `false` | Also draft from demo data (documentation addresses). Demo drafts can never be sent. |
| `ABUSE_ROUND_TIMES` | `true` | Round times in reports to the minute. Set `false` to allow exact times. |
| `ABUSE_REPORT_RETENTION_DAYS` | `730` | Days to keep reports marked sent or closed (the duplicate check needs the history). Discarded drafts are removed after 90 days. |

The reply contact, signature and all wording are not environment variables. The owner types them in Settings > Reporting. Only the reply contact is required. To keep the identity guard accurate, the `api` service also reads the sensor host name variables, `API_ALLOWED_ORIGINS`, `ALERTS_DASHBOARD_URL`, `INDICATORS_IGNORE`, `BLOCKLIST_NEVER`, `AUTH_TRUSTED_PROXIES` and `VPN_WG_ENDPOINT_IP`. These are used only to build the list of terms a report must never contain.

## Replies to reports (M26)

Details in [Replies to reports](replies.md). The worker is off by default. Mail is read only through the VPN, and only when `ABUSE_REPLIES_ENABLED` is `true` **and** you save and enable a mailbox in Settings > Reporting > Replies. The mailbox (server, user name, password, folder, trusted provider name) is never an environment variable. Pasted replies work without any of this.

| Variable | Default | Description |
| --- | --- | --- |
| `ABUSE_REPLIES_ENABLED` | `false` | Run the replies worker in `ingest`. It also processes pasted replies. |
| `ABUSE_REPLY_MAX_BYTES` | `262144` | Largest mail read, in bytes (65,536 to 1,048,576). Larger mail is cut and marked as truncated. |
| `ABUSE_REPLY_MAX_PER_POLL` | `50` | Mails read in one poll (1 to 500). The rest waits for the next poll. |
| `ABUSE_REPLY_DAILY_CAP` | `500` | Mails read per UTC day (1 to 10,000). |
| `ABUSE_REPLY_POLL_DEADLINE_S` | `120` | Seconds one poll may take in total (30 to 600). |
| `ABUSE_REPLY_EXCERPT_CHARS` | `2000` | Characters of a reply kept as an excerpt (0 to 2,000). `0` keeps none. |
| `ABUSE_REPLY_EXCERPT_DAYS` | `180` | Days an excerpt is kept (1 to 3,650). Read by `migrate` for the retention job. |
| `ABUSE_REPLY_MATCH_DAYS` | `120` | A reply is matched to reports sent in the last N days (1 to 730). |
| `ABUSE_NO_ANSWER_DAYS` | `14` | Days without an answer before a sent report shows **No answer** (1 to 365). Read by `api`. |

The check interval of the mailbox is set in Settings (5 to 1440 minutes, 15 by default), not here.

## Takedown tracking and abuse.ch submission (M27)

Details in [Takedowns](takedowns.md). Everything is off by default. The collector re-checks a payload URL only with `TAKEDOWN_ENABLED=true` **and** `COLLECTOR_ENABLED=true`, through the VPN. Re-checks are one bounded GET of a URL that already served a sample. C2 servers and attacking addresses are never contacted.

abuse.ch submission needs three things: `ABUSECH_SUBMIT_ENABLED=true`, a mode other than **Off** in Settings > Reporting > abuse.ch, and an Auth-Key saved there. The key is never an environment variable.

| Variable | Default | Description |
| --- | --- | --- |
| `TAKEDOWN_ENABLED` | `false` | Run the takedown worker in `ingest` and the HTTP re-checks in `collector` (the latter also needs `COLLECTOR_ENABLED=true`). |
| `TAKEDOWN_TRACK_DAYS` | `30` | Days a target is followed after it was reported (7 to 90). |
| `TAKEDOWN_HTTP_DAILY_QUOTA` | `200` | Re-checks per day, read by `collector` (at least 1). |
| `TAKEDOWN_INTEL_DAILY_QUOTA` | `100` | Lookups per day (URLhaus and ThreatFox) that takedown tracking may make. Each one also counts against `ABUSECH_DAILY_QUOTA`. |
| `TAKEDOWN_ABUSEIPDB_DAILY_QUOTA` | `50` | AbuseIPDB reads per day that takedown tracking may make. Each one also counts against `ABUSEIPDB_DAILY_QUOTA`. SuckerPot never reports to AbuseIPDB. |
| `TAKEDOWN_QUIET_DAYS` | `7` | Days without a sighting before an attacking address counts as quiet (1 to 90). |
| `TAKEDOWN_CHECK_RETENTION_DAYS` | `400` | Days to keep individual checks (30 to 3,650). Read by `migrate`. The monthly roll-up is kept forever. |
| `TAKEDOWN_INTERVAL_S` | `600` | Seconds between two takedown cycles in `ingest` (30 to 86,400). Read by the worker. |
| `ABUSECH_SUBMIT_ENABLED` | `false` | Server switch for submitting captured malware URLs to URLhaus, and C2 addresses to ThreatFox. Read by `ingest` and `api`. When it is `false`, the Settings card shows the switch as disabled. |

The abuse.ch lookup key (used to check whether a value is already listed) is the same as before: `ABUSECH_AUTH_KEY`, or the key on the Settings page. The submission Auth-Key is separate and is entered only in Settings > Reporting > abuse.ch.

## SuckerPot network (M29)

The network is an experimental preview and is off by default. Details are in [The SuckerPot network](network.md) and [Network protocol](network-protocol.md). To use it, set `NETWORK_ENABLED=true` and join: through the installer question (the default answer is no, and `--join-network` answers yes) or in Settings, Network. A system sends nothing until it has joined.

| Variable | Default | Service | Description |
| --- | --- | --- | --- |
| `NETWORK_ENABLED` | `false` | `ingest`, `api` | Master switch. It only unlocks joining. With `false` (the default in Compose) the worker never contacts the hub, and the Network pages explain how to allow it. An install that already has `NETWORK_ENABLED=true` in its `.env` keeps it |
| `NETWORK_HUB_URL` | empty | `ingest`, `api` | Address of the hub, for example `https://hub.example.org`. Must be HTTPS, with no path and no credentials. Set it together with `NETWORK_HUB_KEY` |
| `NETWORK_HUB_KEY` | empty | `ingest`, `api` | The hub's public key (base64url, 32 bytes). The node refuses any answer that this key did not sign |
| `NETWORK_INTERVAL_S` | `900` | `ingest` | Seconds between worker cycles, from 30 to 86400. While a join or a leave is pending, the worker checks every 60 seconds |
| `NETWORK_SUBMIT_DELAY_MIN_H` | `2` | `ingest` | Shortest random wait, in hours, after a UTC day ends before its batch is sent. From 0 to 23 |
| `NETWORK_SUBMIT_DELAY_MAX_H` | `20` | `ingest` | Longest random wait, in hours. From 1 to 23, and above the minimum |
| `NETWORK_MAX_SOURCES` | `5000` | `ingest` | Attacker addresses per batch. The most severe are kept first. From 1 to 5000 |

Notes:

- A wrong value (for example a hub URL with a path, or only one of the URL and the key) keeps the network off, and `ingest` logs an error. Check its log after you change these.
- Storing the node key needs `SETTINGS_ENCRYPTION_KEY`. Without it, joining stops with `no_settings_key`.
- `NETWORK_ENABLED`, `NETWORK_HUB_URL` and `NETWORK_HUB_KEY` can be changed with `just set` (for example `just set NETWORK_ENABLED=false`). `NETWORK_HUB_KEY` is the hub's public key, so it is the one `*_KEY` name that `just set` accepts.
- Joining, the pseudonym, the country and leaving are done in the dashboard, not in `.env`. The hub's own settings are in `hub/README.md`.

## Participant mode, verification and automatic updates (M32)

Participant mode is described in [Join the network](participate.md). The installer writes these lines. They are commented out in `.env.example` on purpose, so a full install does not carry them.

| Variable | Default | Service | Description |
| --- | --- | --- | --- |
| `SUCKERPOT_STACK_MODE` | `full` | scripts | `full` or `participant`. Chosen at install. `./scripts/install.sh --full` switches a participant install to full |
| `COMPOSE_FILE` | `docker-compose.yml` | compose | In participant mode: `docker-compose.yml:docker-compose.participant.yml` |
| `COMPOSE_PROFILES` | `egress` (full) | compose | `direct` starts `hubproxy` (no VPN). `egress` starts the VPN. Never both |
| `EGRESS_MODE` | `vpn` | `ingest` | `direct` reaches only the hub, through `hubproxy`. `vpn` uses the VPN proxy |
| `HUBPROXY_ALLOW` | the hub host, port 443 | `hubproxy` | Comma-separated `host:443` pairs, at most two. Direct mode only |
| `NETWORK_CONSENT` | empty | `ingest` | Consent record `v2:<list>:<UTC day>`, written by the installer (participant mode, or a yes to the network question in full mode) or `participant.sh join`. `ingest` joins from it once, and never again after a leave. `ingest` ignores a record older than 7 days. `just set NETWORK_CONSENT=` clears it; `just set` refuses any non-empty value. `ingest` does not join on a version it does not know (`consent_outdated`) |
| `NETWORK_PSEUDONYM` | random | `ingest` | Optional pseudonym |
| `NETWORK_COUNTRY`, `NETWORK_SHOW_COUNTRY` | empty, `false` | `ingest` | Optional two-letter country, shown only if you opt in and enough members share it |
| `NETWORK_VERIFY_REVEALS` | `false` (`true` in participant mode) | `ingest` | Answer the hub when it asks for a link that several sensors saw |
| `NETWORK_VERIFIER` | `false` | `ingest` | Ask to be a verifier. Needs a VPN and `COLLECTOR_VERIFY_ENABLED`. The hub operator must grant the role (`verifier_needs_vpn` and `verifier_needs_collector` explain a refusal) |
| `COLLECTOR_VERIFY_ENABLED` | `false` | `collector` | Let the collector fetch links for the network |
| `NETWORK_VERIFY_DAILY_CAP` | `100` | `ingest` | Local cap on verification fetches per day |
| `NETWORK_VERIFY_HOST_DAILY_CAP` | `3` | `ingest` | Local cap per site per day |
| `SELF_TERMS_AUTO_CONFIRM` | `false` (`true` in participant mode) | `ingest` | Learned own addresses act without a click |
| `SELF_ADDRESS` | empty | `ingest` | Optional own public address. No script looks it up |
| `AUTO_UPDATE_ENABLED` | `false` (`true` in participant mode) | scripts | Install new signed releases once a day from the user's crontab. See [Updates](updates.md#automatic-updates) |

The hub address and key are not in `.env` by default. They ship inside each release (`config/network-defaults.env`), and an explicit `.env` value always wins. `NETWORK_HUB_KEY` accepts up to three comma-separated keys, for a key rollover.

## Community lists (M30)

The community blocklist feeds are free and public. A node can fetch them, and firewalls can fetch the public files directly, with or without a node. Details are in [Community blocklist feeds](feeds.md). Fetching is off by default, and it does not depend on network membership.

| Variable | Default | Service | Description |
| --- | --- | --- | --- |
| `NETWORK_FEED_ENABLED` | `false` | `ingest`, `api` | Fetch the public lists through the VPN gate. Nothing is requested while this is `false`. The Network tab shows the lists as off until it is `true`. |
| `NETWORK_FEED_URL` | empty | `ingest`, `api` | Base address of the feed, for example `https://feeds.example.org/v1`. HTTPS only, no query string, no credentials. The API shows it as the copy address. Set it by hand in `.env`. |
| `NETWORK_FEED_KEY` | empty | `ingest` | The feed's minisign public key, starting with `RW`. This is not the hub key. Set it by hand in `.env`. |
| `NETWORK_FEED_INTERVAL_S` | `3600` | `ingest` | Seconds between fetches, from 900 to 86400 |
| `NETWORK_FEED_LISTS` | `inbound,outbound,outbound-domains` | `ingest` | Lists to store. Choose from `inbound`, `inbound-high`, `outbound`, `outbound-high` and `outbound-domains`. The high lists are subsets, and each stored row carries its tier. |
| `FEEDS_ENABLED` | `false` | `api` | Serves the token-protected mirror under `/feeds`. Needed for the local mirror of the community lists (token kind `network`). The same switch as in [Blocklists and feeds (M16)](#blocklists-and-feeds-m16). |

Notes:

- `NETWORK_FEED_URL` and `NETWORK_FEED_KEY` must be set together. A wrong value leaves the feed unconfigured, and `ingest` logs an error. Check its log after you change them.
- `just set NETWORK_FEED_ENABLED=true` works. `NETWORK_FEED_URL` and `NETWORK_FEED_KEY` are not in the `just set` list, so set them in `.env`.
- Turning the fetch off deletes the stored list rows on the next worker cycle. Leaving the SuckerPot network does not delete them.
- The node checks the signature, the serial (no rollback), `valid_until`, and the sha256 of every file before it stores anything. If a check fails, the last good copy stays. After `valid_until` without a new index, the entries are kept for display only, and the local mirror serves nothing.

## In `.env.example` but not used yet

These names are in the template. The code does not read them, so setting them has no effect today.

| Variable | Default | Milestone | Description |
| --- | --- | --- | --- |

## Data sources and attribution

SuckerPot shows data from third parties. Keep these credits visible if you publish a screenshot or a page that shows the data.

| Data | Used when | Credit |
| --- | --- | --- |
| DB-IP Lite (country, city, ASN) | `GEOIP_PROVIDER` is `auto` without MaxMind keys, or `dbip` | IP geolocation data by DB-IP.com, CC BY 4.0, https://db-ip.com |
| MaxMind GeoLite2 | `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY` are set | This product includes GeoLite2 data created by MaxMind (https://www.maxmind.com) |
| AbuseIPDB, GreyNoise Community | Their API keys are set | Scores are read only. Respect each service's terms and daily quota. |

The API returns the credit text in `GET /api/v1/settings/enrichment` (`geoip.attribution`), and the dashboard shows it. The `.mmdb` files are downloaded by ingest at run time and are never committed to the repository, because their licences do not allow redistribution.
