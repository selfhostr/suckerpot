# Architecture

This page describes how SuckerPot is built: the services, the networks, the queue, the database and the API. For the threat model and the controls, see [Security](SECURITY.md).

```{admonition} Build status
:class: note

**Built and wired in Compose:** Redis, the database and its migrations, ingest (multi-stream, with GeoIP, reputation and tagging), the API with its REST endpoints and live WebSocket feed, the SSH, RDP, Telnet and web sensors, the seven sensors of M9 (Redis, Docker, MySQL, MSSQL, ADB, SMB and SIP), and the web UI (served by the API once built).

**Under security review:** the web sensor (M6) and the M9 sensors. The sensor pages show the status of each one.

**In progress:** the analytics API (M5).

**Built since:** insights, trends and malware endpoints and pages (M7), and dashboard login (M8).

**Built since:** retention, compressed storage, kept-forever aggregates and the database disk guard (see [Data retention](retention.md)), and backups (`just backup`).

**Built in M20:** the Synology NAS sensor (a DSM look-alike on ports 5000 and 5001), the CVE watch fixes (a 60-day window in daily chunks, resumable runs, watched-CVE lookups by id) and a separate Compose overlay for `just test-integration`.

**Built since (M10 to M19):** RDP depth, Settings that edit keys, CVE watch, indicators, users and roles, campaigns and ATT&CK, Defend (blocklists, exports, the opt-in feed, detections and exposure), the script library, alerts and the weekly report, and Today, search and research-scanner labels. The analysis features are in [Analysis workers](#analysis-workers-m15-to-m19).
```

## Overview

SuckerPot runs as a set of Docker Compose services on one host. Fake services, called sensors, take the attacks. Each attack becomes an event. Events go through Redis streams (one per sensor), are checked, enriched and stored by ingest, and end up in PostgreSQL with TimescaleDB. The API reads the database and serves the dashboard.

```
Internet
   │
   ▼
Router or hypervisor firewall
   │
   ▼
Host (nftables table "suckerpot_host", see Deployment)
   │
   ├─► 12 sensors      ─┐  each sensor: sp-ingress (inbound only)
   │   remote shells:     │  + its own internal network to Redis
   │     ssh, telnet, adb │
   │   web and APIs:      │
   │     web, docker,     │
   │     synology         │
   │   databases:         │
   │     redis, mysql,    │
   │     mssql            │
   │   Windows and VoIP:  │
   │     rdp, smb, sip   ─┘
                │  XADD events:<sensor>   (one Redis user per sensor)
                ▼
          Redis Streams  ◄── demo (just demo, network "tools")
                │  XREADGROUP / XACK / XTRIM / XAUTOCLAIM
                ▼
             ingest ──► GeoIP, reputation, tagging (egress network only)
                │
                │  INSERT / UPDATE (role suckerpot_ingest)
                ▼
     PostgreSQL + TimescaleDB
                │  SELECT (role suckerpot_api)
                ▼
     API (FastAPI: REST, WebSocket, built SPA)   network "dashboard"
                ▲
                │  reverse tunnel, such as cloudflared
                │
           Web UI (browser)
```

## Services

| Service | Networks | Role | Status |
| --- | --- | --- | --- |
| `redis` | `sensors-ssh`, `sensors-rdp`, `sensors-telnet`, `sensors-web`, `sensors-redis`, `sensors-docker`, `sensors-mysql`, `sensors-mssql`, `sensors-adb`, `sensors-smb`, `sensors-sip`, `sensors-synology`, `tools`, `backend` | Valkey (Redis protocol) Streams queue. Named ACL users (see below). AOF persistence on `redis-data`. | Built |
| `db` | `backend`, `samples` | PostgreSQL 17 with TimescaleDB 2.31.0, on `db-data`. Runs only as the owner role. | Built |
| `migrate` | `backend` | One-shot. Checks the secrets policy, runs `alembic upgrade head`, then re-applies the application roles and their passwords, and exits with code 0. | Built |
| `ingest` | `backend`, `egress-proxy` | Reads all sensor streams, validates events, enriches and tags them, writes them to the database. Outbound calls go through the `vpn` proxy only. | Built. GeoIP files live on the `geoip-data` volume. |
| `api` | `backend`, `dashboard` | FastAPI (512 MB memory limit). REST endpoints, WebSocket feed, `/healthz`, and the built web UI when present. The only service with a dashboard port. | Built |
| `sensor-ssh` | `ingress`, `sensors-ssh` | SSH honeypot. See [SSH sensor](sensors/ssh.md). | Built |
| `sensor-telnet` | `ingress`, `sensors-telnet` | BusyBox-style Telnet sensor. See [Telnet](sensors/telnet.md). Stream `events:telnet`. | Built |
| `sensor-adb` | `ingress`, `sensors-adb` | Android TV box with `adbd`. See [ADB](sensors/adb.md). Stream `events:adb`. | Built (M9) |
| `sensor-web` | `ingress`, `sensors-web` | See [Web](sensors/web.md). Stream `events:web`. | Built (M6), under security review |
| `sensor-docker` | `ingress`, `sensors-docker` | Exposed Docker Engine API. See [Docker](sensors/docker.md). Stream `events:docker`. | Built (M9) |
| `sensor-redis` | `ingress`, `sensors-redis` | Redis 7.2 with no password. See [Redis](sensors/redis.md). Stream `events:redis`. | Built (M9) |
| `sensor-mysql` | `ingress`, `sensors-mysql` | MySQL 8.0 with weak logins. See [MySQL](sensors/mysql.md). Stream `events:mysql`. | Built (M9) |
| `sensor-mssql` | `ingress`, `sensors-mssql` | SQL Server look-alike. See [MSSQL](sensors/mssql.md). Stream `events:mssql`. | Built (M9) |
| `sensor-rdp` | `ingress`, `sensors-rdp` | RDP sensor (NLA and NTLM). See [RDP](sensors/rdp.md). Stream `events:rdp`. | Built |
| `sensor-smb` | `ingress`, `sensors-smb` | SMB file service, observation only. See [SMB](sensors/smb.md). Stream `events:smb`. | Built (M9) |
| `sensor-sip` | `ingress`, `sensors-sip` | Asterisk-style PBX on UDP and TCP 5060. See [SIP](sensors/sip.md). Stream `events:sip`. | Built (M9) |
| `sensor-synology` | `ingress`, `sensors-synology` | Synology DSM 7.2.1 look-alike on HTTP 5000 and HTTPS 5001. See [Synology](sensors/synology.md). Stream `events:synology`. | Built (M20), under security review |
| `vpn` | `vpn-uplink`, `egress-proxy` | WireGuard client (gluetun) with a kill switch, an HTTP proxy and a small control server. The only container with a route to the internet. Profile `egress`. | Built (M21) |
| `collector` | `samples`, `egress-proxy` | Fetches the files behind captured download URLs through the `vpn` proxy and stores them in quarantine. Never parses or runs them. Profile `egress`. | Built (M21) |
| `analyzer` | `samples` | Static analysis of quarantined files in a resource-limited child process. No route to the internet, Redis or ingest. Profile `egress`. | Built (M21) |
| `demo` | `tools` | Synthetic attack generator. Runs only with `--profile tools`. | Built |

Start order: `redis` and `db` first. `migrate` runs once the database is healthy. `ingest` and `api` start after `migrate` has finished with code 0. Sensors start after Redis is healthy.

## Networks

Each network has a single job. The point of the layout is that a compromised sensor can talk to Redis and to nothing else, and cannot reach another sensor.

| Network | Docker name | Outbound internet | Connected services | Why |
| --- | --- | --- | --- | --- |
| `ingress` | `sp-ingress` | None. Masquerading off, inter-container communication off. | Every sensor | Inbound traffic from attackers. Sensors cannot reach each other or the internet. |
| `sensors-<name>`, one per sensor (`sensors-ssh`, `sensors-web`, `sensors-sip`, ...) | (project prefix); bridge `sp-s-<name>` | None (`internal: true`) | `redis` and one sensor | The one link between a sensor and Redis. One network per sensor. |
| `tools` | (project prefix); bridge `sp-tools` | None (`internal: true`) | `redis`, `demo` | The demo generator reaches Redis and nothing else. |
| `backend` | (project prefix); bridge `sp-backend` | None (`internal: true`) | `redis`, `db`, `migrate`, `ingest`, `api` | Storage and processing stay off the internet. |
| `vpn-uplink` | `sp-vpn` | Outbound, but only through the WireGuard tunnel. Inter-container communication off. | `vpn` only | The one route to the internet in the whole stack. See [Anonymous egress](#anonymous-egress-m21). |
| `egress-proxy` | `sp-egress` | None (`internal: true`) | `vpn`, `ingest`, `collector` | The HTTP proxy and control server of `vpn`. Nothing else may join it. |
| `samples` | `sp-samples` | None (`internal: true`) | `db`, `collector`, `analyzer` | Keeps the collector and analyzer away from Redis, ingest and the API. |
| `dashboard` | `sp-dashboard` | None. Masquerading off. | `api` only | The published dashboard port. |
| `hub-uplink` | `sp-hubgate` | Outbound (participant mode, profile `direct`). Inter-container communication off. | `hubproxy` only | The only route out of a participant without a VPN. The host firewall allows TCP 443 to public addresses and DNS to the host's resolvers only. |
| `hub-proxy` | (project prefix); bridge `sp-hubproxy` | None (`internal: true`) | `hubproxy`, `ingest` (participant overlay) | The allow-list proxy, like `egress-proxy` for `vpn`. |

Every network has a fixed bridge name (`sp-...`, at most 15 characters), so the [host firewall](deployment.md#host-firewall) can match it by name, and none has IPv6 (`enable_ipv6: false`). Every internal network also sets `com.docker.network.bridge.gateway_mode_ipv4: isolated` (Docker Engine 28 or later): the host keeps no address on the bridge, so a compromised sensor, Redis, database or ingest has no host address to connect to. Nothing on an internal network publishes a port. On an older engine this isolation does not apply, and only the host firewall stops these containers from reaching the host. The test overlays (`docker-compose.it.yml`, `docker-compose.participant-it.yml`) drop the fixed names, so a throwaway test project never clashes with a live stack on the same machine.

### Sensors need two networks

Docker does not publish ports on an `internal: true` network. So each sensor joins two networks:

- `sp-ingress` receives the attacker's connection. With masquerading off, the sensor has no usable route back out to the internet, and with inter-container communication off it cannot talk to the other sensors.
- Its own internal network (`sensors-ssh`, ...) links it to Redis. Because the network is per sensor, one sensor cannot even see another sensor's traffic to Redis.

Each sensor also gets `dns: ["127.0.0.1"]` (external names do not resolve), and is published on an explicit IPv4 address (`0.0.0.0:<port>`), so Docker does not also listen on `[::]`.

### Why `backend` is internal

The `backend` network is created with `internal: true`. Docker gives it no route to the internet. Redis and the database sit on this network. Nothing on it can call out, and nothing outside can reach it directly.

### The `dashboard` network, and what it does not do

The `dashboard` network is a normal bridge with IP masquerading turned off. The published dashboard port works for inbound traffic. The API container also gets `dns: 127.0.0.1`, so it cannot resolve external names through Docker's resolver.

```{warning}
This is **not** a complete block on outbound traffic. Without masquerading, packets from the container keep their container address. If the host has a route for that address and no firewall rule drops them, they can still leave. The DNS setting does not stop a connection to a raw IP address. The host firewall in [Deployment](deployment.md#host-firewall) drops new connections from `sp-ingress` and `sp-dashboard`. Keep it loaded, and filter egress upstream as well.
```

### Anonymous egress (M21)

The stack's own outbound traffic never leaves from the home address. The rules:

- **Only `vpn` has an internet route.** It sits on `vpn-uplink` (`sp-vpn`) and on the internal `egress-proxy` network. No other service is attached to a network with a route out, apart from the two inbound-only networks `sp-ingress` and `sp-dashboard`.
- **`ingest` and `collector` go through the proxy.** They reach the internet only with the `suckerpot_egress` client, which sends host names to the `vpn` HTTP proxy. They do not resolve external names themselves (`dns: 127.0.0.1`), and no `HTTP_PROXY` variable is set, so a client that ignores the factory has no route and fails.
- **`analyzer` has no network out.** It shares only `samples` with `db` and `collector`.
- **`vpn` is on no backend or sample network.** Through the proxy one can reach whatever shares a network with `vpn`, so it shares networks only with its two clients.
- **A kill switch.** gluetun's firewall allows only the tunnel and the WireGuard packets to one endpoint. The [host firewall](deployment.md#host-firewall) repeats that rule for `sp-vpn`, so it holds even if gluetun's firewall failed.
- **A gate.** Before any outbound work, `ingest` and `collector` check that the tunnel is up and that the public address seen through the proxy is the one gluetun reports, a global address and inside the expected network. A closed gate pauses lookups. Events are still stored.

Without the `egress` profile there is no `vpn`, so every outbound feature stays idle (GeoIP downloads, reputation, intel, CVE feeds, alert delivery, the collector) and Settings says "no egress". There is no direct mode. Already downloaded GeoIP files keep working.

`scripts/guardrails/` holds a static test of `docker-compose.yml` that fails when these rules are broken. `just egress-check` proves them on the running stack. See [Security](SECURITY.md#anonymous-egress-m21).

### Collector and analyzer

Both run from one image (`collector/`) with different commands, networks and database roles.

| Service | Command | Networks | DB role | Quarantine |
| --- | --- | --- | --- | --- |
| `collector` | `python -m collector fetch` | `samples`, `egress-proxy` | `suckerpot_collector` | read-write |
| `analyzer` | `python -m collector analyze` | `samples` | `suckerpot_analyzer` | read-only |

The collector polls the download URLs that ingest already stored as indicators (it does not read Redis), validates each one, fetches it through the proxy with size, time, redirect and rate caps, and writes the file to the `quarantine` volume under its sha256 name (mode `0400`, never executed). The analyzer identifies the file type and architecture, hashes it (sha256, sha1, md5, TLSH), extracts strings, runs YARA rules from `collector/rules/yara/`, deobfuscates shell scripts as text and extracts URLs and C2 addresses. Next-stage URLs go back to the collector (depth 2 by default); C2 addresses become indicators. The parser runs in a child process with memory, CPU and time limits. The API mounts the quarantine read-only and serves a sample only as a password-protected archive to an administrator.

Both services are off until `COLLECTOR_ENABLED=true`. TFTP and FTP URLs are recorded but not fetched: UDP cannot cross an HTTP proxy.

### Participant mode and `hubproxy` (M32)

Participant mode (`./scripts/install.sh --participant`) runs sensors, `db`, `migrate`, `ingest`, the network node and, without a VPN, `hubproxy`. It is the base `docker-compose.yml` plus the overlay `docker-compose.participant.yml`. The overlay turns `api` off through a profile that is never set, takes the `api` dependency away from `vpn` and joins `ingest` to the `hub-proxy` network. A full install does not use the overlay and renders exactly as before.

- **`hubproxy`** (profile `direct`) is a small allow-list forward proxy, written with the Python standard library only. It accepts `CONNECT host:443` for the names in `HUBPROXY_ALLOW` (at most two: the hub, and the feed host if feeds are on) and refuses everything else, including IP literals and names that resolve to non-global addresses. It sits on the internal `hub-proxy` network (shared with `ingest` only) and on the routed `hub-uplink` network. It is the only service with a route out in that mode.
- **`ingest` keeps no route and no external DNS.** Its egress client points at `hubproxy` instead of `vpn` (`EGRESS_MODE=direct`). The egress gate has a **direct mode** with a host scope: it is open only for the hub and feed hosts, resolved like the network code does (an explicit `NETWORK_HUB_URL` / `NETWORK_FEED_URL` pair, else the shipped defaults; a placeholder or malformed default gives an empty scope, so the gate stays closed). Every other worker sees a closed gate and idles. The collector and analyzer do not run.
- **`vpn` and `hubproxy` never run together.** A participant who adds a VPN (`./scripts/participant.sh vpn <file>`) moves to profile `egress` and `EGRESS_MODE=vpn`.

### Verifier flow (M32)

1. Two or more eligible nodes report the same download link as a blinded hash.
2. The hub lists the hash in `GET /v1/verify/reveals`. A node whose consent includes `verify_reveals` and that holds the clear value sends it, after the identity guard.
3. After a random delay, a node with the `verifier` role leases the task (`GET /v1/verify/tasks`). Its `collector` fetches the link through the VPN, with the usual SSRF and size caps and no recursion.
4. The node posts an attestation (sha256, size, file type, family) to `/v1/verify/results`. The attestation never counts as a sighting.
5. A malware-like attestation plus two reporters makes the link eligible for URLhaus. See [The SuckerPot network](network.md#participants-and-verifiers) and [Network protocol](network-protocol.md#verification-added-in-m32-additive).

### Outbound hosts

| Caller | Destination | When | Rules |
| --- | --- | --- | --- |
| Alerts (Discord) | `discord.com`, `ptb.discord.com`, `canary.discord.com`, `discordapp.com` | A Discord channel is set up and a rule is on | Only `https`, port 443, a webhook path with the expected id and token shape. The URL is stored encrypted. |
| Alerts (Teams) | `outlook.office.com`, `outlook.office365.com`, and hosts under `.webhook.office.com`, `.logic.azure.com` or `.api.powerplatform.com` | A Teams channel is set up and a rule is on | Same checks as Discord, with the Workflows and connector path prefixes. |
| Alerts (e-mail) | The SMTP server you set (`SMTP_HOST`), over STARTTLS (port 587 by default) or SMTPS (465) | An e-mail channel is set up and a rule is on | The certificate is always checked. Plain text is never offered. The sender is the one address you set. |
| GeoIP download, reputation, intel, CVE feeds | The fixed hosts listed in [Enrichment](configuration.md) and in the CVE and indicator sections of [Security](SECURITY.md) | The matching feature is on | Fixed hosts only, quotas enforced, results cached 24 h. |
| Collector | The host in a captured download URL | `COLLECTOR_ENABLED=true` | The only caller whose destination is chosen by an attacker. Public addresses only (see [Security](SECURITY.md#the-collector-and-ssrf)), size, time, redirect and rate caps, never executed. |
| Egress self-check | Two public "what is my address" services (`EGRESS_ECHO_URLS`) | Every `EGRESS_CHECK_INTERVAL_S` | Goes through the proxy like everything else. |
| `vpn` | The one WireGuard endpoint (`VPN_WG_ENDPOINT_IP`, UDP) | Always, with the profile | The host firewall allows nothing else from `sp-vpn`. |
| Network hub (participant, no VPN) | The hub host in `NETWORK_HUB_URL` (and the feed host if feeds are on), port 443 | Participant mode, `EGRESS_MODE=direct` | Through `hubproxy` only: `CONNECT` to the names in `HUBPROXY_ALLOW`. The hub sees the participant's home address and does not store it. Nothing else leaves. |
| Community lists (node) | The feed host in `NETWORK_FEED_URL` (for example `https://feeds.example.org/v1`) | `NETWORK_FEED_ENABLED=true`. The address and key shipped with the release apply unless both are overridden | `GET` only, HTTPS, no redirect, no cookie, no query string, generic client name `spn-feed/1`. Through the VPN gate. The signature and the sha256 are checked before anything is stored. |

Webhook and SMTP targets are checked when they are saved and again just before each send. Private and loopback addresses are refused. Every call in this table leaves through the `vpn` proxy; no service in the stack has a direct outbound route.

The public feed (`/feeds`, see [API](api.md)) is inbound only. It is served by the API on the dashboard port, and it is off until `FEEDS_ENABLED=true`.

The community lists have two sides. The hub publishes them from its own server, outside this stack (see `hub/README.md`). A node only downloads them, through the row above. Nothing in this stack sends a list anywhere. The node's local mirror of the lists is served by the API, like the sensor feed, and reads only the stored, verified rows. See [Community blocklist feeds](feeds.md).

## Redis

### Streams

Each sensor writes to its own stream: `events:ssh`, `events:telnet`, `events:adb`, `events:web`, `events:docker`, `events:redis`, `events:mysql`, `events:mssql`, `events:rdp`, `events:smb`, `events:sip` and `events:synology`. The demo generator writes to the same streams. One stream per sensor means a flood on one sensor cannot hide the events of another, and each stream is trimmed on its own.

### Users and permissions

Redis runs with the `default` user disabled. Each named user has its own password from `.env`. The entrypoint writes the ACL file to a `tmpfs` at start-up, storing SHA-256 hashes instead of clear-text passwords. Permissions below are copied from `redis/entrypoint.sh`.

| User | Password variable | ACL | Used by |
| --- | --- | --- | --- |
| `default` | none | `off` | Nothing. Anonymous access is refused. |
| `admin` | `REDIS_PASSWORD` | `~* &* +@all` | Operators only |
| `health` | `REDIS_HEALTH_PASSWORD` | `resetkeys -@all +ping +hello +auth` | The Redis health check |
| `sensor-ssh` | `REDIS_SENSOR_SSH_PASSWORD` | `resetkeys ~events:ssh -@all +xadd +hello +auth` | `sensor-ssh` |
| `sensor-rdp` | `REDIS_SENSOR_RDP_PASSWORD` | `resetkeys ~events:rdp -@all +xadd +hello +auth` | `sensor-rdp` |
| `sensor-telnet` | `REDIS_SENSOR_TELNET_PASSWORD` | `resetkeys ~events:telnet -@all +xadd +hello +auth` | `sensor-telnet` |
| `sensor-web` | `REDIS_SENSOR_WEB_PASSWORD` | `resetkeys ~events:web -@all +xadd +hello +auth` | `sensor-web` |
| `sensor-redis` | `REDIS_SENSOR_REDIS_PASSWORD` | `resetkeys ~events:redis -@all +xadd +hello +auth` | `sensor-redis` |
| `sensor-docker` | `REDIS_SENSOR_DOCKER_PASSWORD` | `resetkeys ~events:docker -@all +xadd +hello +auth` | `sensor-docker` |
| `sensor-mysql` | `REDIS_SENSOR_MYSQL_PASSWORD` | `resetkeys ~events:mysql -@all +xadd +hello +auth` | `sensor-mysql` |
| `sensor-mssql` | `REDIS_SENSOR_MSSQL_PASSWORD` | `resetkeys ~events:mssql -@all +xadd +hello +auth` | `sensor-mssql` |
| `sensor-adb` | `REDIS_SENSOR_ADB_PASSWORD` | `resetkeys ~events:adb -@all +xadd +hello +auth` | `sensor-adb` |
| `sensor-smb` | `REDIS_SENSOR_SMB_PASSWORD` | `resetkeys ~events:smb -@all +xadd +hello +auth` | `sensor-smb` |
| `sensor-sip` | `REDIS_SENSOR_SIP_PASSWORD` | `resetkeys ~events:sip -@all +xadd +hello +auth` | `sensor-sip` |
| `sensor-synology` | `REDIS_SENSOR_SYNOLOGY_PASSWORD` | `resetkeys ~events:synology -@all +xadd +hello +auth` | `sensor-synology` |
| `demo` | `REDIS_DEMO_PASSWORD` | `resetkeys ~events:* -@all +xadd +hello +auth` | The demo generator |
| `ingest` | `REDIS_INGEST_PASSWORD` | `resetkeys ~events:* -@all +xreadgroup +xack +xgroup\|create +xautoclaim +xtrim +hello +auth (~events:parked +xadd)` | `ingest` |

The one extra right of `ingest` is a selector: `XADD` on the single key `events:parked`, the dead-letter stream (at most 500 entries, each reduced to its identifying fields and 2 KB of data, so it cannot fill the broker) for an event the database keeps refusing (it cannot write to any sensor stream). Every sensor user can only `XADD` to its own stream (`~events:<name>`). Ingest checks the `sensor` field of each event against the stream it came from, so a sensor cannot write as another sensor even if its user had wider rights.

A sensor user can only append to its own stream. It cannot read it, delete it or change its settings. The publisher turns off client info commands so the sensor users do not need `CLIENT SETINFO`. All Redis passwords must be at least 24 characters and pairwise different, or the container refuses to start.

### Server settings

| Setting | Value | Why |
| --- | --- | --- |
| Persistence | AOF, `everysec`, no RDB preamble. No RDB snapshots. | Keeps events across restarts; plain commands in the base file keep the AOF readable by Redis and Valkey alike |
| `maxmemory` | 192 MB | Bounds memory use |
| `maxmemory-policy` | `noeviction` | When memory is full, writes fail. Events are never silently evicted. |
| `proto-max-bulk-len` | 1 MB | Limits one command's payload |
| `client-query-buffer-limit` | 1 MB | Limits one client's input buffer |
| `maxclients` | 512 | Bounds connections |

Redis is never published on the host. It listens only on the internal networks.

## Event flow

1. A sensor (or the demo generator) builds an `Event` and calls `XADD` on its own stream. The stream is capped with `MAXLEN ~ EVENTS_MAXLEN` (default 10,000 entries per stream).
2. If Redis is unavailable, full or refusing the write, the publisher does not raise. It drops the event, counts it, and logs the error at most once every 30 seconds per error kind. It keeps no unbounded buffer.
3. `ingest` reads all streams (`INGEST_STREAMS`) as one consumer in the group `ingest`, with a single `XREADGROUP` call. It creates the group on each stream if needed.
4. An entry with a raw `event` field larger than 64 KiB is rejected before JSON parsing. Any other invalid entry is logged, truncated, and acknowledged so it does not block the stream.
5. **Sensor/stream check.** An event whose `sensor` field differs from the stream suffix (`sensor = rdp` on `events:ssh`) is dropped, counted and acknowledged. A compromised sensor cannot write as another sensor, even if Redis permissions were wrong.
6. Valid events are enriched (GeoIP, ASN, cached reputation) and tagged, then written in batches. The batch size is `INGEST_BATCH_SIZE` (default 100, maximum 500). The `sessions` table is updated with the counters for each session, and session-level tag rules run on the updated counters.
7. After the database commit, `ingest` acknowledges the entries. Entries are never acknowledged before they are stored.
8. After the acknowledgement, `ingest` trims **that stream** with `XTRIM MINID ~` up to the last acknowledged ID. This assumes one consumer, so run exactly one ingest instance.
9. A message that fails writing 5 times in a row because of its own content (a data error) is logged with its ID and acknowledged: dead-lettered. Outages, timeouts and permission errors are never counted. They retry forever, which turns the heartbeat stale and the container unhealthy.

### Per-stream trimming and recovery

State is kept per stream, so one slow or broken stream does not affect the others.

- **Start-up.** Ingest takes over every pending entry on every stream (`XAUTOCLAIM` with no idle minimum), whoever it was delivered to. Then it re-reads each stream from the start of its pending list ("draining") before it reads new entries.
- **No trim while draining.** A stream is trimmed only once its pending list is empty, so entries that were never read cannot be trimmed away.
- **Periodic reclaim.** Every `INGEST_RECLAIM_INTERVAL_S` (60 s), entries idle for more than `INGEST_CLAIM_IDLE_MS` are reclaimed, and the stream goes back to draining.
- **After an error** (Redis or database), all streams go back to draining and the loop retries with a backoff from 1 s to 30 s.
- **Forged IDs.** A producer that sends an explicit entry ID far in the future would make `MINID` trimming wipe the stream. Ingest reports such IDs and never uses them as a trim target.

Delivery is at least once. A batch replayed after a crash between the database commit and the acknowledgement can count twice. Idempotent replay is on the [roadmap](ROADMAP.md).

The exact field layout is in [Event schema](event-schema.md).

## Database

PostgreSQL 17 with TimescaleDB, managed by Alembic migrations in `db/`.

| Object | Kind | Content |
| --- | --- | --- |
| `events` | Hypertable on `ts`, one chunk per day | One row per event, with enrichment columns and `tags` |
| `sessions` | Regular table | One row per session, with counters, first and last times, enrichment and tags |
| `ip_reputation` | Regular table | Cached AbuseIPDB and GreyNoise answers per IP (24 hours) |
| `enrichment_quota` | Regular table | Lookups used per provider and day |
| `enrichment_status` | Regular table | Status of the GeoIP database, the reputation and intel providers and the CVE feeds, shown in Settings |
| `cve` | Regular table | Public vulnerabilities (CISA KEV, NVD, GitHub advisories), one row per CVE id, with a `relevance` (high, medium, none), the matched services and the tags that show it exploited. Public data, not captured data. |
| `cve_sync_state` | Regular table | Last run, last success, last error and item count per feed |
| `indicators` | Regular table | One row per URL, domain, IP or file hash seen in events: first and last seen, sightings, sensors, role guess (payload source, contacted, hash) |
| `indicator_sessions` | Regular table | Bounded links from an indicator to the sessions that showed it |
| `indicator_intel` | Regular table | 24 h cache of URLhaus, ThreatFox and VirusTotal answers per indicator |
| `indicator_contacts` | Regular table | Probable C2 addresses of known hashes, read from VirusTotal and ThreatFox, at most 40 per hash (migration 0016) |
| `indicator_contact_checks` | Regular table | 24 h cache of those lookups, one row per hash and source (ingest only) |
| `attack_techniques` | Regular table | The MITRE ATT&CK catalogue from `ingest/rules/attack/techniques.yaml` (migration 0011) |
| `technique_daily` | Regular table | Sessions per technique and day, for the heatmap |
| `campaigns` | Regular table | One row per campaign: first and last seen, sources, sessions, the story facts (0011) |
| `campaign_keys` | Regular table | The clustering keys of a campaign (script, exploit, credential list, payload host, hash, family) |
| `campaign_sessions` | Regular table | Bounded links from a campaign to its sessions (`CAMPAIGN_LINK_CAP`) |
| `blocklist_entries` | Regular table | Scored blocklist rows, rewritten every cycle (`BLOCKLIST_MAX_ROWS`), with reasons (0012) |
| `blocklist_overrides` | Regular table | Administrator allow and block decisions, with a note and an optional expiry |
| `feed_tokens` | Regular table | Feed tokens as SHA-256 hashes, with limits and revocation time. Never the token itself. |
| `inventory_services` | Regular table | The owner's service inventory for "Your exposure" (free text, compared with our data only) |
| `scripts` | Regular table | One row per distinct command script, with counters that only grow (0013) |
| `script_sessions` | Regular table | Bounded links from a script to its sessions |
| `script_explanations` | Regular table | The annotation-based explanation of a script, with its source and prompt version |
| `alert_channels` | Regular table | Discord, Teams and e-mail targets, encrypted at rest (0014) |
| `alert_rules` | Regular table | The alert rules (new campaign, new download host, malware drop, watched CVE seen, weekly report) with their on/off state and the time each was switched on |
| `alert_cursors` | Regular table | Where each rule has read up to, so enabling a rule never replays history |
| `alert_outbox` | Regular table | Queued messages per channel, with the attempt count and a constant error code |
| `alert_test_requests` | Regular table | "Send a test message" requests, answered by ingest |
| `watched_cves` | Regular table | CVE ids an administrator asked to be told about |
| `weekly_reports` | Regular table | One stored report per finished week (escaped HTML and the summary, capped at about 512 KiB) |
| `users`, `audit_log` | Regular tables | Dashboard accounts (0010) and the one-year audit log. Ingest has no access. |

Migration 0017 widens the check on `inventory_services.service` so that it accepts `synology`. No other table lists sensor names.

Migration 0015 adds columns rather than a table: `events.benign`, `sessions.benign` and `sessions.scanner_name` (research-scanner labels). Migration 0011 adds `events.techniques`, `sessions.techniques`, `sessions.campaign_id` and `sessions.clustered_at`.

The row limits `CAMPAIGNS_MAX_ROWS` and `SCRIPTS_MAX_ROWS` apply to the campaign and script tables. The retention job prunes them, the oldest and least seen first. See [Configuration](configuration.md).

Raw events are dropped after `RETENTION_DAYS` (90), compressed after 7 days, and four continuous aggregates plus `sessions_daily` are kept forever. A disk guard drops the oldest raw chunks when the database grows past `DB_MAX_SIZE_GB`. See [Data retention](retention.md).

### Database roles

Each service connects with its own role. Only the migration step can change the schema.

| Role | Used by | Rights | Statement timeout |
| --- | --- | --- | --- |
| Owner (`POSTGRES_USER`) | `db`, `migrate` | Owns the schema. Used for migrations only. | Not set |
| `suckerpot_ingest` | `ingest` | Insert and update on the tables ingest writes. No schema changes, no role changes. | 30 s |
| `suckerpot_api` | `api` | `SELECT` on the data tables. It also writes the tables the dashboard manages: users and the audit log (append only), provider keys, overrides, inventory, feed tokens, alert channels, alert rules, watched CVEs and script requests. It cannot write events, sessions, campaigns, blocklist rows or alert outbox rows. | 5 s |

Neither application role is a superuser. Neither can create databases or roles. The `migrate` service sets both role passwords on **every** run, from the environment. The password is sent as a SCRAM-SHA-256 verifier, so it never appears in the database logs. This is how you rotate them: see [Rotating secrets](deployment.md#rotating-secrets).

## Enrichment and tagging

```{admonition} Status
:class: note

Built (M4) and wired into Compose: ingest gets the provider variables and the `geoip-data` volume. Without keys it uses the key-less DB-IP Lite database, and reputation lookups stay off.
```

- **GeoIP and ASN** are read from local MMDB files, never from a web service per event. The provider is MaxMind GeoLite2 when `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY` are set, otherwise DB-IP Lite (no key, CC BY 4.0, attribution shown in the dashboard). Ingest downloads and refreshes the files itself, with a size cap and a check that the file opens. `GEOIP_PROVIDER=off` turns it off.
- **Reputation** (AbuseIPDB and GreyNoise Community) runs in a background worker, not in the event path. It picks the busiest addresses with no fresh answer, spends one unit of a persisted daily quota per lookup (`ABUSEIPDB_DAILY_QUOTA`, `GREYNOISE_DAILY_QUOTA`), caches the answer for 24 hours, and pauses for an hour after a rate-limit answer. It only reads. Nothing is ever reported to AbuseIPDB.
- **CVE watch** (`ingest/ingest/cve/`) is a background job. Every 15 minutes it checks which of three feeds is more than 24 hours old, and fetches only those: the CISA KEV catalogue, NVD API 2.0 and GitHub reviewed security advisories (only those with a CVE id). The NVD window reaches back 60 days (the first fetch, and the repair described below). It is read in one-day chunks, oldest first, with at most 50 pages per chunk and 120 pages per run, so a busy day is never cut off at 10,000 results. GitHub advisories are read in 7-day chunks the same way, with 30 pages per run. A run that stops early, for quota or for its page budget, keeps the chunks it finished and moves the cursor only as far as the last complete chunk. The next run resumes from there, so nothing is skipped silently. When ingest starts, it checks whether the stored history of a feed begins later than the lookback. If it does, the feed re-reads the lookback window to fill the gap. Upserts make the re-read safe, and once the history is deep enough the check does nothing. CVEs on the watch list (`watched_cves`) that are missing from the table are looked up by id in the NVD, at most 10 per run, and each id at most once every 24 hours. Each request spends a persisted daily quota (`CVE_NVD_DAILY_QUOTA`, `CVE_GITHUB_DAILY_QUOTA`; KEV is capped at a few requests a day), a failing feed is retried after an hour and does not stop the others, and the NVD is paced to its rate limit (5 requests per 30 s, 50 with `NVD_API_KEY`). The optional NVD key and GitHub token use the same Settings mechanism as the other provider keys. Records are merged per CVE id: each feed only fills the columns it is authoritative for. After a sync, ingest applies the relevance mapping in `ingest/rules/cve/relevance.yaml` to every row: a service (Apache + PHP, OpenSSH, Redis, Synology DSM, ...) matches **high** when a CPE or the vendor or product name matches and **medium** when only the title or description mentions it. The same file maps CVE ids to our tags (for example `php2shell` and `synology-exploit`), and the API counts sessions carrying those tags as "seen in our traffic". CVEs that are neither in KEV nor relevant are deleted after 180 days. The job only reads public data and never deploys or builds anything.
- **Tags** come from a declarative rules engine. Rules are YAML files in `ingest/rules/` (`shell.yaml` for commands, `web.yaml` for HTTP, `services.yaml` for the database, container, mobile, file-sharing and VoIP sensors, and `session.yaml` for session counters). A rule can match URL patterns, typical shell commands, user agents or CVE signatures. Tags include `recon`, `mirai`, `crypto-miner`, `exec-attempt`, `malware-drop`, `credential-stuffing`, `scanner`, `php2shell`, for the M9 sensors `persistence`, `container-escape`, `sql-rce`, `db-ransom`, `eternalblue` and `sip-fraud`, and for the RDP sensor `bluekeep`, `weak-credentials` and `rdp-cleartext`. A broken rule file stops ingest at start-up. A tag that names a specific malware family, CVE or fraud needs evidence specific to that claim; generic activity gets a generic tag (`recon`, `scanner`, `smb-v1-probe`, `php-upload-progress-probe`). On a list field such as `data.flags`, the operator `has` is true when any listed value is present and `has_all` only when every one is. For example `php2shell` needs the exploit shape, not just a request to the upload-progress feature, and `eternalblue` is never set from a bare SMB1 command.

- **Indicators** (M13). While writing a batch, ingest extracts URLs, hosts and file hashes from the events (bounded string scanning, no regular expressions), drops private, documentation and own addresses, and upserts `indicators` and `indicator_sessions` in a savepoint, so a problem there never costs the events. A background worker then asks URLhaus, ThreatFox and (for hashes) VirusTotal about each indicator with the same quota, cache and key mechanism as the reputation worker. It is passive: indicator hosts are never contacted. An hourly job (`suckerpot_indicator_prune`) removes indicators with the raw events and enforces `INDICATORS_MAX_ROWS`. The API serves them at `/api/v1/indicators` and `/api/v1/infrastructure/graph`. See [Security](SECURITY.md#indicators-and-threat-intelligence-passive-by-design).

A **session** is one connection. It is the unit the dashboard tells as a story, such as "tried 37 SSH passwords, then ran a crypto-miner".

## Analysis workers (M15 to M19)

Ingest runs one background worker per feature. Each one is off until its `*_ENABLED` variable is `true` (see [Configuration](configuration.md)). A worker that is off does nothing and holds no secret. The first cycle starts at start-up, and the next one follows the interval below. An error in one cycle is logged with its exception type, and the next cycle runs.

| Worker | Switch | Interval | What it does |
| --- | --- | --- | --- |
| ATT&CK catalogue | `ATTACK_ENABLED` | every hour | Upserts `techniques.yaml` into `attack_techniques`. Removes nothing, so old sessions keep readable ids. |
| Campaigns | `CAMPAIGNS_ENABLED` | every 5 minutes | Clusters finished sessions into campaigns. One bounded cycle: at most a fixed number of sessions, commands and keys per session. No network. |
| Blocklist | `BLOCKLIST_ENABLED` | every 15 minutes | Scores the last `BLOCKLIST_WINDOW_DAYS` and rewrites `blocklist_entries`. Nothing is resolved or contacted. |
| Scripts | `SCRIPTS_ENABLED` | every 5 minutes | Fingerprints sessions with two or more commands into `scripts`. |
| Alerts | `ALERTS_ENABLED` | every 10 seconds for test messages, every minute for rules, then delivery | Reads new rows for each enabled rule, queues one message per channel, and delivers within the rate limits. |
| Weekly report | `REPORTS_ENABLED` | every hour | Builds the report for the last finished week once, on the first check after Monday 06:00 in `SITE_TIMEZONE`. |
| Abuse reports (M22) | `ABUSE_REPORTS_ENABLED` | every `ABUSE_BUILD_INTERVAL_S` (1 hour) | Learns the monitored system's own names, looks up abuse contacts over RDAP and builds draft reports. Sends nothing. See [Anonymous reporting](#anonymous-reporting-m22). |

Two parts run inside the normal write path rather than on a timer. While writing a batch, ingest labels research scanners (`ingest/rules/scanners.yaml`, matched on the network owner) and sets the `benign` flag only when a session did nothing but probe. The tagging engine also adds the ATT&CK technique ids from `ingest/rules/attack/`. Indicator extraction (M13) runs there too.

### How the features fit together

- **Campaigns** group sessions by shared keys: a command script, an exploit request shape, a credential list, a payload host, a file hash and a malware family. Script, exploit and credential-list keys are SHA-256 fingerprints, and the other keys are indicator values. Research scanners are never clustered. A campaign needs at least `CAMPAIGN_MIN_SOURCES` distinct sources.
  - **Merging by key.** Two campaigns merge when one session carries a strong key (seen from enough networks) of both and enough networks bridge them. This almost never fires for one actor that uses several kinds of tooling, because no single session carries two of the keys.
  - **Merging by source addresses.** Each cycle, every campaign that changed since it was last checked is compared with the other live campaigns through `campaign_sessions`. Two campaigns merge when they share a sensor and the same `demo` flag, share at least 5 distinct source addresses, and at least 60% of the smaller campaign's addresses are also in the other (containment, not Jaccard: a campaign links only its newest `CAMPAIGN_LINK_CAP` sessions, so each address set is a sample of the actor's real addresses, and a sample nested in a larger one still shows a high containment). Pairs that qualify merge by single linkage, strongest first, at most 50 merges per cycle; the check runs in its own transaction, so a failure costs only the check. The oldest campaign survives with its id and the others become `merged` with `merged_into` set to it (never a chain: older merged campaigns are re-pointed to the survivor). Their keys and up to `CAMPAIGN_LINK_CAP` links move to it, the counters add up (an address counts once), the severity never drops and the name is rebuilt from the union (for example "Malware dropper and database ransom over MySQL #12"). The thresholds are constants in `ingest/ingest/campaigns/overlap.py`. A campaign is checked in the first cycles after an update or a restart (200 per cycle, oldest change first), so existing data is fixed without a manual step. The query reads `campaign_sessions` without an index on the address; on a node with hundreds of thousands of links it takes about a second, and an index on `campaign_sessions (src_ip)` is the next step if the table grows to millions of rows.
  - **Not covered: credential-only floods.** A flood of logins with no commands (for example hundreds of thousands of RDP sessions from a few dozen addresses in one hosting network) forms no campaign. A session needs a clustering key, and a login-only session has none (a credential-list key needs 20 attempts in one session and addresses from three networks). Grouping them would need a different unit than the session: a periodic roll-up of login-only sessions per sensor and network owner over a sliding window, a new key kind for it (with its label in the API and the web), counters kept on the campaign instead of a `campaign_id` written on every session (a flood would mean millions of updates), and a threshold on sessions and addresses so that every noisy network does not become a campaign.
- **Techniques** come from the tagging rules. They fill `events.techniques` and `sessions.techniques`, and `technique_daily` feeds the heatmap.
- **Blocklists** score indicators by distinct source networks, never by repeat count, and never list private, reserved, public resolver or big hosting names. Overrides are applied on every rewrite.
- **Scripts** normalise the command text first (`ingest/ingest/normalize.py`: addresses, URLs, numbers and long blobs become placeholders). Annotations come from `ingest/rules/annotations/*.yaml`.
- **Alerts** read each rule's own cursor, so enabling a rule never replays old events. Channel targets are decrypted in memory only, right before a send. Failed sends are retried up to three times, only when the error can pass.
- **Weekly report** is stored as escaped HTML plus a summary. It is built once per week.

### Anonymous reporting (M22)

The stack prepares abuse reports for the networks that host hostile sources, payload hosts and C2 servers, and indicator exports for CERTs. By default it sends nothing: the owner reads each draft and sends it from their own mailbox. Optional SMTP sending (off by default) goes through the VPN only, after a last identity check on the complete message. Design: [M22 design](design/m22.md), [M25 design](design/m25.md).

Two pieces share one set of rules.

| Piece | Where | Job |
| --- | --- | --- |
| `reporting/` (`suckerpot_reporting`) | A pure Python package, no I/O, installed in the `ingest` and `api` images | The evidence model (an allow-list of fields), redaction, the identity guard, the renderers (plain text, X-ARF v0.2, `.eml`, STIX 2.1, MISP JSON) and the encrypted sample bundle. It ships no report wording. |
| `ingest/ingest/abuse/` | A background worker in `ingest`, off until `ABUSE_REPORTS_ENABLED=true` | Selects subjects, finds the abuse contact over RDAP, learns the monitored system's own names and builds drafts. |

How a draft is made:

1. **Select.** Sources with enough failed logins, a login followed by commands, a download attempt or a severe tag; payload hosts; high-confidence C2 addresses. Research scanners, benign sessions, private and reserved ranges, the never-block list and anything already reported are skipped.
2. **Find the contact.** RDAP, through the same egress gate as every other lookup (a closed gate means wait, no quota spent). Answers are cached per network and capped in size, time and quota. A domain goes to the registrar only.
3. **Build.** One open draft per recipient and kind. Evidence is copied field by field, passed through redaction, then checked by the identity guard. The result is stored in `abuse_reports` (migration 0019) with the guard outcome.
4. **Render on demand.** The API renders text, X-ARF, `.eml`, STIX, MISP and bundles when asked, and runs the guard again on every artefact right before returning it. Nothing rendered is stored, so a settings change needs no rebuild.

The database roles split the work: `suckerpot_ingest` can write drafts only, `suckerpot_api` can change status, notes and options but cannot rewrite evidence. A trigger allows only the legal status changes and refuses `sent` for demo reports. Learned self terms (`report_self_terms`) are never deleted by retention. See [Security](SECURITY.md#anonymous-reporting-m22).

## API

The API is FastAPI. It serves:

- REST endpoints under `/api/v1`, listed in [API](api.md).
- A WebSocket feed at `/api/v1/live`.
- A health check at `/healthz`.
- Dashboard authentication (`/api/v1/auth/*`): one admin account, a signed `HttpOnly` session cookie and CSRF protection. A middleware guards every other `/api/v1` path, and the WebSocket checks the cookie in its handshake. Its state is in memory, so the API runs as **one** worker. See [API](api.md#authentication).
- The built web UI, when `WEB_DIST_DIR` contains an `index.html`. Unknown paths return the app shell so client-side routes work, and `/api/*` paths never fall back to it.
- The OpenAPI documents at `/docs`, `/redoc` and `/openapi.json`. These are **off** unless `API_ENABLE_DOCS=true`.

The API has no Redis access and no outbound route. It reads the database and writes only the tables listed in [Database roles](#database-roles). Ingest does the rest: campaigns, blocklists, scripts and alerts are all computed there.

The feature endpoints are grouped as follows (each group is documented in [API](api.md)):

| Prefix | Feature | Milestone |
| --- | --- | --- |
| `/api/v1/cves` | CVE watch | M12 |
| `/api/v1/indicators`, `/api/v1/infrastructure` | Indicators | M13 |
| `/api/v1/users`, `/api/v1/audit` | Users and audit log (administrators) | M14 |
| `/api/v1/campaigns`, `/api/v1/attack` | Campaigns and ATT&CK | M15 |
| `/api/v1/defend/...` | Blocklists, exports, overrides, detections, exposure | M16 |
| `/api/v1/scripts` | Script library | M17 |
| `/api/v1/alerts`, `/api/v1/reports` | Alert channels, rules, outbox, weekly report | M18 |
| `/api/v1/today`, `/api/v1/search` | Today and global search | M19 |
| `/feeds/...` | Opt-in public feed, outside `/api/v1` | M16 |

### Live feed

One background task in the API polls the `events` table for rows newer than the last one it sent (once per second, up to 500 rows per tick). It sends the new rows to each connected WebSocket client through a bounded queue of 200 messages. A slow client loses its oldest messages, and is told how many were lost. The hub accepts at most 50 clients in total and 5 per source address. Details are in [API](api.md#live-feed).

### Public feed (opt-in)

When `FEEDS_ENABLED=true`, the API also serves the blocklist feed under `/feeds`, on the dashboard port. It is the only route outside `/api/v1` and outside the dashboard login. Each request must carry a feed token, made in Settings and stored only as a hash, or the request is refused with a plain `404`. Limits are applied per client address and per token. Behind a proxy, set `AUTH_TRUSTED_PROXIES`, or every client looks the same. See [Defend](defend.md#the-subscription-feed-optional).

### Security headers

Every response carries `nosniff`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy` and `Cross-Origin-Resource-Policy: same-origin`. Pages carry a Content Security Policy (`default-src 'self'`, `connect-src 'self'`, no framing). API responses are `Cache-Control: no-store`. Only the documentation pages relax the policy, and only when `API_ENABLE_DOCS=true`.

The WebSocket checks the `Origin` header. Requests with no `Origin` (non-browser clients) are accepted. Browser requests must come from the same host, or from an origin listed in `API_ALLOWED_ORIGINS`.

## Stack

| Layer | Choice |
| --- | --- |
| Sensors | Python 3.15, asyncio, asyncssh (SSH), raw asyncio (Telnet, RDP, ADB, Redis, MySQL, MSSQL, SMB and SIP), hand-written HTTP servers (web, Docker API and Synology DSM, the last one over TLS too) |
| Ingest and API | FastAPI, SQLAlchemy 2 with asyncpg, Alembic |
| Queue | Valkey 9.1 Streams (Redis protocol), AOF on a named volume |
| Database | PostgreSQL 17 with TimescaleDB 2.31.0 |
| Enrichment | MaxMind GeoLite2 or DB-IP Lite (local files), AbuseIPDB, GreyNoise Community, abuse.ch URLhaus and ThreatFox, VirusTotal (hashes only) |
| Alerts and reports | Discord and Microsoft Teams webhooks, SMTP over TLS |
| Web UI | React, Vite, TypeScript (strict), Tailwind, shadcn/ui, TanStack Query. The Live page is a flat SVG map, with no WebGL. Terminal replay planned. |
| Python tooling | uv, ruff, mypy (strict), pytest |
| Web tooling | pnpm, eslint, prettier, vitest, Playwright |
| Task runner | `justfile`. See [Development](development.md). |

## Containers

Every service follows the same rules:

- A multi-stage Dockerfile with a pinned base image.
- A non-root user (UID and GID 10001 for application services).
- A read-only root file system, with `tmpfs` mounts where a service must write.
- `cap_drop: [ALL]` and `no-new-privileges`.
- Memory, CPU and process limits. Sensors also have no swap, so overload fails fast.
- A health check, plus a watchdog inside each sensor (Docker does not restart a container that is only unhealthy).
- Logs rotated by Docker (10 MB, 3 files).

### Resource priorities

When the host runs short of memory, the kernel must pick a victim. `oom_score_adj` sets the order, and `cpu_shares` sets the CPU share when the host is busy. Compose sets them as follows.

| Service | `oom_score_adj` | `cpu_shares` | Why |
| --- | --- | --- | --- |
| `redis`, `db` | `-500` | default | The data path. Last to be killed. |
| `ingest` | `-200` | default | Keeps the events flowing into the database. |
| `api` | `300` | default | The dashboard. Killed before the data path, after the sensors. |
| All twelve `sensor-*` services | `800` | `256` | Sensors take attacker load, so they are the first to be killed under memory pressure, and get a smaller CPU share when the host is busy. Docker restarts them. |

Each sensor has a memory limit (`mem_limit`), no swap, a CPU limit (`cpus`) and a process limit (`pids_limit`). The sensors' combined share can also be capped with an optional systemd slice. See [Deployment](deployment.md#host-safeguards).

The rules are explained in [Security](SECURITY.md#containers).

## Repository layout

```
suckerpot/
├── docker-compose.yml
├── justfile
├── .env.example
├── redis/             # Redis image, ACL entrypoint and config
├── sensors/           # common (Event schema) and the twelve sensors: ssh, telnet, adb, web, docker, synology, redis, mysql, mssql, rdp, smb, sip
├── ingest/            # consumer, writer, enrichment, tagging, rules/*.yaml
├── api/               # FastAPI app: REST, live feed, SPA serving
├── db/                # SQLAlchemy models, Alembic migrations, roles, secrets check
├── web/               # React app (design system in web/DESIGN.md)
├── scripts/
│   ├── demo/          # demo data generator
│   ├── host/          # host firewall (nftables) and its systemd unit
│   ├── check-ports.sh # port layout guard
│   └── ssh-test.sh    # end-to-end check of the SSH sensor
└── docs/              # documentation (this site)
```
