# API

The API is a FastAPI application. It reads the database and returns JSON. It also serves a live WebSocket feed, and the web UI once one is built. The API has no Redis access and cannot change data: it connects as the read-only role `suckerpot_api`.

```{admonition} Build status
:class: note

**Built:** sessions, events, summary, enrichment settings, the analytics endpoints (M5), insights, trends, malware and site settings (M7), the live WebSocket feed, and dashboard authentication (M8, security review passed).

**Planned:** API rate limits beyond the login limits.
```

## Base URL

Every example below uses the dashboard port on the host. With the default `DASHBOARD_PORT=8443`, and with the default bind address `127.0.0.1`, run the examples on the host itself:

```text
http://127.0.0.1:8443
```

## Authentication

Every `/api/v1` path needs a session, except `/api/v1/auth/*`. `/healthz` and the static web app stay public. There are two kinds of account: the owner from `.env`, and users with the role `admin` or `viewer` (see [Users and roles](configuration.md#users-and-roles)). A viewer can call every `GET` that an admin can, except the user and audit endpoints, and nothing that changes data: any other method needs an admin, unless it is sign in, sign out or changing one's own password, and the API answers `403` with `{"code": "admin_required"}`.

### Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/auth/login` | Body `{"username": "...", "password": "..."}`. Returns `204` and sets the cookies. `401` for wrong credentials, `403` for a cross-origin request, `429` with `Retry-After` when rate limited. |
| `POST` | `/api/v1/auth/logout` | Revokes the session and clears the cookie. Needs the CSRF token. Returns `204`. |
| `GET` | `/api/v1/auth/me` | Who is signed in: `username`, `display_name`, `role`, `is_owner`, `must_change_password`, `read_only` and `last_login_at` (the sign-in before this one). `401` otherwise. The web app uses it to decide what to show. |
| `POST` | `/api/v1/auth/password` | Body `{"current_password": "...", "new_password": "..."}`. Changes the signed-in user's own password and keeps this browser signed in; every other session of the user ends. `403` with `reauth_failed` for a wrong current password, `422` with `weak_password` for a rejected new one, `403` with `owner_password_in_env` for the owner. Allowed while `must_change_password` is true. |
| `GET` | `/api/v1/auth/csrf` | `{"token": "..."}` and sets the CSRF cookie. |

### Cookies

| Cookie | Flags | Content |
| --- | --- | --- |
| `__Host-sp_session` | `HttpOnly`, `Secure`, `SameSite=Strict`, path `/`, no `Domain` | A signed token with an expiry (`SESSION_TTL_HOURS`, default 12). No server-side session table. |
| `__Host-sp_csrf` | Readable by JavaScript, `Secure`, `SameSite=Strict`, path `/` | A signed anti-CSRF token, bound to the session |

The `__Host-` prefix makes the browser refuse the cookie unless it is `Secure`, set over HTTPS, for the exact host and without a `Domain`. That stops a sibling subdomain from planting or overwriting it. The prefix exists only when `COOKIE_SECURE=true` (the default). With `COOKIE_SECURE=false` the cookies are named `sp_session` and `sp_csrf` and lose the `Secure` flag. Use that **only for local development over plain HTTP**. In production the dashboard must be served over HTTPS (for example by the tunnel).

The session signing key is derived from `SESSION_SECRET`, the password hash **and a random value created at each API start**. So changing the password signs everybody out, and so does **every restart of the API** (including `docker compose up -d api` after a config change and a container restart). Logging out puts the session into a small in-memory revocation list, and logging in again revokes the previous session.

### CSRF protection (double submit)

Every `POST`, `PUT`, `PATCH` and `DELETE` must send the value of the CSRF cookie in an `X-CSRF-Token` header. The server checks that the two match and that the token carries a valid signature **for the current session**, so a cookie planted by another site, or a token from another session, is refused (`403`). Login is the one exception, because there is no session yet. It requires an `Origin` (or `Referer`) check:

- When `API_ALLOWED_ORIGINS` is set, the **full origin** (scheme, host and port, such as `https://dash.example.com`) must be in the list.
- When it is empty, the origin's host must equal the request's `Host` header, and the scheme is ignored.

A `401` means "sign in". A `403` means "bad or missing CSRF token", or a login from an origin that is not allowed. Call `GET /api/v1/auth/csrf` once and send the token on every unsafe request.

### Rate limits and costs

Login attempts are counted per client address over a sliding 60 seconds (`LOGIN_RATE`, default 5). IPv6 addresses are counted per `/64`, because one subscriber owns a whole `/64`. Beyond the limit the answer is `429` with a `Retry-After` header. A wrong password also costs a short fixed delay. Wrong passwords are also counted for the whole server (`LOGIN_RATE_GLOBAL`, default 30 a minute); over that budget wrong answers are delayed one more second, but no sign-in is ever refused because of it, so other people's attempts cannot lock the owner out.

The password hash is always checked, whether or not the user name exists, so timing does not reveal the account name. Argon2 is expensive on purpose, so the API runs at most `LOGIN_VERIFY_CONCURRENCY` checks at once (default 2). Further attempts queue in order for up to `LOGIN_VERIFY_WAIT` seconds (default 5), then get `429` with `Retry-After`. A flood of login attempts can therefore slow down sign-in, but not the rest of the API, and a correct password only waits its turn.

Failed and successful logins are logged with the client address only. A submitted user name, password, hash or cookie is never logged.

### Client address behind a proxy

Behind a reverse proxy, every request seems to come from the proxy. Set `AUTH_TRUSTED_PROXIES` to the proxy's addresses as a comma-separated list of CIDR ranges. The API then reads `CF-Connecting-IP`, or else the rightmost `X-Forwarded-For` entry that is not itself a trusted proxy, **but only** when the connection comes from one of those addresses. From anyone else the headers are ignored, so nobody can fake their address. With the default (empty), the headers are never read.

### Allowed hosts

The API answers only to host names it expects (a "trusted host" check), which blocks Host-header tricks. `API_ALLOWED_HOSTS` (comma-separated host names) sets the list. Without it, the hosts of `API_ALLOWED_ORIGINS` are used. `localhost` and `127.0.0.1` are always allowed. When both variables are empty the API **allows any host and logs a warning**. In production, set one of them, for example to the tunnel's host name.

### WebSocket

The live WebSocket checks the session cookie in its handshake. Without a valid session the connection is closed with code `1008`. While it is open, the server rechecks the session every 5 seconds and closes with `1008` when it has expired or been revoked. The browser sends the cookie on its own for a same-site WebSocket.

### Single worker

The revocation list, the per-boot signing key and the login counters live in the memory of one process. Run the API with **one** uvicorn worker (the image's default command does). With several workers, a logged-out session could still work on another worker, and the login limits would multiply.

### Setting it up

1. Generate the password hash. The command prompts twice without echo and prints the hash:

   ```bash
   docker compose run --rm api python -m api.hashpw
   ```

2. Put it in `.env`, in **single quotes**. An argon2 hash contains `$` characters, which Compose would otherwise try to expand as variables:

   ```text
   ADMIN_PASSWORD_HASH='$argon2id$v=19$m=65536,t=3,p=4$...'
   ```

3. Set `SESSION_SECRET` to at least 32 random bytes (`openssl rand -base64 48`).
4. Start the stack. The API refuses to start when the hash or the secret is missing or weak.

See [Configuration](configuration.md#dashboard-authentication) for every variable.

## Interactive documentation

The OpenAPI pages are **off by default**. To turn them on while you develop, set `API_ENABLE_DOCS=true` in `.env` and restart the API. Then the following paths are served:

| Path | Content |
| --- | --- |
| `/docs` | Swagger UI |
| `/redoc` | ReDoc |
| `/openapi.json` | Raw OpenAPI schema |

These pages are generated from the code, so they match the running version. Use them for the exact field list. Turn them off again before you expose the port.

## Conventions

- Times are ISO 8601 in UTC, for example `2026-10-24T18:02:11Z`.
- Session lists use **keyset pagination**. Each list response has `items` and `next_cursor`. Pass `next_cursor` back as `cursor` to get the next page. When `next_cursor` is `null`, there are no more items.
- The cursor is opaque. Do not build it yourself. An invalid cursor returns `400`.
- `limit` must be between 1 and 200.
- Session IDs match `^[A-Za-z0-9_-]{1,64}$`. Other values are rejected.
- IP address filters are normalised. An invalid address returns `422`.
- Errors use the FastAPI shape: `{"detail": "..."}`.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Health check. Checks the database. |
| `GET` | `/api/v1/events/recent` | The newest events, newest first |
| `GET` | `/api/v1/sessions` | List sessions, newest first |
| `GET` | `/api/v1/sessions/{session_id}` | One session |
| `GET` | `/api/v1/sessions/{session_id}/events` | Events of one session, oldest first |
| `GET` | `/api/v1/stats/summary` | Totals for the last 24 hours |
| `GET` | `/api/v1/today` | The cards of the Today page (M19) |
| `GET` | `/api/v1/search` | Global search (M19) |
| `GET` | `/api/v1/stats/benign` | Sessions and addresses from research scanners in the last 24 hours (M19) |
| `GET` | `/api/v1/settings/system` | Sensor status, retention policy, disk guard state and database size. See [System settings](#get-apiv1settingssystem). |
| `GET` | `/api/v1/settings/pipeline` | Whether ingest is storing events: `ok`, `stalled` or `unknown`. See [Pipeline health](#get-apiv1settingspipeline). |
| `GET` | `/api/v1/samples` | Files fetched by the collector, with filters and cursor paging. See [Samples and egress](#samples-and-egress-m21). |
| `GET` | `/api/v1/samples/{sha256}` | One sample with its analysis, sources and links |
| `GET` | `/api/v1/samples/{sha256}/chain` | The chain session, URL, sample and C2 of one sample |
| `POST` | `/api/v1/samples/{sha256}/archive` | Download a sample as a password-protected zip (administrators only) |
| `GET` | `/api/v1/egress` | State of the egress gate, collector quota and quarantine use |
| `GET` | `/api/v1/abuse/...` | Abuse reports, recipients, settings, self terms and exports (M22). See [Abuse reports](#abuse-reports-m22). |
| `GET`, `PUT`, `DELETE` | `/api/v1/abuse/smtp` | The optional SMTP profile for sending reports (administrators only). See [Sending abuse reports](#sending-abuse-reports-m25). |
| `GET` | `/api/v1/abuse/send-queue` | Ready reports, one page at a time, for the To send view (administrators only). See [Sending abuse reports](#sending-abuse-reports-m25). |
| `GET`, `PUT`, `DELETE` | `/api/v1/settings/vpn` | The WireGuard configuration of the `vpn` service and the trusted exits (administrators only). See [VPN settings](#vpn-settings-m23-m24). |
| `GET` | `/api/v1/setup/status` | The setup checklist (administrators only). See [Setup checklist](#setup-checklist-m24). |
| `GET` | `/api/v1/settings/enrichment` | GeoIP database status and reputation quotas. See [Enrichment status](#get-apiv1settingsenrichment). |
| `PUT` | `/api/v1/settings/providers/{provider}` | Set or replace an enrichment API key. See [Provider keys](#provider-keys). |
| `DELETE` | `/api/v1/settings/providers/{provider}` | Remove a key set in Settings. See [Provider keys](#provider-keys). |
| `POST` | `/api/v1/settings/providers/{provider}/test` | Ask ingest to test the key with one real call. See [Provider keys](#provider-keys). |
| `WebSocket` | `/api/v1/live` | Live feed of new events and statistics. See [Live feed](#live-feed). |

### `GET /healthz`

Returns `200` when the API can reach the database. Returns `503` when it cannot. Docker uses this endpoint for the container health check.

```json
{
  "status": "ok",
  "db": "ok"
}
```

When the database is unreachable, the response has status `503` and this body:

```json
{
  "status": "degraded",
  "db": "error"
}
```

### `GET /api/v1/events/recent`

The newest events, newest first. This is the REST version of the WebSocket backfill. It returns the live view of an event, without the raw `data` object.

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `limit` | `50` | Number of events, 1 to 200 |

Example request:

```bash
curl -s "http://127.0.0.1:8443/api/v1/events/recent?limit=2"
```

Example response (fake values, documentation addresses only):

```json
{
  "items": [
    {
      "id": 1842,
      "ts": "2026-10-24T18:02:14Z",
      "sensor": "ssh",
      "session_id": "k3J9x2_a7Qe",
      "type": "login_attempt",
      "src_ip": "198.51.100.23",
      "src_port": 51422,
      "dst_port": 22,
      "summary": "login root/123456 failed",
      "country": null,
      "city": null,
      "asn": null,
      "org": null,
      "abuse_score": null,
      "known_scanner": null,
      "tags": []
    },
    {
      "id": 1841,
      "ts": "2026-10-24T18:02:11Z",
      "sensor": "ssh",
      "session_id": "k3J9x2_a7Qe",
      "type": "connect",
      "src_ip": "198.51.100.23",
      "src_port": 51422,
      "dst_port": 22,
      "summary": "connected",
      "country": null,
      "city": null,
      "asn": null,
      "org": null,
      "abuse_score": null,
      "known_scanner": null,
      "tags": []
    }
  ]
}
```

`summary` is a one-line description built by the API. Attacker-controlled text is cleaned (control characters are replaced) and shortened.

### `GET /api/v1/sessions`

Lists sessions, newest first. Order: `started_at` descending, then `session_id`.

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `limit` | `50` | Items per page, 1 to 200 |
| `cursor` | none | Cursor from the previous page |
| `sensor` | none | Only sessions from one sensor: `ssh`, `telnet`, `adb`, `web`, `docker`, `redis`, `mysql`, `mssql`, `rdp`, `smb`, `sip` or `synology`. Repeat the parameter or separate names with commas for several sensors. |
| `src_ip` | none | Only sessions from one source address |
| `tag` | none | Only sessions that carry this tag. Lower-case letters, digits and `-`, up to 32 characters (for example `crypto-miner`). |
| `country` | none | Only sessions from this country. Two letters (ISO 3166-1), case-insensitive. |
| `asn` | none | Only sessions from this autonomous system number (an integer) |
| `since` | none | Only sessions that started at or after this time (ISO 8601, with a time zone) |
| `until` | none | Only sessions that started before this time |

Example request:

```bash
curl -s "http://127.0.0.1:8443/api/v1/sessions?sensor=ssh&limit=2"
```

Example response (values are fake, and use documentation addresses):

```json
{
  "items": [
    {
      "session_id": "k3J9x2_a7Qe",
      "sensor": "ssh",
      "src_ip": "198.51.100.23",
      "src_port": 51422,
      "dst_port": 22,
      "started_at": "2026-10-24T18:02:11Z",
      "ended_at": "2026-10-24T18:02:19Z",
      "last_event_at": "2026-10-24T18:02:19Z",
      "event_count": 4,
      "login_attempts": 3,
      "login_success": false,
      "commands": 0,
      "downloads": 0,
      "http_requests": 0,
      "country": null,
      "city": null,
      "asn": null,
      "org": null,
      "abuse_score": null,
      "known_scanner": null,
      "client_tool": null,
      "tags": []
    },
    {
      "session_id": "Q8mW1-zT4bA",
      "sensor": "ssh",
      "src_ip": "203.0.113.77",
      "src_port": 40018,
      "dst_port": 22,
      "started_at": "2026-10-24T17:48:03Z",
      "ended_at": "2026-10-24T17:49:40Z",
      "last_event_at": "2026-10-24T17:49:40Z",
      "event_count": 12,
      "login_attempts": 1,
      "login_success": true,
      "commands": 6,
      "downloads": 1,
      "http_requests": 0,
      "country": null,
      "city": null,
      "asn": null,
      "org": null,
      "abuse_score": null,
      "known_scanner": null,
      "client_tool": null,
      "tags": []
    }
  ],
  "next_cursor": "WyIyMDI2LTEwLTI0VDE3OjQ4OjAzKzAwOjAwIiwiUThtVzEtelQ0YkEiXQ"
}
```

The cursor in the example is opaque and only shows the format. Do not decode or edit it.

The enrichment fields (`country`, `city`, `asn`, `org`, `abuse_score`, `known_scanner`) are `null` and `tags` is empty until ingest has enriched the session. Enrichment and tagging run in ingest (M4). Ingest has to download a GeoIP database first, so right after a first start the fields stay `null` for a short while. Sessions that were stored before enrichment was running are not enriched afterwards.

`client_tool` is a best-effort guess at the client software of an RDP session (see [RDP sensor](sensors/rdp.md#client-tool-identification)). It is `null` for every other sensor, and for RDP when the guess is `unknown`.

Filters combine with AND. `since` and `until` need a time zone (`2026-10-24T00:00:00Z`). An invalid value returns `422`.

### `GET /api/v1/sessions/{session_id}`

Returns one session, with the same fields as a list item. Returns `404` when the session does not exist.

```json
{
  "detail": "session not found"
}
```

### `GET /api/v1/sessions/{session_id}/events`

Returns the events of one session, oldest first. Order: `ts` ascending, then `id`.

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `limit` | `100` | Items per page, 1 to 200 |
| `cursor` | none | Cursor from the previous page |

Example response:

```json
{
  "items": [
    {
      "id": 1841,
      "ts": "2026-10-24T18:02:11Z",
      "sensor": "ssh",
      "session_id": "k3J9x2_a7Qe",
      "type": "connect",
      "src_ip": "198.51.100.23",
      "src_port": 51422,
      "dst_port": 22,
      "data": {
        "client_version": "SSH-2.0-libssh_0.9.6"
      },
      "country": null,
      "city": null,
      "asn": null,
      "org": null,
      "abuse_score": null,
      "known_scanner": null,
      "tags": []
    },
    {
      "id": 1842,
      "ts": "2026-10-24T18:02:14Z",
      "sensor": "ssh",
      "session_id": "k3J9x2_a7Qe",
      "type": "login_attempt",
      "src_ip": "198.51.100.23",
      "src_port": 51422,
      "dst_port": 22,
      "data": {
        "username": "root",
        "password": "123456",
        "success": false,
        "method": "password"
      },
      "country": null,
      "city": null,
      "asn": null,
      "org": null,
      "abuse_score": null,
      "known_scanner": null,
      "tags": []
    }
  ],
  "next_cursor": null
}
```

The `data` object follows the recommended keys in [Event schema](event-schema.md). An event `cursor` is bounded: an id outside 0 to 2^63-1 returns `400`.

### `GET /api/v1/stats/summary`

Totals for the last 24 hours (`window_hours` is `24`). The `by_sensor` object has one entry per sensor that has data.

Example response (fake values):

```json
{
  "window_hours": 24,
  "events": 18342,
  "sessions": 1260,
  "unique_ips": 417,
  "sessions_with_commands": 88,
  "download_attempts": 14,
  "by_sensor": {
    "rdp": {"events": 1204, "sessions": 150},
    "redis": {"events": 412, "sessions": 38},
    "ssh": {"events": 12010, "sessions": 910},
    "telnet": {"events": 3580, "sessions": 280},
    "web": {"events": 1548, "sessions": 120}
  }
}
```

### `GET /api/v1/settings/system`

Read-only data for the Settings page. Every block becomes `null` or empty when its source is not available, so a partly migrated database never breaks the page.

| Field | Content |
| --- | --- |
| `sensors` | One entry per sensor: `sensor`, `last_event_at`, `events_last_hour` and `status`: `active` (an event in the last 15 minutes), `quiet` (in the last 24 hours) or `silent` |
| `retention` | `raw_days` (when raw events are dropped), `compression_after_days`, `oldest_event_at` (oldest raw event still stored, or `null`), and the names of the `aggregates` that are kept forever |
| `disk_guard` | The state written by the disk guard job (see [Data retention](retention.md#disk-guard)), or `null` |
| `ingest_disk` | The state ingest reports for its own payload trimming, or `null` |
| `database` | `size_bytes` and `max_bytes` (from `DB_MAX_SIZE_GB`) |

### `GET /api/v1/settings/pipeline`

Whether ingest is storing events, read from the heartbeat row ingest keeps in the database.

```json
{"status": "ok", "last_ok_at": "2026-11-09T12:00:00Z", "stalled_for_seconds": 0, "failing_since": null, "last_error": null, "parked_events": 0}
```

| Field | Content |
| --- | --- |
| `status` | `unknown` when there is no heartbeat yet (a fresh install, or an ingest that predates it), `stalled` when `last_ok_at` or `failing_since` is older than `PIPELINE_STALL_SECONDS` (default 300), otherwise `ok` |
| `last_ok_at` | The last time a full ingest loop ran without a failing batch (stamped every 30 seconds) |
| `stalled_for_seconds` | Seconds since `last_ok_at` when `stalled`, otherwise `0` |
| `failing_since` | Start of the current run of failing batches, or `null` |
| `last_error` | Short description of the last failure, for example `57014 QueryCanceledError on events:ssh`, or `null` |
| `parked_events` | Events set aside in the `events:parked` stream because the database kept refusing them, since the install |

### `GET /api/v1/settings/enrichment`

The status of the enrichment providers and today's quota use. It never returns an API key. The Settings page will use it.

```json
{
  "geoip": {
    "provider": "dbip",
    "available": true,
    "files": {
      "city": {"file": "dbip-city-lite.mmdb", "bytes": 131072000, "updated_at": "2026-10-01T03:00:00Z", "age_days": 23.6}
    },
    "last_error": null,
    "refresh_days": 30,
    "attribution": "IP geolocation by DB-IP.com (https://db-ip.com), CC BY 4.0"
  },
  "abuseipdb": {
    "configured": true, "source": "settings", "last4": "a1b2", "updated_at": "2026-10-25T09:00:00Z",
    "secret_error": null, "pending_apply": false,
    "test": {"ok": true, "error": null, "checked_at": "2026-10-25T09:01:00Z"},
    "test_pending": false, "test_requested_at": "2026-10-25T09:00:50Z",
    "daily_quota": 1000, "used_today": 12, "disabled": null, "paused": false, "last_error": null
  },
  "greynoise": {"configured": false, "source": null, "last4": null, "updated_at": null, "secret_error": null,
                "pending_apply": false, "test": null, "test_pending": false, "test_requested_at": null,
                "daily_quota": null, "used_today": 0, "disabled": null, "paused": false, "last_error": null},
  "maxmind": {"configured": false, "source": null, "last4": null, "updated_at": null, "secret_error": null,
              "pending_apply": false, "test": null, "test_pending": false, "test_requested_at": null},
  "key_editing": {"enabled": true, "reason": null},
  "reported_at": null
}
```

For each provider, `source` is `env` (the key comes from `.env`), `settings` (set on the Settings page) or `null` (no key). `last4` and `updated_at` are set only for keys saved in Settings. `secret_error` is `cannot_decrypt` or `no_encryption_key` when a saved key cannot be used; ingest then falls back to the `.env` key. `pending_apply` is true for the few seconds before ingest picks up a change. `test` is the last "Test key" result (`error` is one of `no_key`, `quota_exhausted`, `auth`, `rate_limited`, `error`). `key_editing.enabled` is false when `SETTINGS_ENCRYPTION_KEY` is not set, with the reason in `reason`.

`provider` is `maxmind`, `dbip`, `off`, or `unknown` when ingest has not reported yet. The attribution text must be shown wherever DB-IP data is displayed.

### Users and audit log (administrators)

Every request below needs an administrator and, when it changes something, the administrator's own password in the body (`password`), the same re-authentication as the provider keys. Each change writes an audit entry. A user who must still choose a password gets `403` with `password_change_required` from every other endpoint.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/users` | `owner` (read-only), `items` (users by id) and `next_cursor`. Query: `limit` (1 to 200, default 50), `cursor`. |
| `POST` | `/api/v1/users` | Body `username`, `display_name`, `role`, `password`. `201` with the `user` and a one-time `temporary_password` (`Cache-Control: no-store`). `409` with `username_taken` (also for the owner's name). |
| `PATCH` | `/api/v1/users/{id}` | Body `role`, `disabled` or `display_name` (at least one) and `password`. A role change or a disable ends the user's sessions. |
| `POST` | `/api/v1/users/{id}/reset-password` | Body `password`. Returns a new `temporary_password`, ends the user's sessions and makes them choose a password again. |
| `POST` | `/api/v1/users/{id}/unlock` | Body `password`. Clears the lock after repeated wrong passwords. |
| `POST` | `/api/v1/users/{id}/revoke-sessions` | Body `password`. Ends every session of the user. `204`. |
| `DELETE` | `/api/v1/users/{id}` | Body `password`. `204`. |
| `GET` | `/api/v1/audit` | Newest first. Query: `actor` (exact name, any case), `action` (a name such as `user.create`, or a prefix such as `user.`), `limit` (1 to 200, default 50), `cursor`. |

An administrator cannot disable, demote, reset or delete their own account (`409`, `self_action`). Audit actions: `auth.login`, `user.create`, `user.role`, `user.disable`, `user.enable`, `user.rename`, `user.reset_password`, `user.unlock`, `user.locked`, `user.revoke_sessions`, `user.delete`, `password.change`, `provider_key.set`, `provider_key.remove`, `provider_key.test`.

### Provider keys

`provider` is `abuseipdb`, `greynoise` or `maxmind`. A key is never returned by any endpoint.

| Request | Body | Answer |
| --- | --- | --- |
| `PUT` | `{"key": "...", "password": "<admin password>"}`, plus `"account_id": "<digits>"` for `maxmind` | `200` with `provider`, `source`, `last4`, `updated_at` |
| `DELETE` | `{"password": "<admin password>"}` | `204` |
| `POST .../test` | none | `202` with `requested_at`. Poll `GET /api/v1/settings/enrichment` for `test`. |

Changes need the session cookie, the `X-CSRF-Token` header, a same-origin request and the admin password again. Errors carry a `code`: `editing_disabled` (`503`, no `SETTINGS_ENCRYPTION_KEY`), `invalid_key` (`422`, wrong length or characters), `reauth_failed` (`403`, wrong password), `origin` (`403`), `rate_limited` (`429`, shared with the login limit), `no_key` (`409`), `cooldown` (`429`, one test per 20 seconds), `daily_cap` (`429`, 10 tests per provider per day) and `session_revoked` (`401`, five wrong passwords in a row). A `422` never repeats the submitted values.

## Analytics endpoints

```{admonition} Status
:class: note

Implemented (M5). Check `/openapi.json` (with `API_ENABLE_DOCS=true`) for the exact fields of your version.
```

All analytics endpoints are read-only, run as the `suckerpot_api` role with the 5 second statement timeout, and use TimescaleDB `time_bucket` queries. Lists are paginated or capped (`limit` at most 200). Times are ISO 8601 UTC.

Common optional filters: `since` and `until` (with a time zone; the default window is the last 24 hours for stats, with 30 days as the maximum) and `sensor` (any of the twelve sensor names: `ssh`, `telnet`, `adb`, `web`, `docker`, `redis`, `mysql`, `mssql`, `rdp`, `smb`, `sip`, `synology`).

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/stats/timeseries` | Events and sessions per time bucket and sensor. `bucket` is `5m`, `1h` or `1d`. Empty buckets are filled with zeros. At most 500 points. |
| `GET` | `/api/v1/stats/top` | The most frequent values of one `field`: `country`, `asn`, `org`, `username`, `password`, `command`, `url`, `user_agent`, `tag` or `src_ip`. Returns `value`, `count`, `share`, `first_seen` and `last_seen`. `limit` defaults to 10. |
| `GET` | `/api/v1/stats/heatmap` | 168 cells (day of week, Monday is 0, by hour, in UTC) with an event count each |
| `GET` | `/api/v1/attackers` | Attacker profiles, one per source address. Sort by `last_seen`, `sessions`, `events` or `first_seen`. Filters: `country`, `asn`, `sensor`, `tag`, `q` (address prefix). Cursor pagination. |
| `GET` | `/api/v1/attackers/{ip}` | One profile, with the 20 most recent sessions, the top usernames and commands, and a 30-day timeline |
| `GET` | `/api/v1/asns` | Networks, sorted by `sessions`, `ips` or `events`: `asn`, `org`, `country`, `ips`, `sessions`, `events`, `last_seen` |

An attacker profile has: `ip`, `first_seen`, `last_seen`, `sessions`, `events`, `sensors`, `login_attempts`, `login_success`, `commands`, `downloads`, `country`, `city`, `asn`, `org`, `abuse_score`, `known_scanner` and `tags`.

Example, a top list (fake values):

```json
{
  "field": "username",
  "total": 1280,
  "items": [
    {"value": "root", "count": 540, "share": 0.42, "first_seen": "2026-10-01T02:11:00Z", "last_seen": "2026-10-24T17:58:00Z"}
  ]
}
```

The target is under 300 ms per endpoint on the default demo data set (about 3,000 sessions and 25,000 events).

## Today, search and research scanners (M19)

### `include_benign`

Ingest labels sessions from known research scanners (`ingest/rules/scanners.yaml`) with `benign=true` and `scanner_name`. Every list, chart and summary endpoint leaves them out unless the request has `include_benign=true`: `/sessions`, `/attackers`, `/asns`, `/stats/summary`, `/stats/timeseries`, `/stats/top`, `/stats/heatmap`, `/events/recent`, `/insights`, `/trends/new`, `/trends/tags`, `/today` and the WebSocket `/live` (`?include_benign=1`). `/sessions` also returns them when `src_ip` names one address. Sessions carry `benign` and `scanner_name`; live events carry `benign`. The continuous aggregates are not split by `benign`.

### `GET /api/v1/stats/benign`

`{"window_hours": 24, "sessions": 1204, "sources": 31}`: what the "hide research scanners" switch hides.

### `GET /api/v1/search`

Query `q` (1 to 512 characters, cut to 128). Under two characters the answer is empty. The answer is `{"q": "...", "groups": [{"kind": "ip|campaign|cve|hash|domain", "hits": [...], "more": false}]}` with at most five hits per group. Every lookup uses an index: an exact or dotted-prefix address (`203.0.113.` stands for the /24), a complete CVE id, a file-hash prefix of eight characters or more, a domain or URL prefix, a campaign-name prefix or id. A hit has `kind`, `value` (address, CVE id, indicator id or campaign id), `label` (indicators are defanged), `detail`, `count`, `last_seen` and `benign`. Research scanners are included on purpose. Statements time out after 3 seconds.

### `GET /api/v1/today`

`{"generated_at", "window_hours": 24, "hidden_benign": 0, "cards": [...]}`. Each card has `id` (`happened`, `campaigns`, `act`, `new_week`, `exposure`), a `sentence`, up to three `items` (`kind`, `value`, `label`, `detail`, `count`, `to` = a web route with its filters), one `action` (`label`, `to`) and `empty`. The `exposure` card is only present once the service inventory has rows. The answer is cached for a minute per `include_benign` value.

## Insights, trends and malware (M7)

All of these are read-only and need a session.

### `GET /api/v1/insights`

Up to three short findings, written by fixed rules (no language model). Each is one plain sentence plus the numbers behind it and a link to the filtered dashboard view.

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `since`, `until` | the last 7 days | The window to describe, with a time zone. At most 30 days. The previous period of the same length is the comparison. |

```json
{
  "generated_at": "2026-10-24T18:05:00Z",
  "items": [
    {
      "id": "surge-tag-php2shell",
      "kind": "surge",
      "severity": "severe",
      "sentence": "PHP2Shell exploit attempts tripled since Tuesday (312 vs 104).",
      "evidence": {"metric": "sessions_by_tag", "current": 312, "previous": 104, "ratio": 3.0},
      "link": "/attacks?tag=php2shell&since=2026-10-20T00:00:00Z&until=2026-10-24T18:05:00Z"
    }
  ]
}
```

`kind` is `surge`, `new_value`, `campaign`, `exploit`, `success` or `geo_shift`. `severity` is `info`, `notice`, `warning` or `severe`.

**The rules.** A rule produces a finding only when the volume is large enough, so a quiet host never says "tripled (3 vs 1)". Candidates are ranked by severity first, then by size, and the top three are returned. All times are UTC, so "since Tuesday" and "midnight" are UTC days.

| Kind | Fires when | Wording |
| --- | --- | --- |
| `exploit` | A session tagged `php2shell` or `malware-drop` appears for the first time, with none in the 90 days before | "PHP2Shell exploit attempts appeared for the first time: 12 sessions in the last 7 days, none in the 90 days before." Severity `severe`. |
| `surge` | Sessions for a tag or a sensor: at least 20 now, at least 5 before, and at least 1.5 times the previous period | "<Label> tripled / doubled / up 4.2x / up 40% since <day> (current vs previous)." |
| `success` | Sessions with a successful login: at least 5 now, at least 2 before, and at least twice the previous period | "Successful logins doubled since yesterday (12 vs 5)." Severity `warning`. |
| `campaign` | At least 50 sessions in total, and one network (ASN) has 40% or more of them, or one address has 30% or more | "AS64496 (Example Net) accounts for 62% of all sessions in the last 7 days (620 of 1,000)." |
| `geo_shift` | At least 50 sessions in both periods, and a country with at least 20 sessions, 20% or more of the traffic, and at least double its previous share | "Sessions from NL rose from 8% to 25% of all traffic in the last 7 days." |
| `new_value` | A username, command, URL or ASN never seen in the 90 days before, seen at least 10 times | "A command never seen before showed up 14 times in the last 7 days: ..." Attacker-controlled text has control characters removed and is cut to 60 characters. |

### `GET /api/v1/trends/new`

Values that appeared in the window and **not** in the 90 days before it.

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `field` | required | `username`, `password`, `command`, `url`, `asn` or `user_agent` |
| `days` | `7` | Window length, 1 to 30 days, ending now |
| `limit` | `50` | 1 to 200 |

Returns `{"field": "...", "items": [{"value": "...", "count": 14, "first_seen": "..."}]}`, most frequent first.

### `GET /api/v1/trends/tags`

Sessions per tag over time, for the "tags over time" chart.

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `bucket` | `1d` | `5m`, `1h` or `1d` |
| `since`, `until` | the last 7 days | Window, at most 30 days and 500 buckets |

Returns `series` (the eight most frequent tags, plus `other` when there are more), and `points`, one per bucket, each with a `ts` and a count per series entry. Empty buckets are zero.

## Indicators and infrastructure (M13)

Read-only and passive: nothing is fetched from an indicator. Values come both raw (`value`) and defanged (`defanged`, such as `hxxp://files[.]host[.]tld/a.sh`).

| Endpoint | What it returns |
| --- | --- |
| `GET /api/v1/indicators` | Keyset-paginated list (`cursor`, `limit` 1 to 200). Filters: `type` (`url`, `domain`, `ip`, `hash`), `role` (`download_host`, `contacted_host`, `hash`), `known` (true or false), `family`, `since`, `hours` (seen in the last N hours, 1 to 2160, the graph's window), `q` (literal substring). IPv6 values are defanged too (`2001[:]db8[:][:]1`). Each item has sightings, sessions, distinct source addresses, sensors and the intel verdict (`checked`, `known`, `family`). |
| `GET /api/v1/indicators/c2` | Probable command-and-control addresses of malware dropped here, both roles, read-only. Keyset-paginated (`cursor`, `limit` 1 to 200, default 50). Filters: `min_confidence` (`medium`, the default, or `high`), `kind` (`ip` or `domain`), `hours` (hashes dropped in the last N hours, 1 to 2160, default 720). Each item has `address`, `defanged`, `kind`, `port`, `confidence`, `sources`, `families`, `hashes` (up to 10 of `{sha256, family}`), `hash_count`, `sessions` (our sessions that dropped those hashes), `first_seen`, `last_seen` and `references` (links to VirusTotal and ThreatFox only). Best confidence first, then most recent. See {ref}`Probable C2 addresses <probable-c2-addresses>`. |
| `GET /api/v1/indicators/{id}` | One indicator with the intel answers (source, family, threat type, tags, first reported, reference link), recent sessions, source addresses and indicators seen in the same sessions. |
| `GET /api/v1/infrastructure/graph` | Nodes and edges linking source addresses, indicators (hosts and hashes) and malware families for the last `hours` (1 to 2160, default 168), with a `summary` and `truncated`. At most 300 nodes. |
| `GET /api/v1/indicators/export` | A download of up to 5,000 indicators matching the same filters, as `format=csv` or `format=stix` (a STIX 2.1 bundle of `indicator` objects). |

### `GET /api/v1/malware`

Download URLs recorded from `download_attempt` events, one row per URL, most recently seen first. **Nothing is fetched.**

| Query parameter | Default | Meaning |
| --- | --- | --- |
| `limit` | `50` | 1 to 200 |
| `cursor` | none | From the previous page |
| `tool` | none | Only URLs seen with this tool (`wget`, `curl`, `tftp`, ...) |
| `q` | none | Case-insensitive text search in the URL |

Each item has `url` (cut to 512 characters), `host`, `first_seen`, `last_seen`, `attempts`, `sessions`, `ips`, `tools`, `sensors`, and `sha256`, `size` and `virustotal_url`. The last three are `null` until payload fetching exists, which is off and not implemented.

### `GET /api/v1/malware/detail`

`?url=<the exact URL>`. Returns the same item plus up to 20 recent sessions that used the URL. `404` when the URL is unknown. The URL is a query parameter, not a path part, so it needs no special escaping rules.

```{important}
The API returns URLs exactly as the attacker sent them. They are dangerous strings. The dashboard shows them **defanged** (`hxxp://example[.]com/x.sh`), renders them as text and never as links. Do the same in any tool you build on this API.
```

### `GET /api/v1/settings/site`

The home point of the Live map, where the attack arcs land, as a country-level point.

```json
{"home": {"lat": 46.8, "lon": 8.2, "label": "Switzerland"}}
```

It comes from `SITE_HOME_LAT`, `SITE_HOME_LON` and `SITE_HOME_LABEL`. The values are rounded to one decimal place (about 11 km) on purpose, so the public page never shows an exact location. Do not put the real address of the host in them.

## Samples and egress (M21)

Samples are the files the `collector` fetched from captured download URLs and the `analyzer` examined. The API reads the database and the quarantine volume read-only. It never serves a raw file. All routes need a signed-in user; the archive route needs an administrator.

### `GET /api/v1/samples`

Cursor pagination: `cursor` and `limit` (up to 200, default 50). Sorted by `last_seen`, newest first. Each item also has `origin` (`network_verify` when every source was a network verification fetch, else `local`) and `crawled`: `true` when the collector reached the file only by following links found in other web content and no attacker asked for it (no typed URL, not linked from a script or a binary). A web `kind` at severity `info` with no family and `crawled: true` is plain web content: its links are not followed and its hash feeds nothing.

| Parameter | Meaning |
| --- | --- |
| `kind` | File kind, such as `elf`, `pe`, `script` (case-insensitive) |
| `arch` | Architecture, such as `arm`, `mips`, `x86-64` |
| `family` | Family set by a YARA rule |
| `yara` | Name of a YARA rule that matched |
| `status` | Analysis state: `pending`, `done`, `failed` or `timeout` |
| `q` | A hash prefix or part of a source URL (1 to 128 characters) |
| `since` | Only samples seen since this time |

### `GET /api/v1/samples/{sha256}`

Metadata (kind, architecture, size, sha256, sha1, md5, TLSH, family, severity, whether the file is still stored), the analysis (YARA hits, capped strings, deobfuscated script text and the steps taken), the sources (URLs, first and last fetch, session count, sensors and addresses), the links found inside it (next-stage URLs and C2 addresses; none for plain web content, see `crawled` above; web kinds are `html`, `svg`, `xml`, `css`, `json` and `javascript`), the latest sessions that dropped it, and `virustotal_url`. That is a link only: the API makes no call to VirusTotal. Defang URLs when you paste them anywhere.

### `GET /api/v1/samples/{sha256}/chain`

`{nodes, edges}` for the story session, then URL, then sample, then C2. Bounded to three levels and 100 nodes. Node kinds: `session`, `url`, `sample`, `c2`.

### `POST /api/v1/samples/{sha256}/archive`

Administrators only. The body is `{"password": "<your dashboard password>"}`: the password is asked again. The request also needs the CSRF header and an allowed origin like every write. At most 10 downloads per hour per user (`429` with `Retry-After` beyond that). The answer is an `application/zip` attachment: AES-256, password `infected` (the convention that keeps mail scanners quiet, not a secret), one entry named after the sha256, with `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Each download is written to the audit log. `404` if the file is no longer stored.

### `GET /api/v1/egress`

The state of the anonymous egress, for the Settings card.

| Field | Meaning |
| --- | --- |
| `ingest`, `collector` | `{state, reason, checked_at}` of each gate. `state` is `open` or `closed`. `reason` is a constant code such as `no_vpn`, `tunnel_down`, `echo_failed`, `echo_disagree`, `ip_mismatch` or `ip_not_allowed`. |
| `exit_ip_allowed` | Whether the VPN exit address is in the allowed network |
| `exit_ip` | The VPN exit address (never the home address). The web app hides it until you ask. |
| `collector_quota` | `{used, limit}` of fetches today |
| `quarantine` | `{used_bytes, max_bytes}` |

### Malware

`GET /api/v1/malware` and `/api/v1/malware/detail` now fill `sha256`, `size` and `virustotal_url` from the fetched samples, and add `fetch_status` (for example `fetched`, `pending`, `failed`, `refused`, `unsupported`).

## Abuse reports (M22)

The API prepares reports and never talks SMTP itself: optional sending (M25) queues a request that ingest delivers through the VPN. Every `GET` is open to both roles, except settings and self terms (administrators only). Every write needs an administrator, the CSRF header and an allowed origin. Lists use cursor pagination (`limit` up to 100).

Every render, download and export runs the identity guard before it returns. A failure answers `409` with `{"detail", "code": "identity_guard_failed", "reasons": [...]}`. Reasons are constant codes, never the matched value (see [Security](SECURITY.md#the-identity-guard)). A refused settings save adds `fields`, the reason codes per field name (`{"reply_contact": ["project_term"]}`), so the UI can say which text blocks every report. When the reply contact is empty the answer is `409` with `code: "settings_incomplete"` and `missing: ["reply_contact"]`. It is the only required setting: the introduction, closing, note, signature, subject template and X-ARF user agent are optional (an empty part is left out; an empty subject template gives `Abuse report for {value}`, an empty user agent gives `Mozilla/5.0`).

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/abuse/status` | Worker on or off, gate state, RDAP quota, whether a self address is known (never the value), counts per status, and `blocked_drafts`: how many open drafts the identity check holds back, and how many carry each reason code |
| `GET` | `/api/v1/abuse/reports` | Reports, newest change first. Filters: `status`, `kind`, `recipient`, `demo`. |
| `GET` | `/api/v1/abuse/reports/{public_id}` | One report: subjects, guard result, redaction counters, revision, history and the send state (`send_state`, M25) |
| `GET` | `/api/v1/abuse/reports/{public_id}/render` | `format=text`, `xarf` or `eml`, optional `subject`. Returns To, Subject, body, attachments and revision. |
| `GET` | `/api/v1/abuse/reports/{public_id}/download` | A file: `format=txt`, `eml`, `evidence_csv` or `xarf_yaml`. Attachment, `no-store`, `nosniff`. Audited. |
| `POST` | `/api/v1/abuse/reports/{public_id}/status` | Body `{to, revision, sent_at?}`. `409` on a stale revision or an invalid change. Audited. |
| `PATCH` | `/api/v1/abuse/reports/{public_id}` | Notes and options of an open report |
| `POST` | `/api/v1/abuse/reports/{public_id}/regenerate` | Ask ingest to rebuild the draft. A reviewed report goes back to draft. |
| `GET`, `PATCH` | `/api/v1/abuse/recipients`, `/{id}` | List recipients. Mute one or set an override mailbox. |
| `GET`, `PUT` | `/api/v1/abuse/settings` | Reply contact, signature, wording, X-ARF user agent, default options. Administrators only. Every text field is checked by the guard on its own: `PUT` refuses a text that would block every report (`409`, with `fields`), and `GET` returns `field_issues`, the saved texts that block reports today, as reason codes per field (the rules grow, so an old text can start to block). The audit log records field names, never values. |
| `GET`, `POST`, `PATCH`, `DELETE` | `/api/v1/abuse/self-terms`, `/{id}` | The "never in a report" list. Administrators only. Values are masked unless `reveal=true`. Confirm a learned term with `PATCH`. |
| `GET` | `/api/v1/abuse/exports/stix`, `/misp` | Indicators of one `report`, one `campaign` or a `since`/`until` window, with a `tlp` (default `TLP:GREEN`). Audited. |
| `POST` | `/api/v1/abuse/exports/samples` | Up to 10 stored samples in one AES-256 zip (password `infected`) with a hash table. Administrators only, password asked again, 5 per hour. A sample that contains a self term is excluded and counted in `X-Excluded`. |

Statuses: `draft`, `reviewed`, `sent`, `closed`, `discarded`, `superseded`. Kinds: `attack_source`, `payload_host`, `c2`.

## Sending abuse reports (M25)

Sending is optional and off by default. An administrator saves an SMTP profile and picks a mode in Settings > Reporting > Sending. The API never opens a connection to a mail server: it stores the profile and writes rows in `abuse_send_requests`. Ingest sends the mail through the VPN. Setup steps are in [Deployment](deployment.md#sending-reports).

Every route in this section is administrator only, including the `GET` routes. A viewer gets `403` with `admin_required`. Writes need the CSRF header and an allowed origin. Some routes also ask for the administrator's password again:

| Route | Password in the body |
| --- | --- |
| `PUT /api/v1/abuse/smtp` | `current_password` |
| `DELETE /api/v1/abuse/smtp` | `current_password` |
| `POST /api/v1/abuse/smtp/test` | `current_password` |
| `POST /api/v1/abuse/reports/{public_id}/send` | none |
| `POST /api/v1/abuse/reports/{public_id}/send/cancel` | none |

The re-authentication rules are the same as for the provider keys (see [Provider keys](#provider-keys)): a wrong password is `403` with `reauth_failed`, and five wrong passwords in a row end the session (`401`, `session_revoked`). Send and cancel do not ask for the password. The web app asks for a confirmation instead, and ingest runs the identity guard again before any mail leaves.

### `GET /api/v1/abuse/smtp`

The profile. The password is never returned. `password_set` says whether one is stored.

```json
{
  "configured": true,
  "password_set": true,
  "host": "smtp.example.org",
  "port": 587,
  "security": "starttls",
  "username": "reports@example.org",
  "from_address": "reports@example.org",
  "from_name": "",
  "mode": "click",
  "auto_hold_minutes": 60,
  "daily_cap": 20,
  "sent_today": 2,
  "last_test": {"status": "sent", "error_code": null, "requested_at": "2026-10-30T09:00:00Z", "done_at": "2026-10-30T09:00:41Z"},
  "updated_at": "2026-10-30T08:55:00Z",
  "updated_by": "admin"
}
```

- `configured` is `true` when a host and a sender address are saved, and either a password is stored or the username is empty.
- `sent_today` counts the reports sent since midnight UTC. The daily cap applies to automatic sends only.
- `last_test` is the latest test message, or `null`. Read it here after you ask for a test.
- Without a saved profile the answer is the same shape with `configured` and `password_set` set to `false`, `host` and `from_address` empty, and `mode` set to `off`.

### `PUT /api/v1/abuse/smtp`

Saves the profile. The answer is the new `GET` shape.

| Field | Rule |
| --- | --- |
| `host` | A DNS name such as `smtp.example.org`. Not an IP address, not a single label, not an internal name (`local`, `lan`, `internal` and similar). |
| `port` | 1 to 65535 |
| `security` | `starttls` or `ssl`. Plain text is not offered. The certificate is always checked. |
| `username` | Optional, up to 254 characters, no control characters |
| `from_address` | A mailbox on a public domain, for example `reports@example.org` |
| `from_name` | Optional, up to 100 characters: letters, digits, spaces and `.,'()_-` |
| `password` | The SMTP password, up to 256 characters. Leave it out to keep the stored one. Required on the first save. Stored encrypted and never returned. |
| `mode` | `off` (default), `click` or `auto`. See [Sending reports](deployment.md#sending-reports). |
| `auto_hold_minutes` | 10 to 1440, default 60 |
| `daily_cap` | 1 to 200, default 20 |
| `current_password` | The administrator's own password |

`from_name` and `from_address` go through the identity guard. A value that points to the owner is refused.

| Status | Code | Meaning |
| --- | --- | --- |
| `422` | `invalid_host` | The host is not a public DNS name |
| `422` | `invalid_from_address` | The sender address is not a valid mailbox |
| `422` | `invalid_from_name` | The sender name has characters that are not allowed |
| `422` | `invalid_credentials` | A control character in the username or the password |
| `422` | `identity_guard_failed` | The name or address failed the identity guard. The answer lists the constant `reasons`, never the value. |
| `422` | `password_required` | First save without a password |
| `503` | `editing_disabled` | `SETTINGS_ENCRYPTION_KEY` is not set, so no password can be stored |
| `409` | `already_sending` | A report mail is being sent right now. Try again in a minute. |
| `403` | `reauth_failed` | Wrong `current_password` |

Changing the mode to anything but `auto` makes ingest cancel the automatic requests still waiting, with the error code `mode_changed`. The audit log records the changed field names, never the values.

### `DELETE /api/v1/abuse/smtp`

Body `{"current_password": "..."}`. Removes the profile and the stored password. Every pending request is cancelled. Answers `204`. Also `409` with `already_sending` while a mail is in flight.

### `POST /api/v1/abuse/smtp/test`

Body `{"current_password": "..."}`. Queues a short neutral message to `from_address` itself. Answers `202`:

```json
{"id": 4123, "status": "pending", "scheduled_at": null}
```

| Status | Code | Meaning |
| --- | --- | --- |
| `409` | `smtp_not_configured` | Save the profile first |
| `409` | `already_queued` | A test is already waiting. Only one test at a time. |
| `403` | `reauth_failed` | Wrong password |

If the VPN gate is closed, a test waits for up to two minutes and then fails with `egress_closed`. Read the result in `last_test` of `GET /api/v1/abuse/smtp`.

### `GET /api/v1/abuse/send-queue`

The ready reports, oldest first, one page at a time. This feeds the To send view. A report is ready when it is a draft or reviewed, it is not a demo, its recipient is known and not muted, and the identity guard passes right now.

| Parameter | Meaning |
| --- | --- |
| `limit` | 1 to 25, default 10 |
| `cursor` | The `next_cursor` of the previous page. Opaque. An invalid cursor returns `400` with `invalid_cursor`. |

```json
{
  "items": [
    {
      "id": "3f2c9a1e-5b7d-4e8a-9c21-7d4b6e0f8a12",
      "recipient": "abuse@example.org",
      "subject": "Report: login attempts from 198.51.100.7",
      "body_text": "Plain-text body of the report ...",
      "scheduled_at": null,
      "last_request": null
    }
  ],
  "next_cursor": null,
  "mode": "off",
  "missing": []
}
```

- `id` is the report's public ID, the same value as in the report routes.
- `last_request` is the newest send request of the report, or `null`. `scheduled_at` is set while an automatic send waits for its hold time.
- A report that fails the guard when it is read is left out. A page can therefore hold fewer than `limit` items while `next_cursor` is still set. Keep paging until `next_cursor` is `null`.
- When the reply contact is still empty, `items` is empty and `missing` lists it.
- `mode` tells the web app whether the "Send now" button is shown.

### `POST /api/v1/abuse/reports/{public_id}/send`

Queues one report for sending. The mode must be `click` or `auto`. The body is optional. Send `{"revision": 3}` to make sure the draft you read is still the current one. Answers `202` with the new request, for example `{"id": 4124, "status": "pending", "scheduled_at": null}`. Ingest sends it later, through the VPN.

| Status | Code | Meaning |
| --- | --- | --- |
| `404` | `not_found` | No such report |
| `409` | `smtp_not_configured` | No profile saved |
| `409` | `smtp_off` | The mode is `off` |
| `409` | `revision_mismatch` | The draft changed since you read it |
| `409` | `identity_guard_failed` | The guard refused the report. The answer lists `reasons`. |
| `409` | `demo_report` | Demo reports are never sent |
| `409` | `report_not_ready` | The report is not a draft or reviewed, it is muted, or it has no mailbox |
| `409` | `already_queued` | A request for this report is already waiting or sending |
| `409` | `settings_incomplete` | The reply contact is empty. The answer lists `missing`. |
| `409` | `evidence_invalid` | The stored evidence could not be rendered |

### `POST /api/v1/abuse/reports/{public_id}/send/cancel`

Cancels the requests of one report that have not started. Answers `200` with `{"cancelled": 1}`.

| Status | Code | Meaning |
| --- | --- | --- |
| `404` | `not_found` | No such report |
| `409` | `nothing_to_cancel` | Nothing is waiting for this report |
| `409` | `already_sending` | Ingest has started the connection. The mail may already be on its way, so it cannot be cancelled. |

### Report detail: `send_state`

`GET /api/v1/abuse/reports/{public_id}` adds `send_state`:

```json
"send_state": {
  "scheduled_at": "2026-10-30T10:00:00Z",
  "last_request": {"status": "pending", "error_code": null, "requested_at": "2026-10-30T09:00:00Z", "done_at": null}
}
```

`last_request` is `null` when the report was never queued. `scheduled_at` is set only while an automatic send waits for its hold time.

### Request statuses

| Status | Meaning |
| --- | --- |
| `pending` | Waiting for its hold time, for the VPN gate, or for ingest |
| `sending` | Ingest has started the connection. It cannot be cancelled any more. |
| `sent` | The server accepted the mail. The report is now `sent`, with `sent_via` set to `smtp`. |
| `failed` | Not sent. `error_code` says why. The report stays ready. |
| `cancelled` | Cancelled by the owner, cancelled because the mode changed, or the profile was removed. |

### Error codes of a failed request

These are stored in `error_code`. The values are constants. No server message, address or body text is ever stored.

| Code | Meaning |
| --- | --- |
| `auth_failed` | The server refused the login |
| `tls_failed` | TLS could not be set up, or the certificate did not match the host |
| `refused` | The server refused the sender or the recipient |
| `timeout` | The server did not answer in time |
| `network` | A connection problem |
| `unknown_outcome` | The connection broke after the message data started. The server may have accepted the mail. It is never retried. Check the recipient's mailbox before you send again. |
| `egress_closed` | The VPN gate is closed. A send stays `pending` and waits. A test fails after two minutes. |
| `guard_failed:<codes>` | The identity guard refused the complete message, headers included. The codes after the colon are the guard's constant reason codes (see [Security](SECURITY.md#the-identity-guard)). |
| `not_ready` | The report changed and is no longer ready |
| `not_configured` | No profile was found when ingest looked |
| `mode_off` | The mode is `off` |
| `mode_changed` | An automatic request was cancelled because the mode is no longer `auto` |
| `internal` | An unexpected error before anything was sent |

### Audit

Each change is audited with the actor and the client address: `abuse.smtp.update`, `abuse.smtp.delete`, `abuse.smtp.test`, `abuse.send` (report ID and mode) and `abuse.send.cancel`. Entries never hold the password or the message body.

## VPN settings (M23, M24)

Administrators only, for every route below. Writes need the CSRF header and an allowed origin. The WireGuard file itself is never returned or logged. The answers show only the endpoint, the addresses and a short fingerprint of the peer key. The design is in [M23](design/m23.md) and [M24](design/m24.md).

| Method | Path | Body | Answer |
| --- | --- | --- | --- |
| `GET` | `/api/v1/settings/vpn` | none | The settings (see below) |
| `PUT` | `/api/v1/settings/vpn` | `{"conf": "...", "password": "..."}` | `200` with the settings after the upload |
| `DELETE` | `/api/v1/settings/vpn` | `{"password": "..."}` | `204`. The `vpn` service goes back to the values in `.env`. |
| `POST` | `/api/v1/settings/vpn/check` | none | `202` with `requested_at` |
| `POST` | `/api/v1/settings/vpn/reconnect` | `{"password": "..."}` | `202` with `requested_at` |
| `POST` | `/api/v1/settings/vpn/trusted-exits` | `{"password": "..."}` | `201` with the new range |
| `DELETE` | `/api/v1/settings/vpn/trusted-exits/{exit_id}` | `{"password": "..."}` | `204` |

The `password` field is the administrator's own password. In this section, "Check now" is the only write that does not ask for it.

### `GET /api/v1/settings/vpn`

| Field | Content |
| --- | --- |
| `source` | `env` (the values from `.env`) or `upload` (a file uploaded here) |
| `uploaded_at`, `uploaded_by` | When and by whom the file was uploaded. `null` for `env`. |
| `endpoint_ip`, `endpoint_port`, `addresses`, `peer_key_fingerprint` | The parts of the configuration that are safe to show |
| `gate` | `{state, reason, egress_ip, egress_asn, egress_org, checked_at}` of the ingest egress gate. `state` is `open` or `closed`. `egress_ip` is the VPN exit address. |
| `trusted_exits` | `[{id, cidr, created_at, created_by}]`, at most 8 |
| `trust_candidate` | The range the gate would trust now, or `null` |
| `trust_blocked` | `exit_is_self` or `exit_asn_denied` when the candidate must not be trusted, otherwise `null` |
| `config_writable` | `false` when the configuration volume is missing or read-only. Uploads then answer `503`. |
| `last_check_request` | `{requested_at, done_at}` of the latest "Check now", or `null`. `done_at` is `null` until ingest has checked. |

### `PUT /api/v1/settings/vpn`

Uploads a wg-quick file. The parser is strict. It accepts only the keys it knows, and it refuses anything that runs a command or changes routing. Errors:

| Status | Code | Meaning |
| --- | --- | --- |
| `413` | `too_large` | The file is larger than 4 KiB |
| `422` | `invalid_wireguard_config` | The answer lists `problems`, codes such as `forbidden_key`, `preshared_key_refused`, `bad_private_key`, `endpoint_not_ip` or `not_full_tunnel` (the peer must route `0.0.0.0/0`) |
| `503` | `vpn_config_unavailable` | The configuration volume cannot be written |
| `403` | `reauth_failed` | Wrong password |

### `POST /api/v1/settings/vpn/check`

Asks ingest to check the egress gate now. It changes nothing else and needs no password. Ingest picks the request up within a few seconds. Read the answer in `last_check_request`. At most one request per 10 seconds: a second one answers `429` with `too_soon` and a `Retry-After` header.

### `POST /api/v1/settings/vpn/reconnect`

Restarts the tunnel. The `vpn` service watches a marker file and restarts when it changes. Outbound lookups pause until the tunnel is back. At most one reconnect per 60 seconds (`429`, `too_soon`). Audit action: `vpn.reconnect`.

### `POST /api/v1/settings/vpn/trusted-exits`

Trusts the range in `trust_candidate`. The API stores the /24 (IPv4) or /48 (IPv6) that contains the exit address the gate saw. A client cannot send its own range. Once the range is trusted, the gate accepts exits in it. Errors:

| Status | Code | Meaning |
| --- | --- | --- |
| `409` | `no_candidate` | There is no exit range to trust right now |
| `409` | `exit_is_self` or `exit_asn_denied` | The exit must not be trusted. See `trust_blocked`. |
| `409` | `too_many` | Eight ranges are already trusted. Remove one first. |

### `DELETE /api/v1/settings/vpn/trusted-exits/{exit_id}`

Removes one trusted range. Answers `204`.

## Setup checklist (M24)

`GET /api/v1/setup/status` is for administrators only. It returns the checklist of the Settings page and the last tour step. Every item is computed from real state. `detail` is a short English sentence. It never contains a key, an address or a mailbox. `href` is the dashboard path that fixes the item.

```json
{
  "items": [
    {"id": "sensors", "state": "ok", "detail": "All 12 sensors sent events in the last 24 hours.", "href": "/settings"},
    {"id": "vpn", "state": "warning", "detail": "The egress gate is closed (tunnel_down). Outbound lookups are paused.", "href": "/settings?tab=vpn"}
  ]
}
```

`state` is one of `ok`, `todo`, `warning` or `off`. The items always come in the same order:

| `id` | `ok` when | Other states |
| --- | --- | --- |
| `sensors` | Every sensor sent an event in the last 24 hours | `warning` names the silent sensors |
| `vpn` | The ingest egress gate is open | `todo`: the gate has not reported yet. `warning`: the gate is closed, with its reason. |
| `collector` | Payload fetching is on and its gate is open | `off`: `COLLECTOR_ENABLED` is false. `warning`: on, but its gate is closed. |
| `reporting_settings` | The reply contact is set (the report texts are optional) | `todo` |
| `self_address` | The honeypot's own address is known | `todo` |
| `abuse_worker` | `ABUSE_REPORTS_ENABLED` is true | `off` |
| `alerts` | At least one alert channel is enabled | `off` |
| `provider_keys` | The AbuseIPDB and GreyNoise keys are set | `warning` names the missing key. `off` when neither is set. |

If one check cannot read its data, that item becomes `warning` with the detail "This could not be checked right now.". The other items still answer. The host firewall cannot be seen from inside the stack, so it is not an item. Use `just egress-check` to test it.

## Campaigns and MITRE ATT&CK (M15)

A campaign is a group of sessions that share a script, a payload host, a file hash, a malware family, an exploit or a credential list. Ingest finds them (`CAMPAIGNS_ENABLED`) and labels what each session did with MITRE ATT&CK techniques (`ATTACK_ENABLED`). Everything here is read-only and open to both roles. Research scanners are never clustered.

| Route | What it returns |
| --- | --- |
| `GET /api/v1/campaigns` | Keyset-paginated list, most recently seen first (`cursor`, `limit` 1 to 200). Merged campaigns are hidden unless `status=merged`. Filters: `status` (`active`, `quiet`, `merged`), `sensor`, `technique` (`T1059` or `T1059.004`), `family`, `hours` (1 to 8760) or `days` (1 to 365) since the campaign was last seen, `q` (literal substring of the name), `include_benign` (accepted, no effect). |
| `GET /api/v1/campaigns/{id}` | One campaign: counters, countries, networks, sensors, techniques, stages, tags, families, severity and the representative session. A merged campaign has `status` `merged` and `merged_into`, always the id of the surviving campaign (the oldest), so an old link still resolves. |
| `GET /api/v1/campaigns/{id}/story` | The campaign told in stages (looking around, getting in, running code, staying in, bringing tools, the goal), each with a plain-English sentence and its techniques; up to 12 lines from the representative session; counts; and up to four next actions (`what_to_do`). |
| `GET /api/v1/campaigns/{id}/timeline` | Sessions per hour for the last `days` (1 to 30, default 7), from the campaign's links. Links are capped at `CAMPAIGN_LINK_CAP`; `linked` says how many sessions the points are made of. |
| `GET /api/v1/campaigns/{id}/sessions` | The campaign's sessions, keyset-paginated like `/sessions`. |
| `GET /api/v1/campaigns/{id}/indicators` | The keys that tie it together (payload hosts, hashes, families, script and exploit fingerprints). Hosts also come defanged (`dl[.]example[.]net`). |
| `GET /api/v1/attack/techniques` | The technique catalogue with what was seen in the last `days` (1 to 365, default 30): sessions, events, sources, last day. Keyset-paginated by id (`cursor`, `limit` up to 400); `sensor` filters. |
| `GET /api/v1/attack/matrix` | Sessions per technique per UTC day for the last `days` (default 30), only techniques seen in the window, in story order. Bounded by the catalogue (400 techniques at most), so it is not paginated. `sensor` filters. |

`GET /api/v1/sessions` also accepts `technique` and `campaign_id`, and every session carries `techniques` and `campaign_id`.

## Live feed

`/api/v1/live` is a WebSocket. It pushes new events as they are stored, so a page does not need to poll.

### How it works

- The API checks the database for new events about once per second. It does not read Redis.
- On connect, the client receives a backfill of the 50 newest events, then the latest statistics.
- Each new event is sent once to every client, oldest first.
- Statistics are sent every 5 seconds.
- Each client has a queue of 200 messages. A slow client loses its oldest messages and is told how many were lost.
- The hub accepts at most 50 clients in total and 5 per source address. A connection beyond either limit is closed with code `1013`.
- A client that is slow to receive is dropped after a send timeout of 10 seconds.
- Reconnect politely: the dashboard backs off exponentially and falls back to polling `/api/v1/events/recent`. See [Dashboard](ui.md#the-live-feed).

### Messages

All messages are JSON text frames from the server.

| `kind` | Payload | When |
| --- | --- | --- |
| `backfill` | `events`: list of live events, newest first | Once, right after connecting |
| `stats` | `stats`: window of 60 seconds, with totals and `by_sensor` | After the backfill, then every 5 seconds |
| `event` | `event`: one live event | For each new event, oldest first |
| `dropped` | `count`: messages skipped for this client | When the client was too slow |
| `pong` | none | Reply to a client text frame `ping` |

A live event has the same fields as an item of `/api/v1/events/recent`.

Example `event` message:

```json
{
  "kind": "event",
  "event": {
    "id": 1843,
    "ts": "2026-10-24T18:02:16Z",
    "sensor": "web",
    "session_id": "Lr4pD0c_9Ks",
    "type": "http_request",
    "src_ip": "192.0.2.45",
    "src_port": 38812,
    "dst_port": 80,
    "summary": "GET /wp-login.php → 200",
    "country": null,
    "city": null,
    "asn": null,
    "org": null,
    "abuse_score": null,
    "known_scanner": null,
    "tags": []
  }
}
```

### Origin check

- A client with no `Origin` header (a script or a command-line tool) is accepted.
- A browser must send an `Origin` that matches the `Host` header, or a host listed in `API_ALLOWED_ORIGINS`. Otherwise the connection is closed with `1008`.
- The handshake needs a valid session cookie (see [Authentication](#authentication)). Without it the connection is closed with `1008`, and a session that ends while the socket is open closes it with `1008` too.

### Close codes

| Code | Meaning |
| --- | --- |
| `1000` | Normal close, for example the client left |
| `1001` | The server is shutting down |
| `1008` | The origin is not allowed, there is no valid session, or the session ended |
| `1011` | Internal error on the server |
| `1013` | Too many clients connected (in total or from one address), or the session cannot be checked (database unavailable) |

## Community lists (M30)

The node reads the community lists that its ingest stored. These routes read only. Any signed-in user can call them, and they never contact the feed host. The public files are described in [Community blocklist feeds](feeds.md).

### `GET /api/v1/network/feed/status`

The state of the feed, and the public address of each list file. The file addresses are built as text, from the fixed file names. They exist even while fetching is off.

```json
{"enabled_env": true, "configured": true, "state": "ok", "error_code": null, "serial": 4812,
 "generated_at": "2026-11-01T13:00:00Z", "valid_until": "2026-11-04T13:00:00Z",
 "last_ok_at": "2026-11-01T13:02:11Z", "signature": "verified", "member": false,
 "public_base_url": "https://feeds.example.org/v1",
 "lists": [{"id": "outbound", "direction": "outbound", "entries": 812, "high": 301,
            "seen_here": 3, "helped": null,
            "files": [{"name": "outbound.txt", "format": "txt",
                       "url": "https://feeds.example.org/v1/outbound.txt"}]}],
 "local_mirror": {"feeds_enabled": false}}
```

| Field | Meaning |
| --- | --- |
| `state` | `disabled` (fetch off), `never` (no index yet), `ok`, `stale` (past `valid_until`) or `error` (the last fetch failed; `error_code` says why) |
| `error_code` | Set for `error` and `stale`. Codes include `not_configured`, `egress_closed`, `bad_signature`, `feed_rollback`, `feed_expired`, `feed_invalid`, `too_large` and `http_<code>` |
| `signature` | `verified` when the stored index passed the check, otherwise `null` |
| `lists[].seen_here` | Entries also seen by this sensor in the last 30 days (local data only) |
| `lists[].helped` | Entries that this node helped confirm. Members only. `null` for everyone else. |
| `local_mirror.feeds_enabled` | Whether the local mirror under `/feeds` is switched on (`FEEDS_ENABLED`) |

### `GET /api/v1/network/feed/entries`

Stored entries, one page at a time. Empty while the feed is off.

| Query | Meaning |
| --- | --- |
| `list` | `inbound`, `outbound` or `outbound-domains` |
| `tier` | `standard` or `high` |
| `q` | Text search on the value (up to 64 characters) |
| `seen_here` | `1` for entries this sensor also saw |
| `cursor` | Cursor from the previous page (`next_cursor`) |
| `limit` | 1 to 100, default 50 |

Answer: `{"items": [...], "next_cursor": "..."}`. Each item has `list`, `value`, `family`, `tier`, `categories`, `services`, `tags`, `families`, `ports`, `first_seen`, `last_seen`, `expires`, `reported`, `seen_here` and `helped`. An unknown `list` or `tier` answers `422` with `invalid_filter`.

### The local mirror: `/feeds/.../network/`

The mirror serves the verified entries to a firewall. It is part of the feed routes, so it needs `FEEDS_ENABLED=true`. It sits outside `/api/v1` and works like the sensor feeds in [Defend](defend.md#the-subscription-feed-optional). The token must have the kind `network`.

| Route | Answer |
| --- | --- |
| `GET /feeds/{token}/network/{list}.{txt\|csv}` | Token in the path |
| `GET /feeds/network/{list}.{txt\|csv}` with `Authorization: Bearer <token>` | Token in a header (preferred) |

`{list}` is `inbound`, `inbound-high`, `outbound`, `outbound-high` or `outbound-domains`. The text form has one value per line. The CSV form has a header and CRLF line ends. Each answer has an `ETag`, an `X-Entry-Count` header, and a `304` when the caller sends the matching `If-None-Match`.

- The mirror is empty when the stored state is `stale`, `never` or `disabled`. It fails toward not blocking.
- The administrator's always-allow overrides are removed from the answer. Your own hosts stay off the lists.
- Every value is checked again before it is written out. Demo entries are never served.
- A wrong or revoked token, a token without the `network` kind, and an unknown list all get the same plain `404`. Too many requests from one address or token get `429` with `Retry-After`.

Create a `network` token with `POST /api/v1/defend/feed-tokens` and `"kinds": ["network"]`, as the admin, with the password again. The `min_score` field does not apply to network tokens.

## Not built yet

| Feature | Milestone |
| --- | --- |
| API rate limits beyond the login limits | M8 |
