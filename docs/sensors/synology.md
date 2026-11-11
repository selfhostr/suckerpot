# Synology sensor

```{admonition} Status
:class: note

Built in M20. Wired into `docker-compose.yml` as `sensor-synology`, with the stream `events:synology`, the network `sensors-synology` and the Redis user `sensor-synology`. The sensor's own notes are in `sensors/synology/README.md`. Its security review is still open (see the [roadmap](../ROADMAP.md)).
```

## What it emulates

An internet-exposed Synology NAS that runs DSM 7.2.1-69057 Update 11. That is one update below the fix in Synology-SA-26:13, so it looks unpatched.

The sensor serves the DSM login page and the DSM Web API, over plain HTTP on container port 5000 and over HTTPS on container port 5001. Compose maps the host ports `SYNOLOGY_HTTP_HOST_PORT` (default 5000) and `SYNOLOGY_HTTPS_HOST_PORT` (default 5001) to them.

- **The login page** is the DSM 7 login shell. Its title is a host name that stays the same on each install, such as `DS920plus`, `NAS01` or `DiskStation`.
- **The Web API** (`/webapi/*.cgi`) answers the calls a DSM client makes. `SYNO.API.Info` returns the list of 62 APIs. `SYNO.API.Auth` `login` always fails, with the error codes a real NAS returns. Every other API answers "SID not found", as it does without a session.
- **Logins never succeed.** The sensor never issues a session ID, and it never runs, writes or fetches anything an attacker sends.
- **Responses** carry the headers of DSM's nginx, and an unknown path gets nginx's own `404` page.

## Why it exists

A ransomware campaign called C3RB3R (a Cerber variant) hits exposed Synology NAS devices. It renames files to `*.L0CK3D` and drops a ransom note called `read-me3.txt`. The campaign gets in through two flaws, fixed on 2026-09-18:

| CVE | Weakness | Score |
| --- | --- | --- |
| `CVE-2026-13639` | Insufficient entropy in the login logic (CWE-331) | CVSS 9.8 |
| `CVE-2026-13684` | Improper output encoding in SCGI (CWE-116) | CVSS 9.8 |

The exploit details are not public. So the sensor cannot match an exact exploit. It acts like a real vulnerable DSM and tags the request shapes that fit those two weakness classes.

## What it records

All events use the shared [Event schema](../event-schema.md).

| Event `type` | Content |
| --- | --- |
| `connect` | `tls`, `sni`, `handshake`, `tls_version` and `cipher`. |
| `http_request` | Every request: `method`, `path`, `query`, `host`, `user_agent`, `headers` (32 at most), `body_sha256`, `api`, `api_method`, `api_version`, `params` (24 at most, passwords left out), `flags`, `cve` (only with `sid_forge` or `scgi_injection`), `status` and `route`. |
| `login_attempt` | `username`, `password` (or the encrypted blob, when the client encrypts it), `otp_present`, `success` (always `false`), `error_code` and `encrypted`. |
| `download_attempt` | A URL in any parameter of a `/webapi/` or `/webman/` request. `tool` is `download_station` or `dsm_api`. |
| `scan` | Non-HTTP bytes, incomplete requests, failed TLS handshakes and refused connections. `kind` says which. |
| `disconnect` | `duration_s`, `reason`, `requests`, `login_attempts`, `downloads`, `bytes_out`, `flags` and `statuses`. |

Uploads are never stored. A multipart body is read in memory, only for its field and file names, and then dropped.

### Flags

The flags are in `data.flags` of `http_request`.

| Flag | Set when |
| --- | --- |
| `dsm_api` | The path starts with `/webapi/`. |
| `dsm_login` | `SYNO.API.Auth` `login`, or `/webman/login.cgi` with credentials. |
| `dsm_version_probe` | A request for the version: `SYNO.API.Info`, `SYNO.DSM.Info`, `SYNO.Core.System`, or `/webman/info.cgi`. |
| `sid_forge` | A session ID in a parameter, a header or a cookie of a `/webapi/` call that is not the login, which the sensor never issued. A login (with or without a password) and a session cookie on an ordinary page do not set it. |
| `scgi_injection` | A control byte (CR, LF, NUL) in the path, a parameter or a header. A double-encoded `%0d`, `%0a` or `%00`. SCGI variable names. Header-like text such as `Set-Cookie:`. |
| `file_write` | A FileStation write (upload, rename, delete, copy, compress, extract or create folder), a scheduled task change, or a package install or removal. |
| `ransom_indicator` | `.L0CK3D` or `read-me3.txt` anywhere in the request. |
| `no_user_agent` | The request has no User-Agent header. |
| `oversized_body` | The body was cut: more than 128 KB kept, or more than the 4 MB read limit. |
| `plain_http_on_tls` | Plain HTTP sent to port 5001. |
| `incomplete_body` | The body did not arrive in time. |

When `sid_forge` or `scgi_injection` is set, the event also carries `data.cve`: `["CVE-2026-13639", "CVE-2026-13684"]`. `file_write` and `ransom_indicator` alone do not add it.

## Tags

Rules live in `ingest/rules/services.yaml`.

| Tag | Set when | Severity |
| --- | --- | --- |
| `synology-dsm` | `dsm_api`: any request to the DSM Web API. | Neutral |
| `synology-exploit` | `dsm_api` together with `sid_forge` or `scgi_injection`: a session id or an SCGI injection shape on a DSM Web API call (CVE-2026-13639 and CVE-2026-13684). | Severe |
| `c3rb3r` | `ransom_indicator`: a request that carries a C3RB3R ransomware name. | Severe |
| `malware-drop` | Any `download_attempt`. | Severe |

In the ATT&CK mapping, `synology-exploit` maps to T1190 (Exploit Public-Facing Application), and `c3rb3r` maps to T1486 (Data Encrypted for Impact) and T1190.

The CVE watch links both CVEs to the `synology-exploit` tag. So the CVE page can show that the sensor has seen them in traffic. See the CVE watch section of [Architecture](../ARCHITECTURE.md).

## Limits

Compose sets the caps. The sensor's own defaults are in its README.

| Scope | Limit |
| --- | --- |
| Connections | 200 in total (HTTP and HTTPS together) and 8 per source address. |
| New connections | 5 per second per source address, burst 20. |
| Requests | 20 per second per source address, burst 100. Then `503` and the connection closes. |
| TLS | At most 24 handshakes in flight, 20 per second for the sensor, 8 s handshake timeout. |
| Request line and head | Request line 8190 bytes, head 16 KB and 64 headers. Larger heads get `431`. |
| Body | Read and hashed up to 4 MB. The first 128 KB are parsed. |
| Parameters | 64 per request. 4096 characters are looked at per value. 4 URLs at most. |
| Timeouts | Head within 15 s, each body read 10 s, 45 s in total, keep-alive 15 s, 100 requests or 180 s per connection. |
| Memory | An 80 MB byte budget (`SYNOLOGY_MEMORY_BUDGET_MB`). A cgroup guard refuses new connections above 70 % of the limit, and aborts the largest above 85 %. |
| Events | 20 per second per source address and 200 per second for the sensor. Every field is capped before the event is built. |

The sensor never uses regular expressions, so a crafted input cannot slow it down (ReDoS). A watchdog thread exits the process if the event loop stalls for 10 seconds.

## Login error codes

The login answers use the codes that DSM returns.

| Code | Meaning |
| --- | --- |
| `400` | Wrong account or password. |
| `401` | Account disabled (for example `guest`). |
| `402` | Permission denied (system accounts such as `sshd`). |
| `403` / `404` | Two-step verification required, or failed. This is stable for each account name, and it is never shown for `admin` or `root`. |
| `407` | IP blocked: 12 failures from one address within 5 minutes. |

Other errors are `101` (missing parameter), `102` (unknown API), `103` (unknown method) and `104` (unsupported version).

## Environment variables

Set these in `.env`. The full list is in [Configuration](../configuration.md#sensors-added-in-m20).

| Variable | Default | Meaning |
| --- | --- | --- |
| `REDIS_SENSOR_SYNOLOGY_PASSWORD` | none | Password of the Redis `sensor-synology` user. Required. |
| `SYNOLOGY_HTTP_HOST_PORT` | `5000` | Host port for HTTP. |
| `SYNOLOGY_HTTPS_HOST_PORT` | `5001` | Host port for HTTPS. |
| `SYNOLOGY_HTTP_REDIRECT` | `false` | Redirect the HTTP login page to HTTPS. Off by default, because DSM serves the UI on port 5000. |
| `SYNOLOGY_MAX_CONNECTIONS`, `SYNOLOGY_MAX_PER_IP` | `200`, `8` | Connection caps. |
| `SYNOLOGY_CONN_RATE`, `SYNOLOGY_CONN_BURST` | `5`, `20` | New connections per second per source address, and the burst. |
| `SYNOLOGY_MEMORY_BUDGET_MB` | `80` | Byte budget for connections and bodies in flight. |
| `SYNOLOGY_EVENTS_PER_SEC`, `SYNOLOGY_GLOBAL_EVENTS_PER_SEC` | `20`, `200` | Event caps per source address and for the sensor. |

The dashboard port can never be 5000 or 5001. The [port guard](../deployment.md#port-guard) refuses both.

## Identity and TLS

The host name, the model and the serial number come from a random secret. The sensor stores it in `/data/profile.json`, in the `synology-sensor-data` volume, with mode 0600. The same install keeps the same identity after a restart.

The HTTPS certificate is an RSA 2048 certificate. It is made on the first start and kept in `/data/tls`. Its subject is `C=TW, L=Taipei, O=Synology Inc., CN=synology`, and it is issued by `Synology Inc. CA`, valid for ten years, like the factory certificate. The sensor speaks TLS 1.2 and TLS 1.3.

## Container

Same hardening as the other sensors: non-root (UID 10001), read-only root file system, `tmpfs` at `/tmp`, all capabilities dropped, `no-new-privileges`, 160 MB of memory with no swap, 0.5 CPU and 128 processes. The health check is `python -m synology_sensor.healthcheck`. The data volume must be writable by UID 10001.

## Design rules

- **Hand-written HTTP.** A framework would normalise or reject malformed requests in ways that identify it. The SCGI-shaped requests need the raw bytes.
- **Nothing is executed.** The test suite walks the code and fails on `subprocess`, `eval`, `exec`, `pickle`, `re`, outbound clients and file writes outside the data directory.
- **Downloads are recorded only.** A download URL becomes a `download_attempt` event. The sensor never fetches it.
