# Web sensor

A low-to-medium interaction HTTP and HTTPS honeypot that looks like an unpatched Ubuntu 24.04
server: Apache 2.4.58 with mod_php 8.3.6 (below 8.3.36, so it looks vulnerable to PHP2Shell),
hosting a WordPress 6.8.1 site (Twenty Twenty-Four), phpMyAdmin 5.2.1 and a `phpinfo()` page.
It records every request precisely and never executes or fetches anything.

Run with `python -m web_sensor`. Container ports: **8080** (HTTP) and **8443** (HTTPS). Compose
maps the public ports (see `compose.fragment.yml`, ready to merge).

## Why a hand written HTTP server

Starlette/uvicorn (h11) would leak what they are: lower-cased header names, their own `server`
and error bodies, no HTTP/0.9, normalised or rejected malformed requests, a different `Date`
and keep-alive behaviour. The sensor therefore speaks HTTP/1.x itself (`httpio.py`,
`response.py`, `apache.py`) so that it can reproduce Apache byte for byte. Dependencies:
`cryptography` (certificate generation) and `defusedxml` (XML-RPC parsing). No regular
expressions are used anywhere on attacker input.

## Fidelity to Apache

A reference server (a throwaway `ubuntu:24.04` + `apache2` + `libapache2-mod-php` container,
never part of the sensor) was used to diff behaviour:

* `tests/ref_compare.py`: 61 request/response cases (error pages, malformed requests, HTTP/1.0,
  HTTP/0.9, absolute-form, `OPTIONS *`, TRACE, HEAD, bad `Content-Length`/`Transfer-Encoding`,
  oversized lines and bodies, expect/continue, pipelining, ...): **61/61 byte-identical** apart
  from Date and the server address. The captured result is checked in offline as
  `tests/golden/apache_errors.json` (`tests/test_golden.py`).
* `tests/ref_compare_static.py`: static files, directory listings, gzip, ranges, conditionals,
  HEAD: **32/32 identical**.
* Header order, `ETag` (`"<size hex>-<mtime micros hex>"`, `-gzip` suffix), `Accept-Ranges`,
  `Vary`, `Content-Length` vs chunked (the 8000-byte switch of mod_php output), keep-alive
  (`Keep-Alive: timeout=5, max=100` only when asked for, `Connection: close` on the 100th
  request), `Server: Apache/2.4.58 (Ubuntu)`, `X-Powered-By: PHP/8.3.6` on PHP responses only.
* `phpinfo()` comes from a real PHP 8.3.6 build (`tools/make_phpinfo_template.py`); only host and
  request specific values are substituted. `session.upload_progress.enabled` is `On` and the SAPI
  is `Apache 2.0 Handler`.
* The TLS certificate imitates Ubuntu's `ssl-cert` snakeoil certificate (RSA 2048, SHA-256,
  subject = issuer = the host name, CA:TRUE, ten years), dates and serial from the deployment
  profile. Cipher list `HIGH:!aNULL`, TLS 1.2 and 1.3 (what Ubuntu's OpenSSL 3 allows by
  default). Plain HTTP on the TLS port gets mod_ssl's "You're speaking plain HTTP" page.

Known deviations (also listed in the final report): `X-Powered-By` is sent although stock Ubuntu
has `expose_php = Off` (`WEB_EXPOSE_PHP=false` removes it and the phpinfo value follows);
`xmlrpc.php` header order differs slightly from IXR's (`Connection`/`Content-Length` come from
the server layer); a connection that sends nothing is closed after 60 s (Apache keeps it for
300 s); the request head is limited to 128 KB in total (Apache: 100 fields x 8190 bytes);
WordPress pages are templated look-alikes, not the real theme output.

## What is served

| Path | Behaviour |
| --- | --- |
| `/`, posts, `/author/<slug>/`, search, feeds | WordPress 6.8.1, Twenty Twenty-Four; unknown paths give WordPress's 404 page |
| `/wp-login.php` | form; POST records `login_attempt` (`method` = `wp-login`), answers with WordPress's real error text (user enumeration included) |
| `/xmlrpc.php` | GET 405 "XML-RPC server accepts POST requests only."; POST parses XML safely (DTDs and entities forbidden) and answers `faultCode` 403 for every credential call; `system.multicall` answers every entry like WordPress (the canned `listMethods` array, or WordPress's exact fault) and records credentials for the first 200 (`method` = `xmlrpc`); a response bigger than the memory budget can hold is a 503. Multicalls are limited to 1/s per IP (burst 3) and 4/s overall (burst 8), their gzip output is cached by response hash (2 MB) and fresh compressions draw on a 4 MB/s budget; excess gets Apache's 503 (flag `rate_limited`) |
| `/wp-json/`, `/wp-json/wp/v2/users`, `/?author=N` | user list / redirect (enumeration bait) |
| `/wp-admin/` | 302 to the login page |
| `/phpmyadmin/`, `/pma/` | phpMyAdmin 5.2.1 login; POST records `login_attempt` (`method` = `phpmyadmin`) with a real-looking error |
| `/info.php`, `/phpinfo.php` | `phpinfo()` bait |
| `/server-status` | 403; `/.env`, `/.git/*`, `/cgi-bin/` | Apache 404 (recorded as recon); `.htaccess`: 403 |
| `/readme.html`, `/license.txt`, theme and plugin files, `/wp-content/uploads/` listing | static, with `ETag`/`Last-Modified` |
| `Authorization: Basic` on any request | recorded as `login_attempt` (`method` = `http-basic`) |

## PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

Detected (not executed, not reflected): a field named like `session.upload_progress.name`
(`WEB_UPLOAD_PROGRESS_NAME`, default `PHP_SESSION_UPLOAD_PROGRESS`) in a multipart or urlencoded
body or in the query, with the `PHPSESSID` cookie, oversized or slow uploads, and follow-up
requests that include `/tmp/sess_<id>` or `/var/lib/php/sessions/sess_<id>` (also through
`php://filter` etc.). The server answers like a vulnerable but unexploited server: the normal
page. `http_request` events carry `data.flags` (`php2shell`, `upload_progress`, `lfi`,
`session_include`, `session_cookie`, `oversized_upload`, `slow_upload`, `session_ref_match`),
`data.cve` and `data.php2shell` (`field`, `value_preview`, `phpsessid`, `progress_before_file`,
`session_ref`, `session_ref_same_ip`, ...).

## Events

All events use `suckerpot_common.Event`; `dst_port` is the public port of the listener (80 or
443). One TCP connection is one session. No events for 127.0.0.1 (healthcheck).

| type | data |
| --- | --- |
| `connect` | `tls`, `sni`, `tls_version`, `cipher`, `handshake` |
| `http_request` | `method`, `path`, `query`, `http_version`, `host`, `headers` (dict, wire order, 64 max, values 512 chars), `user_agent`, `body_preview` (2 KB), `body_sha256`, `body_length` (read up to 1 MiB), `body_truncated`, `content_length`, `chunked`, `status`, `tls`, `sni`, `app` (`wordpress`/`phpmyadmin`/`phpinfo`/`apache`), `route`, `flags` (list), `cve` (list), `traps` (trap pack hits, up to 4 `{pack, v, trap, level}`), `php2shell` (when relevant), `request_head_preview` (malformed or incomplete requests) |
| `login_attempt` | `username`, `password`, `success` (always false), `method`, `path`, `user_agent` |
| `download_attempt` | `url`, `tool` (`wget`, `curl`, `tftp`, `rfi`, `jndi`, `xmlrpc-pingback`, ...), `command`, `via`, `path`, `user_agent` (recorded only) |
| `scan` | `kind` = `tls_handshake_failed` or `non_tls_on_tls_port` (+ details) |
| `disconnect` | `duration_s`, `reason`, `requests`, `login_attempts`, `downloads`, `bytes_out`, `tls`, `sni`, `flags`, `statuses`, `suppressed` (events dropped by rate limits) |

Other flags: `recon_dotfile`, `config_leak`, `backup_probe`, `rce`, `php_code`, `sqli`, `xss`,
`path_traversal`, `lfi`, `rfi`, `php_wrapper`, `ssrf`, `log4shell`, `shellshock`, `scanner_ua`,
`no_user_agent`, `wordpress`, `phpmyadmin`, `phpinfo_probe`, `phpunit_rce`, `laravel_rce`,
`router_probe`, `router_exploit`, `webshell_probe`, `wp_user_enum`, `xmlrpc`, `xmlrpc_multicall`,
`directory_listing`, `malformed`, `incomplete_request`, `oversized_body`, `plain_http_on_tls`.
Exploit flags (`SEVERE` in `detect.py`, plus the flags of `exploit` traps in the loaded trap packs)
give an event the guaranteed quota. `phpunit_rce`, `phpunit_probe`, `log4shell` and `router_exploit`
come from the trap packs bundled in `web_sensor/data/traps-bundled.json` (engine: `traps.py`;
format and authoring: `docs/trap-packs.md`).

## Limits

Global 200 connections, 10 per IP, 64 concurrent TLS connections (checked, together with a 5/s
per-IP connection rate, the memory guard and the connection budget, before any TLS work); request
line and header lines 8190 bytes, 100 headers, 128 KB head; body read cap 1 MiB then 413 (only a
64 KB prefix, 256 KB for `xmlrpc.php`, is kept in memory, the SHA-256 covers everything read);
headers within 20 s (up to 40 s at 500 B/s), body 10 s + 1 s per 500 B (120 s max), keep-alive
5 s / 100 requests, 600 s per connection, 30 s write timeout, 10 s TLS handshake; 20 events/s per
session (burst 100) with a separate guaranteed bucket for credentials, downloads and exploit
requests, 200 events/s per sensor. Important events also have a per-IP bucket (20/s, burst 200);
one global bucket keeps a reserved share for them, and refused connections are reported as one
aggregated `scan` (`kind=rate_limited`) per IP per minute. The event queue holds at most 5000
events and 4 MB (JSON size). An event-loop watchdog thread exits the process if the loop stalls
for 10 s.

### Memory

Three layers keep the 256 MB container alive under connection floods:

1. **Small buffers per connection.** Kernel socket buffers are charged to the container, so
   `SO_RCVBUF`/`SO_SNDBUF` are set to 32 KiB on the listening socket (about 64 KB effective,
   no autotuning to several MB). The `StreamReader` pauses the socket at 32 KiB. asyncio's
   `SSLProtocol` allocates a 256 KiB receive buffer for every TLS connection
   (`SSLProtocol.max_size`); it is lowered to 16 KiB (the TLS record size) before the listeners
   start, and the decrypted-side read high-water mark goes from 256 to 32 KiB. TLS responses are
   written in 16 KiB chunks with 32 KiB high-water marks on both TLS layers, because
   `SSLProtocol` hands each encrypted write to the socket transport whatever that buffer holds.
   Once a response is serialised, the request head and the response object are released; only
   the bytes on the wire stay.
2. **A byte budget** (`WEB_MEMORY_BUDGET_MB`, 96 MB): each connection is charged its measured
   cost at admission (192 KiB, plus 224 KiB for TLS) and each response its size until it has
   drained. Measured with `tests/load/measure.sh` (100 clients sending three pipelined 118 KB
   requests and never reading): 327 KiB per plain connection and 544 KiB per TLS connection,
   including the 146 KB pending `phpinfo()` response (before these changes: 896 KiB and
   1302 KiB). When the budget is exhausted, new connections are refused slowly (a short read,
   0.1–0.6 s of jitter) and plain HTTP requests get Apache's 503 page; responses that do not fit
   become 503s, and handlers that build big bodies (`system.multicall`) check the size first.
3. **A memory guard** (`memguard.py`): once per second it reads the cgroup's `memory.current`
   minus `inactive_file` (what `docker stats` shows; RSS against `WEB_MEMORY_LIMIT_MB` without
   cgroup v2). At 70 % of the limit new connections are refused like above; at 85 % the
   connections holding the most buffered bytes are aborted (at most half of them per tick,
   `reason` = `memory-pressure` in their `disconnect`). The local healthcheck (127.0.0.1/::1)
   is never refused, by the guard or by any other limit, so the container does not flap
   unhealthy under load.

Responses are written in 64 KB chunks (16 KB over TLS) that must each drain at the same minimum
rate (64 KB per 10 s), with a 64 KB transport high-water mark; at close, the tail of a response
gets the same time to drain before the connection is aborted. Request data reflected by
`phpinfo()` is capped (256 chars per value, 64 KB total). Accepted sockets get
`TCP_USER_TIMEOUT` 30 s.

## Environment variables

| variable | default | meaning |
| --- | --- | --- |
| `REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD`, `EVENTS_STREAM`, `EVENTS_MAXLEN` | see `suckerpot_common` | publisher (`EVENTS_STREAM=events:web`) |
| `WEB_HTTP_PORT` / `WEB_HTTPS_PORT` | `8080` / `8443` | container ports |
| `WEB_HTTP_PUBLIC_PORT` / `WEB_HTTPS_PUBLIC_PORT` | `80` / `443` | reported as `dst_port` |
| `WEB_HOSTNAME` | `srv-web01` | certificate CN/SAN, phpinfo |
| `WEB_DATA_DIR` | `/data` | profile secret and certificate (volume) |
| `WEB_SERVER_TOKEN` | `Apache/2.4.58 (Ubuntu)` | `Server` header |
| `WEB_PHP_VERSION` | `8.3.6` | must be 8.3.N, N < 36 |
| `WEB_EXPOSE_PHP` | `true` | `X-Powered-By` |
| `WEB_WP_VERSION` / `WEB_PMA_VERSION` | `6.8.1` / `5.2.1` | |
| `WEB_UPLOAD_PROGRESS_NAME` | `PHP_SESSION_UPLOAD_PROGRESS` | field to detect |
| `WEB_MAX_CONNECTIONS` / `WEB_MAX_PER_IP` | `200` / `10` | caps |
| `WEB_MAX_TLS_CONNECTIONS` | `64` | concurrent TLS connections |
| `WEB_CONN_RATE` / `WEB_CONN_BURST` | `5` / `20` | new connections per IP |
| `WEB_MEMORY_BUDGET_MB` | `96` | connection and response byte budget |
| `WEB_MEMORY_LIMIT_MB` | `256` | memory guard limit when the cgroup has none (keep it equal to `mem_limit`) |
| `WEB_EVENTS_PER_SEC` / `WEB_GLOBAL_EVENTS_PER_SEC` | `20` / `200` | |

## Development

```
uv sync
uv run ruff check && uv run ruff format --check && uv run mypy . && uv run pytest
```

`tests/ref_compare*.py` and `tests/flood.py` are manual tools (they need a reference Apache or a
running sensor). `tests/blackbox.sh` runs curl, nmap, nikto and nuclei against a built image.
`tests/load/` holds the memory regression tools: `churn.py` (a client that reconnects, sends
pipelined requests and never reads), `run_load.sh <image> <plain clients> <tls clients>
<pipeline> <seconds>` (the hardened 256 MB container against one client container per source
IP, memory sampled every 10 s), `measure.sh` (measured cost of one stuck connection) and
`run_mcflood.sh` (gzip multicall flood with `mcflood.py`, CPU and `probe.py` latency of `GET /`).
