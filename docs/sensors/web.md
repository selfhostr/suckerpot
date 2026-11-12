# Web sensor

```{admonition} Status
:class: note

Built (M6) and wired into `docker-compose.yml` as `sensor-web`. It is still under security review. See `sensors/web/README.md` for the sensor's own notes. This page may change before the milestone is done.
```

## What it emulates

An HTTP and HTTPS server that looks like an unpatched LAMP stack:

- **Apache 2.4.58 (Ubuntu)** with **PHP 8.3.6** as `mod_php`. The PHP version is below 8.3.36, so the server looks vulnerable to PHP2Shell (CVE-2026-109618 and CVE-2026-109619, unauthenticated code execution through the upload-progress feature, fixed in PHP 8.3.36).
- A **WordPress** site: `wp-login.php`, `xmlrpc.php`, the REST API and common theme and plugin paths.
- **phpMyAdmin**.
- Static files, directory listings, Apache-style error pages, and a `phpinfo()` page.
- HTTP on container port 8080 and HTTPS on 8443. Compose will map host ports 80 and 443. The HTTPS certificate is self-signed, generated once, and made to look like the Debian and Ubuntu `ssl-cert` "snakeoil" certificate.

Nothing in a request is executed or fetched. Request analysis is passive pattern matching with byte searches, with no regular expressions, over a bounded slice of the request. URLs found in payloads are only reported.

## What it records

| Event `type` | When | Main `data` keys |
| --- | --- | --- |
| `connect` | A connection opens | `tls`, `sni`, `tls_version`, `cipher`, `handshake` |
| `http_request` | Each request | `method`, `path`, `query`, `http_version`, `host`, `headers`, `user_agent`, `status`, `body_preview`, `body_sha256`, `body_length`, `body_truncated`, `tls`, `sni`, `app`, `route`, `flags`, `cve`, and `php2shell` details (the upload-progress findings, also for a probe that is not flagged `php2shell`) |
| `login_attempt` | A WordPress login, an XML-RPC call with credentials, or HTTP Basic credentials | `username`, `password`, `success`, `method`, `path`, `user_agent` |
| `download_attempt` | A URL found in a payload that looks like a fetch | `url`, `path`, `user_agent` |
| `scan` | Non-TLS bytes on the TLS port, or a failed TLS handshake | `kind` = `non_tls_on_tls_port` or `tls_handshake_failed`, `payload_preview`, `error` |
| `disconnect` | A connection closes | `duration_s`, `reason`, `requests`, `login_attempts`, `downloads` |

### Detection flags

Each request is analysed and gets flags. Examples: `php2shell`, `upload_progress`, `rce`, `php_code`, `rfi`, `lfi`, `log4shell`, `shellshock`, `phpunit_rce`, `laravel_rce`, `router_exploit`, `webshell_probe`, `session_include`, `scanner_ua`, `no_user_agent`, `recon_dotfile`, `config_leak` and `backup_probe`.

- Requests that touch the PHP upload-progress feature are flagged `upload_progress` and tagged `php-upload-progress-probe`. Only the exploit shape is flagged `php2shell` (and tagged `php2shell`, with the CVE ids): the upload-progress field carrying PHP code, or the include of a session file that the sensor saw created through that field. The tagging rules in `ingest/rules/web.yaml` turn the flags into session tags.
- `env-file-probe` is set for the secret and leftover paths the rule lists (`.env`, `.git/config`, cloud credentials) and for any request the sensor flags `recon_dotfile`, `config_leak` or `backup_probe`: a dot-directory, a config file such as `/admin/config.php`, or a backup or dump name.
- `service-probe` is set for a `GET`, `HEAD` or `OPTIONS` that the sensor flags as a probe for a specific application or device (`wordpress`, `phpmyadmin`, `phpinfo_probe`, `spring_probe`, `jenkins_probe`, `vpn_probe`, `router_probe`, `recon` and the other `*_probe` flags), unless the same request also carries an exploit flag. A plain homepage, `robots.txt` or favicon request is not tagged.
- `scanner` is also set when the sensor flags `scanner_ua` (nikto, sqlmap, gobuster and the other scanner names it knows).
- The **severe** flags (the exploit ones) get a guaranteed share of the event quota, so a flood of noise cannot hide an exploit attempt.

## Limits and abuse resistance

| Scope | Limit |
| --- | --- |
| Connections | `WEB_MAX_CONNECTIONS` (200) in total, `WEB_MAX_PER_IP` (10) per source. A per-source connection rate limit is checked before any TLS work. |
| Request | Request line and each header line 8190 bytes, 100 headers, 128 KiB of headers, 1 MiB of body (only 64 KiB is kept for analysis) |
| Timeouts | First byte 60 s, headers 20 s (40 s at most), body 10 s with a minimum data rate, whole body 120 s, keep-alive 5 s and 100 requests, connection age 600 s, TLS handshake 10 s |
| Memory | A budget over all requests (`WEB_MEMORY_BUDGET_MB`, 48) |
| Events | Per-source rate (`WEB_EVENTS_PER_SEC`, 20) and sensor-wide rate (`WEB_GLOBAL_EVENTS_PER_SEC`, 200), a bounded queue of 5000 events, and at most 200 XML-RPC calls per request |

Output towards a slow or stuck client is bounded too:

- Each accepted socket gets a small send buffer (`SO_SNDBUF` of 64 KiB) and a `TCP_USER_TIMEOUT` of 30 s, so data that the peer never acknowledges cannot sit in the kernel for minutes.
- When a client does not read the response, the sensor aborts the connection instead of holding the buffers open, and it does the same when a write is stuck past the write timeout.

A watchdog thread exits the process if the event loop stalls, so Compose restarts the container.

## Configuration

See [Configuration](../configuration.md#web-sensor) for the table. The identity values are validated at start-up, and the sensor refuses a PHP version outside the vulnerable range (8.3.0 to 8.3.35) and a server token that does not look like Apache 2.4.

## Fingerprint notes

- `X-Powered-By: PHP/8.3.6` is sent by default (`WEB_EXPOSE_PHP`). Stock Ubuntu does not send it. It is on to make the vulnerable version easy to find.
- The Apache, PHP, WordPress and phpMyAdmin versions are consistent with each other and with Ubuntu 24.04.
- The host name is `srv-web01`. The word "honeypot" appears nowhere.
