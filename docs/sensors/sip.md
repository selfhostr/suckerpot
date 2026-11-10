# SIP sensor

```{admonition} Status
:class: note

Built in M9. Wired into `docker-compose.yml` as `sensor-sip`, on UDP and TCP port 5060, with the stream `events:sip`, the network `sensors-sip` and the Redis user `sensor-sip`. The sensor's own notes are in `sensors/sip/README.md`.
```

## What it emulates

A small PBX endpoint that only observes. It answers on UDP 5060 and, by default, on TCP 5060, like an Asterisk server. It answers `OPTIONS` with `200 OK`, challenges `REGISTER` with a Digest nonce (`401`), and challenges `INVITE` (`407`). It records the scanners and the toll-fraud attempts that send `INVITE`.

It listens on container port 5060. Compose maps the host port `SIP_HOST_PORT` (default 5060) to both UDP and TCP.

- **No calls.** An `INVITE` never gets `200 OK`. With a weak credential it gets `486 Busy Here`. There is no dialog, no SDP answer and no RTP.
- **Weak accounts.** A correct digest for one of the `user:password` pairs in `SENSOR_SIP_WEAK_CREDENTIALS` (default `100:100`, `1000:1000` and `admin:admin`) gets a stateless `200 OK` on `REGISTER`. Nothing is registered or remembered, so the brute forcer moves on to the `INVITE`. Nothing is ever cracked: the sensor only compares digests for the passwords it already knows.
- **Replies are small and bounded.** Every reply is never larger than the request that caused it, and the rate of replies is capped. See [anti-reflection](../SECURITY.md#sip-anti-reflection).

## What it records

All events use the shared [Event schema](../event-schema.md). A *session* is one source address. UDP and TCP traffic from the same address share one session.

| Event `type` | Content |
| --- | --- |
| `connect` | `transport`, `protocol`, `source_verified`. |
| `login_attempt` | `REGISTER` or `INVITE` with credentials: `username`, `password` (only a weak password that matched, otherwise `null`), `success`, `realm`, `uri`, `algorithm`, `response_preview` (8 characters), `user_agent`, `response_code`. |
| `command` | `INVITE` only: `input` (the request line), `to`, `from`, `dialled`, `user_agent`, `body_preview`. |
| `scan` | `options_scan`, `sip_probe` (the first low-value message of a session), `sip_malformed`, and `sip_summary` at the end of a session (message count, methods, user agents and the users probed). |
| `disconnect` | `duration_s`, `reason` (`idle`, `max_session`, `shutdown` or `memory_pressure`), `messages`, `replies`, `silent`, `methods`, `transports`. |

`source_verified` is `true` when the source address is proven not to be spoofed: it returned a valid nonce that is bound to its address, or it connected over TCP. Verified sources get their own admission lane, so a spoofed flood cannot lock out real attackers.

## Flags and tags

Rules live in `ingest/rules/services.yaml`.

| Tag | Set when the sensor flags |
| --- | --- |
| `sip-fraud` | `invite` and `toll_fraud` together: an INVITE to a number that starts with `+`, `00` or `011` and is long enough for a real number. |
| `recon` | `register` or `invite` without `toll_fraud`: registration floods and call probes. |
| `scanner` | `options_scan` or `scanner_ua` (the User-Agent of a known SIP scanner, such as SIPVicious, `sipcli` or `iWar`). |

`injection_attempt` (a JNDI string, PHP code or shell metacharacters in a URI or header) and `unknown_method` are shown on the session.

## Limits

| Scope | Limit (environment variable, default) |
| --- | --- |
| Datagrams | Datagrams over 4096 bytes are dropped unread. Packets are capped at `SENSOR_SIP_PPS_PER_IP` 50 per second per source and `SENSOR_SIP_PPS_GLOBAL` 3000 per second. |
| Replies | `SENSOR_SIP_REPLY_PER_IP_RATE` 2 per second per source (burst 5). `SENSOR_SIP_REPLY_GLOBAL_RATE` 100 per second (burst 200). `SENSOR_SIP_REPLY_BYTES_RATE` 32 KiB per second (burst 64 KiB). |
| Sessions | 50 new sessions per second over all sources. Each source gets a burst of 5 plus 0.1 per second. Up to 5000 sessions are open at once. |
| TCP | Connection caps: Compose sets `SENSOR_MAX_CONNECTIONS` to 200 and `SENSOR_MAX_PER_IP` to 8. Timeouts: first data 15 s, idle 30 s, whole session 120 s. |
| Memory | A guard reads the container's memory use each second. Above 70 % of the limit, new datagrams and connections are dropped. Above 85 %, TCP connections are aborted. |
| Events | 200 ordinary, 300 priority and 60 disconnect events per second for the sensor. A session gets 200 high-value events, then only counts. Strings are cut to 2048 characters. |

A watchdog thread exits the process if the event loop stalls for 10 seconds.

## Networking: the sensor needs real source addresses

The sensor answers each UDP datagram to its sender, and its per-source limits depend on the real address. The host must forward UDP 5060 without the Docker userland proxy. See [Deployment](../deployment.md#forward-the-ports).

## Container

Same hardening as the other sensors: non-root (UID 10001), read-only root file system, `tmpfs` at `/tmp`, all capabilities dropped, `no-new-privileges`, 256 MB of memory with no swap, 0.5 CPU and 128 processes. Health check: `python -m sip_sensor.healthcheck`. The profile secret, which seeds the server version and the nonces, is kept in the `sip-sensor-data` volume. Keep that volume, so the nonces and the version stay stable across restarts.
