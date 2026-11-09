# SMB sensor

```{admonition} Status
:class: note

Built in M9. Wired into `docker-compose.yml` as `sensor-smb`, with the stream `events:smb`, the network `sensors-smb` and the Redis user `sensor-smb`. The sensor's own notes are in `sensors/smb/README.md`.
```

## What it emulates

A Windows Server 2019 or 2022 file service on TCP 445. The sensor is an **observation sink only**. It parses the NetBIOS framing and the SMB headers, answers the first messages the way a modern Windows server does, records what the client sends, and closes the connection. It never grants a session and never checks a password.

It listens on container port 4450. Compose maps the host port `SMB_HOST_PORT` (default 445) to it, so the container runs without any privilege.

- **SMB2 and SMB3.** `NEGOTIATE` answers with the highest dialect the client offers, up to 3.1.1. Signing is enabled but not required, as on a default Windows server.
- **Session setup.** The sensor sends a realistic NTLM challenge with NetBIOS and DNS names derived from its profile. It records the user name, domain, workstation and a short preview of the response, then always answers `STATUS_LOGON_FAILURE`.
- **Legacy SMB1.** A client that offers SMB 2.??? gets the SMB2 switch response. A client that offers only SMB1 dialects gets the connection reset, as on Windows with SMB1 disabled. The rule is `SMB_SMB1_MODE`: `steer` (the default) or `reset`. Any SMB1 command after that is recorded as a `scan` and the connection is closed. The sensor never implements SMB1 command handling.
- **Anything else** that is not valid SMB framing is recorded with a hex preview and a protocol guess.

## What it records

All events use the shared [Event schema](../event-schema.md).

| Event `type` | Content |
| --- | --- |
| `connect` | `transport`. |
| `login_attempt` | NTLM AUTHENTICATE: `username`, `domain`, `workstation`, `ntlm_version`, short response previews, `anonymous`. `password` is always `null` and `success` is always `false`. |
| `scan` | `kind` such as `smb1_negotiate`, `smb1_command`, `non_smb`, `netbios_control`, `oversized_pdu` or `malformed_smb2`. SMB1 traffic also records `smb1_command_name`. |
| `disconnect` | `duration_s`, `reason`, `dialect`, `offered_dialects`, `flags`, `events_suppressed`, `events_dropped`. |

## Flags and tags

Rules live in `ingest/rules/services.yaml`.

| Tag | Set when |
| --- | --- |
| `smb-v1-probe` | A client that speaks only SMB1 (the sensor resets it), or an SMB1 command after the negotiate (`Trans`, `Trans2`, `NT Transact`, `Session Setup`...). It does not say which exploit was meant. |
| `eternalblue` | Only when the sensor sets the `eternalblue` or `ms17_010` flag. The sensor keeps SMB1 messages opaque and cannot see the malformed transaction of MS17-010, so it does not set them today. |

A multi-protocol negotiate from a modern client (steered to SMB2) is not tagged. The flags `ntlm`, `smbv1`, `null_session` and `compound_request` are shown on the session.

## Limits

| Scope | Limit (environment variable, default) |
| --- | --- |
| Connections | `SMB_MAX_CONNECTIONS` 200 in total, `SMB_MAX_PER_IP` 10 per source. Idle connections are evicted under pressure. |
| Timeouts | First data 10 s, idle 20 s, one PDU 10 s, whole connection 60 s (`SMB_MAX_SESSION`). |
| Messages | `SMB_MAX_PDU_BYTES` 128 KiB per message, `SMB_MAX_PDUS` 64 per connection. |
| Input and memory | `SMB_MAX_SESSION_INPUT` 256 KiB per connection. `SMB_MAX_BUFFERED` 32 MiB for all buffers and pending output together. Pending output per connection is capped (`SMB_MAX_PENDING_OUTPUT`). |
| CPU | Expensive answers (the 3.1.1 negotiate and the NTLM challenge) spend a per-source CPU token (`SMB_CPU_PER_SEC_PER_IP` 80, burst 320). A source over budget is cut. |
| New sessions | `SMB_SESSIONS_PER_SEC_PER_IP` 2 per source (burst 30), `SMB_GLOBAL_SESSIONS_PER_SEC` 50 in total. |
| Events | `SMB_PER_IP_EVENTS_PER_SEC` 20 per source, `SMB_GLOBAL_EVENTS_PER_SEC` 200. Priority events (`connect`, `login_attempt`, `disconnect`) have their own per-source and global buckets, so a flood cannot hide a logon attempt. `SMB_SESSION_EVENT_QUOTA` 24 events per connection. |

Sockets have small kernel buffers and a 30 s `TCP_USER_TIMEOUT`. A connection whose client does not read is aborted, not kept.

## Container

Same hardening as the other sensors: non-root (UID 10001), read-only root file system, `tmpfs` at `/tmp`, all capabilities dropped, `no-new-privileges`, 256 MB of memory with no swap, 0.5 CPU and 128 processes. Health check: `python -m smb_sensor.healthcheck`. The profile secret is kept in the `smb-sensor-data` volume.
