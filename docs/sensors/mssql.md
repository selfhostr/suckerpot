# MSSQL sensor

```{admonition} Status
:class: note

Built in M9. Wired into `docker-compose.yml` as `sensor-mssql`, with the stream `events:mssql`, the network `sensors-mssql` and the Redis user `sensor-mssql`. The sensor's own notes are in `sensors/mssql/README.md`.
```

## What it emulates

A Microsoft SQL Server 2019 or 2022 look-alike. The TDS protocol is written by hand: PRELOGIN, LOGIN7, SQL batches and RPC calls. That is enough for `nmap -sV`, `sqlcmd`, impacket's `mssqlclient` and `pymssql`.

It listens on container port 1433. Compose maps the host port `MSSQL_HOST_PORT` (default 1433) to it.

- **Logins.** The account `sa` accepts a short list of classic weak passwords (`SENSOR_MSSQL_ACCEPT_PASSWORDS`). Any other login gets `Msg 18456, Login failed for user`, and the connection closes.
- **After login**, the sensor answers `@@VERSION`, `SERVERPROPERTY`, `DB_NAME()`, `sys.databases`, catalog views, a few fake tables and `sp_who`.
- **Command execution is refused the way a real server refuses it.** `xp_cmdshell` and `sp_OACreate` return error 15281 ("turned off") until the attacker runs `sp_configure` and `RECONFIGURE`. The whole chain is recorded. After that, `xp_cmdshell` answers a canned line for `whoami`, `hostname` and `ver`, and nothing else.
- **Windows authentication.** An NTLM negotiation gets a challenge with plausible machine and domain names. The AUTHENTICATE message is recorded and refused.
- **TLS** uses a self-signed fallback certificate, created once, and TLS 1.2. The answer to each client's encryption setting is the one a real server gives.
- **Non-TDS traffic** gets one `scan` event with a protocol guess and a hex preview.

## What it records

All events use the shared [Event schema](../event-schema.md).

| Event `type` | Content |
| --- | --- |
| `connect` | The connection is open. |
| `login_attempt` | `username`, `password`, `success`, `method` (`tds-sql` or `tds-sspi`), `hostname`, `app_name`, `client_library`, `database`, `tds_version`. |
| `command` | `input` (4096 characters at most), `kind` (`sql_batch` or `rpc`), `rpc`, `flags`, `output_preview`, `database`, `login`. |
| `download_attempt` | A URL found in a command, recorded only. |
| `scan` | `non_tds`, `tds_malformed`, `rate_limited`, `events_limited`. |
| `disconnect` | `duration_s`, `reason`, `bytes_in`, `bytes_out`, `messages`, `logins`, `authenticated`, `client_encryption`, `config_changes`. |

## Flags and tags

Rules live in `ingest/rules/services.yaml`.

| Tag | Set when the sensor flags |
| --- | --- |
| `sql-rce` | `xp_cmdshell`, `sp_oacreate`, `ole_automation`, `shell_command` or `lolbin`. |
| `db-ransom` | `ransom_note` or `drop_database`. |
| `malware-drop` | Any `download_attempt`. |
| `service-probe` | A read-only query for the version, server name or database list (`SELECT @@version`, `@@servername`, `sys.databases`), unless the same batch carries a dangerous flag. |

Other flags are shown on the session: `sp_configure`, `reconfigure`, `openrowset`, `bulk_insert`, `xp_dirtree` (a UNC path), `xp_regread`, `add_login`, `sqli_probe` and `time_probe`.

## Limits

| Scope | Limit (environment variable, default) |
| --- | --- |
| Connections | `SENSOR_MAX_CONNECTIONS` 200 in total, `SENSOR_MAX_PER_IP` 8 per source. |
| New connections | 3 per second per source (burst 40), 200 per second for the sensor. Checked before any work. |
| Timeouts | First data 15 s, idle 45 s, whole connection 240 s, write 10 s. |
| Messages | `SENSOR_MAX_COMMANDS` 1000 per connection. Messages are capped at 128 KiB and a batch at 16 statements. |
| Input and memory | `SENSOR_MAX_BYTES_IN` 2 MiB per connection. `SENSOR_MAX_BUFFERED` 24 MiB for all buffers and pending output together. |
| CPU | Work is sliced into 10 ms per loop turn. Each message costs its measured CPU time to a per-source bucket, so a heavy client only slows itself. |
| TLS | At most `SENSOR_MAX_TLS` (48) encrypted sessions at a time. Beyond that, clients get `NOT_SUP`. |
| Events | Per-source buckets (count and bytes) before a shared priority queue. Repeated statements are aggregated. |

A watchdog thread exits the process if the event loop stalls for 10 seconds.

## Container

Same hardening as the other sensors: non-root (UID 10001), read-only root file system, `tmpfs` at `/tmp`, all capabilities dropped, `no-new-privileges`, 256 MB of memory with no swap, 0.5 CPU and 128 processes. Health check: `python -m mssql_sensor.healthcheck`. The profile secret and the TLS certificate are kept in the `mssql-sensor-data` volume.
