# MySQL sensor

```{admonition} Status
:class: note

Built in M9. Wired into `docker-compose.yml` as `sensor-mysql`, with the stream `events:mysql`, the network `sensors-mysql` and the Redis user `sensor-mysql`. The sensor's own notes are in `sensors/mysql/README.md`.
```

## What it emulates

A MySQL 8.0 server (8.0.43 on Ubuntu 24.04 by default). The protocol is written by hand, with strict bounds on every length. The handshake looks like a stock server: a fresh salt per connection, the usual capability flags, TLS offered and `caching_sha2_password` as the default plugin.

It listens on container port 3306. Compose maps the host port `MYSQL_HOST_PORT` (default 3306) to it.

- **Logins** succeed for the `user:password` pairs in `SENSOR_MYSQL_ACCOUNTS`. The default list is `root` with an empty password, `root:root`, `admin:admin` and `mysql:mysql`. Scrambles are checked against those passwords only. The sensor never tries to recover an unknown password.
- **Queries** are answered from constants and a few synthetic rows. There is no SQL engine, no storage and no execution.
- **Other protocols** sent to the port (HTTP, TLS, SSH, SMB) get the reply a real server gives. For example, a wrong sequence number gets error 1156 and a close.
- **Connection limits** get the real errors: 1129 for a source over its connection cap, and 1040 for the global cap.

## What it records

All events use the shared [Event schema](../event-schema.md).

| Event `type` | Content |
| --- | --- |
| `connect` | `server_version`. |
| `login_attempt` | `username`, `password` (clear text when known), `success`, `method` (the auth plugin), `password_source`, `client_plugin`, `database`, `tls`, `client_attrs`. |
| `command` | `input` (the SQL text, capped), `protocol_command`, `database`, `statements`, `length`, `flags`, `output_preview`. |
| `download_attempt` | A URL found in the SQL text. Recorded, never fetched. |
| `scan` | `non_mysql`, `malformed_mysql`, rate-limited connections, and `suppressed_logins`: one summary per source and minute, with the top username and password pairs. |
| `disconnect` | `duration_s`, `reason`, `stage`, `bytes_in`, `bytes_out`, `commands`, `auth_attempts`, `logged_in`, `tls_version`. |

## Flags and tags

Rules live in `ingest/rules/services.yaml`.

| Tag | Set when the sensor flags |
| --- | --- |
| `sql-rce` | `udf` (for example `CREATE FUNCTION ... SONAME` or `sys_exec`). |
| `db-ransom` | `ransom_note` (a write that mentions bitcoin, wallet or a recovery message) or `drop_database`. |
| `malware-drop` | Any `download_attempt`. |
| `service-probe` | A read-only query for the version, host or user, or the list of databases and tables (`SELECT @@version`, `SHOW DATABASES`, `information_schema`: the flags `schema_recon` and `show_databases`). A statement that also writes a file, loads a library, changes privileges or delays is not a fingerprint. |

Other flags are shown on the session: `into_outfile`, `load_file`, `load_data_infile`, `log_file_write`, `sql_delay` (`sleep()` and `benchmark()`), `user_dump` and `privilege_change`. `schema_recon` and `show_databases` tag `service-probe`, as above.

## Limits

| Scope | Limit (environment variable, default) |
| --- | --- |
| Connections | `SENSOR_MAX_CONNECTIONS` 200 in total, `SENSOR_MAX_PER_IP` 8 per source. |
| New connections | `SENSOR_CONNECTIONS_PER_SEC_PER_IP` 25 per source (burst 50). Over the limit, the refusal is delayed by 1 second. |
| Timeouts | `SENSOR_HANDSHAKE_TIMEOUT` 10 s, `SENSOR_IDLE_TIMEOUT` 120 s, `SENSOR_MAX_SESSION` 600 s. |
| Authentication | `SENSOR_MAX_AUTH_ATTEMPTS` 3 per connection. |
| Commands | `SENSOR_MAX_COMMANDS` 1000 per connection. `SENSOR_QUERY_STEPS` caps the work of one query. |
| Input and output | 24 MiB of input and 2 MiB of output per connection. |
| TLS | 5 handshakes per second per source, 16 at a time, 30 RSA decryptions per second over all sources (`SENSOR_RSA_PER_SEC`). |
| Events | 200 per second for the sensor. Important events are capped at 10 per second per source (burst 50). |

## Container

Same hardening as the other sensors: non-root (UID 10001), read-only root file system, `tmpfs` at `/tmp`, all capabilities dropped, `no-new-privileges`, 256 MB of memory with no swap, 0.5 CPU and 128 processes. Health check: `python -m mysql_sensor.healthcheck`. The profile secret, RSA keys and TLS certificate are generated once and kept in the `mysql-sensor-data` volume.
