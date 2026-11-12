# Redis sensor

```{admonition} Status
:class: note

Built in M9. Wired into `docker-compose.yml` as `sensor-redis`, with the stream `events:redis`, the network `sensors-redis` and the Redis user `sensor-redis`. The sensor's own notes are in `sensors/redis/README.md`.
```

## What it emulates

An exposed Redis 7.2 server with no password, held entirely in memory. It speaks RESP2 and RESP3 and answers the commands that bots and scanners send with the replies a real server gives. Unknown commands get Redis' own error text. Each connection starts with its own small fake keyspace of 3 to 5 keys.

It listens on container port 6379. Compose maps the host port `REDIS_HOST_PORT` (default 6379) to it. No capability is needed.

- **Configuration, persistence and replication are only recorded.** `CONFIG SET dir` and `dbfilename` followed by `SAVE` writes nothing. `SLAVEOF` records the target and never connects. `MODULE LOAD` and `EVAL` are recorded, never loaded or run.
- **Nothing is fetched.** A URL found in a stored or sent value becomes a `download_attempt` event.
- **HTTP aimed at Redis** (a line starting with `POST` or `Host:`) gets the connection closed without a reply, as a real Redis does, and is recorded as a `scan`.
- **`AUTH` produces a `login_attempt`** and no `command` event. Passwords are recorded in clear text.

## What it records

All events use the shared [Event schema](../event-schema.md).

| Event `type` | Content |
| --- | --- |
| `connect` | The connection is open. |
| `login_attempt` | `username`, `password`, `success`, `method` (`redis-auth` or `redis-hello`). |
| `command` | `input` (the command line, 2048 characters at most), `command`, `argc`, `flags`, `output_preview`, `db`, and `repeated_before` when identical commands were folded. |
| `download_attempt` | `url`, `tool`, `command`, `via` (the Redis command that carried the URL). |
| `scan` | Replication handshake, cross-protocol HTTP, protocol errors, and rate-limited connections. |
| `disconnect` | `duration_s`, `reason`, `bytes_in`, `bytes_out`, `commands`, all indicator `flags`, `config_changes` and `config_history`. |

## Flags and tags

Rules live in `ingest/rules/services.yaml`. They key on the `flags` set by the sensor.

| Tag | Set when a `command` or `disconnect` carries |
| --- | --- |
| `persistence` | `cron_write`, `ssh_key_write`, `cron_payload`, `ssh_key_payload` |
| `redis-rogue-master` | `slaveof`, `module_load` |
| `crypto-miner` | `miner`, `kinsing` |
| `db-ransom` | `ransom_note` |
| `malware-drop` | Any `download_attempt` (Redis never fetches files legitimately). |
| `service-probe` | A read-only command that identifies the server or looks at what it holds: `INFO`, `PING`, `ECHO`, `QUIT`, `GET`, `GETRANGE`, `STRLEN`, `TYPE`, `TTL`, `EXISTS`, `DBSIZE`, `KEYS`, `SCAN`, `COMMAND`, `CLIENT`, `ROLE`, `TIME`, `MEMORY`, `LATENCY`, `SLOWLOG` or `CONFIG GET`. Writes, `CONFIG SET`, replication, modules and unknown commands are never `service-probe`. |

Other flags, such as `config_set`, `flushall`, `eval` and `lua_sandbox_escape`, are kept on the event for the session view. They do not tag by themselves.

## Limits

| Scope | Setting (environment variable, default) |
| --- | --- |
| Connections | `SENSOR_MAX_CONNECTIONS` 200 in total, `SENSOR_MAX_PER_IP` 8 per source. |
| New connections | `SENSOR_SESSIONS_PER_SEC_PER_IP` 2 per source, `SENSOR_GLOBAL_SESSIONS_PER_SEC` 50 in total. |
| Timeouts | First data 15 s, idle 45 s, whole connection 240 s, write 10 s. |
| Per connection | `SENSOR_MAX_COMMANDS` 3000 commands, `SENSOR_MAX_BYTES_IN` 4 MiB of input. Arguments are kept to a prefix, so a large payload does not grow memory. |
| Parser memory | `SENSOR_MAX_BUFFERED` 32 MiB over all connections. |
| CPU | Glob work per connection, per source and for the sensor (`SENSOR_CPU_STEPS_*`), so one `KEYS` pattern cannot hold the event loop. |
| Events | 200 per second for the sensor, 300 priority, 60 disconnect events. Each source has its own bucket in front. |

A watchdog thread exits the process if the event loop stalls for 10 seconds, so Compose restarts the container.

## Container

Non-root (UID 10001), read-only root file system, a 16 MB `tmpfs` at `/tmp`, all capabilities dropped, `no-new-privileges`, 256 MB of memory with no swap, 0.5 CPU and 128 processes. Health check: `python -m redis_sensor.healthcheck`. The only file the sensor writes is its profile secret in the `redis-sensor-data` volume.
