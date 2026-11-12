# ADB sensor

```{admonition} Status
:class: note

Built in M9. Wired into `docker-compose.yml` as `sensor-adb`, with the stream `events:adb`, the network `sensors-adb` and the Redis user `sensor-adb`. The sensor's own notes are in `sensors/adb/README.md`.
```

## What it emulates

An Android TV set-top box with `adbd` listening on TCP 5555 and no authentication, as on the many boxes with `ro.adb.secure=0` that botnets scan for. The sensor never asks for `AUTH`.

It listens on container port 5555. Compose maps the host port `ADB_HOST_PORT` (default 5555) to it.

- **Banner.** The device model is chosen from a random per-deployment secret. It is one of a few cheap TV boxes on Android 7.1.2 or 9, with plausible properties, serial number and MAC address.
- **Shell.** `shell:` (interactive or one-shot) and `exec:` run in an emulated Android `sh`. It has a toybox command set, `getprop`, `pm`, `am`, `dumpsys`, `/sdcard` and a writable `/data/local/tmp`. Nothing is executed.
- **Files.** `sync:` (`STAT`, `LIST`, `RECV`, `SEND`) works on the fake file system. A pushed file is hashed and dropped. Only its first 8 KiB are kept in memory for the session, so `ls -l` looks right.
- **Installs.** `exec:cmd package install` is accepted. The APK is hashed and thrown away, and the reply is `Success`.
- **Mirai-style loaders** print plausible BusyBox output when the box has BusyBox. The URL is recorded and a stub file is left. A dropped "binary" does nothing when it is run.
- **Other services** (`tcp:`, `localabstract:`, `forward`, `jdwp:`) are refused as adbd refuses them, and recorded.

## What it records

All events use the shared [Event schema](../event-schema.md).

| Event `type` | Content |
| --- | --- |
| `connect` | `banner` (the sensor's identity), `client_version`, `client_banner`. |
| `command` | `input`, `output_preview`, `cwd`, `user`, `service` (`shell` or `exec`), `interactive`, `flags`. Pushes add `path`, `sha256`, `size`, `mode`. Installs add `sha256` and `size`. |
| `download_attempt` | `url`, `tool` (`wget`, `curl`, `tftp`, `ftpget` or `command-line`), `command`. |
| `scan` | Raw payloads, refused services (`adb_service`), `adb_auth`, `connection_summary`. |
| `disconnect` | `duration_s`, `reason`, `commands`, `downloads`, `pushes`, `installs`, `streams_opened`, `replay`. |

There is no login on ADB, so there are no `login_attempt` events.

The session replay of an interactive shell is kept in the `disconnect` event, as on the SSH sensor. See [SSH sensor](ssh.md#terminal-recording).

## Flags and tags

Rules live in `ingest/rules/services.yaml`.

| Tag | Set when the sensor flags |
| --- | --- |
| `malware-drop` | `adb_push` or `adb_install`, or any `download_attempt`. |
| `mirai` | A Mirai-family indicator in a shell command or a recorded download: the BusyBox echo-check with a variant token (`busybox ECCHI`, `busybox MIRAI`, ...) or a Mirai binary name. Plain `busybox` use is not tagged. |
| `recon` | A device fingerprinting command in a shell: `getprop` (model, CPU and Android version), `screencap`, `id`, `uname` and the like. |

Other flags on the session: `adb_shell`, `adb_pull`, `adb_reboot` and `adb_service`.

## Limits

Compose sets `ADB_MAX_CONNECTIONS` to 200 and `ADB_MAX_PER_IP` to 8. The sensor's own defaults are in its README.

| Scope | Limit (environment variable, default) |
| --- | --- |
| Connections | `SENSOR_MAX_CONNECTIONS` and `SENSOR_MAX_PER_IP`, see above. |
| New connections | `SENSOR_CONN_RATE_PER_IP` 1 per second per source, burst 10. |
| Timeouts | Handshake 20 s, message 30 s, idle 300 s, whole session 1800 s. |
| Streams | 8 open streams per connection, 200 in total. A stream that is not acknowledged after 512 messages is no longer written to. |
| Input and hashing | 24 MiB of input and 16 MiB hashed per connection (`SENSOR_MAX_INPUT_MB`, `SENSOR_MAX_HASH_MB`). |
| Commands | `SENSOR_MAX_COMMANDS` 2000 per connection. `SENSOR_LINE_BUDGET` 0.15 s of CPU per command line. |
| CPU and memory | `SENSOR_SHELL_CPU_SHARE` 0.3 CPU-seconds per second for all sessions, shared fairly between sources. `SENSOR_MEMORY_BUDGET_MB` 112 for all sessions. |
| Events | `SENSOR_EVENTS_PER_SEC` 20 `connect` events per source, `SENSOR_GLOBAL_EVENTS_PER_SEC` 200 for the sensor. |

## Container

Same hardening as the other sensors: non-root (UID 10001), read-only root file system, `tmpfs` at `/tmp`, all capabilities dropped, `no-new-privileges`, 256 MB of memory with no swap, 0.5 CPU and 128 processes. Health check: `python -m adb_sensor.healthcheck`. The profile secret is kept in the `adb-sensor-data` volume.
