# Telnet sensor

```{admonition} Status
:class: note

Built (M6) and wired into Compose as `sensor-telnet`, with the stream `events:telnet`, the internal network `sensors-telnet`, the Redis user `sensor-telnet` and the volume `telnet-data`.
```

## What it emulates

A Telnet server that looks like a cheap embedded Linux device running BusyBox: an IP camera or DVR, or a home router. It is built for the Mirai family of bots, and is equally happy with a human typing. It listens on container port 2323. Compose maps the host port (`TELNET_HOST_PORT`, default 23) to it.

- **Handshake.** Raw asyncio, no Telnet library. The server opens like BusyBox `telnetd` (`IAC DO ECHO, DO NAWS, WILL ECHO, WILL SGA`), so `nmap -sV` reports `telnet BusyBox telnetd`. It prints `<hostname> login: ` and `Password: ` (no echo) and answers a wrong password with `Login incorrect` after a 3 s delay, like `login(1)`.
- **Option negotiation** is what BusyBox does: the four-command opener, then nothing. What the client sends is recorded and never answered, so two peers cannot loop. The server never asks for TTYPE or LINEMODE. Subnegotiations are bounded to 64 bytes.
- **Logins.** The credential list is the classic Mirai dictionary, trimmed (`TELNET_ACCEPT_CREDENTIALS`). Every attempt is recorded, successful or not. Optionally any non-empty password is accepted (`TELNET_ACCEPT_RANDOM_PROB`).
- **Shell.** After login the client gets BusyBox's `built-in shell (ash)` banner and a `~ # ` prompt. The shell is the [SSH sensor](ssh.md)'s emulation, restricted to BusyBox applets and re-skinned (`sh: foo: not found`, `/bin/busybox FOO` answers `FOO: applet not found`, BusyBox-format `ps`, `free`, `df`, `ifconfig`, `netstat`, `ping`, `uname`, `uptime`). Echo-loader idioms work, and `cat /bin/echo` returns a real ELF header for the device's architecture, so a loader that sniffs the architecture picks a binary. `enable`, `system`, `shell` and `linuxshell` answer "not found", as on a plain BusyBox.
- **No execution, no fetching.** `wget`, `tftp` and `ftpget` only emit `download_attempt` events and drop a 400-byte stub file. `curl` answers "not found" like the real device, but the URL is still recorded. Running a dropped "binary" starts silently and does nothing.
- **Personalities** (`TELNET_PERSONALITY`): `dvr` (ARMv7, BusyBox 1.19.4, kernel 3.0.8) and `router` (MIPS, BusyBox 1.17.3, kernel 2.6.31). `/proc` files, `uname`, `ps`, `df` and `netstat` follow the personality.

## What it records

All events use the shared [Event schema](../event-schema.md). `dst_port` is the public port.

| Event `type` | `data` keys |
| --- | --- |
| `connect` | `banner`, `client_options` (the `WILL`/`DO` commands the client sent), `window`, `terminal` |
| `login_attempt` | `username`, `password`, `success`, `method` = `telnet` |
| `command` | `input`, `output` (8 KiB cap), `output_preview` (256 characters), `cwd`, `user`, `prompt`, `status` |
| `download_attempt` | `url`, `tool` (`wget`, `tftp`, `ftpget`, `curl`), `command`, `cwd`, `user` |
| `scan` | `kind` = `raw_payload` (`payload_preview` in hex, `bytes`, `client_options`), `connection_summary` or `events_suppressed` |
| `disconnect` | `duration_s`, `reason`, `login_attempts`, `commands`, `downloads`, `bytes_in`, `bytes_out`, `events_suppressed`, `replay`, `replay_truncated` |

A connection that never completes a login attempt produces no `connect` or `disconnect`. It is summarised per source address in a periodic `scan` event (`connection_summary`). If it sent bytes (an HTTP request on port 23, an exploit blob), a `scan` event with `kind = raw_payload` carries the first 256 bytes as hex.

### Terminal recording

Same format as the SSH sensor: `disconnect.data.replay` is a list of `[delta_seconds, "o" | "i", text]` frames, with the newest frames that fit in 12 KiB kept. Passwords are not in the recording (they are in `login_attempt`). It holds attacker-controlled bytes, so the replay must follow the [safety contract](../SECURITY.md#terminal-replay-safety-contract).

## Tags

Rules live in `ingest/rules/shell.yaml`. They are shared with the SSH sensor, with one addition that only applies here.

| Tag | Set when a `command` is |
| --- | --- |
| `iot-shell-probe` | One of the shell-escape words loaders send first (`enable`, `system`, `shell`, `linuxshell`, `sh`, `ping; sh`), a BusyBox applet probe (`/bin/busybox` followed by any word) or the architecture check (`cat /proc/self/exe`). It names no malware family. |
| `mirai` | The BusyBox echo-check with a known Mirai variant token (`/bin/busybox ECCHI`), or a Mirai binary name. Plain BusyBox use is not Mirai. |
| `recon`, `exec-attempt`, `persistence`, `crypto-miner` | As on the SSH sensor. |

## Limits and abuse resistance

| Scope | Limit |
| --- | --- |
| Connections | 200 in total, 8 per source address, new connections per address rate limited (1 per second, burst 10) before anything is sent |
| Timeouts | Login 60 s, idle 300 s, whole session 1800 s, 10 s to flush a write (a client that never reads is dropped) |
| Input | 1 MiB per connection, 4 KiB per line (extra characters are dropped), 2000 commands |
| Output | 2 MiB per session, 64 KiB per command line |
| Shell | The SSH shell's limits (1 MiB and 2000-node fake file system, 200 simple commands per line), a CPU budget of 0.15 s per line, and a total shell budget of 0.3 CPU-seconds per second for all sessions together. A session that overspends waits, and after 10 s of debt a line fails with `can't fork`. |
| Memory | A 48 MB budget over all sessions. New connections are refused beyond it. Running sessions are kept. |
| Events | Per-address and per-session quotas, a separate quota for commands and downloads, `disconnect` never limited, a sensor-wide cap. Suppressed events are counted and reported. |

A watchdog thread exits the process (status 70) when the event loop stalls for 10 s, so Compose restarts the container. Attacker text never reaches a regular expression with nested quantifiers. Banner texts are checked at start-up and may not contain "honeypot" or "suckerpot". The output never says "SSH", "Ubuntu", "bash" or "Python".

## Configuration

See [Configuration](../configuration.md#telnet-sensor). The device identity (host name, LAN address, MAC, uptime) comes from a random secret created once under `TELNET_DATA_DIR` (a volume, mode 0600). Keep the volume.

## Compose service

- `sensor-telnet` on `sp-ingress` and its own internal network `sensors-telnet`, published as `0.0.0.0:${TELNET_HOST_PORT:-23}:2323` (IPv4 only).
- Redis user `sensor-telnet`, limited to `XADD` on `events:telnet`, with the password `REDIS_SENSOR_TELNET_PASSWORD`.
- Volume `telnet-data` for the profile secret.
- The same container hardening as the other sensors.

The Telnet image also contains the SSH sensor package as a library, because the shell is shared.
