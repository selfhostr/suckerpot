# SSH sensor

An SSH server whose shell is pure emulation. Run with `python -m ssh_sensor`; it listens on
container port 2222 (compose maps the host port 22).

## What it does

- Presents itself as OpenSSH 9.6p1 on Ubuntu (`SSH_BANNER`). Key exchange, cipher, MAC,
  compression and host key algorithm lists are those of OpenSSH 9.6 on Ubuntu 24.04, in the
  same order. Not matchable with asyncssh: `sntrup761x25519-sha512@openssh.com` (post-quantum
  KEX) is missing (so the HASSHServer value differs), compression is `none` only (a real
  server also offers `zlib@openssh.com`; offering it would allow decompression bombs), and
  the RSA host key is not offered as `ssh-rsa` (as in a real 9.6 server, but nmap's
  `ssh-hostkey` script then lists only ECDSA and ED25519).
- Host keys (ed25519, RSA 3072, ECDSA P-256) are generated on first start into
  `SSH_HOSTKEY_DIR` (a volume), mode 0600, and reused. The fake host identity (private IP, MAC,
  uptime, last-login address, DNS answers) is derived from a random secret generated once next
  to the host keys (`profile_secret`, 0600). It is deliberately NOT derived from the public host
  key fingerprint, otherwise anyone could predict the fake `ip a` output and recognise the
  sensor. Keep `/data` on a persistent volume (a warning is logged whenever keys are generated).
- Password logins succeed for `SSH_ACCEPT_CREDENTIALS` (or randomly
  with `SSH_ACCEPT_RANDOM_PROB`). Public keys are recorded (type + SHA256 fingerprint) and
  rejected. `SSH_MAX_AUTH_ATTEMPTS` failures end the connection with OpenSSH's
  "Too many authentication failures".
- The fake shell supports interactive PTY sessions, piped stdin and `exec` requests. It has
  an in-memory copy-on-write filesystem built from `ssh_sensor/shell/baseimage.py`. Nothing
  is ever executed or fetched: downloads (`wget`, `curl`, `tftp`, `ftpget`, `scp host:path`)
  only emit `download_attempt` events and drop a few-byte stub file. `scp -t` uploads are
  hashed and discarded (recorded in a `command` event under `scp_upload`).
- Port forwarding requests are refused and recorded as `scan` events. The `sftp` subsystem is
  accepted and then closed with exit status 127, like an sshd with a broken `sftp-server`.
- Errors (bash messages, wget progress) go to the SSH stderr channel when there is no PTY.

## Resource limits

Per connection: 2 session channels, 20 refused requests (extra channels, port forwards), one
shared fake filesystem (1 MiB, 2000 nodes), 5000 commands, auth requests capped at 4 times
`SSH_MAX_AUTH_ATTEMPTS`. Per shell: 256 variables / 64 KiB, 64 KiB of history, 64 KiB per
expanded word. Per command line: a CPU time budget (`SSH_LINE_BUDGET`, default 0.15 s; the
line is aborted with `Killed`), 200 simple commands, 64 KiB of output. Sensor-wide: a memory
budget over all sessions (`SSH_MEMORY_BUDGET_MB`, default 48; beyond it new sessions are
refused and commands fail with `Cannot allocate memory`; one source IP may hold at most
`SSH_MEMORY_SHARE_PER_IP` of it), and a watchdog thread that exits the process (status 70, so
the container restarts) if the event loop does not run for 10 s (lags over 1 s are logged).

Floods. Input: each session channel has a small flow-control window (`SSH_CHANNEL_WINDOW_KB`,
default 32), and the window accounting counts data that is still buffered (asyncssh would
re-open the whole window while older packets are queued), so a channel never holds more than
about twice the window of unread input; a session whose unread input still exceeds four
windows is closed (`input flood`). Socket data is metered before asyncssh decrypts it: it is
fed in 4 KiB slices, one per loop step, within a per-connection budget
(`SSH_INBOUND_CONN_KB_PER_SEC`, default 32) and a sensor-wide one (`SSH_INBOUND_KB_PER_SEC`,
default 256) shared fairly between source IPs; meanwhile the socket is not read and TCP
pushes back on the client (this bounds tiny-packet floods, where every packet costs a
decryption). Shell CPU: all command lines share `SSH_SHELL_CPU_SHARE` CPU-seconds per second
(default 0.3, burst 0.2); when it is used up, commands queue and the source IP that used the
least CPU recently goes first, so one IP with many channels cannot starve the others; a
command that waits more than 10 s fails with `fork: retry: Resource temporarily unavailable`
(status 254). Process memory: once a second the guard compares the container's memory
(cgroup `memory.current` without inactive page cache, else RSS against `SSH_MEMORY_LIMIT_MB`)
with its limit; above `SSH_MEMORY_PRESSURE` (0.70) new connections and sessions are refused
and the biggest connections stop being read, above `SSH_MEMORY_CRITICAL` (0.85) the biggest
connections are closed (`memory limit`). The guard acts only while sessions and queued events
hold at least 10% of the limit (otherwise the memory is heap the allocator kept after a burst).
Attacker-controlled text never reaches `re` with nested or adjacent quantifiers: awk and sed
programs are parsed by hand, grep patterns are translated to globs.

Output sizes are computed or capped BEFORE a result is built, never built and then truncated:
256 KiB per command (stdout and stderr share it, also through `sudo`/`xargs`/`busybox`), 2000
characters per line and 5000 lines when a command splits text into lines, 1 MiB read over all
the file operands of one command, 256 KiB of input for `sort`/`uniq`, `wc` counts without
splitting, `sed` replacements of at most 256 characters substituted on a bounded line, `tr`
sets of at most 1024 characters, base64 input cut to what the output budget can hold, `>>` and
`tee` checked against the filesystem cap before concatenating or encoding, nested shells
(`sh -c`, scripts, `$(...)`) capped while they run, 128 KiB of expanded words per command
(`Argument list too long`), `date +FORMAT` limited to 128 format and 1024 output characters.
Internal emulation errors log a full traceback at most once per minute per exception type.

Event limits: `connect` per source IP, `scan`/`login_attempt` per session, `command` and
`download_attempt` per session in a separate quota. Every event, `disconnect` included, is also
capped sensor-wide (`SSH_GLOBAL_EVENTS_PER_SEC`); 10% of that bucket is reserved for the
`disconnect` (and `events_suppressed` report) of sessions that logged in or ran a command, so
those are only lost when the reserve is exhausted too. Suppressed events are counted: the
`disconnect` event carries `events_suppressed` and, for sessions that logged in or ran a
command, a `scan` event with `kind = events_suppressed` is emitted.

Event bytes (approximate JSON size of `data`) are budgeted too: per source IP
(`SSH_IP_EVENT_BYTES_PER_SEC`, default 20000, burst 1 MB) and sensor-wide
(`SSH_GLOBAL_EVENT_BYTES_PER_SEC`, default 200000, burst 2 MB). An event that does not fit
loses its bulk first (a `command` keeps `input` and the 1 KiB `output_preview` and gets
`output_omitted`; a `disconnect` loses its replay and gets `replay_omitted`), and is dropped
(and counted as suppressed) if even that does not fit. The event queue is capped at 8 MiB.
Consecutive identical command lines of a connection are collapsed: the first one is a normal
`command` event, the repeats are reported as one `command` event with `repeat_count`,
`first_ts` and `last_ts` (when another line comes, at the end of the session, or every 1000
repeats).

### Fields consumers must handle

- `command.repeat_count`, `first_ts`, `last_ts` (ISO 8601 UTC): this event stands for
  `repeat_count` consecutive repeats of the same `input` between `first_ts` and `last_ts`. It has
  no `output`. The first occurrence is always a separate normal `command` event.
- `command.output_omitted` (true): `output` was dropped by the byte budget; `input` and
  `output_preview` are still present.
- `disconnect.replay_omitted` (true): `replay` was dropped by the byte budget (not the same as
  `replay_truncated`, which means only older frames were cut).

New connections are also limited per source IP (`SSH_CONN_RATE_PER_IP`, burst
`SSH_CONN_BURST_PER_IP`); excess connections are closed at once. Connections that never send
an authentication request (port scans, banner grabs) and connections refused by any connection
limit get no `connect`/`disconnect` events: they are counted per source IP and reported every
`SSH_SUMMARY_INTERVAL` seconds as one `scan` event with `kind = connection_summary`.

## Events

All events use the shared `suckerpot_common.Event` model, `dst_port` is the public port
(`SSH_PUBLIC_PORT`). No events are emitted for connections from 127.0.0.1 (container
healthcheck).

| type | data |
| --- | --- |
| `connect` | `client_version`, `banner` |
| `login_attempt` | `username`, `password` (null for publickey), `success`, `method`; publickey adds `key_type`, `key_fingerprint` |
| `command` | `input`, `output` (8 KiB cap), `output_preview` (1 KiB), `cwd`, `user`, `prompt`, `status`; `output_omitted` when the byte budget dropped `output`; for collapsed repeats `repeat_count`, `first_ts`, `last_ts` (no `output`) |
| `download_attempt` | `url`, `tool`, `command`, `cwd`, `user` |
| `scan` | `kind` = `tcp_forward_attempt`, `host`, `port`; or `kind` = `events_suppressed`, `count`; or `kind` = `connection_summary`, `count`, `rejected`, `first_seen`, `last_seen`, `interval_s` (`src_port` is 0) |
| `disconnect` | `duration_s`, `reason`, `login_attempts`, `commands`, `downloads`, `events_suppressed`, `replay`, `replay_truncated`, `replay_omitted` |

### Terminal replay

`truncate_data` caps lists at 64 items, which is unusable for a terminal recording, so the
frames are not passed through it. The `disconnect` event carries `data.replay`: a list of
asciicast-v2-like frames `[delta_seconds, "o" | "i", text]` (`o` = bytes sent to the client
including the echo, `i` = bytes typed by the client; `delta_seconds` is relative to the
previous frame). The newest frames that fit into 12 KiB of compact JSON are kept; when older
frames were dropped `data.replay_truncated` is `true`. The whole event stays below 16 KiB.
`command` events also carry `input`/`output`/`prompt` with accurate timestamps, so a
command-level replay works even when the raw stream was truncated.

## Environment variables

| variable | default | meaning |
| --- | --- | --- |
| `REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD`, `EVENTS_STREAM`, `EVENTS_MAXLEN` | see `suckerpot_common` | Redis stream publisher |
| `SSH_PORT` | `2222` | listen port inside the container |
| `SSH_PUBLIC_PORT` | `22` | port reported as `dst_port` |
| `SSH_BANNER` | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14` | version string |
| `SSH_HOSTNAME` | `srv-web01` | fake hostname |
| `SSH_HOSTKEY_DIR` | `/data/host_keys` | host key directory (volume) |
| `SSH_ACCEPT_CREDENTIALS` | weak set (root:root, root:123456, ...) | comma list of `user:pass` |
| `SSH_ACCEPT_RANDOM_PROB` | `0.0` | probability of accepting any non-empty password |
| `SSH_MAX_AUTH_ATTEMPTS` | `6` | attempts per connection |
| `SSH_MAX_CONNECTIONS` / `SSH_MAX_PER_IP` | `200` / `5` | connection caps |
| `SSH_LOGIN_TIMEOUT` / `SSH_IDLE_TIMEOUT` / `SSH_MAX_SESSION` | `30` / `300` / `1800` | seconds |
| `SSH_MAX_LINE` | `4096` | longest accepted input line |
| `SSH_EVENTS_PER_SEC` | `20` | `connect` events per source IP (burst 2x); see event limits above |
| `SSH_FAKE_IP` | derived | private address shown by `ifconfig` / `ip a` |
| `SSH_OS_VERSION` / `SSH_KERNEL` / `SSH_KERNEL_BUILD` | `24.04.4` / `6.8.0-100-generic` / matching build string | fake OS and kernel versions (keep consistent with `SSH_BANNER`) |
| `SSH_LINE_BUDGET` | `0.15` | CPU seconds allowed per command line |
| `SSH_MEMORY_BUDGET_MB` | `48` | memory budget over all sessions |
| `SSH_MAX_COMMANDS` | `5000` | commands per session |
| `SSH_GLOBAL_EVENTS_PER_SEC` | `200` | sensor-wide event cap |
| `SSH_CONN_RATE_PER_IP` / `SSH_CONN_BURST_PER_IP` | `1` / `10` | new connections per second per source IP (token bucket) |
| `SSH_SUMMARY_INTERVAL` | `60` | seconds between per-IP `connection_summary` events |
| `SSH_STATS_INTERVAL` | `60` | seconds between `stats` log lines |
| `SSH_CHANNEL_WINDOW_KB` | `32` | SSH flow-control window per session channel |
| `SSH_INBOUND_CONN_KB_PER_SEC` / `SSH_INBOUND_KB_PER_SEC` | `32` / `256` | inbound socket bytes per connection / sensor-wide (fair between IPs) |
| `SSH_SHELL_CPU_SHARE` / `SSH_SHELL_CPU_BURST` | `0.3` / `0.2` | shell CPU-seconds per second for all sessions, fair between IPs |
| `SSH_MEMORY_LIMIT_MB` | `256` | memory limit when the cgroup has none (RSS is compared with it) |
| `SSH_MEMORY_PRESSURE` / `SSH_MEMORY_CRITICAL` | `0.70` / `0.85` | memory guard levels (refuse and pause / close the biggest sessions) |
| `SSH_MEMORY_SHARE_PER_IP` | `0.25` | share of `SSH_MEMORY_BUDGET_MB` one source IP may hold |
| `SSH_IP_EVENT_BYTES_PER_SEC` / `SSH_IP_EVENT_BYTES_BURST` | `20000` / `1000000` | event bytes per source IP |
| `SSH_GLOBAL_EVENT_BYTES_PER_SEC` / `SSH_GLOBAL_EVENT_BYTES_BURST` | `200000` / `2000000` | event bytes sensor-wide |

## asyncssh pin

asyncssh is pinned to an exact version because the flow control swaps `__class__` on asyncssh
objects and reads private attributes. `tests/test_asyncssh_contract.py` fails with
"asyncssh internals changed: re-verify flow control" when they change.

## Development

```
uv sync
uv run ruff check && uv run ruff format --check && uv run mypy . && uv run python -m pytest
```
