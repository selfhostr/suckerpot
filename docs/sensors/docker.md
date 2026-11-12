# Docker sensor

```{admonition} Status
:class: note

Built in M9. Wired into `docker-compose.yml` as `sensor-docker`, with the stream `events:docker`, the network `sensors-docker` and the Redis user `sensor-docker`. The sensor's own notes are in `sensors/docker/README.md`.
```

## What it emulates

An exposed, unauthenticated Docker Engine API: `dockerd` 27.3.1 (API 1.47) on Ubuntu 24.04, over plain HTTP with no TLS and no authentication. The real `docker` CLI (`version`, `info`, `ps`, `images`, `run`, `exec`), `curl` and `nmap -sV` all get believable answers.

It listens on container port 2375. Compose maps the host port `DOCKER_HOST_PORT` (default 2375) to it.

- **Read requests** (`/version`, `/info`, `/containers/json`, `/images/json`, `/networks`, `/volumes`) get canned or generated JSON. Containers that the same address created earlier show up in later listings.
- **Creating and running containers** is recorded in full. The container gets an ID and a state. Nothing is started, pulled or built. The output of trivial commands (`id`, `whoami`, `echo`) is produced by reading the command text, never by running it.
- **Pulls** report bounded, realistic progress. No image is fetched.
- **Builds, image loads, commits and archive uploads** are recorded and answered with a generic result. Remote URLs inside them are recorded as downloads.
- **Swarm** answers `503 This node is not a swarm manager`. `swarm init` and `swarm join` are recorded.
- **Registry login** (`POST /auth`, or an `X-Registry-Auth` header) records the credentials and answers `401`.

## What it records

All events use the shared [Event schema](../event-schema.md).

| Event `type` | Content |
| --- | --- |
| `connect` | `transport`. |
| `http_request` | Every request: `method`, `path`, `query`, `headers`, `user_agent`, `body_preview`, `body_sha256`, `status`, `route`, and for container creates the image, command, entrypoint, environment, binds, `privileged`, `pid_mode`, `network_mode`, `cap_add` and `user`. |
| `command` | Container create or exec: `input` (entrypoint and command), `kind`, `image`, `flags`. |
| `download_attempt` | A URL found in a command, an environment variable, `fromSrc` or a build context. |
| `login_attempt` | Registry credentials (`username`, `password`, `server`, `method` = `registry_auth`). |
| `scan` | Non-HTTP bytes, incomplete requests, and rate-limited connections. |
| `disconnect` | `duration_s`, `reason`, `requests`, `commands`, `logins`, `downloads`. |

## Flags and tags

Rules live in `ingest/rules/services.yaml`.

| Tag | Set when the sensor flags |
| --- | --- |
| `container-escape` | `privileged`, `host_mount` (a bind from `/`, `/etc`, `/root`, `/proc`, `/sys`, `/home` and similar), or `docker_sock_mount`. |
| `crypto-miner` | `miner` (an image, command or environment that names a known miner, such as xmrig or kinsing). |
| `malware-drop` | Any `download_attempt`. |
| `service-probe` | A `GET` or `HEAD` that identifies the daemon or lists what it runs: `/_ping`, or any request the sensor flags `recon` (`/version`, `/info`, `/containers/json`, `/images/json`, networks, volumes). Creating or running a container never matches. |

Other flags, such as `pid_host`, `net_host`, `cap_add`, `image_build` and `swarm_join`, are shown on the session.

## Limits

Compose sets `DOCKER_MAX_CONNECTIONS` to 200 and `DOCKER_MAX_PER_IP` to 8. The sensor's own defaults are in its README.

| Scope | Limit |
| --- | --- |
| New connections | 5 per second per source, burst 20. |
| Request | Request line 8 KB, head 32 KB and 64 headers. Larger requests get `431` or `414`. |
| Body | Read and hashed up to 8 MB. The first 256 KB are parsed. JSON is checked for size and depth (24) before parsing. |
| Timeouts | Head 20 s, body 60 s in total, keep-alive 15 s, 200 requests or 300 s per connection, write 10 s. |
| Memory | A 96 MB byte budget (`DOCKER_MEMORY_BUDGET_MB`). A guard refuses new connections above 70 % of the container limit. |
| Per-address state | 512 addresses, with 8 containers and 16 execs each. Least recently used entries go first. |
| Events | 20 per second per session, 200 per second for the sensor, plus a guaranteed bucket for commands, downloads and logins. |

A watchdog thread exits the process if the event loop stalls for 10 seconds.

## Container

Same hardening as the other sensors: non-root (UID 10001), read-only root file system, `tmpfs` at `/tmp`, all capabilities dropped, `no-new-privileges`, 256 MB of memory with no swap, 0.5 CPU and 128 processes. Health check: `python -m docker_sensor.healthcheck`. The profile (a random identity for the fake daemon) is stored in the `docker-sensor-data` volume.
