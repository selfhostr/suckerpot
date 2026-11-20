# Sensors

Sensors are the fake services that face the internet. Each one speaks just enough of a protocol to look real, records what the attacker does, and publishes it as [events](../event-schema.md). A sensor never runs attacker input and never makes an outbound connection.

SuckerPot runs twelve sensors in four families. The family sets the colour in the dashboard. The sensor name and icon tell them apart.

| Family | Sensor | Fake service | Host port (default) | Stream |
| --- | --- | --- | --- | --- |
| Remote shells | [SSH](ssh.md) | OpenSSH 9.6 on Ubuntu, with an emulated shell | 22 | `events:ssh` |
| Remote shells | [Telnet](telnet.md) | BusyBox-style DVR or router login | 23 | `events:telnet` |
| Remote shells | [ADB](adb.md) | Android TV box with `adbd` and no authentication | 5555 | `events:adb` |
| Web and APIs | [Web](web.md) | Apache 2.4 with PHP 8.3 (unpatched), WordPress and phpMyAdmin | 80 and 443 | `events:web` |
| Web and APIs | [Docker](docker.md) | Exposed Docker Engine API (dockerd 27.3.1) | 2375 | `events:docker` |
| Web and APIs | [Synology](synology.md) | Synology NAS with unpatched DSM 7.2.1: login page and Web API, over HTTP and HTTPS | 5000 and 5001 | `events:synology` |
| Databases | [Redis](redis.md) | Redis 7.2 with no password | 6379 | `events:redis` |
| Databases | [MySQL](mysql.md) | MySQL 8.0 with weak logins | 3306 | `events:mysql` |
| Databases | [MSSQL](mssql.md) | SQL Server 2019 or 2022 with weak logins | 1433 | `events:mssql` |
| Windows and VoIP | [RDP](rdp.md) | Windows Server 2022 with NLA: NTLM logins, decoy password checks, optional cleartext mode | 3389 | `events:rdp` |
| Windows and VoIP | [SMB](smb.md) | Windows Server file service, observation only | 445 | `events:smb` |
| Windows and VoIP | [SIP](sip.md) | Asterisk-style PBX on UDP and TCP | 5060 (UDP and TCP) | `events:sip` |

All twelve are wired into `docker-compose.yml`. The web and Synology sensors are still under security review (see the [roadmap](../roadmap.md)).

## Rules every sensor follows

- **No execution.** No `subprocess`, `os.system`, `eval` or `exec` on attacker input. Fake commands return canned or generated output.
- **No fetching.** A download command only records the URL. Fetching, when it exists, is done by ingest and is off by default.
- **No outbound traffic.** A sensor sits on `sp-ingress` (inbound only) and on its own internal network to reach Redis. See [Architecture](../ARCHITECTURE.md#networks).
- **Bounded everything.** Connection caps (total and per source IP), timeouts on every read, a size cap on every captured field, a memory budget, and bounded queues.
- **A watchdog.** Docker does not restart a container that is only *unhealthy*. Each sensor runs a watchdog thread that exits the process when the event loop stalls, so `restart: unless-stopped` brings it back.
- **Drop, never block.** When Redis refuses a write, the event is dropped and counted. A sensor never waits for Redis inside a connection handler.
- **Its own stream and Redis user.** A sensor can only `XADD` to its own stream. Ingest checks that the `sensor` field of every event matches the stream.
- **Realistic identity.** Plausible banners and host names. The words "honeypot" and "suckerpot" never appear anywhere a client could see.
- **No events from the health check.** Connections from loopback (the container health check) produce no events.

```{toctree}
:maxdepth: 1
:hidden:

ssh
telnet
adb
web
docker
synology
redis
mysql
mssql
rdp
smb
sip
```
