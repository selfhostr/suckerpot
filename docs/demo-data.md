# Load demo data

`just demo` fills SuckerPot with synthetic attack data. Use it to try the pipeline and the dashboard, to develop against it.

The demo data is fake. The generator never contacts real attackers and never sends traffic to the internet. It publishes events to Redis the same way a sensor does, so the rest of the pipeline is tested too.

## Run it

```bash
just demo
```

This runs the `demo` service from `docker-compose.yml`, which is in the `tools` profile. It is not started by `docker compose up`. It connects to Redis as its own `demo` user. That user can only `XADD` to the `events:*` streams, the same kind of permission a real sensor has, and it sits on its own internal network (`tools`) that reaches Redis and nothing else.

You can also run it without `just`:

```bash
docker compose --profile tools run --rm demo
```

Arguments after `just demo` go to the generator:

```bash
just demo --days 3 --sessions 200 --seed 7
```

## Indicators in the demo

Some demo droppers use a few shared hosts (documentation addresses and example domains) and carry made-up payload hashes, so the Infrastructure page has shared infrastructure to show. Every demo event carries `demo: true`, so the extraction keeps these documentation addresses and example (`.example`, `.test`) domains, flags them, and never sends them to an intel service. Only the source addresses of the demo sessions look like public addresses. `just demo` prints a note when intel keys are set.

## Campaigns and techniques in the demo

Telnet loaders reuse a few probe words and several droppers share hosts, so with `ATTACK_ENABLED=true` and `CAMPAIGNS_ENABLED=true` in `.env` the Campaigns and Techniques pages fill with demo campaigns a few minutes after `just demo` (ingest groups finished sessions every five minutes).

## What it generates

The generator first creates a **backfill**: sessions spread over the last `--days` days. Then, with `--live`, it keeps sending new sessions. Each session is a short story made of events. The four sensors are covered:

| Sensor | Session types in the generator | Example story |
| --- | --- | --- |
| SSH | Password guessing, successful login with reconnaissance, persistence attempts, a miner install | Tried a list of passwords, then logged in and ran a miner |
| Telnet | Single logins, and botnet waves that arrive together | Part of a coordinated wave of weak-password attempts |
| Web | Generic HTTP scanning, WordPress login probes, and PHP upload probes | Looked for admin pages, then tried an exploit |
| RDP | Connection probes, NTLM logins (some with a decoy password), BlueKeep-style channel probes, and standard clients (FreeRDP, mstsc, nmap and others) | Tried one username, or logged in with a common password and was refused |

Some SSH sessions come from one campaign: a single source tries many passwords. The mix, the timing and the source addresses aim to look realistic, with busy hours, quiet nights and a few repeat visitors.

The generator uses only the documentation address ranges (`192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`). Nothing is captured from the internet.

```{note}
The generator sends the events directly to the per-sensor streams, as the `demo` Redis user, and does not need a sensor to be running. The event shape is the same as the one the sensors send. See [Event schema](event-schema.md).
```

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--days N` | `DEMO_DAYS` (30) | Spread the backfill over the last N days. Must be at least 1. |
| `--sessions N` | `DEMO_SESSIONS` (3000) | Number of backfill sessions |
| `--seed N` | `DEMO_SEED` (42) | Random seed. The same seed gives the same data. |
| `--now ISO` | current time | The time to treat as "now", for reproducible output, for example `2026-10-24T12:00:00Z` |
| `--live` | off | After the backfill, keep sending new sessions until you stop it with Ctrl+C. Use `just demo-live` for this. |
| `--live-only` | off | Skip the backfill and send new sessions only |
| `--live-min S` | `1.0` | Minimum seconds between live sessions |
| `--live-max S` | `8.0` | Maximum seconds between live sessions |
| `--live-speed X` | `1.0` | Time compression for the events of one live session |
| `--dry-run` | off | Print the events as JSON lines on standard output, and send nothing to Redis |

Defaults come from `.env`. Command-line options override them.

```bash
# Print 2 days of events as JSON lines, without touching Redis
docker compose --profile tools run --rm demo --days 2 --sessions 50 --dry-run
```

## Running it twice

Each run adds data. To start from scratch on purpose, stop the stack and remove the database volume by name (`docker volume rm suckerpot_db-data`); `docker compose down -v` no longer deletes the data volumes, which are external. See [Deployment](deployment.md#deleting-data-on-purpose). This deletes all data, real or fake.
