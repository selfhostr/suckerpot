# Data retention

Raw events are kept for `RETENTION_DAYS` (default 90). Compact aggregates are kept forever, so
long-term trends survive while disk usage stays bounded. Everything runs inside TimescaleDB as
background jobs; there is no cron container and no extra service.

## What runs, and when

| Job | Schedule | What it does |
| --- | --- | --- |
| Retention policy on `events` | Daily (TimescaleDB default) | Drops whole chunks older than `RETENTION_DAYS`. No row-by-row delete, no bloat. |
| Compression policy on `events` | Every 12 hours (TimescaleDB default) | Compresses chunks older than 7 days (segmented by `sensor`, ordered by `ts DESC`). Typically a large saving; reads and late inserts keep working. |
| Refresh policies on the four aggregates | Hourly | Recompute the last 3 days only. The refresh window never reaches dropped chunks. |
| `suckerpot_indicator_prune` | Hourly | Deletes indicators (with their links and threat-intel answers) not seen for `RETENTION_DAYS`, then enforces `INDICATORS_MAX_ROWS`: the least sighted, oldest single-source indicators go first, and the ceiling is halved while the disk guard is trimming. |
| `suckerpot_maintenance` | Hourly | Rolls sessions older than `RETENTION_DAYS` (whole UTC days) up into `sessions_daily`, then deletes them. Prunes `ip_reputation` rows nobody refreshed for the retention window (90 days at least; a known score is kept and used until the worker replaces it) and `enrichment_quota` rows older than 30 days. |

The `migrate` service (re)creates all of these after every upgrade from the current
`RETENTION_DAYS`, so changing the value and re-running `docker compose up -d` applies it.
`RETENTION_DAYS` must be between 7 and 3650; anything else makes `migrate` fail loudly instead of
guessing. It is read by the `migrate` service only.

## What is kept forever

| Relation | Kind | Grain | Columns |
| --- | --- | --- | --- |
| `events_hourly` | continuous aggregate | hour, sensor, event type | `events` |
| `events_daily_tags` | continuous aggregate | day, sensor, tag set (events with no tag are skipped) | `events` |
| `events_daily_country` | continuous aggregate | day, sensor, country (events without a country are skipped) | `events` |
| `events_daily_ip` | continuous aggregate | day, sensor, source IP | `events`, `login_attempts`, `commands`, `downloads`, `http_requests`, `first_seen`, `last_seen`, `country`, `asn` |
| `sessions_daily` | plain table, filled by the maintenance job | day, sensor | `sessions`, `events`, `login_attempts`, `logins_succeeded`, `commands`, `downloads`, `http_requests`, `unique_ips` |

The continuous aggregates are real-time views: recent buckets that are not materialised yet are
read from the raw events, so they are never stale. `events_daily_tags.tags` is the full tag set of
the events in the bucket; to count events per tag use
`SELECT bucket, t, sum(events) FROM events_daily_tags, unnest(tags) t GROUP BY 1, 2`.
`sessions_daily.unique_ips` is a per-sensor, per-day count, so it must not be summed across
sensors or days.

The `api` database role has `SELECT` on all five and nothing else; `ingest` has no access to them.
Grants are re-applied by `migrate` on every run, like the other tables.

## Reading beyond the raw window

Every analytics query caps its window at 30 days today, which is inside the default retention, so
nothing needs to change yet. If the window is ever widened, or `RETENTION_DAYS` is set below 30,
these queries (in `api/api/analytics_queries.py`, `trends.py`, `insights_queries.py`,
`malware.py`) would silently lose data and need to read an aggregate instead:

| Query | Raw source today | Fallback beyond retention |
| --- | --- | --- |
| `timeseries`, events part (`events_bucket_stmt`) | `events` | `events_hourly` for `1h` and `1d` buckets. `5m` cannot be served; clamp it to the raw window. |
| `timeseries`, sessions part (`sessions_bucket_stmt`) | `sessions` | `sessions_daily` for `1d` buckets only. |
| `top` for `country`, `tag`, `src_ip` | `sessions` (counts sessions) | `events_daily_country`, `events_daily_tags`, `events_daily_ip`. These count events, not sessions: label the unit accordingly. |
| `top` for `username`, `password`, `command`, `user_agent`, `url`; `top_values` | `events.data` | None. Payload values are not aggregated, so these are limited to the raw window. |
| `top` for `asn`, `org`; `list_asns` | `sessions` | `events_daily_ip.asn` grouped by ASN (no organisation name). |
| `heatmap` (day by hour) | `events` | `events_hourly`: group by `isodow` and `hour` of `bucket`. |
| `ip_timeline` | `events` | `events_daily_ip` for the IP. |
| `list_attackers`, `get_attacker` (first/last seen, totals) | `sessions`, `events` | `events_daily_ip` (`first_seen`, `last_seen`, counters). Per-session details are gone. |
| `trends_new` ("never seen before") | `events` and `sessions` over a window | Only IP and country can be answered from aggregates. Usernames, passwords and commands cannot. |
| `trends/tags` (`_tag_stmt`) | `sessions` | `events_daily_tags` (day grain only). |
| `insights_queries`, `/malware` | `sessions`, `events` | None. Download URLs and payload data are raw-only. |

A practical rule for the API: when `since` is older than `now() - RETENTION_DAYS`, serve the part
before the cutoff from the aggregate and the rest from the raw tables, and never mix units.

## CVE data

The `cve` table holds public vulnerability data, not captured data. The CVE watch job in ingest
deletes rows that are neither in the CISA KEV catalogue nor relevant to an emulated service once
their publication date is older than 180 days. KEV and relevant CVEs are kept.

## Operating notes

* A chunk is dropped only when it is entirely older than `RETENTION_DAYS`, so raw data can stay up
  to one day longer than configured.
* Lowering `RETENTION_DAYS` frees disk at the next daily run of the retention policy.
  Raising it keeps already-aggregated history; the dropped raw events do not come back.
* Do not refresh the aggregates over a period whose raw chunks were dropped: TimescaleDB would
  recompute those buckets as empty. The `migrate` backfill starts at the oldest remaining raw
  event for exactly this reason.
* Compressed chunks answer lookups by `session_id` and `src_ip` more slowly than uncompressed ones;
  the session detail page therefore stays fast for the last week and is slower for older sessions.
* To check disk use: `SELECT * FROM hypertable_detailed_size('events');` as the database owner.

## Disk guard

Retention is time-based. The disk guard is a size-based safety net that holds even if a sensor
bug floods the database. The ceiling is `DB_MAX_SIZE_GB` (default 10, minimum 1), read by `migrate`
(job) and `ingest` (payload trimming). `DB_MAX_SIZE_MB` overrides it and exists for tests only.

| Database size | What happens |
| --- | --- |
| Above 90% | The `suckerpot_disk_guard` job (every 5 minutes) drops the oldest raw `events` chunks, one at a time, until the size is below 80%. It logs a warning, writes a row to `maintenance_log` and updates `system_status`. Chunks from the last 4 days are never dropped, and nothing but `events` chunks is touched, so the aggregates and `sessions_daily` stay. If it cannot get under 90%, the state is `critical`. |
| Above 95% | `ingest` (checking every 30 seconds) keeps writing, but `command` and `http_request` events are cut to short previews (keys kept, values up to 256 characters, about 1 KB per event, `_truncated: true`). It leaves this mode below 90%. Other event types are untouched. |

`system_status` (key, value, updated_at; readable by the API) holds two rows for the Settings page:

* `disk_guard` (job): `state` (`ok`, `trimmed` or `critical`), `active`, `size_bytes`, `max_bytes`,
  `percent`, and after a trim `last_trim_at` and `last_trim_chunks`.
* `ingest_disk` (ingest): `degraded`, `degraded_writes` (events written in degraded mode since the
  service started), `size_bytes`, `max_bytes`, `percent`.

`maintenance_log` (id, ts, action, detail; 90 days kept) records every drop.
