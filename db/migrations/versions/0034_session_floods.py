"""Flood groups: one row for a source's plain connections of one hour.

Revision ID: 0034
Revises: 0033

A source that opens thousands of plain connections an hour (a credential spray, a scanner) used to
leave one ``sessions`` row each: about 1 KB per row plus a dozen indexes, never compressed, and
removed only by the retention job. The disk guard drops ``events`` chunks only, so a growing
``sessions`` table made it eat the raw events instead. A connection that is complete, plain and
part of a flood is now merged into one group row (``kind = 'burst'``, ``connections = N``) by
``fold_session_buckets``. Events are never touched.

* ``kind`` and ``connections`` (CHECKs: a group has a ``burst-`` id, only a group counts more than
  one connection). Existing rows keep ``kind = 'session'`` and ``connections = 1``.
* ``ix_sessions_src_ip`` becomes ``(src_ip, sensor, started_at DESC)``: the function and the
  per-address lookups read one bucket (address, sensor, hour) as a range of that index.
* Autovacuum scale factors 0.05 on ``sessions`` (it now sees many deletes).
* ``fold_session_buckets(...)``: SECURITY DEFINER, so the ingest role merges rows without holding
  DELETE on ``sessions``. Only the DB owner (migrate) owns it; ingest gets EXECUTE from
  ``suckerpot_db.roles``; nobody else can call it. Its work is bounded whatever a source sent in
  the hour, it measures idle connections against the caller's progress, not the clock, and it
  refuses CVE, payload and severe tags whatever the caller passes.
* ``restore_folded_sessions(text[])``: same rights. A late event of a folded connection gives
  it its row back and takes it out of its group, so it is never counted twice.
* ``suckerpot_maintenance`` rolls up ``sum(connections)`` instead of counting rows, so
  ``sessions_daily.sessions`` is the same with and without folding.

The downgrade is lossy by nature (the folded connections cannot be rebuilt), so it refuses while
a group exists.
"""

from collections.abc import Sequence

from alembic import op

from suckerpot_db.locks import SESSION_FOLD
from suckerpot_db.retention import MAINTENANCE_PROC

revision: str = "0034"
down_revision: str | None = "0033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SIGNATURE = (
    "fold_session_buckets(inet[], text[], timestamptz[], integer, text[], interval, integer, "
    "timestamptz)"
)
RESTORE_SIGNATURE = "restore_folded_sessions(text[])"

# Tags that tell a story of their own and therefore never fold, whatever list the caller passes:
# every attack tag of ``ingest/ingest/scanners.py`` except the three that only describe a spray of
# credentials, plus the severe tags of the abuse and campaign code. The ingest loader
# (``ingest/ingest/floods/rules.py``) refuses the same tags and every ``cve-*`` one; a test there
# checks that this list covers what it refuses.
REFUSED_TAGS = (
    "bluekeep", "c3rb3r", "container-escape", "crypto-miner", "db-ransom", "eternalblue",
    "exec-attempt", "exploit", "iot-shell-probe", "malware-drop", "mirai", "persistence",
    "php2shell", "phpmyadmin-bruteforce", "redis-rogue-master", "sip-fraud", "sql-rce",
    "synology-exploit", "wordpress-bruteforce",
)  # fmt: skip
_REFUSED_SQL = ", ".join(f"'{t}'" for t in REFUSED_TAGS)

# Events a plain connection may hold besides its login attempts: the connect, the disconnect and
# the handshake the sensor records as a ``scan`` (RDP: the X.224 negotiation; SMB: the SMB1
# negotiate; most others: none). SIP also sends its first message and an end-of-session summary.
# A connection with more events than that carries something else (a payload sent as a ``scan``,
# say) and keeps its row.
EXTRA_EVENTS = 3
EXTRA_EVENTS_SIP = 4

# A plain connection is one nobody needs to read on its own: complete, no login success, no
# command, download or HTTP request, fewer than 20 login attempts (the credential-list campaign
# threshold, so a plain row is never clusterable), at most EXTRA_EVENTS events besides them
# (EXTRA_EVENTS_SIP on SIP), no campaign, no scanner name, not benign, only tags the caller calls
# plain and none of REFUSED_TAGS, no indicator link, no demo event of its own. A source is flooding
# when its rows of one UTC hour sum to at least p_min connections, or when it already has a group
# the hour before.
#
# Bounded work: the flood test reads at most p_min rows per bucket, the scan stops after p_limit
# rows to fold (a row that does not qualify is passed, not counted), and the demo test reads only
# the events of the rows it checks (``ix_events_session_id_ts``, a handful each), never the
# source's whole hour. Callers also cap the statement time.
#
# Idle is measured against p_now, how far the caller has stored the streams (the newest event it
# wrote), never later than the clock: when ingest lags, a connection whose later events are still
# queued is not idle. A NULL p_now is "unknown": only connections that ended fold.
#
# A row to fold that another transaction holds is skipped, never waited for (a group row it holds
# is waited for at most lock_timeout); the sums come from DELETE ... RETURNING, so a row changed in
# the meantime is counted as it was deleted. Every name is schema-qualified, so the search_path
# holds only pg_catalog (and pg_temp, last).
_FOLD = f"""
CREATE OR REPLACE FUNCTION public.fold_session_buckets(
    p_src inet[], p_sensor text[], p_hour timestamptz[], p_min integer, p_plain_tags text[],
    p_idle interval, p_limit integer, p_now timestamptz
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s'
AS $$
DECLARE
    v_min integer := greatest(coalesce(p_min, 20), 5);
    v_idle interval := greatest(coalesce(p_idle, interval '15 minutes'), interval '5 minutes');
    v_limit integer := least(greatest(coalesce(p_limit, 1000), 1), 5000);
    v_quiet_before timestamptz :=
        least(coalesce(p_now, '-infinity'::timestamptz), now()) - v_idle;
    v_tags text[];
    v_folded integer;
BEGIN
    IF p_src IS NULL OR p_sensor IS NULL OR p_hour IS NULL OR cardinality(p_src) = 0 THEN
        RETURN 0;
    END IF;
    IF cardinality(p_src) <> cardinality(p_sensor) OR cardinality(p_src) <> cardinality(p_hour) THEN
        RAISE EXCEPTION 'fold_session_buckets: the bucket arrays differ in length';
    END IF;
    IF cardinality(p_src) > 5000 THEN
        RAISE EXCEPTION 'fold_session_buckets: too many buckets';
    END IF;
    -- The caller names the plain tags; a CVE, payload or severe tag is never one of them.
    v_tags := ARRAY(
        SELECT DISTINCT t FROM unnest(coalesce(p_plain_tags, ARRAY[]::text[])) AS t
        WHERE t IS NOT NULL AND lower(t) NOT LIKE 'cve-%'
          AND lower(t) <> ALL (ARRAY[{_REFUSED_SQL}]::text[])
    );
    IF NOT pg_try_advisory_xact_lock({SESSION_FOLD}) THEN
        RETURN 0;
    END IF;

    WITH req AS MATERIALIZED (
        SELECT DISTINCT b.src, b.sensor, date_trunc('hour', b.hr, 'UTC') AS hr
        FROM unnest(p_src, p_sensor, p_hour) AS b(src, sensor, hr)
        WHERE b.src IS NOT NULL AND b.sensor IS NOT NULL AND b.hr IS NOT NULL
    ),
    hot AS MATERIALIZED (
        SELECT r.src, r.sensor, r.hr FROM req r
        WHERE (
            -- Every row stands for one connection or more, so the first v_min rows decide.
            (SELECT coalesce(sum(x.connections), 0)
             FROM (SELECT y.connections FROM public.sessions y
                   WHERE y.src_ip = r.src AND y.sensor = r.sensor
                     AND y.started_at >= r.hr AND y.started_at < r.hr + interval '1 hour'
                   LIMIT v_min) x) >= v_min
            OR EXISTS (SELECT 1 FROM public.sessions g
                       WHERE g.kind = 'burst' AND g.src_ip = r.src AND g.sensor = r.sensor
                         AND g.started_at >= r.hr - interval '1 hour' AND g.started_at < r.hr)
        )
    ),
    victims AS (
        -- One short range of ix_sessions_src_ip_sensor_started_at per hot bucket; the
        -- outer LIMIT stops the scan (and the locking) as soon as enough rows are found.
        SELECT v.session_id
        FROM hot h
        CROSS JOIN LATERAL (
            SELECT s.session_id
            FROM public.sessions s
            WHERE s.src_ip = h.src AND s.sensor = h.sensor
              AND s.started_at >= h.hr AND s.started_at < h.hr + interval '1 hour'
              AND s.kind = 'session' AND NOT s.benign AND s.scanner_name IS NULL
              AND NOT s.login_success AND s.commands = 0 AND s.downloads = 0
              AND s.http_requests = 0 AND s.login_attempts < 20
              AND s.event_count <= s.login_attempts
                  + CASE WHEN s.sensor = 'sip' THEN {EXTRA_EVENTS_SIP} ELSE {EXTRA_EVENTS} END
              AND s.campaign_id IS NULL AND coalesce(s.tags <@ v_tags, false)
              AND (s.ended_at IS NOT NULL OR s.last_event_at < v_quiet_before)
              AND NOT EXISTS (SELECT 1 FROM public.indicator_sessions i
                              WHERE i.src_ip = s.src_ip AND i.session_id = s.session_id)
              -- A scalar subquery, not NOT EXISTS: it stays a probe of this row's own events
              -- (never a join that reads every event of the chunk) on compressed chunks too.
              AND (SELECT count(*) FROM (
                       SELECT 1 FROM public.events e
                       WHERE e.session_id = s.session_id
                         AND e.ts >= s.started_at AND e.ts <= s.last_event_at
                         AND coalesce(e.data ->> 'demo', 'false') = 'true'
                       LIMIT 1) z) = 0
            LIMIT v_limit
            FOR UPDATE OF s SKIP LOCKED
        ) v
        LIMIT v_limit
    ),
    gone AS (
        DELETE FROM public.sessions d USING victims v WHERE d.session_id = v.session_id
        RETURNING d.*
    ),
    norm AS (
        SELECT g.*,
               ARRAY(SELECT DISTINCT t FROM unnest(g.tags) AS t ORDER BY t) AS tags_n,
               ARRAY(SELECT DISTINCT t FROM unnest(g.techniques) AS t ORDER BY t) AS techniques_n,
               date_trunc('hour', g.started_at, 'UTC') AS hr
        FROM gone g
    ),
    grp AS (
        SELECT n.sensor, n.src_ip, n.dst_port, n.hr, (n.login_attempts > 0) AS stage,
               n.tags_n, n.techniques_n, n.client_tool,
               sum(n.connections)::integer AS connections,
               sum(n.event_count)::integer AS event_count,
               sum(n.login_attempts)::integer AS login_attempts,
               min(n.started_at) AS started_at,
               max(n.last_event_at) AS last_event_at,
               max(coalesce(n.ended_at, n.last_event_at)) AS ended_at,
               max(n.country) AS country, max(n.city) AS city, max(n.asn) AS asn,
               max(n.org) AS org, max(n.abuse_score) AS abuse_score,
               bool_or(n.known_scanner) AS known_scanner
        FROM norm n
        GROUP BY n.sensor, n.src_ip, n.dst_port, n.hr, (n.login_attempts > 0), n.tags_n,
                 n.techniques_n, n.client_tool
    ),
    ins AS (
        INSERT INTO public.sessions AS t (
            session_id, sensor, src_ip, src_port, dst_port, started_at, ended_at, last_event_at,
            event_count, login_attempts, login_success, commands, downloads, http_requests,
            country, city, asn, org, abuse_score, known_scanner, tags, client_tool, techniques,
            campaign_id, clustered_at, benign, scanner_name, kind, connections
        )
        SELECT 'burst-' || left(md5(concat_ws(chr(31), p.sensor, host(p.src_ip), p.dst_port::text,
                   extract(epoch FROM p.hr)::bigint::text, p.stage::text,
                   array_to_string(p.tags_n, chr(30)), array_to_string(p.techniques_n, chr(30)),
                   coalesce(p.client_tool, ''))), 24),
               p.sensor, p.src_ip, 0, p.dst_port, p.started_at, p.ended_at, p.last_event_at,
               p.event_count, p.login_attempts, false, 0, 0, 0,
               p.country, p.city, p.asn, p.org, p.abuse_score, p.known_scanner, p.tags_n,
               p.client_tool, p.techniques_n, NULL, now(), false, NULL, 'burst', p.connections
        FROM grp p
        ON CONFLICT (session_id) DO UPDATE SET
            connections = t.connections + EXCLUDED.connections,
            event_count = t.event_count + EXCLUDED.event_count,
            login_attempts = t.login_attempts + EXCLUDED.login_attempts,
            started_at = least(t.started_at, EXCLUDED.started_at),
            last_event_at = greatest(t.last_event_at, EXCLUDED.last_event_at),
            ended_at = greatest(t.ended_at, EXCLUDED.ended_at),
            country = coalesce(t.country, EXCLUDED.country),
            city = coalesce(t.city, EXCLUDED.city),
            asn = coalesce(t.asn, EXCLUDED.asn),
            org = coalesce(t.org, EXCLUDED.org),
            abuse_score = greatest(t.abuse_score, EXCLUDED.abuse_score),
            known_scanner = coalesce(t.known_scanner OR EXCLUDED.known_scanner,
                                     t.known_scanner, EXCLUDED.known_scanner),
            clustered_at = now()
        WHERE t.kind = 'burst'
        RETURNING 1
    )
    SELECT coalesce(sum(g.connections), 0)::integer INTO v_folded FROM gone g;
    RETURN v_folded;
END
$$
"""

# A late event of a folded connection (one more login attempt, a command after a long silence)
# reaches ingest after its row was merged. The upsert then creates a new row for the id, from the
# late events only. The writer calls this function for such fresh rows (no ``connect`` in the
# batch). For each one that has events of its own from before its new start, it gives the
# connection back its story and takes it out of its group, so it is counted once and every event
# of it is read from its own row:
#
# * the earlier events (same id and sensor, up to one day back, at most 1000) are summed into the
#   row exactly as the writer sums a batch: start, end, counters, tags, techniques;
# * the group that counted it (same source, sensor and port, started in that hour and covering
#   those events, same stage, the one whose tags contain the connection's first) loses one
#   connection and those counters, or is deleted when it was its only one.
#
# It returns the ids it restored. Nothing else changes: an id with no earlier events (the normal
# case) is left alone, a group is never created, events are never touched.
_RESTORE = """
CREATE OR REPLACE FUNCTION public.restore_folded_sessions(p_ids text[])
RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s'
AS $$
DECLARE
    r record;
    e record;
    v_tags text[];
    v_techniques text[];
    v_group text;
    v_connections integer;
BEGIN
    IF p_ids IS NULL OR cardinality(p_ids) = 0 THEN
        RETURN;
    END IF;
    IF cardinality(p_ids) > 5000 THEN
        RAISE EXCEPTION 'restore_folded_sessions: too many sessions';
    END IF;
    FOR r IN
        SELECT s.session_id, s.sensor, s.src_ip, s.dst_port, s.started_at
        FROM public.sessions s
        WHERE s.session_id = ANY (p_ids) AND s.kind = 'session'
        ORDER BY s.session_id
    LOOP
        SELECT count(*)::integer AS n,
               count(*) FILTER (WHERE x.type = 'login_attempt')::integer AS logins,
               coalesce(bool_or(x.type = 'login_attempt' AND x.data -> 'success' = 'true'::jsonb),
                        false) AS success,
               count(*) FILTER (WHERE x.type = 'command')::integer AS commands,
               count(*) FILTER (WHERE x.type = 'download_attempt')::integer AS downloads,
               count(*) FILTER (WHERE x.type = 'http_request')::integer AS http,
               min(x.ts) AS first_ts, max(x.ts) AS last_ts,
               max(x.ts) FILTER (WHERE x.type = 'disconnect') AS ended,
               coalesce(bool_and(coalesce(x.benign, false)), false) AS benign
        INTO e
        FROM (SELECT ev.ts, ev.type, ev.data, ev.benign
              FROM public.events ev
              WHERE ev.session_id = r.session_id AND ev.sensor = r.sensor
                AND ev.ts >= r.started_at - interval '1 day' AND ev.ts < r.started_at
              ORDER BY ev.ts
              LIMIT 1000) x;
        CONTINUE WHEN e.n = 0;
        v_tags := ARRAY(
            SELECT DISTINCT t
            FROM public.events ev, unnest(ev.tags) AS t
            WHERE ev.session_id = r.session_id AND ev.sensor = r.sensor
              AND ev.ts >= e.first_ts AND ev.ts <= e.last_ts
            ORDER BY t
        );
        v_techniques := ARRAY(
            SELECT DISTINCT t
            FROM public.events ev, unnest(coalesce(ev.techniques, ARRAY[]::text[])) AS t
            WHERE ev.session_id = r.session_id AND ev.sensor = r.sensor
              AND ev.ts >= e.first_ts AND ev.ts <= e.last_ts
            ORDER BY t LIMIT 64
        );

        v_group := NULL;
        SELECT g.session_id, g.connections INTO v_group, v_connections
        FROM public.sessions g
        WHERE g.kind = 'burst' AND g.src_ip = r.src_ip AND g.sensor = r.sensor
          AND g.dst_port = r.dst_port
          AND g.started_at >= date_trunc('hour', e.first_ts, 'UTC') AND g.started_at <= e.first_ts
          AND g.last_event_at >= e.last_ts
          AND g.event_count >= e.n AND g.login_attempts >= e.logins
          AND (g.login_attempts > 0) = (e.logins > 0)
        ORDER BY (g.tags @> v_tags) DESC, g.session_id
        LIMIT 1
        FOR UPDATE OF g;
        IF v_group IS NOT NULL THEN
            IF v_connections > 1 THEN
                UPDATE public.sessions
                SET connections = connections - 1, event_count = event_count - e.n,
                    login_attempts = login_attempts - e.logins
                WHERE session_id = v_group;
            ELSE
                DELETE FROM public.sessions WHERE session_id = v_group;
            END IF;
        END IF;

        UPDATE public.sessions s SET
            started_at = least(s.started_at, e.first_ts),
            last_event_at = greatest(s.last_event_at, e.last_ts),
            ended_at = greatest(s.ended_at, e.ended),
            event_count = s.event_count + e.n,
            login_attempts = s.login_attempts + e.logins,
            login_success = s.login_success OR e.success,
            commands = s.commands + e.commands,
            downloads = s.downloads + e.downloads,
            http_requests = s.http_requests + e.http,
            tags = ARRAY(SELECT DISTINCT t FROM unnest(s.tags || v_tags) AS t ORDER BY t),
            techniques = ARRAY(
                SELECT DISTINCT t
                FROM unnest(coalesce(s.techniques, ARRAY[]::text[]) || v_techniques) AS t
                ORDER BY t LIMIT 64),
            benign = s.benign AND e.benign AND v_group IS NULL
        WHERE s.session_id = r.session_id;
        RETURN NEXT r.session_id;
    END LOOP;
END
$$
"""

# Same body as migration 0032. Only the three counts of sessions_daily change: a session is
# ``coalesce(sum(connections), 0)``, never a row count.
_BODY_HEAD = """
DECLARE
    days integer := COALESCE((config ->> 'retention_days')::integer, 90);
    cutoff timestamptz := date_trunc('day', now() - make_interval(days => days), 'UTC');
BEGIN
    -- Whole UTC days only, so each day is rolled up exactly once and then removed.
    INSERT INTO sessions_daily AS d (
        day, sensor, sessions, events, login_attempts, logins_succeeded, commands, downloads,
        http_requests, unique_ips
    )
"""

_SELECT_NEW = """
    SELECT (started_at AT TIME ZONE 'UTC')::date, sensor, coalesce(sum(connections), 0),
           sum(event_count), sum(login_attempts),
           coalesce(sum(connections) FILTER (WHERE login_success), 0), sum(commands),
           sum(downloads), sum(http_requests), count(DISTINCT src_ip)
"""

_SELECT_OLD = """
    SELECT (started_at AT TIME ZONE 'UTC')::date, sensor, count(*), sum(event_count),
           sum(login_attempts), count(*) FILTER (WHERE login_success), sum(commands),
           sum(downloads), sum(http_requests), count(DISTINCT src_ip)
"""

_BODY_TAIL = """
    FROM sessions WHERE started_at < cutoff
    GROUP BY 1, 2
    ON CONFLICT (day, sensor) DO UPDATE SET
        sessions = d.sessions + EXCLUDED.sessions,
        events = d.events + EXCLUDED.events,
        login_attempts = d.login_attempts + EXCLUDED.login_attempts,
        logins_succeeded = d.logins_succeeded + EXCLUDED.logins_succeeded,
        commands = d.commands + EXCLUDED.commands,
        downloads = d.downloads + EXCLUDED.downloads,
        http_requests = d.http_requests + EXCLUDED.http_requests,
        unique_ips = d.unique_ips + EXCLUDED.unique_ips;
    DELETE FROM sessions WHERE started_at < cutoff;
    -- Reputation answers are kept until they are refreshed (the worker re-checks one after
    -- REPUTATION_RECHECK_DAYS and the writer keeps using the last answer meanwhile). Only a row
    -- nobody refreshed for the whole retention window (90 days at least) is dropped.
    DELETE FROM ip_reputation
    WHERE GREATEST(updated_at, abuse_checked_at, gn_checked_at)
          < now() - make_interval(days => GREATEST(days, 90));
    DELETE FROM enrichment_quota WHERE day < (now() AT TIME ZONE 'UTC')::date - 30;
END
$$
"""


def _procedure(select: str) -> str:
    return (
        f"CREATE OR REPLACE PROCEDURE {MAINTENANCE_PROC}(job_id integer, config jsonb)\n"
        f"LANGUAGE plpgsql AS $$"
        f"{_BODY_HEAD}{select}{_BODY_TAIL}"
    )


def upgrade() -> None:
    # A volatile default is not needed: both defaults are constants, so the columns are added
    # without rewriting the table.
    op.execute("ALTER TABLE sessions ADD COLUMN kind text NOT NULL DEFAULT 'session'")
    op.execute("ALTER TABLE sessions ADD COLUMN connections integer NOT NULL DEFAULT 1")
    op.execute(
        "ALTER TABLE sessions ADD CONSTRAINT sessions_kind_check "
        "CHECK (kind IN ('session', 'burst'))"
    )
    op.execute(
        "ALTER TABLE sessions ADD CONSTRAINT sessions_burst_id_check "
        "CHECK ((kind = 'burst') = (session_id LIKE 'burst-%'))"
    )
    op.execute(
        "ALTER TABLE sessions ADD CONSTRAINT sessions_connections_check "
        "CHECK (connections >= 1 AND (kind = 'burst' OR connections = 1))"
    )
    op.execute(
        "CREATE INDEX ix_sessions_src_ip_sensor_started_at "
        "ON sessions (src_ip, sensor, started_at DESC)"
    )
    op.execute("DROP INDEX ix_sessions_src_ip")
    op.execute(
        "ALTER TABLE sessions SET (autovacuum_vacuum_scale_factor = 0.05, "
        "autovacuum_analyze_scale_factor = 0.05)"
    )
    op.execute(_FOLD)
    op.execute(f"REVOKE ALL ON FUNCTION {SIGNATURE} FROM PUBLIC")
    op.execute(_RESTORE)
    op.execute(f"REVOKE ALL ON FUNCTION {RESTORE_SIGNATURE} FROM PUBLIC")
    # CREATE OR REPLACE keeps the owner and the schedule of the TimescaleDB job.
    op.execute(_procedure(_SELECT_NEW))


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM sessions WHERE kind = 'burst') THEN
                RAISE EXCEPTION 'downgrade refused: flood groups exist (sessions.kind = burst). '
                    'The connections they stand for cannot be rebuilt. To go back anyway run '
                    'DELETE FROM sessions WHERE kind = ''burst'' (the events stay) and retry.';
            END IF;
        END
        $$
        """
    )
    # The procedure and the functions go first: the old body does not read the new columns.
    op.execute(_procedure(_SELECT_OLD))
    op.execute(f"DROP FUNCTION IF EXISTS {RESTORE_SIGNATURE}")
    op.execute(f"DROP FUNCTION IF EXISTS {SIGNATURE}")
    op.execute(
        "ALTER TABLE sessions RESET "
        "(autovacuum_vacuum_scale_factor, autovacuum_analyze_scale_factor)"
    )
    op.execute("CREATE INDEX ix_sessions_src_ip ON sessions (src_ip)")
    op.execute("DROP INDEX ix_sessions_src_ip_sensor_started_at")
    op.execute("ALTER TABLE sessions DROP CONSTRAINT sessions_connections_check")
    op.execute("ALTER TABLE sessions DROP CONSTRAINT sessions_burst_id_check")
    op.execute("ALTER TABLE sessions DROP CONSTRAINT sessions_kind_check")
    op.execute("ALTER TABLE sessions DROP COLUMN connections")
    op.execute("ALTER TABLE sessions DROP COLUMN kind")
