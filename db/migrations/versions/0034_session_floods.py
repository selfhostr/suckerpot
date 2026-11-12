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
  ``suckerpot_db.roles``; nobody else can call it.
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
    "fold_session_buckets(inet[], text[], timestamptz[], integer, text[], interval, integer)"
)

# A plain connection is one nobody needs to read on its own: complete, no login success, no
# command, download or HTTP request, fewer than 20 login attempts (the credential-list campaign
# threshold, so a plain row is never clusterable), no campaign, no scanner name, not benign, only
# tags the caller calls plain, no indicator link. A source is flooding when its rows of one UTC
# hour sum to at least p_min connections, or when it already has a group the hour before. An hour
# with a demo event never folds. Rows are locked in session_id order and a locked row is skipped,
# never waited for; the sums come from DELETE ... RETURNING, so a row changed in the meantime is
# counted as it was deleted.
_FOLD = f"""
CREATE OR REPLACE FUNCTION fold_session_buckets(
    p_src inet[], p_sensor text[], p_hour timestamptz[], p_min integer, p_plain_tags text[],
    p_idle interval, p_limit integer
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
SET lock_timeout = '2s'
AS $$
DECLARE
    v_min integer := greatest(coalesce(p_min, 20), 5);
    v_idle interval := greatest(coalesce(p_idle, interval '15 minutes'), interval '5 minutes');
    v_limit integer := least(greatest(coalesce(p_limit, 1000), 1), 5000);
    v_tags text[] := coalesce(p_plain_tags, ARRAY[]::text[]);
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
    IF NOT pg_try_advisory_xact_lock({SESSION_FOLD}) THEN
        RETURN 0;
    END IF;

    WITH req AS (
        SELECT DISTINCT b.src, b.sensor, date_trunc('hour', b.hr, 'UTC') AS hr
        FROM unnest(p_src, p_sensor, p_hour) AS b(src, sensor, hr)
        WHERE b.src IS NOT NULL AND b.sensor IS NOT NULL AND b.hr IS NOT NULL
    ),
    hot AS (
        SELECT r.src, r.sensor, r.hr FROM req r
        WHERE (
            (SELECT coalesce(sum(x.connections), 0) FROM public.sessions x
             WHERE x.src_ip = r.src AND x.sensor = r.sensor
               AND x.started_at >= r.hr AND x.started_at < r.hr + interval '1 hour') >= v_min
            OR EXISTS (SELECT 1 FROM public.sessions g
                       WHERE g.kind = 'burst' AND g.src_ip = r.src AND g.sensor = r.sensor
                         AND g.started_at >= r.hr - interval '1 hour' AND g.started_at < r.hr)
        )
        AND NOT EXISTS (SELECT 1 FROM public.events e
                        WHERE e.src_ip = r.src AND e.sensor = r.sensor
                          AND e.ts >= r.hr AND e.ts < r.hr + interval '1 hour'
                          AND coalesce(e.data ->> 'demo', 'false') = 'true')
    ),
    victims AS (
        SELECT s.session_id
        FROM hot h
        JOIN public.sessions s ON s.src_ip = h.src AND s.sensor = h.sensor
             AND s.started_at >= h.hr AND s.started_at < h.hr + interval '1 hour'
        WHERE s.kind = 'session' AND NOT s.benign AND s.scanner_name IS NULL
          AND NOT s.login_success AND s.commands = 0 AND s.downloads = 0 AND s.http_requests = 0
          AND s.login_attempts < 20 AND s.campaign_id IS NULL AND s.tags <@ v_tags
          AND (s.ended_at IS NOT NULL OR s.last_event_at < now() - v_idle)
          AND NOT EXISTS (SELECT 1 FROM public.indicator_sessions i
                          WHERE i.src_ip = s.src_ip AND i.session_id = s.session_id)
        ORDER BY s.session_id
        LIMIT v_limit
        FOR UPDATE OF s SKIP LOCKED
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
    # The procedure and the function go first: the old body does not read the new columns.
    op.execute(_procedure(_SELECT_OLD))
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
