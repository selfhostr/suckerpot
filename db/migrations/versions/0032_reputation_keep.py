"""Keep reputation answers until they are refreshed.

Revision ID: 0032
Revises: 0031

The hourly maintenance job deleted every ``ip_reputation`` row that had not been refreshed for
48 hours. The worker looks an address up only when it has no row (or no answer), so after two
days every known address looked new again: the busiest ones were looked up over and over, the
daily quota never reached the quieter addresses, and the share of sessions with a score kept
falling. The job now keeps a row until nobody has refreshed it for the whole retention window
(at least 90 days), which still bounds the table.

Rows already lost are rebuilt from the sessions: every lookup writes its answer to all sessions
of the address, so ``sessions.abuse_score`` and ``sessions.known_scanner`` still hold it. The
check time is taken from the last event of those sessions (never in the future), and a row that
already exists is only completed, never overwritten.
"""

from collections.abc import Sequence

from alembic import op

from suckerpot_db.retention import MAINTENANCE_PROC

revision: str = "0032"
down_revision: str | None = "0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Same body as migration 0004 except for the ip_reputation statement.
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
    SELECT (started_at AT TIME ZONE 'UTC')::date, sensor, count(*), sum(event_count),
           sum(login_attempts), count(*) FILTER (WHERE login_success), sum(commands),
           sum(downloads), sum(http_requests), count(DISTINCT src_ip)
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
"""

_BODY_TAIL = """
    DELETE FROM enrichment_quota WHERE day < (now() AT TIME ZONE 'UTC')::date - 30;
END
$$
"""

_NEW_REPUTATION = """
    -- Reputation answers are kept until they are refreshed (the worker re-checks one after
    -- REPUTATION_RECHECK_DAYS and the writer keeps using the last answer meanwhile). Only a row
    -- nobody refreshed for the whole retention window (90 days at least) is dropped.
    DELETE FROM ip_reputation
    WHERE GREATEST(updated_at, abuse_checked_at, gn_checked_at)
          < now() - make_interval(days => GREATEST(days, 90));
"""

_OLD_REPUTATION = """
    -- Enrichment caches: reputation answers live 24 h, keep a day of grace.
    DELETE FROM ip_reputation
    WHERE GREATEST(updated_at, abuse_checked_at, gn_checked_at) < now() - INTERVAL '48 hours';
"""


def _procedure(reputation: str) -> str:
    return (
        f"CREATE OR REPLACE PROCEDURE {MAINTENANCE_PROC}(job_id integer, config jsonb)\n"
        f"LANGUAGE plpgsql AS $$"
        f"{_BODY_HEAD}{reputation}{_BODY_TAIL}"
    )


def upgrade() -> None:
    # CREATE OR REPLACE keeps the owner and the schedule of the TimescaleDB job.
    op.execute(_procedure(_NEW_REPUTATION))
    op.execute(
        """
        INSERT INTO ip_reputation (ip, abuse_score, abuse_checked_at)
        SELECT DISTINCT ON (src_ip) src_ip, abuse_score, least(last_event_at, now())
        FROM sessions WHERE abuse_score IS NOT NULL
        ORDER BY src_ip, last_event_at DESC
        ON CONFLICT (ip) DO UPDATE
            SET abuse_score = EXCLUDED.abuse_score,
                abuse_checked_at = EXCLUDED.abuse_checked_at
            WHERE ip_reputation.abuse_checked_at IS NULL
        """
    )
    op.execute(
        """
        INSERT INTO ip_reputation (ip, gn_noise, gn_checked_at)
        SELECT DISTINCT ON (src_ip) src_ip, known_scanner, least(last_event_at, now())
        FROM sessions WHERE known_scanner IS NOT NULL
        ORDER BY src_ip, last_event_at DESC
        ON CONFLICT (ip) DO UPDATE
            SET gn_noise = EXCLUDED.gn_noise,
                gn_checked_at = EXCLUDED.gn_checked_at
            WHERE ip_reputation.gn_checked_at IS NULL
        """
    )


def downgrade() -> None:
    # The rebuilt rows stay: they are real answers.
    op.execute(_procedure(_OLD_REPUTATION))
