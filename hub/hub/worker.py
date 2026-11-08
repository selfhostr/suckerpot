"""The hub worker: ``python -m hub.worker [--once | --health]``.

Every cycle (hourly by default): built-in never-list entries, consensus, takedown votes,
never-list re-check, expiry, link verification tasks (when enabled), daily jobs (reputation,
statistics and the network summary), the public observatory (when enabled), retention, then
grouped reports (queue, auto-approve in ``auto`` mode, send what is approved), then the abuse.ch
submissions (same three steps) when a mode and an Auth-Key are set.
A failing step is logged by type only and never stops the others.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from . import abusech, consensus, egress_check, observatory, reputation, retention, stats, verify
from . import logging as hub_logging
from .config import Settings
from .db import make_engine, make_sessionmaker, utcnow
from .external import Corroborator
from .feeds import external as feed_ranges
from .feeds import job as feed_job
from .never import load_never
from .never_seed import ensure_seed
from .reports import select as report_select
from .reports import send as report_send
from .reports import tunnel as report_tunnel
from .reports.rdap import RdapDirectory, Resolver

log = logging.getLogger("hub.worker")

HEARTBEAT = "heartbeat"
STATS_MARKER = "stats_day"
OBSERVATORY_MARKER = "observatory_day"


@dataclass
class WorkerContext:
    settings: Settings
    sessionmaker: async_sessionmaker[AsyncSession]
    clock: Callable[[], datetime] = utcnow
    corroborate: consensus.Corroborate | None = None
    resolver: Resolver | None = None
    mailer: report_send.Mailer | None = None
    # Fetches the CDN and Tor ranges before the feed job. None (the default) never contacts
    # anything, so tests stay offline; main_async turns it on.
    # Sends one submission to abuse.ch. None (the default) never contacts anything.
    abusech_submit: abusech.Submitter | None = None
    ranges: Callable[[AsyncSession, Settings, datetime], Awaitable[dict[str, str]]] | None = None


@dataclass
class CycleReport:
    steps: dict[str, object] = field(default_factory=dict)
    failed: list[str] = field(default_factory=list)


async def _set_marker(session: AsyncSession, key: str, value: str) -> None:
    await session.execute(
        text(
            "INSERT INTO worker_state (key, value) VALUES (:k, :v) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {"k": key, "v": value},
    )
    await session.commit()


async def _get_marker(session: AsyncSession, key: str) -> str | None:
    row = (
        await session.execute(text("SELECT value FROM worker_state WHERE key = :k"), {"k": key})
    ).first()
    return str(row[0]) if row else None


async def run_cycle(ctx: WorkerContext) -> CycleReport:
    s = ctx.settings
    now = ctx.clock()
    today = now.date()
    out = CycleReport()

    async def step(name: str, fn: Callable[[AsyncSession], Awaitable[object]]) -> None:
        try:
            async with ctx.sessionmaker() as session:
                out.steps[name] = await fn(session)
        except Exception as exc:  # one failing step must not stop the others
            log.error("step %s failed: %s", name, type(exc).__name__)
            out.failed.append(name)

    await step("seed", lambda ses: ensure_seed(ses))
    holder: dict[str, object] = {}

    async def do_consensus(ses: AsyncSession) -> object:
        never = await load_never(ses)
        eligible = await consensus.eligible_nodes(ses, s, today)
        holder["never"], holder["eligible"] = never, eligible
        res = await consensus.run_consensus(
            ses, s, today, never=never, corroborate=ctx.corroborate, eligible=eligible
        )
        return {"groups": res.groups, "confirmed": res.confirmed, "candidates": res.candidates}

    await step("consensus", do_consensus)

    async def do_takedowns(ses: AsyncSession) -> object:
        eligible = holder.get("eligible")
        if not isinstance(eligible, dict):
            eligible = await consensus.eligible_nodes(ses, s, today)
        return await consensus.update_takedowns(ses, s, today, eligible)

    await step("takedowns", do_takedowns)

    async def do_never(ses: AsyncSession) -> object:
        never = await load_never(ses)
        return await consensus.recheck_never_list(ses, never, s, today)

    await step("never_recheck", do_never)
    await step("expire", lambda ses: consensus.expire_stale(ses, today))

    async def do_verify(ses: AsyncSession) -> object:
        res = await verify.run(ses, s, now, never=await load_never(ses))
        return {
            "created": res.created,
            "admitted": res.admitted,
            "refused": res.refused,
            "expired": res.expired,
            "self_attested": res.self_attested,
            "waiting": res.waiting,
        }

    if s.verify_enabled:
        await step("verify", do_verify)

    if ctx.ranges is not None:
        refresh_ranges = ctx.ranges
        await step("ranges", lambda ses: refresh_ranges(ses, s, now))

    async def do_feeds(ses: AsyncSession) -> object:
        return feed_job.summary(await feed_job.run_once(ses, s, now, corroborate=ctx.corroborate))

    await step("feeds", do_feeds)
    await step("reputation", lambda ses: reputation.run_daily(ses, s, today))

    async def do_stats(ses: AsyncSession) -> object:
        if await _get_marker(ses, STATS_MARKER) == today.isoformat():
            return "done_today"
        await stats.run_daily(ses, today)
        await _set_marker(ses, STATS_MARKER, today.isoformat())
        return "ran"

    await step("stats", do_stats)

    async def do_observatory(ses: AsyncSession) -> object:
        # Independent of HUB_FEED_MODE: only the directory is shared with the feeds.
        frozen = await observatory.freeze_days(ses, s, today)
        root = Path(s.feed_dir)
        published = await _get_marker(ses, OBSERVATORY_MARKER) == today.isoformat()
        if published and frozen == 0 and (root / observatory.FILE).exists():
            return {"frozen": 0, "published": False}
        data = observatory.render_bytes(await observatory.load(ses, s, today))
        await asyncio.to_thread(observatory.publish, root, data)
        await _set_marker(ses, OBSERVATORY_MARKER, today.isoformat())
        return {"frozen": frozen, "published": True}

    if s.observatory_enabled:
        await step("observatory", do_observatory)
    await step("retention", lambda ses: retention.run_retention(ses, s, now, today))

    if s.report_mode != "off" and ctx.resolver is not None:
        resolver = ctx.resolver

        async def do_queue(ses: AsyncSession) -> object:
            never = await load_never(ses)
            res = await report_select.queue_reports(ses, s, today, resolver=resolver, never=never)
            return {"queued": res.queued, "updated": res.updated, "skipped": res.skipped}

        await step("reports_queue", do_queue)
        await step("reports_approve", lambda ses: report_select.auto_approve(ses, s, today))
        if ctx.mailer is not None:
            mailer = ctx.mailer
            await step(
                "reports_send",
                lambda ses: report_send.send_due(ses, s, now, today, mailer),
            )

    if s.abusech_active:

        async def do_abusech_queue(ses: AsyncSession) -> object:
            res = await abusech.queue_submissions(ses, s, today, never=await load_never(ses))
            return {"queued": res.queued, "skipped": res.skipped}

        await step("abusech_queue", do_abusech_queue)
        await step("abusech_approve", lambda ses: abusech.auto_approve(ses, s, today))
        if ctx.abusech_submit is not None:
            submit = ctx.abusech_submit

            async def do_abusech_send(ses: AsyncSession) -> object:
                res = await abusech.send_due(ses, s, now, submit, never=await load_never(ses))
                return {"sent": res.sent, "failed": res.failed, "deferred": res.deferred}

            await step("abusech_send", do_abusech_send)

    async def beat(ses: AsyncSession) -> object:
        await _set_marker(ses, HEARTBEAT, now.isoformat())
        return None

    await step("heartbeat", beat)
    log.info("cycle done: failed=%s", ",".join(out.failed) or "none")
    return out


async def healthy(ctx: WorkerContext) -> bool:
    async with ctx.sessionmaker() as session:
        raw = await _get_marker(session, HEARTBEAT)
    if raw is None:
        return False
    return ctx.clock() - datetime.fromisoformat(raw) < timedelta(
        seconds=3 * ctx.settings.worker_interval_s
    )


async def main_async(argv: list[str]) -> int:
    s = Settings.from_env()
    engine = make_engine(s.worker_database_url)
    ctx = WorkerContext(settings=s, sessionmaker=make_sessionmaker(engine))
    try:
        if "--health" in argv:
            return 0 if await healthy(ctx) else 1
        if not egress_check.egress_ok(report_tunnel.proxy_url_from_env()):
            log.error("refusing to start: %s", egress_check.CODE)
            return 3
        corroborator = Corroborator(s)
        directory = RdapDirectory()
        ctx.corroborate = corroborator if corroborator.enabled else None
        ctx.resolver = directory.resolve
        ctx.mailer = report_send.smtp_mailer(s, ctx.clock)
        ctx.ranges = feed_ranges.refresh
        abusech_client = abusech.AbusechClient() if s.abusech_active else None
        if abusech_client is not None:
            ctx.abusech_submit = abusech_client.submit
        try:
            while True:
                await run_cycle(ctx)
                if "--once" in argv:
                    return 0
                await asyncio.sleep(s.worker_interval_s)
        finally:
            await corroborator.aclose()
            await directory.aclose()
            if abusech_client is not None:
                await abusech_client.aclose()
    finally:
        await engine.dispose()


def main() -> None:
    hub_logging.configure()
    sys.exit(asyncio.run(main_async(sys.argv[1:])))


if __name__ == "__main__":
    main()
