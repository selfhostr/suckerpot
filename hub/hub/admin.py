"""Operator CLI: ``python -m hub.admin <command>``. No web admin: a smaller attack surface.

Commands: gen-signing-key, gen-feed-key, show-public-key, reports list|show|approve|cancel,
abusech list|approve|reject|cancel, target dispute, never add|remove|list,
node suspend|unsuspend|role grant|role revoke|roles, verify status|list|show|approve|refuse,
stats, feeds
status|diff|release|discard|pause|resume|rebuild, allow add|remove|list, delist
list|show|accept|reject, ranges status|refresh. Every change writes ``hub_audit`` with the action
and counts only (no node data, no addresses). Key generation touches no database.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Callable
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_netproto import blind, sign
from suckerpot_netproto.feeds import minisign

from . import abusech, dormant, egress_check, reputation
from .config import ConfigError, Settings, load_signing_key
from .db import make_engine, make_sessionmaker, utcnow
from .feeds import job as feed_job
from .feeds.select import BASE_LISTS as DELIST_LISTS
from .reports import tunnel as report_tunnel

Out = Callable[[str], None]


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hub.admin")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-signing-key", help="make the hub signing key and print its public part")
    g.add_argument("--out", help="file to write (mode 0400); with --alt defaults to the alt file")
    g.add_argument("--force", action="store_true", help="overwrite an existing file")
    g.add_argument(
        "--alt",
        action="store_true",
        help="make the alternate key for a rollover; never overwrites, even with --force",
    )

    k = sub.add_parser("show-public-key", help="print the public key of a signing key file")
    k.add_argument("--key-file", default=os.environ.get("HUB_SIGNING_KEY_FILE", ""))
    k.add_argument("--alt-key-file", default=os.environ.get("HUB_SIGNING_KEY_ALT_FILE", ""))
    k.add_argument("--all", action="store_true", help="print the primary and alternate keys")

    r = sub.add_parser("reports")
    rs = r.add_subparsers(dest="action", required=True)
    rl = rs.add_parser("list")
    rl.add_argument("--state", choices=["queued", "approved", "sent", "failed", "cancelled"])
    for name in ("show", "approve", "cancel"):
        rs.add_parser(name).add_argument("id", type=int)

    ab = sub.add_parser("abusech")
    abs_ = ab.add_subparsers(dest="action", required=True)
    abl = abs_.add_parser("list")
    abl.add_argument("--state", choices=["queued", "approved", "sent", "failed", "rejected"])
    for name in ("approve", "reject"):
        abs_.add_parser(name).add_argument("id", type=int)
    abc = abs_.add_parser(
        "cancel", help="withdraw unsent submissions: one id, or every verified (path B) one"
    )
    abc.add_argument("id", type=int, nargs="?")
    abc.add_argument("--all-verified", action="store_true")

    t = sub.add_parser("target")
    ts = t.add_subparsers(dest="action", required=True)
    td = ts.add_parser("dispute")
    td.add_argument("id")
    td.add_argument("--note", required=True)

    n = sub.add_parser("never")
    ns = n.add_subparsers(dest="action", required=True)
    na = ns.add_parser("add")
    na.add_argument("value")
    na.add_argument("--kind", choices=["ip", "domain", "sha256"])
    na.add_argument("--note", default="")
    ns.add_parser("remove").add_argument("value")
    ns.add_parser("list")

    nd = sub.add_parser("node")
    nds = nd.add_subparsers(dest="action", required=True)
    for name in ("suspend", "unsuspend"):
        nds.add_parser(name).add_argument("fingerprint")
    ndr = nds.add_parser("role", help="grant or revoke a node role")
    ndrs = ndr.add_subparsers(dest="role_action", required=True)
    for name in ("grant", "revoke"):
        rp = ndrs.add_parser(name)
        rp.add_argument("fingerprint")
        rp.add_argument("role", choices=sorted(NODE_ROLES))
    nds.add_parser("roles", help="list the nodes that hold a role")

    vf = sub.add_parser("verify", help="link verification tasks (M32)")
    vfs = vf.add_subparsers(dest="action", required=True)
    vfs.add_parser("status")
    vl = vfs.add_parser("list")
    vl.add_argument("--state", choices=sorted(VERIFY_STATES))
    vfs.add_parser("show").add_argument("id")
    vfs.add_parser("approve").add_argument("id")
    vr = vfs.add_parser("refuse", aliases=["reject"])
    vr.add_argument("id")
    vr.add_argument("--note", required=True)
    vr.add_argument(
        "--abuse",
        action="store_true",
        help="also dispute the url candidate (lowers its contributors' reputation)",
    )

    sub.add_parser("stats")

    fk = sub.add_parser(
        "gen-feed-key", help="make the feed signing key (minisign) and print its public part"
    )
    fk.add_argument("--out", required=True, help="file to write (mode 0600)")
    fk.add_argument("--force", action="store_true", help="overwrite an existing file")

    f = sub.add_parser("feeds")
    fs = f.add_subparsers(dest="action", required=True)
    for name in ("status", "pause", "resume", "rebuild"):
        fs.add_parser(name)
    for name in ("diff", "release", "discard"):
        fs.add_parser(name).add_argument("serial", type=int)

    a = sub.add_parser("allow")
    als = a.add_subparsers(dest="action", required=True)
    aa = als.add_parser("add")
    aa.add_argument("value", help="an address, a CIDR or a domain (suffix match)")
    aa.add_argument("--reason", required=True, choices=sorted(ALLOW_REASONS))
    aa.add_argument("--expires", help="a date (YYYY-MM-DD) or a number of days")
    aa.add_argument("--note", default="")
    als.add_parser("remove").add_argument("value")
    als.add_parser("list")

    d = sub.add_parser("delist")
    ds = d.add_subparsers(dest="action", required=True)
    dl = ds.add_parser("list")
    dl.add_argument("--state", choices=["received", "suppressed", "accepted", "rejected"])
    ds.add_parser("show").add_argument("id")
    da = ds.add_parser("accept")
    da.add_argument("id")
    da.add_argument(
        "--as", dest="outcome", required=True, choices=["false_positive", "remediated", "policy"]
    )
    da.add_argument("--note", required=True, help="PUBLIC: shown to the requester")
    da.add_argument(
        "--list",
        dest="list_id",
        choices=DELIST_LISTS,
        help="apply the decision to this list only (narrows a request that covers every list)",
    )
    dr = ds.add_parser("reject")
    dr.add_argument("id")
    dr.add_argument("--note", required=True, help="PUBLIC: shown to the requester")

    rg = sub.add_parser("ranges")
    rgs = rg.add_subparsers(dest="action", required=True)
    rgs.add_parser("status")
    rgs.add_parser("refresh")
    return p


NODE_ROLES = frozenset({"verifier"})
VERIFY_STATES = frozenset(
    {
        "waiting_reveal", "pending_review", "queued", "leased", "attested", "failed", "refused",
        "expired",
    }
)  # fmt: skip
# States in which the clear link may be shown to the operator (design 7.5).
VERIFY_SHOW_URL = frozenset({"pending_review", "queued", "leased"})
# States an operator may still refuse (a leased task is left to finish or expire).
VERIFY_REFUSABLE = frozenset({"waiting_reveal", "pending_review", "queued", "attested"})
ALLOW_REASONS = frozenset(
    {"owner_request", "shared_infra", "remediated", "policy", "false_positive"}
)
EXPIRING_REASONS = frozenset({"remediated", "owner_request"})
DEFAULT_EXPIRY_DAYS = 90
NOTE_MAX = 500


def _safe(text_: object) -> str:
    """Operator output: requester text is untrusted, so control characters never reach a terminal."""
    return "".join(
        c if c.isprintable() or c in "\n " else "?" for c in str(text_ if text_ is not None else "")
    )


def _kind_of(value: str) -> str:
    import ipaddress

    try:
        ipaddress.ip_network(value, strict=False)
        return "ip"
    except ValueError:
        pass
    if len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value):
        return "sha256"
    return "domain"


async def _audit(
    session: AsyncSession, actor: str, action: str, detail: dict[str, Any] | None = None
) -> None:
    await session.execute(
        text("INSERT INTO hub_audit (actor, action, detail) VALUES (:a, :b, CAST(:d AS jsonb))"),
        {"a": actor, "b": action, "d": json.dumps(detail or {})},
    )


def gen_signing_key(out_path: str, force: bool, out: Out, *, alt: bool = False) -> int:
    if alt:
        force = False  # a rollover key is never replaced: the old one may still be pinned
    path = Path(out_path)
    seed = sign.generate_private_key()
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    try:
        if force and path.exists():
            path.chmod(0o600)
        fd = os.open(path, flags, 0o400)
    except FileExistsError:
        out("refusing to overwrite an existing key file (use --force)")
        return 1
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(sign.b64u_encode(seed) + "\n")
    path.chmod(0o400)
    out(f"{'hub_key_alt' if alt else 'hub_key'}={sign.node_key(sign.public_key_of(seed))}")
    return 0


def gen_feed_key(out_path: str, force: bool, out: Out) -> int:
    """Write a minisign secret key (mode 0600) and print the public key only."""
    path = Path(out_path)
    secret = minisign.generate_keypair()
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    try:
        if force and path.exists():
            path.chmod(0o600)
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        out("refusing to overwrite an existing key file (use --force)")
        return 1
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(minisign.serialize_secret_key(secret))
    path.chmod(0o600)
    out(f"feed_public_key={secret.public.encoded}")
    out(f"feed_key_id={secret.public.key_id_hex}")
    return 0


async def run(
    argv: list[str],
    *,
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
    out: Out = print,
    actor: str | None = None,
    settings: Settings | None = None,
) -> int:
    args = _parser().parse_args(argv)
    if args.cmd == "gen-signing-key":
        target = args.out or (os.environ.get("HUB_SIGNING_KEY_ALT_FILE", "") if args.alt else "")
        if not target:
            out("give --out (or set HUB_SIGNING_KEY_ALT_FILE with --alt)")
            return 2
        return gen_signing_key(target, args.force, out, alt=args.alt)
    if args.cmd == "gen-feed-key":
        return gen_feed_key(args.out, args.force, out)
    if args.cmd == "show-public-key":
        try:
            seed = load_signing_key(args.key_file)
        except ConfigError as exc:
            out(str(exc))
            return 1
        out(f"hub_key={sign.node_key(sign.public_key_of(seed))}")
        if args.all:
            if not args.alt_key_file:
                out("hub_key_alt=none")
            else:
                try:
                    alt = load_signing_key(args.alt_key_file)
                except ConfigError as exc:
                    out(str(exc))
                    return 1
                out(f"hub_key_alt={sign.node_key(sign.public_key_of(alt))}")
        return 0

    engine = None
    if sessionmaker is None:
        settings = settings or Settings.from_env()
        engine = make_engine(settings.worker_database_url)
        sessionmaker = make_sessionmaker(engine)
    who = actor or os.environ.get("HUB_ADMIN_ACTOR", "cli")
    try:
        async with sessionmaker() as session:
            return await _dispatch(args, session, who, out, settings)
    finally:
        if engine is not None:
            await engine.dispose()


async def _dispatch(
    args: argparse.Namespace,
    session: AsyncSession,
    who: str,
    out: Out,
    settings: Settings | None = None,
) -> int:
    if args.cmd == "feeds":
        return await _feeds(args, session, who, out, settings)
    if args.cmd == "allow":
        return await _allow(args, session, who, out)
    if args.cmd == "delist":
        return await _delist(args, session, who, out)
    if args.cmd == "ranges":
        return await _ranges(args, session, who, out, settings)
    if args.cmd == "reports":
        return await _reports(args, session, who, out)
    if args.cmd == "abusech":
        return await _abusech(args, session, who, out)
    if args.cmd == "target":
        penalised = await reputation.dispute(session, args.id)
        await abusech.withdraw_target(session, args.id)
        await _audit(
            session, who, "target.dispute", {"penalised": penalised, "note": args.note[:200]}
        )
        await session.commit()
        out(f"disputed {args.id}; {penalised} contributors lowered")
        return 0
    if args.cmd == "never":
        return await _never(args, session, who, out)
    if args.cmd == "verify":
        return await _verify(args, session, who, out, settings)
    if args.cmd == "node" and args.action in ("role", "roles"):
        return await _node_roles(args, session, who, out)
    if args.cmd == "node":
        state = "soft_suspended" if args.action == "suspend" else "active"
        result = await session.execute(
            text(
                "UPDATE nodes SET standing = :s WHERE substr(encode(sha256(pubkey), 'hex'), 1, 8) = :fp"
            ),
            {"s": state, "fp": args.fingerprint.lower()},
        )
        count = int(getattr(result, "rowcount", 0) or 0)
        await _audit(session, who, f"node.{args.action}", {"nodes": count})
        await session.commit()
        out(f"{args.action}: {count} node(s)")
        return 0 if count else 1
    if args.cmd == "stats":
        rows = (
            await session.execute(
                text(
                    "SELECT (SELECT count(*) FROM nodes) AS nodes, "  # noqa: S608
                    f"(SELECT count(*) FROM nodes n WHERE NOT {dormant.ACTIVE}) AS dormant, "
                    "(SELECT count(*) FROM nodes WHERE standing = 'soft_suspended') AS suspended, "
                    "(SELECT count(*) FROM targets WHERE state = 'candidate') AS candidates, "
                    "(SELECT count(*) FROM targets WHERE state = 'confirmed') AS confirmed, "
                    "(SELECT count(*) FROM targets WHERE state = 'reported') AS reported, "
                    "(SELECT count(*) FROM targets WHERE state = 'taken_down') AS taken_down, "
                    "(SELECT count(*) FROM reports WHERE state = 'queued') AS reports_queued"
                ),
                dormant.params(utcnow().date()),
            )
        ).one()
        for key, value in rows._mapping.items():
            out(f"{key}: {value}")
        return 0
    return 2


async def _reports(args: argparse.Namespace, session: AsyncSession, who: str, out: Out) -> int:
    if args.action == "list":
        sql = (
            "SELECT id, state, kind, recipient, array_length(target_ids, 1) AS n, created_day, "
            "(SELECT count(*) FROM abusech_submissions a WHERE a.target_id = ANY(reports.target_ids) "
            "AND a.state IN ('queued', 'approved', 'sent')) AS ab FROM reports"
        )
        params: dict[str, Any] = {}
        if args.state:
            sql += " WHERE state = :s"
            params["s"] = args.state
        for r in (await session.execute(text(sql + " ORDER BY id DESC LIMIT 200"), params)).all():
            mark = f"\tabuse.ch: {r.ab}" if r.ab else ""
            out(
                f"{r.id}\t{r.state}\t{r.kind}\t{r.recipient}\t{r.n} target(s)\t{r.created_day}{mark}"
            )
        return 0
    row = (
        await session.execute(
            text("SELECT id, state, body_text, xarf FROM reports WHERE id = :id"), {"id": args.id}
        )
    ).first()
    if row is None:
        out("no such report")
        return 1
    if args.action == "show":
        out(f"state: {row.state}\n\n{row.body_text}")
        if row.xarf:
            out("\n--- X-ARF ---\n" + row.xarf)
        return 0
    if args.action == "approve":
        if row.state != "queued":
            out(f"only a queued report can be approved (this one is {row.state})")
            return 1
        await session.execute(
            text("UPDATE reports SET state = 'approved', approved_by = :w WHERE id = :id"),
            {"w": who, "id": args.id},
        )
        await _audit(session, who, "report.approve", {"report": args.id})
        await session.commit()
        out(f"approved {args.id}; it is sent by the next worker cycle")
        return 0
    if row.state not in ("queued", "approved"):
        out(f"only a queued or approved report can be cancelled (this one is {row.state})")
        return 1
    await session.execute(
        text("UPDATE reports SET state = 'cancelled' WHERE id = :id"), {"id": args.id}
    )
    await _audit(session, who, "report.cancel", {"report": args.id})
    await session.commit()
    out(f"cancelled {args.id}")
    return 0


async def _abusech(args: argparse.Namespace, session: AsyncSession, who: str, out: Out) -> int:
    if args.action == "list":
        sql = (
            "SELECT id, state, kind, basis, indicator, malware, result_code, created_day "
            "FROM abusech_submissions"
        )
        params: dict[str, Any] = {}
        if args.state:
            sql += " WHERE state = :s"
            params["s"] = args.state
        for r in (await session.execute(text(sql + " ORDER BY id DESC LIMIT 200"), params)).all():
            out(
                f"{r.id}\t{r.state}\t{r.kind}\t{r.basis}\t{_safe(r.indicator)}\t{r.malware or '-'}"
                f"\t{r.result_code or '-'}\t{r.created_day}"
            )
        return 0
    if args.action == "cancel":
        return await _abusech_cancel(args, session, who, out)
    row = (
        await session.execute(
            text("SELECT id, state FROM abusech_submissions WHERE id = :id"), {"id": args.id}
        )
    ).first()
    if row is None:
        out("no such submission")
        return 1
    if args.action == "approve":
        if row.state != "queued":
            out(f"only a queued submission can be approved (this one is {row.state})")
            return 1
        await session.execute(
            text(
                "UPDATE abusech_submissions SET state = 'approved', approved_by = :w, "
                "approved_manually = true WHERE id = :id"
            ),
            {"w": who, "id": args.id},
        )
        await _audit(session, who, "abusech.approve", {"submission": args.id})
        await session.commit()
        out(f"approved {args.id}; it is sent by the next worker cycle")
        return 0
    if row.state not in ("queued", "approved"):
        out(f"only a queued or approved submission can be rejected (this one is {row.state})")
        return 1
    await session.execute(
        text("UPDATE abusech_submissions SET state = 'rejected' WHERE id = :id"), {"id": args.id}
    )
    await _audit(session, who, "abusech.reject", {"submission": args.id})
    await session.commit()
    out(f"rejected {args.id}")
    return 0


async def _abusech_cancel(
    args: argparse.Namespace, session: AsyncSession, who: str, out: Out
) -> int:
    """Withdraw unsent submissions: one by id, or every verified one (a verifier is distrusted)."""
    if args.all_verified == (args.id is not None):
        out("give exactly one of: a submission id, --all-verified")
        return 2
    if args.all_verified:
        count = await abusech.withdraw_verified(session)
    else:
        res = await session.execute(
            text(
                "UPDATE abusech_submissions SET state = 'rejected', result_code = :c "
                "WHERE id = :id AND state IN ('queued', 'approved')"
            ),
            {"c": abusech.WITHDRAWN, "id": args.id},
        )
        count = int(getattr(res, "rowcount", 0) or 0)
    await _audit(session, who, "abusech.cancel", {"submissions": count, "all": args.all_verified})
    await session.commit()
    out(f"cancelled {count} submission(s)")
    return 0 if count else 1


async def _node_roles(args: argparse.Namespace, session: AsyncSession, who: str, out: Out) -> int:
    if args.action == "roles":
        rows = (
            await session.execute(
                text(
                    "SELECT substr(encode(sha256(n.pubkey), 'hex'), 1, 8) AS fp, r.role, "
                    "r.granted_day FROM node_roles r JOIN nodes n ON n.id = r.node_id "
                    "ORDER BY r.granted_day, fp"
                )
            )
        ).all()
        for r in rows:
            out(f"{r.fp}\t{r.role}\t{r.granted_day}")
        return 0
    fp = args.fingerprint.lower()
    ids = [
        r.id
        for r in await session.execute(
            text("SELECT id FROM nodes WHERE substr(encode(sha256(pubkey), 'hex'), 1, 8) = :fp"),
            {"fp": fp},
        )
    ]
    if len(ids) != 1:
        out("no node has that fingerprint" if not ids else "the fingerprint is ambiguous")
        return 1
    if args.role_action == "grant":
        res = await session.execute(
            text(
                "INSERT INTO node_roles (node_id, role, granted_day) VALUES (:n, :r, :d) "
                "ON CONFLICT DO NOTHING"
            ),
            {"n": ids[0], "r": args.role, "d": utcnow().date()},
        )
        granted = int(getattr(res, "rowcount", 0) or 0)
        await _audit(session, who, "node.role.grant", {"role": args.role, "granted": granted})
        await session.commit()
        out(f"granted {args.role}" if granted else f"already holds {args.role}")
        return 0
    res = await session.execute(
        text("DELETE FROM node_roles WHERE node_id = :n AND role = :r"),
        {"n": ids[0], "r": args.role},
    )
    revoked = int(getattr(res, "rowcount", 0) or 0)
    released = withdrawn = 0
    if revoked and args.role == "verifier":
        # Its open leases go back to the queue; verified submissions nobody else vouches for are
        # withdrawn (a send is also re-checked against the role just before it leaves).
        rel = await session.execute(
            text(
                "UPDATE verify_tasks SET state = 'queued', release_at = NULL, lease_node = NULL, "
                "lease_until = NULL WHERE lease_node = :n AND state = 'leased'"
            ),
            {"n": ids[0]},
        )
        released = int(getattr(rel, "rowcount", 0) or 0)
        withdrawn = await abusech.withdraw_unattested(session)
    await _audit(
        session,
        who,
        "node.role.revoke",
        {
            "role": args.role,
            "revoked": revoked,
            "leases_released": released,
            "withdrawn": withdrawn,
        },
    )
    await session.commit()
    out(f"revoked {args.role}; {released} lease(s) released, {withdrawn} submission(s) withdrawn")
    return 0 if revoked else 1


async def _verify(
    args: argparse.Namespace,
    session: AsyncSession,
    who: str,
    out: Out,
    settings: Settings | None,
) -> int:
    s = settings or Settings()
    today = utcnow().date()
    if args.action == "status":
        out(f"mode: {s.verify_mode}")
        for r in await session.execute(
            text("SELECT state, count(*) AS n FROM verify_tasks GROUP BY state ORDER BY state")
        ):
            out(f"{r.state}: {r.n}")
        admitted = (
            await session.execute(
                text(
                    "SELECT count(*) FROM verify_tasks WHERE revealed_day = :d AND url IS NOT NULL "
                    "AND state NOT IN ('waiting_reveal', 'refused')"
                ),
                {"d": today},
            )
        ).scalar_one()
        out(
            f"admitted today: {admitted} of {s.verify_daily_cap} (per site: {s.verify_host_daily_cap})"
        )
        return 0
    if args.action == "list":
        sql = (
            "SELECT id, state, site, reporters, reporter_cohorts, last_report_day, release_at "
            "FROM verify_tasks"
        )
        params: dict[str, Any] = {}
        if args.state:
            sql += " WHERE state = :s"
            params["s"] = args.state
        for r in await session.execute(
            text(sql + " ORDER BY created_day DESC, id LIMIT 200"), params
        ):
            out(
                f"{r.id}\t{r.state}\t{_safe(r.site or '-')}\t{r.reporters}/{r.reporter_cohorts}"
                f"\t{r.last_report_day}\t{r.release_at.isoformat() if r.release_at else '-'}"
            )
        return 0
    task = (
        await session.execute(
            text(
                "SELECT id, state, url, site, refusal, reporters, reporter_cohorts, "
                "last_report_day, created_day, revealed_day, release_at, attempts, ended_day "
                "FROM verify_tasks WHERE id = :i FOR UPDATE"
            ),
            {"i": args.id},
        )
    ).first()
    if task is None:
        out("no such task")
        return 1
    if args.action == "show":
        for key in ("id", "state", "site", "refusal", "reporters", "reporter_cohorts",
                    "last_report_day", "created_day", "revealed_day", "release_at", "attempts",
                    "ended_day"):  # fmt: skip
            out(f"{key}: {_safe(getattr(task, key))}")
        if task.state in VERIFY_SHOW_URL:
            out(f"url: {_safe(task.url)}")
        for a in await session.execute(
            text(
                "SELECT outcome, file_type, family, malware_like, day FROM verify_attestations "
                "WHERE task_id = :i ORDER BY day"
            ),
            {"i": args.id},
        ):
            out(
                f"attestation: {a.day} {a.outcome} type={a.file_type or '-'} "
                f"family={a.family or '-'} malware_like={a.malware_like}"
            )
        return 0
    if args.action == "approve":
        if task.state != "pending_review" or not task.url:
            out(f"only a pending_review task can be approved (this one is {task.state})")
            return 1
        await session.execute(
            text("UPDATE verify_tasks SET state = 'queued', release_at = NULL WHERE id = :i"),
            {"i": args.id},
        )
        await _audit(session, who, "verify.approve", {"task": args.id})
        await session.commit()
        out(f"approved {args.id}; a verifier can lease it now")
        return 0
    # refuse
    if task.state not in VERIFY_REFUSABLE:
        out(f"a {task.state} task cannot be refused")
        return 1
    await session.execute(
        text(
            "UPDATE verify_tasks SET state = 'refused', refusal = 'operator', ended_day = :d, "
            "release_at = NULL WHERE id = :i"
        ),
        {"d": today, "i": args.id},
    )
    withdrawn = await abusech.withdraw_task(session, args.id)
    await _audit(
        session,
        who,
        "verify.refuse",
        {"task": args.id, "abuse": args.abuse, "withdrawn": withdrawn, "note": args.note[:200]},
    )
    penalised = 0
    if args.abuse:
        target = (
            await session.execute(
                text(
                    "SELECT t.id FROM targets t JOIN verify_tasks v ON v.url_b = t.value_b "
                    "WHERE v.id = :i AND t.kind = 'url'"
                ),
                {"i": args.id},
            )
        ).first()
        if target is not None:
            withdrawn += await abusech.withdraw_target(session, target.id)
            penalised = await reputation.dispute(session, target.id)  # commits
    await session.commit()
    out(f"refused {args.id}; {withdrawn} submission(s) withdrawn, {penalised} contributors lowered")
    return 0


async def _never(args: argparse.Namespace, session: AsyncSession, who: str, out: Out) -> int:
    if args.action == "list":
        for r in (
            await session.execute(
                text("SELECT value, kind, note FROM never_list ORDER BY kind, value")
            )
        ).all():
            out(f"{r.kind}\t{r.value}\t{r.note or ''}")
        return 0
    if args.action == "add":
        kind = args.kind or _kind_of(args.value)
        value = (
            blind.canonical_domain(args.value) if kind == "domain" else args.value.strip().lower()
        )
        await session.execute(
            text(
                "INSERT INTO never_list (value, kind, note) VALUES (:v, :k, :n) "
                "ON CONFLICT (value) DO UPDATE SET kind = EXCLUDED.kind, note = EXCLUDED.note"
            ),
            {"v": value, "k": kind, "n": args.note[:200]},
        )
        await _audit(session, who, "never.add", {"kind": kind})
        await session.commit()
        out(f"added {kind} {value}")
        return 0
    result = await session.execute(
        text("DELETE FROM never_list WHERE value = :v"), {"v": args.value.strip().lower()}
    )
    removed = int(getattr(result, "rowcount", 0) or 0)
    await _audit(session, who, "never.remove", {"removed": removed})
    await session.commit()
    out(f"removed {removed}")
    return 0 if removed else 1


async def _state(session: AsyncSession, key: str) -> str | None:
    row = (
        await session.execute(text("SELECT value FROM worker_state WHERE key = :k"), {"k": key})
    ).first()
    return str(row[0]) if row else None


SLA_DAYS = 3  # the 72 h delisting SLA, in whole days (requests hold days, never times)


async def _overdue_warning(session: AsyncSession, out: Out) -> None:
    """One line when open delisting requests are past the 72 h SLA (counts and a day only)."""
    row = (
        await session.execute(
            text(
                "SELECT count(*) AS n, min(created_day) AS oldest FROM delist_requests "
                "WHERE decided_day IS NULL AND created_day < :due"
            ),
            {"due": utcnow().date() - timedelta(days=SLA_DAYS)},
        )
    ).one()
    if row.n:
        out(
            f"WARNING: {row.n} open delisting request(s) past the 72 h SLA, oldest from "
            f"{row.oldest}; see `delist list --state received` and `--state suppressed`"
        )


async def _feeds(
    args: argparse.Namespace, session: AsyncSession, who: str, out: Out, settings: Settings | None
) -> int:
    # release, discard, pause and resume write hub_audit themselves (feeds.job).
    if args.action == "status":
        out(f"paused: {await _state(session, feed_job.PAUSED_KEY) == '1'}")
        await _overdue_warning(session, out)
        out(f"last status: {_safe(await _state(session, feed_job.STATUS_KEY))}")
        rows = await session.execute(
            text(
                "SELECT serial, state, run_at, error_code FROM feed_runs "
                "ORDER BY serial DESC LIMIT 10"
            )
        )
        for r in rows:
            out(f"{r.serial}\t{r.state}\t{r.run_at.isoformat()}\t{r.error_code or ''}")
        return 0
    if args.action == "diff":
        diff = (
            await session.execute(
                text("SELECT diff FROM feed_runs WHERE serial = :s AND state = 'held'"),
                {"s": args.serial},
            )
        ).scalar_one_or_none()
        if diff is None:
            out("no held run with that serial")
            return 1
        out(_safe(json.dumps(diff, indent=2, sort_keys=True)))
        return 0
    if args.action in ("release", "discard"):
        hook = feed_job.release if args.action == "release" else feed_job.discard
        if not await hook(session, args.serial):
            out("no held run with that serial")
            return 1
        out(f"{args.action}d {args.serial}; the next feed run applies it")
        return 0
    if args.action in ("pause", "resume"):
        await feed_job.set_paused(session, args.action == "pause")
        out(args.action + "d")
        return 0
    result = await feed_job.run_once(session, settings or Settings.from_env(), utcnow(), force=True)
    await _audit(session, who, "feeds.rebuild", {"state": result.state})
    await session.commit()
    out(f"{result.state} serial={result.serial} error={result.error_code or ''}")
    return 0 if result.state in ("published", "unchanged", "held") else 1


def _parse_expiry(raw: str | None, reason: str, today: date) -> date | None:
    if raw:
        if raw.isdigit():
            return today + timedelta(days=int(raw))
        return date.fromisoformat(raw)
    return today + timedelta(days=DEFAULT_EXPIRY_DAYS) if reason in EXPIRING_REASONS else None


def _allow_value(raw: str) -> tuple[str, str]:
    """``(canonical value, kind)``; CIDRs are fine here, allowing is safe."""
    import ipaddress

    value = raw.strip()
    kind = _kind_of(value)
    if kind == "ip":
        net = ipaddress.ip_network(value, strict=False)
        return (str(net.network_address) if net.num_addresses == 1 else str(net)), kind
    if kind == "domain":
        return blind.canonical_domain(value), kind
    raise ValueError("an address, a CIDR or a domain is required")


async def _allow(args: argparse.Namespace, session: AsyncSession, who: str, out: Out) -> int:
    if args.action == "list":
        rows = await session.execute(
            text(
                "SELECT value, kind, reason, source, list, expires_day, note FROM feed_allow "
                "ORDER BY kind, value"
            )
        )
        for r in rows:
            out(
                f"{r.kind}\t{_safe(r.value)}\t{r.reason}\t{r.source}\t{r.list or 'all lists'}\t"
                f"{r.expires_day or 'never'}\t{_safe(r.note)}"
            )
        return 0
    if args.action == "add":
        try:
            value, kind = _allow_value(args.value)
            expires = _parse_expiry(args.expires, args.reason, utcnow().date())
        except ValueError as exc:
            out(_safe(exc))
            return 1
        await session.execute(
            text(
                "INSERT INTO feed_allow (value, kind, reason, note, added_day, expires_day, source) "
                "VALUES (:v, :k, :r, :n, :t, :e, 'admin') ON CONFLICT (value) DO UPDATE SET "
                "kind = EXCLUDED.kind, reason = EXCLUDED.reason, note = EXCLUDED.note, "
                "added_day = EXCLUDED.added_day, expires_day = EXCLUDED.expires_day, "
                "source = EXCLUDED.source, list = NULL"
            ),
            {
                "v": value,
                "k": kind,
                "r": args.reason,
                "n": args.note[:NOTE_MAX],
                "t": utcnow().date(),
                "e": expires,
            },
        )
        await _audit(session, who, "allow.add", {"kind": kind, "reason": args.reason})
        await session.commit()
        out(f"allowed {kind} {value} until {expires or 'further notice'}")
        return 0
    try:
        value, _kind = _allow_value(args.value)
    except ValueError as exc:
        out(_safe(exc))
        return 1
    result = await session.execute(text("DELETE FROM feed_allow WHERE value = :v"), {"v": value})
    removed = int(getattr(result, "rowcount", 0) or 0)
    await _audit(session, who, "allow.remove", {"removed": removed})
    await session.commit()
    out(f"removed {removed}")
    return 0 if removed else 1


async def _delist(args: argparse.Namespace, session: AsyncSession, who: str, out: Out) -> int:
    if args.action == "list":
        await _overdue_warning(session, out)
        sql = "SELECT id, state, outcome, category, list, created_day, value FROM delist_requests"
        params: dict[str, Any] = {}
        if args.state:
            sql += " WHERE state = :s"
            params["s"] = args.state
        for r in await session.execute(
            text(sql + " ORDER BY created_day DESC, id LIMIT 200"), params
        ):
            out(
                f"{r.id}\t{r.state}\t{r.outcome or ''}\t{r.category}\t{r.list or 'any'}\t"
                f"{r.created_day}\t{_safe(r.value)}"
            )
        return 0
    row = (
        await session.execute(
            text(
                "SELECT id, value, list, scope, category, evidence, contact, state, outcome, "
                "public_note, created_day, decided_day FROM delist_requests WHERE id = :id"
            ),
            {"id": args.id},
        )
    ).first()
    if row is None:
        out("no such request")
        return 1
    if args.action == "show":
        for key, val in row._mapping.items():
            out(f"{key}: {_safe(val)}")
        return 0
    if row.state not in ("received", "suppressed"):
        out(f"this request is already decided ({row.state})")
        return 1
    today = utcnow().date()
    outcome = "rejected" if args.action == "reject" else args.outcome
    penalised = 0
    scope = row.scope
    if args.action == "accept" and args.list_id is not None:
        # The operator may narrow a request that covers every list, never widen one.
        if scope is not None and scope != args.list_id:
            out(f"this request concerns {scope} only")
            return 1
        scope = args.list_id
    if args.action == "accept":
        kind = _kind_of(row.value)
        reason = outcome
        expires = today + timedelta(days=DEFAULT_EXPIRY_DAYS) if reason == "remediated" else None
        if reason == "false_positive":
            targets = (
                await session.execute(
                    text(
                        "SELECT DISTINCT target_id FROM feed_entries "
                        "WHERE value = :v AND target_id IS NOT NULL "
                        # Only the targets behind the list the decision is about: an inbound
                        # false positive never disputes the same address as a malware host.
                        "AND (CAST(:l AS text) IS NULL OR list = :l)"
                    ),
                    {"v": row.value, "l": scope},
                )
            ).all()
            for (target_id,) in targets:
                penalised += await reputation.dispute(session, target_id)
                await abusech.withdraw_target(session, target_id)
        await session.execute(
            text(
                "INSERT INTO feed_allow (value, kind, reason, note, added_day, expires_day, source, "
                "list) VALUES (:v, :k, :r, :n, :t, :e, 'delist', :l) ON CONFLICT (value) DO UPDATE "
                "SET kind = EXCLUDED.kind, reason = EXCLUDED.reason, note = EXCLUDED.note, "
                "added_day = EXCLUDED.added_day, expires_day = EXCLUDED.expires_day, "
                "source = EXCLUDED.source, "
                # Two decisions on one value only ever widen what is allowed.
                "list = CASE WHEN feed_allow.list = EXCLUDED.list THEN EXCLUDED.list END"
            ),
            {
                "v": row.value,
                "l": scope,
                "k": kind,
                "r": reason,
                "n": "delisting " + row.id,
                "t": today,
                "e": expires,
            },
        )
        if scope != "inbound":  # an inbound-only decision does not touch outbound submissions
            await abusech.withdraw_value(session, row.value)
        if outcome == "policy":
            await session.execute(
                text(
                    "INSERT INTO never_list (value, kind, note) VALUES (:v, :k, :n) "
                    "ON CONFLICT (value) DO UPDATE SET kind = EXCLUDED.kind, note = EXCLUDED.note"
                ),
                {"v": row.value, "k": kind, "n": "delisting " + row.id},
            )
    await session.execute(
        text(
            "UPDATE delist_requests SET state = :st, outcome = :o, public_note = :n, "
            "decided_day = :d, scope = :sc WHERE id = :id"
        ),
        {
            "sc": scope,
            "st": "rejected" if args.action == "reject" else "accepted",
            "o": outcome,
            "n": args.note[:NOTE_MAX],
            "d": today,
            "id": row.id,
        },
    )
    await _audit(
        session, who, f"delist.{args.action}", {"outcome": outcome, "penalised": penalised}
    )
    await session.commit()
    out(f"{args.action}ed {row.id} ({outcome})")
    return 0


async def _ranges(
    args: argparse.Namespace,
    session: AsyncSession,
    who: str,
    out: Out,
    settings: Settings | None = None,
) -> int:
    if args.action == "status":
        rows = await session.execute(
            text(
                "SELECT source, count(*) AS n, max(fetched_day) AS day FROM feed_auto_ranges "
                "GROUP BY source ORDER BY source"
            )
        )
        for r in rows:
            out(f"{r.source}\t{r.n} prefixes\tfetched {r.day}")
        return 0
    if not egress_check.egress_ok(report_tunnel.proxy_url_from_env()):
        out(egress_check.CODE)  # a proxy is set but a direct route exists: refuse to go online
        return 1
    import importlib

    try:
        fetcher = importlib.import_module("hub.feeds.external")
    except ImportError:
        out("the range fetcher is not part of this build")
        return 1
    outcome: dict[str, str] = await fetcher.refresh(
        session, settings or Settings.from_env(), utcnow(), force=True
    )
    for name, result in sorted(outcome.items()):
        out(f"{name}\t{result}")
    count = sum(int(v.split(":", 1)[1]) for v in outcome.values() if v.startswith("updated:"))
    await _audit(session, who, "ranges.refresh", {"prefixes": count})
    await session.commit()
    out(f"refreshed {count} prefixes")
    return 0


def main() -> None:
    sys.exit(asyncio.run(run(sys.argv[1:])))


if __name__ == "__main__":
    main()
