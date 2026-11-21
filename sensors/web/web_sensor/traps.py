"""Trap pack engine for the web sensor (M37).

Packs are data, validated by ``suckerpot_common.traps``. This module compiles the valid ones
into an immutable ``TrapSet`` and matches it against the areas the detector already builds:
``in`` on bounded, decoded, lowercased bytes. No regular expressions, nothing executed, nothing
fetched, no file written. A matching trap adds flags; one with ``respond`` may also shape the
answer from a fixed template.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from functools import cache
from pathlib import Path
from typing import Any

from suckerpot_common import traps as fmt

log = logging.getLogger("web_sensor.traps")

BUNDLED = Path(__file__).parent / "data" / "traps-bundled.json"
# Per-request search budget. A search of one needle costs at most about 3 ns per haystack byte on
# crafted input (a needle like "aaaa...b" over "aaaa..."), so the budget counts both searches and
# haystack bytes.
# - The packs that own reserved flags (fmt.CORE_PACKS, the bundled ones) run first and outside the
#   budget; the loader caps what they can search at fmt.CORE_SCAN_BYTES (256 KiB).
# - Traps without a path never run out: the loader keeps their distinct needles within 64 and
#   their worst-case searched bytes within fmt.MAX_SCAN_BYTES (512 KiB).
# - Traps with a path share MAX_SEARCHES searches and fmt.MAX_SCAN_BYTES, most specific first;
#   the ones the budget skips are reported in the event (data.trap_budget) and counted in
#   ``TrapSet.budget_exhausted``.
# Worst case: 1.25 MiB searched per request, about 3.5 ms on the reference host whatever the
# packs and the request (tested under 5 ms); typical requests stay far below.
MAX_SEARCHES = 96
MAX_UNPATHED_SEARCHES = fmt.MAX_UNPATHED_NEEDLES  # 64: every distinct unpathed needle fits
MAX_SCAN_BYTES = fmt.MAX_SCAN_BYTES


@dataclass(frozen=True, slots=True)
class Areas:
    """What the detector built for one request (the same bytes, the same caps)."""

    path: bytes  # decoded path (4 KiB)
    query: bytes  # decoded query (4 KiB)
    body: bytes  # decoded body (16 KiB)
    headers: bytes  # "name: value" lines (32 KiB)
    blob: bytes  # path ? query \n body (24 KiB)
    path_low: bytes
    query_low: bytes
    body_low: bytes
    headers_low: bytes
    blob_low: bytes

    def get(self, area: str, exact: bool) -> bytes:
        if area == "path":
            return self.path if exact else self.path_low
        if area == "query":
            return self.query if exact else self.query_low
        if area == "body":
            return self.body if exact else self.body_low
        if area == "headers":
            return self.headers if exact else self.headers_low
        return self.blob if exact else self.blob_low


@dataclass(frozen=True, slots=True)
class Hit:
    pack: fmt.Pack
    trap: fmt.Trap

    def entry(self) -> dict[str, Any]:
        return {
            "pack": self.pack.id,
            "v": self.pack.version,
            "trap": self.trap.id,
            "level": self.trap.level,
        }


def _path_ok(cond: fmt.PathCond, path: bytes) -> bool:
    if cond.op == "exact":
        return path == cond.value
    if cond.op == "prefix":
        return path.startswith(cond.value)
    if cond.op == "suffix":
        return path.endswith(cond.value)
    return cond.value in path


@dataclass
class TrapSet:
    """An immutable set of compiled traps. Swapping sets is one reference assignment."""

    packs: tuple[fmt.Pack, ...] = ()
    rejected: tuple[tuple[str, str], ...] = ()
    seq: int = 0
    _traps: tuple[tuple[fmt.Pack, fmt.Trap], ...] = field(default=(), repr=False)
    severe: frozenset[str] = frozenset()
    groups: dict[str, tuple[str, ...]] = field(default_factory=dict)
    budget_exhausted: int = 0

    @classmethod
    def empty(cls) -> TrapSet:
        return cls()

    @classmethod
    def from_packs(
        cls,
        packs: list[fmt.Pack],
        rejected: list[tuple[str, str]] | None = None,
        seq: int = 0,
    ) -> TrapSet:
        ordered = sorted(packs, key=lambda p: p.id)
        # Most specific path first (the order of the answer choice), then pack and trap id.
        pairs = tuple(
            sorted(
                ((p, t) for p in ordered for t in p.traps),
                key=lambda pt: (pt[0].id not in fmt.CORE_PACKS, specificity(Hit(pt[0], pt[1]))),
            )
        )
        severe = frozenset(f for _, t in pairs if t.level == "exploit" for f in t.flags)
        groups: dict[str, list[str]] = {}
        for p in ordered:
            if p.group:
                groups.setdefault(p.group, []).append(p.id)
        return cls(
            tuple(ordered),
            tuple(rejected or ()),
            seq,
            pairs,
            severe,
            {g: tuple(ids) for g, ids in groups.items()},
        )

    @property
    def size(self) -> int:
        return len(self._traps)

    def match(
        self,
        method: str,
        areas: Areas,
        query_keys: frozenset[str],
        header_names: frozenset[str],
    ) -> tuple[list[Hit], int]:
        """Every trap whose conditions all hold, and how many traps the search budget skipped.

        Traps run most specific path first. Traps with a path share ``MAX_SEARCHES`` distinct
        needle searches and ``MAX_SCAN_BYTES`` of haystack; when either is spent, the remaining
        ones that still need a search are skipped (and counted). Traps without a path have their
        own budget, so a request crafted to match many path traps can never starve them. Linear
        in the bounded trap and needle data."""
        hits: list[Hit] = []
        memo: dict[tuple[str, bool, bytes], bool] = {}
        budget = {True: MAX_SEARCHES, False: MAX_UNPATHED_SEARCHES}
        scan = {True: MAX_SCAN_BYTES, False: MAX_SCAN_BYTES}
        skipped = 0
        for pack, trap in self._traps:
            if trap.methods and method not in trap.methods:
                continue
            pathed = trap.path is not None
            core = pack.id in fmt.CORE_PACKS
            if trap.path is not None and not _path_ok(
                trap.path, areas.path if trap.exact_case else areas.path_low
            ):
                continue
            if any(k not in query_keys for k in trap.query_keys):
                continue
            if any(h not in header_names for h in trap.header_names):
                continue
            ok = True
            for cond in trap.needles:
                hay = areas.get(cond.area, trap.exact_case)
                found = False
                for needle in cond.any:
                    key = (cond.area, trap.exact_case, needle)
                    seen = memo.get(key)
                    if seen is None:
                        cost = max(len(hay), 64)
                        if not core:
                            if budget[pathed] <= 0 or scan[pathed] < cost:
                                break
                            budget[pathed] -= 1
                            scan[pathed] -= cost
                        seen = needle in hay
                        memo[key] = seen
                    if seen:
                        found = True
                        break
                else:
                    ok = False
                    break
                if not found:  # the budget ran out inside this condition
                    ok = False
                    skipped += 1
                    break
            if ok:
                hits.append(Hit(pack, trap))
        if skipped:
            self.budget_exhausted += 1
        return hits, skipped


def load_bytes(data: bytes, *, today: date | None = None, source: str = "bundled") -> TrapSet:
    """Validate and compile a bundle. Invalid packs are logged (id and reason) and skipped; an
    invalid file gives an empty set."""
    day = today or datetime.now(UTC).date()
    try:
        result = fmt.load_bundle(data, sensor="web", today=day)
    except fmt.PackError as err:
        log.error("trap bundle %s rejected: %s", source, err.reason)
        return TrapSet.empty()
    for pid, reason in result.rejected:
        log.warning("trap pack rejected: id=%s reason=%s source=%s", pid, reason, source)
    ts = TrapSet.from_packs(result.packs, result.rejected, result.seq)
    log.info("trap packs loaded: %d packs, %d traps (%s)", len(ts.packs), ts.size, source)
    return ts


def load_docs(
    docs: list[dict[str, Any]],
    *,
    disabled: frozenset[str] = frozenset(),
    today: date | None = None,
    source: str = "bundled",
) -> TrapSet:
    """Compile the packs of several checked bundles (bundled plus downloaded). Never raises."""
    day = today or datetime.now(UTC).date()
    result = fmt.load_docs(docs, sensor="web", today=day, disabled=disabled)
    for pid, reason in result.rejected:
        log.warning("trap pack rejected: id=%s reason=%s source=%s", pid, reason, source)
    for pid in result.disabled:
        log.info("trap pack disabled: id=%s", pid)
    ts = TrapSet.from_packs(result.packs, result.rejected, result.seq)
    log.info(
        "trap packs loaded: %d packs, %d traps, seq %d (%s)", len(ts.packs), ts.size, ts.seq, source
    )
    return ts


def load_file(path: Path, *, today: date | None = None) -> TrapSet:
    """Read a bundle file (size checked before reading). Never raises."""
    try:
        if path.stat().st_size > fmt.MAX_BUNDLE_BYTES:
            log.error("trap bundle %s rejected: limits", path.name)
            return TrapSet.empty()
        data = path.read_bytes()
    except OSError:
        log.error("trap bundle %s missing or unreadable", path.name)
        return TrapSet.empty()
    return load_bytes(data, today=today, source=path.name)


@cache
def bundled() -> TrapSet:
    """The packs shipped in the image (read once per process)."""
    return load_file(BUNDLED)


# -- fake answers ----------------------------------------------------------------------------


def _echo(value: str) -> str:
    return "".join(c for c in value if c in fmt.ECHO_CHARS)[: fmt.MAX_ECHO]


@dataclass(frozen=True)
class RenderValues:
    """Values a template may use. Everything but ``echo`` comes from the install, not the
    request; ``base_url`` uses the Host header the way the rest of the site does."""

    hostname: str
    server_ip: str
    site_title: str
    base_url: str
    server_token: str
    php_version: str
    now: float
    install_ts: float
    query: dict[str, str]


def render_template(
    tpl: fmt.Template, values: RenderValues, derive: Any, rng: Any, label: str
) -> str:
    out: list[str] = []
    n_hex = n_int = 0
    for part in tpl:
        if isinstance(part, str):
            out.append(part)
            continue
        name = part.name
        if name == "rand_hex":
            out.append(derive(f"{label}:hex:{n_hex}", part.n))
            n_hex += 1
        elif name == "rand_int":
            out.append(str(part.lo + rng(f"{label}:int:{n_int}").randrange(part.hi - part.lo + 1)))
            n_int += 1
        elif name == "echo":
            out.append(_echo(values.query.get(part.key, "")))
        elif name == "date_http":
            out.append(time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(values.now)))
        elif name == "year":
            out.append(str(time.gmtime(values.now).tm_year))
        elif name == "install_date":
            out.append(time.strftime("%Y-%m-%d", time.gmtime(values.install_ts)))
        else:
            out.append(_simple(values, name))
    return "".join(out)


def specificity(hit: Hit) -> tuple[int, int, int, str, str]:
    """Sort key: the most specific responding trap first (design 3.6)."""
    t = hit.trap
    rank = {"exact": 0, "prefix": 1, "suffix": 2, "contains": 3}
    op = rank[t.path.op] if t.path else 4
    plen = -len(t.path.value) if t.path and t.path.op == "prefix" else 0
    return (op, plen, -t.conditions, hit.pack.id, t.id)


def _simple(values: RenderValues, name: str) -> str:
    table = {
        "hostname": values.hostname,
        "server_ip": values.server_ip,
        "site_title": values.site_title,
        "base_url": values.base_url,
        "server_token": values.server_token,
        "php_version": values.php_version,
    }
    return table.get(name, "")
