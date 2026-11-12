"""Deterministic insight rules: pure functions over pre-aggregated facts (no I/O, no LLM).

Every rule has a minimum-volume threshold so a quiet deployment (or fresh demo data) never
produces silly claims such as "tripled (3 vs 1)". Sentence builders are pure and unit tested.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import quote, urlencode

from api.insights_schemas import Evidence, Insight, Severity
from api.sensors import SENSOR_LABELS

MAX_INSIGHTS = 3
MAX_CANDIDATES = 6

MIN_SURGE_CURRENT = 20
MIN_SURGE_PREVIOUS = 5
SURGE_RATIO = 1.5
MIN_NEW_COUNT = 10
MIN_SUCCESS_CURRENT = 5
MIN_SUCCESS_PREVIOUS = 2
SUCCESS_RATIO = 2.0
CAMPAIGN_MIN_SESSIONS = 50
CAMPAIGN_ASN_SHARE = 0.4
CAMPAIGN_IP_SHARE = 0.3
GEO_MIN_TOTAL = 50
GEO_MIN_SHARE = 0.2
GEO_MIN_SESSIONS = 20
BRUTE_MIN_ATTEMPTS = 100
BRUTE_MIN_IP_ATTEMPTS = 50

SEVERITY_RANK: dict[Severity, int] = {"info": 0, "notice": 1, "warning": 2, "severe": 3}

TAG_LABELS: dict[str, str] = {
    "php2shell": "PHP2Shell exploit attempts",
    "malware-drop": "Malware download attempts",
    "mirai": "Mirai-style botnet sessions",
    "crypto-miner": "Crypto-miner sessions",
    "recon": "Reconnaissance sessions",
    "service-probe": "Service fingerprinting sessions",
    "iot-shell-probe": "IoT shell-probe sessions",
    "brute-force": "Brute-force sessions",
    "container-escape": "Container escape attempts",
    "sql-rce": "Database command-execution attempts",
    "eternalblue": "EternalBlue exploit attempts",
    "db-ransom": "Database ransom attempts",
    "redis-rogue-master": "Redis rogue-master attempts",
    "sip-fraud": "SIP fraud attempts",
    "synology-exploit": "Synology NAS exploit attempts",
    "c3rb3r": "NAS ransomware attempts",
    "persistence": "Persistence attempts",
    "bluekeep": "BlueKeep probes",
    "weak-credentials": "Guessed weak credentials",
    "rdp-cleartext": "RDP cleartext logins",
}
TAG_SEVERITY: dict[str, Severity] = {
    "php2shell": "severe",
    "malware-drop": "severe",
    "mirai": "warning",
    "crypto-miner": "warning",
    "container-escape": "severe",
    "sql-rce": "severe",
    "eternalblue": "severe",
    "db-ransom": "warning",
    "redis-rogue-master": "warning",
    "sip-fraud": "warning",
    "synology-exploit": "severe",
    "c3rb3r": "severe",
    "persistence": "warning",
    # A BlueKeep probe only shows the scanner looked for the vulnerable channel; no payload is
    # sent, so it is a warning, unlike eternalblue where the exploit transaction itself arrived.
    "bluekeep": "warning",
    # A decoy password was guessed: the RDP counterpart of a successful login.
    "weak-credentials": "warning",
}
EXPLOIT_TAGS = ("php2shell", "malware-drop", "synology-exploit")
NEW_VALUE_NOUNS = {
    "username": "username",
    "command": "command",
    "url": "URL",
    "asn": "network (ASN)",
}
NEW_VALUE_SEVERITY: dict[str, Severity] = {
    "command": "notice",
    "url": "notice",
    "username": "info",
    "asn": "info",
}

Counts = dict[str, tuple[int, int]]  # key -> (current, previous)


@dataclass(frozen=True)
class NewValue:
    value: str
    count: int


@dataclass
class Facts:
    """Everything the rules need, gathered by ``insights_queries.gather_facts``."""

    since: datetime
    until: datetime
    total: tuple[int, int] = (0, 0)
    tags: Counts = field(default_factory=dict)
    sensors: Counts = field(default_factory=dict)
    countries: Counts = field(default_factory=dict)
    asns: Counts = field(default_factory=dict)
    asn_orgs: dict[str, str] = field(default_factory=dict)
    top_ip: tuple[str, int] | None = None
    success: tuple[int, int] = (0, 0)
    exploit_current: dict[str, int] = field(default_factory=dict)
    exploit_seen_before: set[str] = field(default_factory=set)
    new_values: dict[str, list[NewValue]] = field(default_factory=dict)
    # Login attempts in the window, grouped by source: (ip, sensor, attempts), busiest first.
    brute_force: list[tuple[str, str, int]] = field(default_factory=list)
    brute_total: int = 0


@dataclass(frozen=True)
class Candidate:
    insight: Insight
    magnitude: float


# --------------------------------------------------------------------------- formatting


def fmt_int(n: int) -> str:
    return f"{n:,}"


def clean_text(value: str, limit: int = 60) -> str:
    """Strip control characters and truncate an attacker-controlled string for a sentence."""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", value).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def describe_change(current: int, previous: int) -> str:
    """Wording for a rise: ``tripled``, ``doubled``, ``up 4.2x`` or ``up 40%``."""
    if previous <= 0:
        raise ValueError("previous must be positive")
    ratio = current / previous
    if 2.75 <= ratio < 3.5:
        return "tripled"
    if 1.8 <= ratio < 2.5:
        return "doubled"
    if ratio >= 3.5:
        text = f"{ratio:.1f}".removesuffix(".0")
        return f"up {text}x"
    return f"up {round((ratio - 1) * 100)}%"


def relative_day(since: datetime, now: datetime) -> str:
    """Name the window start relative to ``now``: midnight, yesterday, a weekday or a date."""
    days = (now.date() - since.date()).days
    if days <= 0:
        return "midnight" if since.hour == 0 else "earlier today"
    if days == 1:
        return "yesterday"
    if days < 7:
        return since.strftime("%A")
    return f"{since.strftime('%b')} {since.day}"


def describe_span(since: datetime, until: datetime) -> str:
    span = until - since
    hours = round(span / timedelta(hours=1))
    if hours < 48:
        return f"in the last {fmt_int(max(hours, 1))} hours"
    return f"in the last {fmt_int(round(span / timedelta(days=1)))} days"


def ui_link(path: str, since: datetime, until: datetime, **filters: str | int) -> str:
    params = {k: str(v) for k, v in filters.items()}
    params["since"] = since.isoformat().replace("+00:00", "Z")
    params["until"] = until.isoformat().replace("+00:00", "Z")
    return f"{path}?{urlencode(params, quote_via=quote)}"


# --------------------------------------------------------------------------- sentences


def surge_sentence(label: str, current: int, previous: int, since_text: str) -> str:
    return (
        f"{label} {describe_change(current, previous)} since {since_text} "
        f"({fmt_int(current)} vs {fmt_int(previous)})."
    )


def new_value_sentence(field_name: str, value: str, count: int, span_text: str) -> str:
    noun = NEW_VALUE_NOUNS[field_name]
    article = "An" if noun[0].lower() in "aeiou" else "A"
    times = "once" if count == 1 else f"{fmt_int(count)} times"
    return f"{article} {noun} never seen before showed up {times} {span_text}: {clean_text(value)}."


def success_sentence(current: int, previous: int, since_text: str) -> str:
    return (
        f"Successful logins {describe_change(current, previous)} since {since_text} "
        f"({fmt_int(current)} vs {fmt_int(previous)})."
    )


def campaign_sentence(who: str, count: int, total: int, span_text: str) -> str:
    pct = round(100 * count / total)
    return (
        f"{who} accounts for {pct}% of all sessions {span_text} "
        f"({fmt_int(count)} of {fmt_int(total)})."
    )


def exploit_sentence(label: str, count: int, span_text: str) -> str:
    plural = "session" if count == 1 else "sessions"
    return (
        f"{label} appeared for the first time: {fmt_int(count)} {plural} {span_text}, "
        "none in the 90 days before."
    )


def brute_force_sentence(ip: str, sensor_label: str, count: int, total: int, span_text: str) -> str:
    pct = round(100 * count / total)
    return (
        f"{ip} guessed credentials {fmt_int(count)} times on {sensor_label} {span_text}, "
        f"{pct}% of all {fmt_int(total)} login attempts."
    )


def geo_shift_sentence(country: str, share_now: float, share_before: float, span_text: str) -> str:
    return (
        f"Sessions from {country} rose from {round(100 * share_before)}% to "
        f"{round(100 * share_now)}% of all traffic {span_text}."
    )


# --------------------------------------------------------------------------- rules


def _evidence(metric: str, current: int, previous: int) -> Evidence:
    return Evidence(
        metric=metric,
        current=current,
        previous=previous,
        ratio=round(current / max(previous, 1), 2),
    )


def _surges(facts: Facts, since_text: str) -> list[Candidate]:
    out: list[Candidate] = []
    groups: list[tuple[str, Counts]] = [("tag", facts.tags), ("sensor", facts.sensors)]
    for dim, counts in groups:
        for key, (cur, prev) in counts.items():
            if cur < MIN_SURGE_CURRENT or prev < MIN_SURGE_PREVIOUS or cur / prev < SURGE_RATIO:
                continue
            if dim == "tag":
                label = TAG_LABELS.get(key, f"Sessions tagged {key}")
                severity: Severity = TAG_SEVERITY.get(key, "notice")
                link = ui_link("/attacks", facts.since, facts.until, tag=key)
            else:
                label = f"{SENSOR_LABELS.get(key, key)} sessions"
                severity = "info"
                link = ui_link("/attacks", facts.since, facts.until, sensor=key)
            out.append(
                Candidate(
                    Insight(
                        id=f"surge-{dim}-{key}",
                        kind="surge",
                        severity=severity,
                        sentence=surge_sentence(label, cur, prev, since_text),
                        evidence=_evidence(f"sessions_by_{dim}", cur, prev),
                        link=link,
                    ),
                    cur * min(cur / prev, 10.0),
                )
            )
    return out


def _new_values(facts: Facts, span_text: str) -> list[Candidate]:
    out: list[Candidate] = []
    for name, values in facts.new_values.items():
        eligible = [v for v in values if v.count >= MIN_NEW_COUNT]
        if not eligible or name not in NEW_VALUE_NOUNS:
            continue
        top = max(eligible, key=lambda v: v.count)
        shown = top.value
        if name == "asn":
            org = facts.asn_orgs.get(top.value)
            shown = f"AS{top.value} ({org})" if org else f"AS{top.value}"
            link = ui_link("/attackers", facts.since, facts.until, asn=top.value)
        else:
            link = ui_link("/trends", facts.since, facts.until, field=name)
        out.append(
            Candidate(
                Insight(
                    id=f"new-{name}",
                    kind="new_value",
                    severity=NEW_VALUE_SEVERITY[name],
                    sentence=new_value_sentence(name, shown, top.count, span_text),
                    evidence=_evidence(f"new_{name}", top.count, 0),
                    link=link,
                ),
                float(top.count),
            )
        )
    return out


def _success(facts: Facts, since_text: str) -> list[Candidate]:
    cur, prev = facts.success
    if cur < MIN_SUCCESS_CURRENT or prev < MIN_SUCCESS_PREVIOUS or cur / prev < SUCCESS_RATIO:
        return []
    return [
        Candidate(
            Insight(
                id="success-spike",
                kind="success",
                severity="warning",
                sentence=success_sentence(cur, prev, since_text),
                evidence=_evidence("login_success_sessions", cur, prev),
                link=ui_link("/attacks", facts.since, facts.until),
            ),
            cur * min(cur / prev, 10.0),
        )
    ]


def _campaigns(facts: Facts, span_text: str) -> list[Candidate]:
    total = facts.total[0]
    if total < CAMPAIGN_MIN_SESSIONS:
        return []
    out: list[Candidate] = []
    if facts.asns:
        key, (cur, prev) = max(facts.asns.items(), key=lambda kv: kv[1][0])
        if cur / total >= CAMPAIGN_ASN_SHARE:
            org = facts.asn_orgs.get(key)
            who = f"AS{key} ({org})" if org else f"AS{key}"
            out.append(
                Candidate(
                    Insight(
                        id=f"campaign-asn-{key}",
                        kind="campaign",
                        severity="warning" if cur / total >= 0.6 else "notice",
                        sentence=campaign_sentence(who, cur, total, span_text),
                        evidence=_evidence("sessions_by_asn", cur, prev),
                        link=ui_link("/attackers", facts.since, facts.until, asn=key),
                    ),
                    float(cur),
                )
            )
    if facts.top_ip is not None:
        ip, cur = facts.top_ip
        if cur / total >= CAMPAIGN_IP_SHARE:
            out.append(
                Candidate(
                    Insight(
                        id=f"campaign-ip-{ip}",
                        kind="campaign",
                        severity="notice",
                        sentence=campaign_sentence(
                            f"A single address ({ip})", cur, total, span_text
                        ),
                        evidence=_evidence("sessions_by_ip", cur, 0),
                        link=ui_link("/attackers", facts.since, facts.until, q=ip),
                    ),
                    float(cur),
                )
            )
    return out


def _exploits(facts: Facts, span_text: str) -> list[Candidate]:
    out: list[Candidate] = []
    for tag, count in facts.exploit_current.items():
        if count < 1 or tag in facts.exploit_seen_before or tag not in EXPLOIT_TAGS:
            continue
        label = TAG_LABELS.get(tag, tag)
        out.append(
            Candidate(
                Insight(
                    id=f"exploit-first-{tag}",
                    kind="exploit",
                    severity="severe",
                    sentence=exploit_sentence(label, count, span_text),
                    evidence=_evidence("sessions_by_tag", count, 0),
                    link=ui_link("/attacks", facts.since, facts.until, tag=tag),
                ),
                float(count),
            )
        )
    return out


def _brute_force(facts: Facts, span_text: str) -> list[Candidate]:
    total = facts.brute_total
    out: list[Candidate] = []
    if facts.brute_force and total >= BRUTE_MIN_ATTEMPTS:
        ip, sensor, n = facts.brute_force[0]
        if n >= BRUTE_MIN_IP_ATTEMPTS:
            label = SENSOR_LABELS.get(sensor, sensor)
            out.append(
                Candidate(
                    Insight(
                        id=f"brute-force-{sensor}-{ip}",
                        kind="brute_force",
                        severity="notice",
                        sentence=brute_force_sentence(ip, label, n, total, span_text),
                        evidence=_evidence("login_attempts_by_ip", n, 0),
                        link=ui_link("/attackers", facts.since, facts.until, q=ip),
                    ),
                    float(n),
                )
            )
    return out


def _geo_shifts(facts: Facts, span_text: str) -> list[Candidate]:
    total_cur, total_prev = facts.total
    if total_cur < GEO_MIN_TOTAL or total_prev < GEO_MIN_TOTAL:
        return []
    out: list[Candidate] = []
    for key, (cur, prev) in facts.countries.items():
        share_now, share_before = cur / total_cur, prev / total_prev
        if cur < GEO_MIN_SESSIONS or share_now < GEO_MIN_SHARE or share_now < 2 * share_before:
            continue
        out.append(
            Candidate(
                Insight(
                    id=f"geo-shift-{key.lower()}",
                    kind="geo_shift",
                    severity="notice",
                    sentence=geo_shift_sentence(key, share_now, share_before, span_text),
                    evidence=_evidence("sessions_by_country", cur, prev),
                    link=ui_link("/attacks", facts.since, facts.until, country=key),
                ),
                share_now / max(share_before, 0.01) * cur,
            )
        )
    return out


def rank(candidates: list[Candidate]) -> list[Candidate]:
    """Severity first, then magnitude, then id (a stable tie-break)."""
    return sorted(
        candidates,
        key=lambda c: (-SEVERITY_RANK[c.insight.severity], -c.magnitude, c.insight.id),
    )


def build_candidates(facts: Facts, now: datetime) -> list[Candidate]:
    since_text = relative_day(facts.since, now)
    span_text = describe_span(facts.since, facts.until)
    found = [
        *_exploits(facts, span_text),
        *_surges(facts, since_text),
        *_success(facts, since_text),
        *_campaigns(facts, span_text),
        *_brute_force(facts, span_text),
        *_geo_shifts(facts, span_text),
        *_new_values(facts, span_text),
    ]
    return rank(found)[:MAX_CANDIDATES]


def build_insights(facts: Facts, now: datetime) -> list[Insight]:
    return [c.insight for c in build_candidates(facts, now)[:MAX_INSIGHTS]]
