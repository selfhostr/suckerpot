"""Classification rules for incoming replies (design M26, section 6).

Rule files live in ``ingest/rules/replies/*.yaml``. The condition grammar is the tagging
engine's (no regular expressions, so a rule cannot backtrack); only the field vocabulary is
different. The loader refuses anything unknown and fails the worker start, never a poll.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml

from ingest.tagging.engine import Cond, RuleError, compile_condition, evaluate

from .parse import BODY_FOR_RULES, ParsedReply, strip_quoted

OUTCOMES: Final = (
    "auto_ack",
    "ticket_opened",
    "resolved",
    "rejected",
    "bounce",
    "human_reply",
    "unknown",
)
REPLY_FIELDS: Final = frozenset(
    {
        "from_address",
        "from_domain",
        "from_local",
        "subject",
        "body",
        "auto_submitted",
        "precedence",
        "x_autoreply",
        "x_autorespond",
        "content_type",
        "report_type",
        "dsn_action",
        "dsn_status",
        "has_in_reply_to",
        "attachment_count",
        "matched",
        "ticket_id",  # the id extracted by a ``tickets`` entry, if any
    }
)
MAX_RULES: Final = 200
MAX_TICKET_RULES: Final = 50
MAX_AFTER: Final = 40
RULE_KEYS: Final = frozenset({"id", "outcome", "priority", "description", "when"})
TICKET_KEYS: Final = frozenset({"id", "after", "fields", "min_len", "max_len", "chars"})
TICKET_FIELDS: Final = frozenset({"subject", "body"})
MAX_TICKET_LEN: Final = 64


@dataclass(frozen=True, slots=True)
class ReplyRule:
    id: str
    outcome: str
    priority: int
    description: str
    when: Cond


@dataclass(frozen=True, slots=True)
class TicketRule:
    id: str
    after: tuple[str, ...]
    fields: tuple[str, ...]
    min_len: int
    max_len: int
    chars: frozenset[str]


@dataclass(frozen=True, slots=True)
class Verdict:
    outcome: str
    rule_id: str | None
    ticket_id: str | None


def _fresh(reply: ParsedReply) -> str:
    """What the sender wrote, for the rules: never the quoted original (our own report, which
    holds words like "suspended" or "abuse" that no rule may read as an answer)."""
    return strip_quoted(reply.body[: BODY_FOR_RULES * 4])[:BODY_FOR_RULES]


class ReplyRules:
    def __init__(self, rules: list[ReplyRule], tickets: list[TicketRule]) -> None:
        self.rules = sorted(rules, key=lambda r: (r.priority, r.id))
        self.tickets = tickets

    def description(self, rule_id: str | None) -> str | None:
        return next((r.description for r in self.rules if r.id == rule_id), None)

    def extract_ticket(self, reply: ParsedReply) -> str | None:
        return self._ticket(reply, _fresh(reply))

    def _ticket(self, reply: ParsedReply, fresh: str) -> str | None:
        for rule in self.tickets:
            for name in rule.fields:
                text = reply.subject if name == "subject" else fresh
                found = find_ticket(text, rule)
                if found:
                    return found
        return None

    def classify(self, reply: ParsedReply, *, matched: bool) -> Verdict:
        fresh = _fresh(reply)
        ticket = self._ticket(reply, fresh)
        values: dict[str, Any] = {
            "from_address": reply.from_address,
            "from_domain": reply.from_domain,
            "from_local": reply.from_local,
            "subject": reply.subject,
            "body": fresh,
            "auto_submitted": reply.auto_submitted,
            "precedence": reply.precedence,
            "x_autoreply": reply.x_autoreply,
            "x_autorespond": reply.x_autorespond,
            "content_type": reply.content_type or None,
            "report_type": reply.report_type,
            "dsn_action": reply.dsn_action,
            "dsn_status": reply.dsn_status,
            "has_in_reply_to": reply.has_in_reply_to,
            "attachment_count": reply.attachments.get("count", 0),
            "matched": matched,
            "ticket_id": ticket,
        }
        for rule in self.rules:
            if evaluate(rule.when, values.get):
                return Verdict(rule.outcome, rule.id, ticket)
        automatic = (
            reply.auto_submitted not in (None, "no")
            or reply.precedence in ("auto_reply", "bulk", "junk", "list")
            or reply.x_autoreply is not None
            or reply.x_autorespond is not None
        )
        if not automatic and reply.from_domain and len(reply.body.strip()) >= 20:
            return Verdict("human_reply", None, ticket)
        return Verdict("unknown", None, ticket)


# --- ticket ids: a linear scan, no regular expression --------------------------------------


def parse_chars(spec: str) -> frozenset[str]:
    """``A-Za-z0-9-_`` style set: ``x-y`` is a range, any other character stands for itself."""
    out: set[str] = set()
    i = 0
    while i < len(spec):
        if i + 2 < len(spec) and spec[i + 1] == "-":
            lo, hi = spec[i], spec[i + 2]
            if ord(lo) > ord(hi):
                raise RuleError(f"bad character range {lo}-{hi}")
            out.update(chr(c) for c in range(ord(lo), ord(hi) + 1))
            i += 3
        else:
            out.add(spec[i])
            i += 1
    return frozenset(out)


def find_ticket(text: str, rule: TicketRule) -> str | None:
    """The first run of ``rule.chars`` right after one of the ``after`` markers whose length is
    within bounds and which holds a digit. The text is lowered for the search, so the id is
    returned in lower case."""
    low = text[:BODY_FOR_RULES].lower()
    allowed = {c.lower() for c in rule.chars}
    for marker in rule.after:
        start = low.find(marker)
        while start != -1:
            i = start + len(marker)
            while i < len(low) and low[i] in " \t#:":
                i += 1
            j = i
            while j < len(low) and low[j] in allowed and j - i <= rule.max_len:
                j += 1
            run = low[i:j].strip("-_")
            if rule.min_len <= len(run) <= rule.max_len and any(c.isdigit() for c in run):
                return run
            start = low.find(marker, start + 1)
    return None


# --- loading -------------------------------------------------------------------------------


def _ticket_rule(raw: Any, source: str) -> TicketRule:
    if not isinstance(raw, Mapping):
        raise RuleError(f"{source}: each ticket entry must be a mapping")
    unknown = set(raw) - TICKET_KEYS
    if unknown:
        raise RuleError(f"{source}: unknown ticket keys {sorted(map(str, unknown))}")
    tid = raw.get("id")
    where = f"{source}:{tid}"
    if not isinstance(tid, str) or not tid:
        raise RuleError(f"{source}: ticket entry without id")
    after = raw.get("after")
    if (
        not isinstance(after, list)
        or not after
        or len(after) > MAX_AFTER
        or not all(isinstance(a, str) and a for a in after)
    ):
        raise RuleError(f"{where}: 'after' needs 1 to {MAX_AFTER} non-empty strings")
    fields = raw.get("fields", ["subject", "body"])
    if not isinstance(fields, list) or not fields or not set(fields) <= TICKET_FIELDS:
        raise RuleError(f"{where}: 'fields' must list subject and/or body")
    lengths = []
    for key, default in (("min_len", 4), ("max_len", 32)):
        value = raw.get(key, default)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= MAX_TICKET_LEN
        ):
            raise RuleError(f"{where}: {key} must be an integer from 1 to {MAX_TICKET_LEN}")
        lengths.append(value)
    if lengths[0] > lengths[1]:
        raise RuleError(f"{where}: min_len is above max_len")
    chars = raw.get("chars", "A-Za-z0-9-_")
    if not isinstance(chars, str) or not chars:
        raise RuleError(f"{where}: 'chars' must be a non-empty string")
    return TicketRule(
        tid,
        tuple(a.lower() for a in after),
        tuple(fields),
        lengths[0],
        lengths[1],
        parse_chars(chars),
    )


def _reply_rule(raw: Any, source: str) -> ReplyRule:
    if not isinstance(raw, Mapping):
        raise RuleError(f"{source}: each rule must be a mapping")
    unknown = set(raw) - RULE_KEYS
    if unknown:
        raise RuleError(f"{source}: unknown rule keys {sorted(map(str, unknown))}")
    rid = raw.get("id")
    if not isinstance(rid, str) or not rid or len(rid) > 64:
        raise RuleError(f"{source}: rule without a valid id")
    where = f"{source}:{rid}"
    outcome = raw.get("outcome")
    if outcome not in OUTCOMES:
        raise RuleError(f"{where}: outcome must be one of {', '.join(OUTCOMES)}")
    priority = raw.get("priority")
    if isinstance(priority, bool) or not isinstance(priority, int) or not 1 <= priority <= 999:
        raise RuleError(f"{where}: priority must be an integer from 1 to 999")
    description = raw.get("description", "")
    if not isinstance(description, str) or len(description) > 300:
        raise RuleError(f"{where}: description must be text of at most 300 characters")
    when = compile_condition(raw.get("when"), where, fields=REPLY_FIELDS)
    return ReplyRule(rid, outcome, priority, description, when)


def load_reply_rules(directory: Path) -> ReplyRules:
    """Load ``*.yaml`` from ``directory`` (sorted); raises ``RuleError`` on any problem."""
    rules: list[ReplyRule] = []
    tickets: list[TicketRule] = []
    for path in sorted(directory.glob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise RuleError(f"{path.name}: cannot read ({type(exc).__name__})") from exc
        if not isinstance(doc, Mapping) or not set(doc) <= {"rules", "tickets"}:
            raise RuleError(f"{path.name}: top level must be a mapping of 'rules'/'tickets'")
        for key, items in doc.items():
            if not isinstance(items, list):
                raise RuleError(f"{path.name}: '{key}' must be a list")
        rules.extend(_reply_rule(r, path.name) for r in doc.get("rules", []))
        tickets.extend(_ticket_rule(t, path.name) for t in doc.get("tickets", []))
    if len(rules) > MAX_RULES or len(tickets) > MAX_TICKET_RULES:
        raise RuleError("too many reply rules")
    ids = [r.id for r in rules]
    if len(set(ids)) != len(ids):
        raise RuleError("duplicate reply rule ids")
    if len({t.id for t in tickets}) != len(tickets):
        raise RuleError("duplicate ticket entry ids")
    return ReplyRules(rules, tickets)
