"""Rule engine: safe by construction.

Attacker-controlled text is only ever matched with linear-time primitives: substring tests,
``startswith``/``endswith``, a tiny iterative glob matcher and exact/word comparisons. There
is NO regular-expression support, so a rule cannot introduce catastrophic backtracking.
Every matched string is capped at ``MAX_TEXT`` characters first.

Rule file format (``ingest/rules/*.yaml``)::

    rules:
      - id: recon-commands          # unique
        tag: recon                  # tag produced
        scope: event                # event (default) or session
        description: ...
        when:                       # a condition node
          all:                      # all / any / not combinators, or a leaf
            - {field: type, equals: command}
            - {field: data.input, command_any: [uname, nproc]}

Leaf operators (one per leaf, next to ``field``): equals, in, contains, contains_any,
startswith, endswith (string or list), glob (string or list), command_any, has, has_all, gte,
gt, lte, lt, exists. String comparisons are case-insensitive unless ``ci: false``. On a list
field (``data.flags``), ``has`` is true when ANY of the listed values is present and ``has_all``
is true only when EVERY listed value is present.

A tag that names a specific malware family, CVE or fraud must rest on evidence specific to that
claim (``has_all`` or a combination of conditions); generic activity gets a generic tag.

Event rules see ``type``, ``sensor`` and a whitelist of ``data.*`` fields. Session rules see
``session.*`` counters and the session's accumulated tags, evaluated after each upsert.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

MAX_TEXT = 4096
MAX_RULES = 500
# YAML files in the rules directory that are not tagging rules (loaded by their own module).
NON_TAG_FILES = frozenset({"scanners.yaml", "floods.yaml"})
MAX_DEPTH = 8
TAG_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")

EVENT_FIELDS = {"type", "sensor"}
DATA_FIELDS = {
    "input", "path", "query", "user_agent", "method", "url", "username", "password",
    "body_preview", "tool", "command", "kind", "host", "port", "status", "flags", "reason",
    "smb1_command_name", "smb1_outcome", "success",
}  # fmt: skip
SESSION_FIELDS = {
    "session.sensor", "session.event_count", "session.login_attempts", "session.login_success",
    "session.commands", "session.downloads", "session.http_requests", "session.tags",
    "session.known_scanner", "session.abuse_score",
}  # fmt: skip
OPERATORS = {
    "equals", "in", "contains", "contains_any", "startswith", "endswith", "glob",
    "command_any", "has", "has_all", "gte", "gt", "lte", "lt", "exists",
}  # fmt: skip
_SEPARATORS = str.maketrans({c: " " for c in ";|&()`$<>=\"'{}[]\t\n\r,"})


class RuleError(ValueError):
    """Invalid rule definition."""


# ---- matching primitives ---------------------------------------------------------------------


def glob_match(pattern: str, text: str) -> bool:
    """Iterative ``*`` / ``?`` glob (no backtracking explosion: O(len(pattern) * len(text)))."""
    p = t = 0
    star = -1
    mark = 0
    while t < len(text):
        if p < len(pattern) and pattern[p] in (text[t], "?") and pattern[p] != "*":
            p += 1
            t += 1
        elif p < len(pattern) and pattern[p] == "*":
            star = p
            mark = t
            p += 1
        elif star != -1:
            p = star + 1
            mark += 1
            t = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def command_words(text: str) -> set[str]:
    """Basenames of the whitespace/shell-separated words of a command line."""
    words: set[str] = set()
    for token in text.translate(_SEPARATORS).split():
        words.add(token.rsplit("/", 1)[-1] or token)
    return words


# ---- condition tree --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Leaf:
    field: str
    op: str
    arg: Any
    ci: bool = True


@dataclass(frozen=True, slots=True)
class Node:
    kind: str  # all | any | not
    children: tuple[Cond, ...]


Cond = Leaf | Node


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    tag: str
    scope: str
    when: Cond
    description: str = ""


@dataclass(slots=True)
class SessionFacts:
    """Session state after an upsert, as seen by session-scoped rules."""

    values: dict[str, Any] = field(default_factory=dict)


def _norm(value: Any, ci: bool) -> Any:
    if isinstance(value, str):
        value = value[:MAX_TEXT]
        return value.lower() if ci else value
    return value


def _as_list(arg: Any) -> list[Any]:
    return list(arg) if isinstance(arg, list) else [arg]


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _eval_leaf(leaf: Leaf, value: Any) -> bool:
    op, arg, ci = leaf.op, leaf.arg, leaf.ci
    if op == "exists":
        return (value is not None) == bool(arg)
    if value is None:
        return False
    if op in ("gte", "gt", "lte", "lt"):
        n = _num(value)
        if n is None:
            return False
        a = float(arg)
        return {"gte": n >= a, "gt": n > a, "lte": n <= a, "lt": n < a}[op]
    if op == "has":  # element membership in a list field
        if not isinstance(value, list):
            return False
        have = {_norm(v, ci) for v in value if isinstance(v, str | int | float | bool)}
        return any(_norm(a, ci) in have for a in _as_list(arg))
    if op == "has_all":  # every listed element is present in a list field
        if not isinstance(value, list):
            return False
        have = {_norm(v, ci) for v in value if isinstance(v, str | int | float | bool)}
        return all(_norm(a, ci) in have for a in _as_list(arg))
    if op == "equals":
        if isinstance(arg, bool) or isinstance(value, bool):
            return value is arg
        if isinstance(arg, int | float) and not isinstance(arg, bool):
            n = _num(value)
            return n is not None and n == float(arg)
        return isinstance(value, str) and _norm(value, ci) == _norm(arg, ci)
    if op == "in":
        return any(_eval_leaf(Leaf(leaf.field, "equals", a, ci), value) for a in arg)
    # string operators
    if not isinstance(value, str):
        return False
    text = _norm(value, ci)
    needles = [_norm(a, ci) for a in _as_list(arg)]
    if op in ("contains", "contains_any"):
        return any(n in text for n in needles)
    if op == "startswith":
        return any(text.startswith(n) for n in needles)
    if op == "endswith":
        return any(text.endswith(n) for n in needles)
    if op == "glob":
        return any(glob_match(n, text) for n in needles)
    if op == "command_any":
        return not command_words(text).isdisjoint(needles)
    raise AssertionError(op)  # unreachable: validated at load time


def _eval(cond: Cond, get: Any) -> bool:
    if isinstance(cond, Leaf):
        return _eval_leaf(cond, get(cond.field))
    if cond.kind == "all":
        return all(_eval(c, get) for c in cond.children)
    if cond.kind == "any":
        return any(_eval(c, get) for c in cond.children)
    return not _eval(cond.children[0], get)


# ---- loading and validation ------------------------------------------------------------------


def _fields_of(cond: Cond) -> set[str]:
    if isinstance(cond, Leaf):
        return {cond.field}
    return set().union(*(_fields_of(c) for c in cond.children)) if cond.children else set()


def _parse_cond(raw: Any, depth: int, where: str, fields: frozenset[str] | None = None) -> Cond:
    if depth > MAX_DEPTH:
        raise RuleError(f"{where}: conditions nested too deeply")
    if not isinstance(raw, Mapping):
        raise RuleError(f"{where}: a condition must be a mapping")
    for kind in ("all", "any"):
        if kind in raw:
            if len(raw) != 1 or not isinstance(raw[kind], list) or not raw[kind]:
                raise RuleError(f"{where}: '{kind}' takes a non-empty list")
            return Node(kind, tuple(_parse_cond(c, depth + 1, where, fields) for c in raw[kind]))
    if "not" in raw:
        if len(raw) != 1:
            raise RuleError(f"{where}: 'not' takes exactly one condition")
        return Node("not", (_parse_cond(raw["not"], depth + 1, where, fields),))
    keys = set(raw) - {"field", "ci"}
    if "field" not in raw or len(keys) != 1:
        raise RuleError(f"{where}: a leaf needs 'field' and exactly one operator")
    fld = raw["field"]
    (op,) = keys
    if op not in OPERATORS:
        raise RuleError(f"{where}: unknown operator {op!r}")
    ci = raw.get("ci", True)
    if not isinstance(ci, bool):
        raise RuleError(f"{where}: 'ci' must be a boolean")
    arg = raw[op]
    if op in ("gte", "gt", "lte", "lt"):
        if isinstance(arg, bool) or not isinstance(arg, int | float):
            raise RuleError(f"{where}: {op} needs a number")
    elif op == "exists":
        if not isinstance(arg, bool):
            raise RuleError(f"{where}: exists needs a boolean")
    elif op in ("in", "contains_any", "command_any", "has_all"):
        if not isinstance(arg, list) or not arg:
            raise RuleError(f"{where}: {op} needs a non-empty list")
        if op != "in" and not all(isinstance(i, str) and i for i in arg):
            raise RuleError(f"{where}: {op} needs non-empty strings")
    elif op in ("startswith", "endswith", "contains", "glob"):
        items = _as_list(arg)
        if not items or not all(isinstance(i, str) and i for i in items):
            raise RuleError(f"{where}: {op} needs non-empty strings")
    if op == "command_any" and not all(isinstance(i, str) and "/" not in i for i in arg):
        raise RuleError(f"{where}: command_any takes bare command names")
    if fields is not None:
        if fld not in fields:  # a caller with its own vocabulary (the reply rules)
            raise RuleError(f"{where}: field {fld!r} is not allowed")
    elif fld in EVENT_FIELDS or fld in SESSION_FIELDS:
        pass
    elif isinstance(fld, str) and fld.startswith("data.") and fld[5:] in DATA_FIELDS:
        pass
    else:
        raise RuleError(f"{where}: field {fld!r} is not allowed")
    return Leaf(fld, op, arg, ci)


def compile_condition(raw: Any, where: str, *, fields: frozenset[str] | None = None) -> Cond:
    """Compile a ``when:`` condition of any rule-like file; raises RuleError on a bad one.

    Public so other rule files (the ATT&CK mapping, the reply classifier) share the grammar and
    its safety limits. ``fields`` replaces the event/session field whitelist with the caller's own.
    """
    return _parse_cond(raw, 0, where, fields)


def evaluate(cond: Cond, get: Callable[[str], Any]) -> bool:
    """Evaluate a compiled condition; ``get`` maps a field name to its value (None if absent)."""
    return _eval(cond, get)


def match_event_condition(cond: Cond, etype: str, sensor: str, data: Mapping[str, Any]) -> bool:
    """Evaluate a compiled event-scope condition on one event."""

    def get(name: str) -> Any:
        if name == "type":
            return etype
        if name == "sensor":
            return sensor
        return data.get(name[5:])

    return _eval(cond, get)


def condition_fields(cond: Cond) -> set[str]:
    """Every field a compiled condition reads."""
    return _fields_of(cond)


def _parse_rule(raw: Any, source: str) -> Rule:
    if not isinstance(raw, Mapping):
        raise RuleError(f"{source}: each rule must be a mapping")
    rid = raw.get("id")
    where = f"{source}:{rid}"
    if not isinstance(rid, str) or not rid:
        raise RuleError(f"{source}: rule without id")
    tag = raw.get("tag")
    if not isinstance(tag, str) or not tag or not set(tag) <= TAG_CHARS or len(tag) > 32:
        raise RuleError(f"{where}: tag must be 1-32 chars of a-z, 0-9 and '-'")
    scope = raw.get("scope", "event")
    if scope not in ("event", "session"):
        raise RuleError(f"{where}: scope must be 'event' or 'session'")
    when = _parse_cond(raw.get("when"), 0, where)
    uses_session = any(f.startswith("session.") for f in _fields_of(when))
    if uses_session != (scope == "session"):
        raise RuleError(f"{where}: session.* fields belong to (and only to) session-scope rules")
    return Rule(rid, tag, scope, when, str(raw.get("description", "")))


def load_rules(directory: Path) -> RuleSet:
    """Load every ``*.yaml`` in ``directory`` (sorted); raises RuleError on any problem."""
    rules: list[Rule] = []
    files = [p for p in sorted(directory.glob("*.yaml")) if p.name not in NON_TAG_FILES]
    for path in files:
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise RuleError(f"{path.name}: cannot read ({type(exc).__name__})") from exc
        raw_rules = (doc or {}).get("rules") if isinstance(doc, Mapping) else None
        if not isinstance(raw_rules, list):
            raise RuleError(f"{path.name}: top level must be a mapping with a 'rules' list")
        rules.extend(_parse_rule(r, path.name) for r in raw_rules)
    if len(rules) > MAX_RULES:
        raise RuleError("too many rules")
    ids = [r.id for r in rules]
    if len(set(ids)) != len(ids):
        raise RuleError("duplicate rule ids")
    return RuleSet(rules)


class RuleSet:
    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules = list(rules)
        self.event_rules = [r for r in self.rules if r.scope == "event"]
        self.session_rules = [r for r in self.rules if r.scope == "session"]

    @property
    def tags(self) -> list[str]:
        return sorted({r.tag for r in self.rules})

    def tag_event(self, etype: str, sensor: str, data: Mapping[str, Any]) -> list[str]:
        """Tags for one event (sorted, unique)."""

        def get(name: str) -> Any:
            if name == "type":
                return etype
            if name == "sensor":
                return sensor
            return data.get(name[5:])

        return sorted({r.tag for r in self.event_rules if _eval(r.when, get)})

    def tag_session(self, facts: Mapping[str, Any]) -> list[str]:
        """Tags for a session from its counters and accumulated tags (``session.*`` keys)."""
        return sorted({r.tag for r in self.session_rules if _eval(r.when, facts.get)})


def tags_union(*groups: Sequence[str]) -> list[str]:
    return sorted(set().union(*groups))
