"""The tags a connection may carry and still count as plain (``rules/floods.yaml``).

A flood group keeps the tags of the connections it merged, so a connection that carries a tag
which tells a story of its own (a payload, an exploit, a CVE) must keep its row. The list is
data, but the loader refuses what must never be on it, so a careless edit cannot hide an attack
inside a group. The database enforces the same list: ``fold_session_buckets`` only merges a row
whose tags are all in it.

The loader refuses, at start-up, a tag that is

* a CVE tag (``cve-...``),
* a payload or severe tag (the attack tags of ``ingest/scanners.py`` other than the three that
  describe a credential spray, ``bluekeep`` and ``eternalblue`` included),
* or not a tag of the rules at all (a typo, or a new tag nobody classified yet).
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import yaml

from ingest.scanners import ATTACK_TAGS, BENIGN_TAGS
from ingest.tagging import RuleError

FILE_NAME = "floods.yaml"
MAX_TAGS = 32
MAX_TAG_LEN = 64

#: Attack tags that only describe a spray of credentials: the one kind of "attack" a plain
#: connection may carry.
SPRAY_TAGS = frozenset({"credential-stuffing", "weak-credentials", "rdp-cleartext"})
#: Tags of the abuse and campaign code that are not rule tags but are severe all the same.
ALWAYS_REFUSED = frozenset({"exploit", "bluekeep", "eternalblue"})


def refusal(tag: str) -> str | None:
    """Why ``tag`` can never be plain, or None."""
    if tag.startswith("cve-"):
        return "a CVE tag"
    if tag in ALWAYS_REFUSED or (tag in ATTACK_TAGS and tag not in SPRAY_TAGS):
        return "a payload or severe tag"
    if tag not in ATTACK_TAGS and tag not in BENIGN_TAGS:
        return "not a tag of the rules"
    return None


def parse(doc: object) -> frozenset[str]:
    """The plain tags of a parsed ``floods.yaml``; raises ``RuleError`` on anything unsafe."""
    raw = doc.get("plain_tags") if isinstance(doc, Mapping) else None
    if not isinstance(raw, list) or len(raw) > MAX_TAGS:
        raise RuleError(f"{FILE_NAME}: top level must have a 'plain_tags' list")
    tags: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item or len(item) > MAX_TAG_LEN:
            raise RuleError(f"{FILE_NAME}: every plain tag must be a short, non-empty string")
        why = refusal(item)
        if why is not None:
            raise RuleError(f"{FILE_NAME}: '{item}' cannot be a plain tag ({why})")
        tags.append(item)
    if len(set(tags)) != len(tags):
        raise RuleError(f"{FILE_NAME}: duplicate plain tags")
    return frozenset(tags)


def load_plain_tags(directory: Path) -> frozenset[str]:
    """Read ``floods.yaml``. A missing file leaves no tag plain (only untagged connections fold)."""
    path = directory / FILE_NAME
    if not path.is_file():
        return frozenset()
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuleError(f"{FILE_NAME}: cannot read ({type(exc).__name__})") from exc
    return parse(doc)
