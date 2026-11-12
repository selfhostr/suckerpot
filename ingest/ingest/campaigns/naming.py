"""Deterministic campaign names, severity and stages.

The name never comes from attacker input beyond a malware family label, which is reduced to
letters, digits and a few separators first. Same inputs, same name.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping

from ingest.attack.mapping import STAGES

#: What a campaign is "about", most telling first. Used to pick the dominant objective tag.
OBJECTIVE_TAGS = (
    "php2shell",
    "eternalblue",
    "sql-rce",
    "container-escape",
    "crypto-miner",
    "mirai",
    "malware-drop",
    "db-ransom",
    "redis-rogue-master",
    "sip-fraud",
    "synology-exploit",
    "c3rb3r",
    "credential-stuffing",
    "wordpress-bruteforce",
    "phpmyadmin-bruteforce",
    "bluekeep",
    "weak-credentials",
    "persistence",
    "iot-shell-probe",
    "env-file-probe",
    "service-probe",
    "scanner",
    "recon",
)
OBJECTIVE_NAMES = {
    "php2shell": "PHP2Shell exploitation",
    "eternalblue": "EternalBlue exploitation",
    "sql-rce": "SQL command execution",
    "container-escape": "Container escape",
    "crypto-miner": "Crypto-miner drop",
    "mirai": "Mirai-style loader",
    "malware-drop": "Malware dropper",
    "db-ransom": "Database ransom",
    "redis-rogue-master": "Redis rogue master",
    "sip-fraud": "Phone fraud",
    "synology-exploit": "Synology NAS exploitation",
    "c3rb3r": "NAS ransomware",
    "credential-stuffing": "Credential stuffing",
    "wordpress-bruteforce": "WordPress password guessing",
    "phpmyadmin-bruteforce": "phpMyAdmin password guessing",
    "bluekeep": "BlueKeep probing",
    "weak-credentials": "Weak password guessing",
    "persistence": "Persistence setup",
    "iot-shell-probe": "IoT shell probing",
    "env-file-probe": "Secrets hunting",
    "service-probe": "Service fingerprinting",
    "scanner": "Scanning",
    "recon": "Reconnaissance",
}
#: What a merged campaign says it also did, in the middle of a sentence. Only attacker goals are
#: listed: a campaign that also guessed passwords or looked around is not named after that.
ALSO_NAMES = {
    "php2shell": "PHP2Shell exploitation",
    "eternalblue": "EternalBlue exploitation",
    "sql-rce": "SQL command execution",
    "container-escape": "container escape",
    "crypto-miner": "crypto-miner drop",
    "mirai": "Mirai-style loader",
    "malware-drop": "malware dropper",
    "db-ransom": "database ransom",
    "redis-rogue-master": "Redis rogue master",
    "sip-fraud": "phone fraud",
    "synology-exploit": "Synology NAS exploitation",
    "c3rb3r": "NAS ransomware",
}
#: Goals the main one already says: a loader or a miner always drops a file, and the NAS
#: ransomware always comes with the NAS exploit.
IMPLIED_BY = {
    "mirai": frozenset({"malware-drop"}),
    "crypto-miner": frozenset({"malware-drop"}),
    "synology-exploit": frozenset({"c3rb3r"}),
    "c3rb3r": frozenset({"synology-exploit"}),
}
FAMILY_NOUNS = {
    "crypto-miner": "miner",
    "mirai": "loader",
    "malware-drop": "dropper",
    "db-ransom": "ransom",
}
SENSOR_LABELS = {
    "ssh": "SSH", "telnet": "Telnet", "web": "HTTP", "rdp": "RDP", "redis": "Redis",
    "docker": "Docker", "mysql": "MySQL", "mssql": "SQL Server", "adb": "ADB", "smb": "SMB",
    "sip": "SIP", "synology": "Synology NAS",
}  # fmt: skip
SEVERE_TAGS = frozenset(
    {
        "php2shell", "crypto-miner", "mirai", "malware-drop", "container-escape", "sql-rce",
        "eternalblue", "synology-exploit", "c3rb3r",
    }
)  # fmt: skip
WARNING_TAGS = frozenset({"db-ransom", "redis-rogue-master", "sip-fraud", "persistence"})
SEVERITY_ORDER = ("info", "notice", "warning", "severe")
NAME_MAX = 100


def clean_family(label: str) -> str:
    """A malware family label reduced to a safe display name."""
    kept = "".join(c for c in label.strip() if c.isalnum() or c in " ._-+")[:32].strip()
    return kept[:1].upper() + kept[1:] if kept else ""


def dominant(tags: Iterable[str]) -> str | None:
    """The objective tag that tells the story: most sessions first, then the priority order."""
    counts = Counter(t for t in tags if t in OBJECTIVE_NAMES)
    if not counts:
        return None
    rank = {t: i for i, t in enumerate(OBJECTIVE_TAGS)}
    return min(counts, key=lambda t: (-counts[t], rank[t]))


def also_goal(tags: Iterable[str], primary: str | None) -> str | None:
    """A second goal worth naming next to ``primary``, when the campaign did more than one thing
    (credential stuffing, then a dropper, then a ransom note), in priority order."""
    if primary is None:
        return None
    present = set(tags)
    rank = {t: i for i, t in enumerate(OBJECTIVE_TAGS)}
    others = [
        t
        for t in present
        if t in ALSO_NAMES and t != primary and t not in IMPLIED_BY.get(primary, frozenset())
    ]
    return min(others, key=lambda t: rank[t]) if others else None


def campaign_name(
    families: Iterable[str],
    tags: Iterable[str],
    sensors: Iterable[str],
    campaign_id: int | None = None,
) -> str:
    """``<Family> loader over Telnet #41``: family, else objective (and a second goal), else
    just the sensor."""
    tags = list(tags)
    objective = dominant(tags)
    family = Counter(f for f in (clean_family(x) for x in families) if f)
    sensor_counts = Counter(sensors)
    top_sensor = min(sensor_counts, key=lambda s: (-sensor_counts[s], s)) if sensor_counts else None
    if family:
        label = min(family, key=lambda f: (-family[f], f))
        base = f"{label} {FAMILY_NOUNS.get(objective or '', 'campaign')}"
    elif objective:
        base = OBJECTIVE_NAMES[objective]
        also = also_goal(tags, objective)
        if also:
            base = f"{base} and {ALSO_NAMES[also]}"
    else:
        base = "Shared activity"
    where = f" over {SENSOR_LABELS.get(top_sensor, top_sensor)}" if top_sensor else ""
    suffix = f" #{campaign_id}" if campaign_id is not None else ""
    return f"{base}{where}{suffix}"[:NAME_MAX]


def severity_of(tags: Iterable[str], commands: int = 0, login_attempts: int = 0) -> str:
    """info / notice / warning / severe, the same meaning as a session's severity."""
    tagset = set(tags)
    if tagset & SEVERE_TAGS:
        return "severe"
    if tagset & WARNING_TAGS or commands > 0:
        return "warning"
    if login_attempts > 0 or tagset:
        return "notice"
    return "info"


def max_severity(*levels: str) -> str:
    """The most serious of several severity levels (unknown values rank lowest)."""
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return max(levels, key=lambda s: rank.get(s, -1), default="info")


def stages_of(technique_ids: Iterable[str], stage_by_technique: Mapping[str, str]) -> list[str]:
    """The stages the techniques cover, in story order."""
    present = {stage_by_technique[t] for t in technique_ids if t in stage_by_technique}
    return [s for s in STAGES if s in present]
