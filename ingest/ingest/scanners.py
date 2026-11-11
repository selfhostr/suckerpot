"""Known research scanners: harmless, self-announcing internet crawlers (M19).

The list lives in ``rules/scanners.yaml``. A scanner is recognised only by the network that owns
the address (ASN or organisation name, both from the local GeoIP database). The HTTP user-agent
is attacker-controlled, so it never makes a session benign.

Being benign is an allowlist, decided on what the session did, not on what it claims to be: it
may only connect, disconnect, probe (``scan``) and send GET, HEAD or OPTIONS requests; every flag
a sensor set must be a plain probe flag (:data:`SAFE_FLAGS`) and every tag a benign tag
(:data:`BENIGN_TAGS`). Anything else (a login attempt, a command, a download, an exploit flag, an
unknown flag or tag, a POST) makes the session non-benign for good. Matching is a plain
substring test (no regular expressions).
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ingest.tagging import RuleError

FILE_NAME = "scanners.yaml"
MAX_SCANNERS = 100
MAX_ENTRIES = 32
MAX_NAME = 64
MAX_NEEDLE = 96
MAX_TEXT = 512  # an attacker-sized user-agent or organisation is cut before it is compared

# Tags a scanner session may carry. Every tag of ingest/rules/*.yaml is classified in exactly one
# of the two sets (a test fails when a new tag is not): add new tags to ATTACK_TAGS unless they
# only describe looking around.
BENIGN_TAGS = frozenset(
    {
        "scanner",
        "recon",
        "env-file-probe",
        "synology-dsm",
        "smb-v1-probe",
        "php-upload-progress-probe",
    }
)
ATTACK_TAGS = frozenset(
    {
        "bluekeep", "c3rb3r", "container-escape", "credential-stuffing", "crypto-miner",
        "db-ransom", "eternalblue", "exec-attempt", "malware-drop", "mirai", "persistence",
        "php2shell", "phpmyadmin-bruteforce", "rdp-cleartext", "redis-rogue-master", "sip-fraud",
        "sql-rce", "synology-exploit", "weak-credentials", "wordpress-bruteforce",
    }
)  # fmt: skip

SAFE_TYPES = frozenset({"connect", "disconnect", "http_request", "scan"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Sensor flags that only describe looking around. Any other flag (rce, php_code, shellshock,
# lfi, sqli, ssrf, container_create, bluekeep_probe...) disqualifies the session.
SAFE_FLAGS = frozenset(
    {
        "recon", "recon_dotfile", "config_leak", "backup_probe", "scanner_ua", "no_user_agent",
        "router_probe", "cgi_probe", "console_probe", "db_admin_probe", "docker_api_probe",
        "exchange_probe", "f5_probe", "geoserver_probe", "jenkins_probe", "laravel_probe",
        "phpinfo_probe", "phpmyadmin", "phpunit_probe", "solr_probe", "spring_probe",
        "tomcat_probe", "vpn_probe", "wordpress",
    }
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class Scanner:
    name: str
    asns: frozenset[int] = frozenset()
    orgs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScannerSet:
    scanners: tuple[Scanner, ...] = ()

    def match(self, *, asn: int | None, org: str | None) -> str | None:
        """The name of the first scanner whose network owns the address, or None."""
        org_text = org[:MAX_TEXT].lower() if isinstance(org, str) else ""
        for s in self.scanners:
            if asn is not None and asn in s.asns:
                return s.name
            if org_text and any(n in org_text for n in s.orgs):
                return s.name
        return None


def event_is_benign_safe(etype: str, data: Mapping[str, Any], tags: Collection[str]) -> bool:
    """True when this one event is something a harmless scanner could have sent."""
    if etype not in SAFE_TYPES or not BENIGN_TAGS.issuperset(tags):
        return False
    if etype == "http_request":
        method = data.get("method")
        if not isinstance(method, str) or method.upper() not in SAFE_METHODS:
            return False
    flags = data.get("flags")
    if flags is None:
        return True
    if not isinstance(flags, list):
        return False
    return all(isinstance(f, str) and f.lower() in SAFE_FLAGS for f in flags)


def stays_benign(
    *,
    commands: int,
    downloads: int,
    login_attempts: int,
    login_success: bool,
    tags: Collection[str],
) -> bool:
    """False as soon as the session did more than look around (session counters and tags)."""
    if commands > 0 or downloads > 0 or login_attempts > 0 or login_success:
        return False
    return BENIGN_TAGS.issuperset(tags)


def _strings(raw: Any, where: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > MAX_ENTRIES:
        raise RuleError(f"{where}: must be a list of at most {MAX_ENTRIES} strings")
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip() or len(item) > MAX_NEEDLE:
            raise RuleError(f"{where}: entries must be short, non-empty strings")
        out.append(item.strip().lower())
    return tuple(out)


def _asns(raw: Any, where: str) -> frozenset[int]:
    if raw is None:
        return frozenset()
    if not isinstance(raw, list) or len(raw) > MAX_ENTRIES:
        raise RuleError(f"{where}: 'asns' must be a list of AS numbers")
    for a in raw:
        if not isinstance(a, int) or isinstance(a, bool) or not 0 < a < 2**32:
            raise RuleError(f"{where}: 'asns' must be a list of AS numbers")
    return frozenset(raw)


def _parse(raw: Any, index: int) -> Scanner:
    where = f"{FILE_NAME}: scanner #{index + 1}"
    if not isinstance(raw, Mapping):
        raise RuleError(f"{where}: must be a mapping")
    unknown = set(raw) - {"name", "asns", "orgs"}
    if unknown:
        raise RuleError(f"{where}: unknown keys {sorted(map(str, unknown))}")
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > MAX_NAME:
        raise RuleError(f"{where}: 'name' must be a string of at most {MAX_NAME} characters")
    scanner = Scanner(
        name=name.strip(),
        asns=_asns(raw.get("asns"), where),
        orgs=_strings(raw.get("orgs"), f"{where} orgs"),
    )
    if not (scanner.asns or scanner.orgs):
        raise RuleError(f"{where}: needs at least one of asns, orgs")
    return scanner


def load_scanners(directory: Path) -> ScannerSet:
    """Read ``scanners.yaml``; a missing file means no scanner is labelled, a broken one raises."""
    path = directory / FILE_NAME
    if not path.is_file():
        return ScannerSet()
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuleError(f"{FILE_NAME}: cannot read ({type(exc).__name__})") from exc
    raw = doc.get("scanners") if isinstance(doc, Mapping) else None
    if not isinstance(raw, list) or len(raw) > MAX_SCANNERS:
        raise RuleError(f"{FILE_NAME}: top level must have a 'scanners' list")
    scanners = tuple(_parse(r, i) for i, r in enumerate(raw))
    if len({s.name for s in scanners}) != len(scanners):
        raise RuleError(f"{FILE_NAME}: duplicate scanner names")
    return ScannerSet(scanners)
