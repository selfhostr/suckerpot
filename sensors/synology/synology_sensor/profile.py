"""Per-deployment fake NAS identity.

The host name, model and serial come from a random secret generated once and stored in
``<data_dir>/profile.json`` (mode 0600). Nothing here is taken from public data and the secret
is never shown to clients.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import random
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger("synology_sensor.profile")

# model -> (DSM platform, first sale year). Every model here runs DSM 7.2.1, the build this
# sensor claims, and its serial can only carry a year from its launch on.
MODELS: dict[str, tuple[str, int]] = {
    "DS118": ("rtd1296", 2017), "DS218+": ("apollolake", 2018), "DS220+": ("geminilake", 2020),
    "DS220j": ("rtd1296", 2020), "DS418": ("rtd1296", 2018), "DS418play": ("apollolake", 2018),
    "DS423+": ("geminilake", 2022), "DS620slim": ("apollolake", 2018),
    "DS718+": ("apollolake", 2017), "DS720+": ("geminilake", 2020),
    "DS723+": ("r1000", 2022), "DS918+": ("apollolake", 2018), "DS920+": ("geminilake", 2020),
    "DS923+": ("r1000", 2023), "DS1019+": ("apollolake", 2019), "DS1520+": ("geminilake", 2020),
    "DS1522+": ("r1000", 2022), "DS1618+": ("denverton", 2018), "DS1621+": ("v1000", 2021),
    "DS1819+": ("denverton", 2019), "DS1821+": ("v1000", 2021), "DS2419+": ("denverton", 2019),
    "DS2422+": ("v1000", 2022), "DS3018xs": ("broadwellnk", 2018),
    "DS3622xs+": ("broadwellnk", 2022), "RS422+": ("r1000", 2022), "RS820+": ("apollolake", 2019),
    "RS1221+": ("v1000", 2021), "RS2421+": ("v1000", 2021),
}  # fmt: skip
_MODELS = list(MODELS)
# Host names an owner would plausibly pick.
_NAMES = [
    "DiskStation", "NAS01", "nas", "SynologyNAS", "Storage", "FileServer", "Diskstation1",
    "NAS", "nas01", "BackupNAS", "HomeNAS", "OfficeNAS", "Archive", "MediaServer", "syno",
    "Vault", "DataStore", "FamilyNAS", "Fileshare", "NASMain", "Cube", "Silo", "Depot",
    "PhotoNAS", "TimeMachine", "SharedDrive", "Server01", "Library",
]  # fmt: skip


def _model_host(model: str) -> str:
    return model.replace("+", "plus").lower()


@dataclass(frozen=True)
class Profile:
    secret: bytes
    created: float
    hostname: str
    model: str
    serial: str
    arch: str = ""

    def self_identity(self) -> dict[str, list[str]]:
        """Per-install names only. Host names come from a shared pool (or the model name), so
        they are generic words and are not declared: ingest would treat them as deny terms."""
        base = self.hostname.rstrip("0123456789").lower()
        generic = {n.lower() for n in _NAMES} | {_model_host(m) for m in _MODELS}
        if not self.hostname or base in generic or self.hostname.lower() in generic:
            return {"names": []}
        return {"names": [self.hostname[:64]]}

    def rng(self, label: str) -> random.Random:
        digest = hmac.new(self.secret, label.encode(), hashlib.sha256).digest()
        return random.Random(int.from_bytes(digest[:16], "big"))  # noqa: S311 - content only


def build_profile(secret: bytes, created: float) -> Profile:
    base = Profile(secret, created, "", "", "")
    rng = base.rng("layout")
    model = rng.choice(_MODELS)
    # Models are sometimes used as the host name (DS920plus), otherwise a friendly name.
    hostname = (
        model.replace("+", "plus")
        if rng.random() < 0.4
        else rng.choice(_NAMES) + (str(rng.randrange(2, 9)) if rng.random() < 0.2 else "")
    )
    arch, launched = MODELS[model]
    first = max(launched, 2018)
    now_year = datetime.fromtimestamp(created, UTC).year
    year = first + rng.randrange(0, max(1, now_year - first + 1))
    serial = "{}{}{}{:06d}".format(
        f"{year % 100:02d}",
        rng.choice(["0", "1", "2"]) + rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ"),
        rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") + rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ"),
        rng.randrange(0, 999999),
    )
    return Profile(secret, created, hostname, model, serial, arch)


def load_or_create_profile(data_dir: str) -> Profile:
    """Read the profile from ``data_dir`` or create it. Falls back to an ephemeral secret."""
    path = Path(data_dir) / "profile.json"
    try:
        doc = json.loads(path.read_text())
        secret = bytes.fromhex(doc["secret"])
        created = float(doc["created"])
        if len(secret) >= 16:
            return build_profile(secret, created)
    except OSError, ValueError, KeyError, TypeError:
        pass
    secret = secrets.token_bytes(32)
    created = float(int(time.time()))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps({"secret": secret.hex(), "created": created}))
        os.replace(tmp, path)
    except OSError:
        log.warning("cannot persist the profile in %s; identity will change on restart", data_dir)
    return build_profile(secret, created)
