"""Per-deployment fake host identity.

The daemon ID, kernel build, hardware, the container set (count, names, images, tags, ports),
image IDs and creation dates come from a random secret generated once and stored in
``<data_dir>/profile.json`` (mode 0600). Nothing here is taken from public data, two installs
never share a container list and the secret is never shown to clients.
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
from pathlib import Path

from docker_sensor.catalog import APPS, BASE_IMAGES, EXTRA_BASE, PROJECTS

log = logging.getLogger("docker_sensor.profile")

# (OS release string, kernels shipped with that point release): both agree on every install.
_OS_RELEASES = [
    ("Ubuntu 24.04.1 LTS", ("6.8.0-45-generic", "6.8.0-48-generic", "6.8.0-49-generic")),
    ("Ubuntu 24.04.1 LTS", ("6.8.0-50-generic", "6.8.0-51-generic")),
    ("Ubuntu 24.04.2 LTS", ("6.8.0-52-generic", "6.8.0-53-generic", "6.8.0-55-generic")),
    ("Ubuntu 24.04.2 LTS", ("6.8.0-57-generic", "6.8.0-58-generic", "6.8.0-60-generic")),
    ("Ubuntu 24.04.3 LTS", ("6.8.0-71-generic", "6.8.0-78-generic", "6.8.0-84-generic")),
]
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


@dataclass(frozen=True)
class FakeContainer:
    id: str
    name: str
    image: str
    image_id: str
    command: str
    created: int
    ports: tuple[tuple[int, int], ...]  # (private, public) TCP ports; public 0 = not published
    ip: str
    labels: tuple[tuple[str, str], ...] = ()  # Compose labels; plain containers have none


@dataclass(frozen=True)
class Profile:
    secret: bytes
    created: float
    daemon_id: str
    kernel: str
    cpus: int
    mem_bytes: int
    boot_ts: float
    net_prefix: str
    containers: tuple[FakeContainer, ...]
    images: tuple[tuple[str, str, int, int], ...]  # (repo:tag, id, size, created)
    os_name: str = "Ubuntu 24.04.1 LTS"

    def derive(self, label: str, length: int = 64) -> str:
        digest = hmac.new(self.secret, label.encode(), hashlib.sha256).hexdigest()
        return digest[:length]

    def rng(self, label: str) -> random.Random:
        digest = hmac.new(self.secret, label.encode(), hashlib.sha256).digest()
        return random.Random(int.from_bytes(digest[:16], "big"))  # noqa: S311 - content only


def _service_name(
    rng: random.Random, style: int, project: str, svc: str, taken: set[str]
) -> tuple[str, int]:
    """(name, container number): plain or one of the naming schemes, unique within the host."""
    for n in range(1, 9):
        if style == 0:
            name = svc if n == 1 else f"{svc}{n}"
        elif style == 1:
            name = f"{project}-{svc}-{n}"
        elif style == 2:
            name = f"{project}_{svc}_{n}"
        else:
            name = f"{project}-{svc}" if n == 1 else f"{project}-{svc}{n}"
        if name not in taken:
            return name, n
    return f"{svc}-{rng.randrange(10, 99)}", 1


def build_profile(secret: bytes, created: float) -> Profile:
    base = Profile(secret, created, "", "", 0, 0, 0.0, "", (), ())
    rng = base.rng("layout")
    daemon = ":".join("".join(rng.choice(_B32) for _ in range(4)) for _ in range(12))
    prefix = f"172.{rng.choice([17, 18])}.0"
    boot = created - rng.randrange(3, 60) * 86400 - rng.randrange(0, 86400)
    os_name, kernels = rng.choice(_OS_RELEASES)
    images: list[tuple[str, str, int, int]] = []
    containers: list[FakeContainer] = []
    crng = base.rng("containers")
    project = crng.choice(PROJECTS)
    style = crng.randrange(4)
    taken: set[str] = set()
    ip_last = 2
    span = max(int(created - boot) - 7200, 3600)
    for i, idx in enumerate(crng.sample(range(len(APPS)), crng.randint(2, 6))):
        repo, tags, size, cmd, ports, svcs = APPS[idx]
        ref = f"{repo}:{crng.choice(tags)}"
        image_id = "sha256:" + base.derive(f"image-{i}")
        svc = crng.choice(svcs)
        name, number = _service_name(crng, style, project, svc, taken)
        taken.add(name)
        # Some containers came up with the host, others were (re)created weeks later.
        started = crng.randrange(60, 7200) if crng.random() < 0.5 else crng.randrange(60, span)
        container_created = int(boot + started)
        # An image is always older than the container made from it.
        image_created = min(
            int(created - crng.randrange(20, 160) * 86400),
            container_created - crng.randrange(3600, 30 * 86400),
        )
        images.append((ref, image_id, size + crng.randrange(0, 3_000_000), image_created))
        labels: tuple[tuple[str, str], ...] = ()
        if style in (1, 2):  # the two Compose naming schemes (v2 uses "-", v1 uses "_")
            wd = f"/srv/{project}"
            labels = (
                ("com.docker.compose.config-hash", base.derive(f"cfg-{i}")),
                ("com.docker.compose.container-number", str(number)),
                ("com.docker.compose.oneoff", "False"),
                ("com.docker.compose.project", project),
                ("com.docker.compose.project.config_files", f"{wd}/docker-compose.yml"),
                ("com.docker.compose.project.working_dir", wd),
                ("com.docker.compose.service", svc),
                ("com.docker.compose.version", "2.29.7" if style == 1 else "1.29.2"),
            )
        containers.append(
            FakeContainer(
                id=base.derive(f"container-{i}"),
                name=name,
                image=ref,
                image_id=image_id,
                command=cmd,
                created=container_created,
                ports=tuple((priv, crng.choice(pub)) for priv, pub in ports),
                ip=f"{prefix}.{ip_last}",
                labels=labels,
            )
        )
        ip_last += 1
    extra_rng = base.rng("extra-images")
    extra = BASE_IMAGES + extra_rng.sample(EXTRA_BASE, extra_rng.choice([1, 2, 3]))
    for j, (ref, size) in enumerate(extra):
        if any(img[0] == ref for img in images):
            continue
        jitter = extra_rng.randrange(0, 2_000_000)
        images.append(
            (
                ref,
                "sha256:" + base.derive(f"extra-image-{j}"),
                size + jitter,
                int(created - extra_rng.randrange(10, 200) * 86400),
            )
        )
    return Profile(
        secret=secret,
        created=created,
        daemon_id=daemon,
        kernel=rng.choice(kernels),
        cpus=rng.choice([4, 4, 8]),
        mem_bytes=rng.choice([8, 16, 16, 32]) * 1024**3 - rng.randrange(0, 600) * 1024**2,
        boot_ts=boot,
        net_prefix=prefix,
        containers=tuple(containers),
        images=tuple(images),
        os_name=os_name,
    )


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
