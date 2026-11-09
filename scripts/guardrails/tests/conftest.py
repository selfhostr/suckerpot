"""A sandbox to run the host scripts (install, update, rollback, env-set, env-migrate) safely.

Every test runs the scripts in a temporary copy of the files they need, with fake `docker`, `git`,
`curl`, `ss` and `sleep` programs first on PATH. The fakes only record what they were asked to do;
they never reach a real Docker daemon, a real repository or the network. DOCKER_HOST points at
a socket that does not exist, so a leaked real call fails instead of acting on a live stack.
"""

import os
import shutil
import stat
import subprocess
import textwrap
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]

COPIED = [
    "scripts/install.sh",
    "scripts/env-set.sh",
    "scripts/env-migrate.sh",
    "scripts/update.sh",
    "scripts/rollback.sh",
    "scripts/check-ports.sh",
    "scripts/check-vpn-env.sh",
    "scripts/ensure-volumes.sh",
    "scripts/restore-db.sh",
    "scripts/verify-images.sh",
    "scripts/compose-fresh.sh",
    "scripts/lib/env.sh",
    "scripts/lib/pseudonym.sh",
    "scripts/lib/ports-check.sh",
    "scripts/lib/ports_check_filter.py",
    "netproto/suckerpot_netproto/data/pseudonym_words.txt",
    ".env.example",
    "docker-compose.yml",
]

DOCKER_SHIM = r"""#!/bin/sh
# Fake docker: records the call, answers just enough for the scripts, never does anything.
echo "docker $*" >> "$SHIM_LOG"
case "$*" in
  "version "*) echo "27.0.1" ;;
  "compose version"*) echo "2.29.1" ;;
  "info "*) echo "$SHIM_DIR/dockerroot" ;;
  "volume inspect "*)
    for v in $SHIM_EXISTING_VOLUMES; do [ "volume inspect $v" = "$*" ] && exit 0; done
    exit 1 ;;
  "volume ls "*) for v in $SHIM_EXISTING_VOLUMES; do echo "$v"; done ;;
  "ps -a "*) [ -z "${SHIM_PROJECT_CONTAINERS:-}" ] || echo "${SHIM_PROJECT_CONTAINERS}" ;;
  "volume create "*) echo "${3:-}" ;;
  "pull "* | "build "*) ;;
  "run "*api.hashpw*)
    cat > "$SHIM_DIR/hash-stdin"
    echo '$argon2id$v=19$m=65536,t=3,p=4$ZmFrZXNhbHQ$ZmFrZWhhc2g' ;;
  "run "*cosign*" verify "*)
    [ -z "${SHIM_COSIGN_NODIGEST:-}" ] || { echo '[]'; exit 0; }
    echo '[{"critical":{"image":{"docker-manifest-digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}}]' ;;
  "run "*"--entrypoint test"*) [ -z "${SHIM_DUMP_MISSING:-}" ] || exit 1 ;;
  "run "*) echo 0 ;;
  "image inspect "*) echo "sha256:0123456789abcdef" ;;
  "compose ps backup --format"*) echo "${SHIM_BACKUP_HEALTH:-healthy}" ;;
  "compose ps -a --format"*) echo "api=shim/api:1"; echo "ingest=shim/ingest:1" ;;
  "compose ps -a migrate --format"*) [ -z "${SHIM_MIGRATE_STATE:-}" ] || echo "$SHIM_MIGRATE_STATE" ;;
  "compose ps --format"*)
    # SHIM_HEALTH_BEFORE / SHIM_HEALTH_AFTER: "service health" lines, switched by the first `up`.
    if [ -f "$SHIM_DIR/upped" ]; then h="${SHIM_HEALTH_AFTER:-}"; else h="${SHIM_HEALTH_BEFORE:-}"; fi
    if [ -n "$h" ]; then printf '%s\n' "$h"; else echo "api healthy"; echo "db healthy"; fi ;;
  "compose exec -T db sh -c"*) [ -z "${SHIM_ALEMBIC:-}" ] || echo "$SHIM_ALEMBIC" ;;
  "compose exec -T backup /bin/sh /backup-service.sh now preupdate") exit "${SHIM_BACKUP_RC:-0}" ;;
  "compose exec -T backup sh -c"*) echo "/backups/suckerpot-preupdate-20261101T020000Z.dump" ;;
  "compose exec -T api printenv SUCKERPOT_RUNNING_VERSION") echo "${SHIM_RUNNING_VERSION:-}" ;;
  "compose up"*)
    touch "$SHIM_DIR/upped"
    echo "ENV_AT_UP SUCKERPOT_VERSION=${SUCKERPOT_VERSION:-unset} DASHBOARD_PORT=${DASHBOARD_PORT:-unset} SENSOR_WEB=${SENSOR_WEB:-unset}" >> "$SHIM_LOG"
    [ "${SHIM_UP_RC:-0}" = 0 ] || exit "$SHIM_UP_RC" ;;
  *) ;;
esac
exit 0
"""

GIT_SHIM = r"""#!/bin/sh
# Fake git: a scripted answer table in $SHIM_DIR/git, never touches a repository.
echo "git $*" >> "$SHIM_LOG"
mode=$(cat "$SHIM_DIR/gitstate/mode" 2>/dev/null || echo none)
rd() { cat "$SHIM_DIR/gitstate/$1" 2>/dev/null || true; }
case "$*" in
  "rev-parse --git-dir")
    [ "$mode" = none ] && exit 128
    echo .git ;;
  "rev-parse --absolute-git-dir")
    if [ "$mode" = linked ]; then echo "/shim/main/.git/worktrees/x"; else echo "/shim/main/.git"; fi ;;
  "rev-parse --path-format=absolute --git-common-dir") echo "/shim/main/.git" ;;
  "rev-parse HEAD") rd head ;;
  "rev-parse --short HEAD") rd head | cut -c1-7 ;;
  "rev-parse -q --verify refs/tags/"*)
    t=${4#refs/tags/}
    grep -qx "$t" "$SHIM_DIR/gitstate/tags" 2>/dev/null; exit $? ;;
  "rev-parse -q --verify refs/heads/"*) echo "$(rd head)" ;;
  "rev-parse -q --verify "*) echo deadbeefdeadbeef ;;
  "rev-parse v"*|"rev-parse refs/tags/"*) rd tagcommit ;;
  "symbolic-ref --short -q HEAD") b=$(rd branch); [ -n "$b" ] && echo "$b" || exit 1 ;;
  "describe --tags --always"*) rd describe ;;
  "describe --tags --exact-match HEAD") exit 128 ;;
  "status --porcelain"*) rd dirty ;;
  "fetch "*) ;;
  "tag -l v*.*.* --sort"*) rd tags | sort -rV ;;
  "tag -l --format="*) rd notes ;;
  "checkout --quiet --detach "*) printf '%s' "$4" > "$SHIM_DIR/gitstate/head" ;;
  "checkout "*) ;;
  "pull "*) ;;
  *) ;;
esac
exit 0
"""

CURL_SHIM = r"""#!/bin/sh
echo "curl $*" >> "$SHIM_LOG"
exit 0
"""

SS_SHIM = r"""#!/bin/sh
cat "$SHIM_DIR/ss-output" 2>/dev/null || true
exit 0
"""

SLEEP_SHIM = "#!/bin/sh\nexit 0\n"


@dataclass
class Sandbox:
    """A throwaway copy of the host scripts with fakes on PATH."""

    root: Path
    shim: Path
    env: dict[str, str] = field(default_factory=dict)

    @property
    def log(self) -> Path:
        return self.shim / "calls.log"

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []

    def docker_calls(self) -> list[str]:
        return [c for c in self.calls() if c.startswith("docker ")]

    def git_mode(self, mode: str) -> None:
        (self.shim / "gitstate" / "mode").write_text(mode)

    def git_set(self, name: str, value: str) -> None:
        (self.shim / "gitstate" / name).write_text(value)

    def write_env(self, text: str) -> Path:
        path = self.root / ".env"
        path.write_text(text)
        path.chmod(0o600)
        return path

    def run(
        self,
        script: str,
        *args: str,
        stdin: str | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = {**self.env, **(extra_env or {})}
        return subprocess.run(  # noqa: S603
            ["bash", str(self.root / script), *args],  # noqa: S607
            cwd=self.root,
            env=env,
            input=stdin if stdin is not None else "",
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def sandbox(tmp_path: Path) -> Sandbox:
    root = tmp_path / "repo"
    shim = tmp_path / "shim"
    root.mkdir()
    (shim / "gitstate").mkdir(parents=True)
    (shim / "dockerroot").mkdir()
    for rel in COPIED:
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dest)
    (root / "api").mkdir(exist_ok=True)
    (root / "api" / "Dockerfile").write_text("FROM scratch\n")
    for name, text in {
        "docker": DOCKER_SHIM,
        "git": GIT_SHIM,
        "curl": CURL_SHIM,
        "ss": SS_SHIM,
        "sleep": SLEEP_SHIM,
    }.items():
        _write_exec(shim / name, text)
    meminfo = shim / "meminfo"
    meminfo.write_text("MemTotal:        8000000 kB\n")
    env = {
        "PATH": f"{shim}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "LANG": "C",
        "SHIM_DIR": str(shim),
        "SHIM_LOG": str(shim / "calls.log"),
        "SHIM_EXISTING_VOLUMES": "",
        "SELFHOSTR_MEMINFO": str(meminfo),
        "SELFHOSTR_FREE_DISK_KB": str(100 * 1024 * 1024),
        "DOCKER_HOST": "unix:///nonexistent/selfhostr-test.sock",
    }
    return Sandbox(root=root, shim=shim, env=env)


@pytest.fixture
def parse_env() -> Callable[[Path], dict[str, str]]:
    def parse(path: Path) -> dict[str, str]:
        out: dict[str, str] = {}
        for line in path.read_text().splitlines():
            if line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            out[key] = value
        return out

    return parse


def dedent(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


def is_real_docker_untouched(sandbox: Sandbox) -> bool:
    """True when the only docker on PATH is the fake one."""
    found = shutil.which("docker", path=sandbox.env["PATH"])
    return found == str(sandbox.shim / "docker") and os.access(found, os.X_OK)
