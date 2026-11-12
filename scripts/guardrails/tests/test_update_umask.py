"""A restrictive umask must never reach the checkout or the build.

scripts/update.sh keeps umask 077 around its state file, and scripts/auto-update.sh runs under it
as a whole. A checkout made under 077 leaves files 0600 and folders 0700, which the non-root users
inside the containers cannot read (the `migrate` container failed with "Permission denied" on its
migrations, and scripts such as backup-service.sh became 0700). These tests run the real scripts
against the fake git of conftest.py, whose checkout and pull create files the way git does: under
the umask of the process that runs them.
"""

import os
import re
import stat
from pathlib import Path

import pytest
from conftest import ROOT, Sandbox
from test_install import PASSWORD
from test_update import ENV, OLD, prepare, run_update, write_state

# What the fake checkout writes ("x" marks an executable), in folders that do not exist yet.
REWRITTEN = [
    "scripts/backup-service.sh x",
    "scripts/move-admin-ssh.sh x",
    "db/migrations/versions/0032_reputation_keep.py",
    "README.md",
]
# Tracked files an earlier update (or a clone made under umask 077) left unreadable.
HIT_FILES = {
    "config/old.yaml": 0o600,
    "scripts/old-helper.sh": 0o700,
    "deep/nested/f.txt": 0o600,
    "hub/README.md": 0o600,
}
HIT_DIRS = ["config", "deep/nested", "deep", "hub"]
# Never tracked: the secrets of the node. Their mode must survive.
PRIVATE_FILES = {
    ".env.bak-20261101": 0o600,
    "hub/.env": 0o600,
    "hub/secrets/token": 0o600,
}
PRIVATE_DIRS = {"hub/secrets": 0o700}


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def make(sb: Sandbox, rel: str, perm: int) -> None:
    path = sb.root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("content\n")
    path.chmod(perm)


def stage(sb: Sandbox) -> Path:
    """Unreadable tracked files, private untracked ones, and a fake checkout that rewrites files.

    Returns a file outside the checkout that a tracked symlink points to.
    """
    for rel, perm in HIT_FILES.items():
        make(sb, rel, perm)
    for rel, perm in PRIVATE_FILES.items():
        make(sb, rel, perm)
    for rel, perm in PRIVATE_DIRS.items():
        (sb.root / rel).chmod(perm)
    for rel in HIT_DIRS:
        (sb.root / rel).chmod(0o700)
    outside = sb.root.parent / "outside-secret"
    outside.write_text("secret\n")
    outside.chmod(0o600)
    (sb.root / "link-to-outside").symlink_to(outside)
    tracked = [r.split()[0] for r in REWRITTEN] + list(HIT_FILES) + ["link-to-outside"]
    sb.git_set("tracked", "".join(f"{p}\0" for p in tracked))
    sb.git_set("rewrites", "\n".join(REWRITTEN) + "\n")
    return outside


def check_readable(sb: Sandbox, outside: Path) -> None:
    root = sb.root
    # What the checkout wrote: readable by everyone, executables too.
    assert mode(root / "scripts/backup-service.sh") == 0o755
    assert mode(root / "scripts/move-admin-ssh.sh") == 0o755
    assert mode(root / "db/migrations/versions/0032_reputation_keep.py") == 0o644
    assert mode(root / "README.md") == 0o644
    for folder in ("db", "db/migrations", "db/migrations/versions", "scripts"):
        assert mode(root / folder) & 0o055 == 0o055, folder
    # What an earlier update left behind: repaired, folders in between included.
    assert mode(root / "config/old.yaml") == 0o644
    assert mode(root / "scripts/old-helper.sh") == 0o755
    assert mode(root / "deep/nested/f.txt") == 0o644
    for folder in ("config", "deep", "deep/nested", "hub"):
        assert mode(root / folder) & 0o055 == 0o055, folder
    # Never touched: what git does not track, and the target of a tracked symlink.
    assert mode(root / ".env") == 0o600
    for rel, perm in PRIVATE_FILES.items():
        assert mode(root / rel) == perm, rel
    for rel, perm in PRIVATE_DIRS.items():
        assert mode(root / rel) == perm, rel
    assert mode(outside) == 0o600


@pytest.mark.parametrize("install_mode", ["images", "source"])
def test_update_under_umask_077_leaves_a_readable_checkout(
    sandbox: Sandbox, install_mode: str
) -> None:
    prepare(sandbox, mode=install_mode, branch="main" if install_mode == "source" else "")
    if install_mode == "source":
        sandbox.env["SHIM_RUNNING_VERSION"] = "v0.8.0"
    outside = stage(sandbox)
    proc = sandbox.run("scripts/update.sh", "--yes", umask="077")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = sandbox.calls()
    expected = "git pull --ff-only --quiet" if install_mode == "source" else "git checkout"
    assert any(c.startswith(expected) for c in calls)
    check_readable(sandbox, outside)
    # The rollback state stays private.
    state = sandbox.root / ".suckerpot-state"
    assert mode(state) == 0o700
    assert mode(state / "last-update.json") == 0o600
    assert '"completed": true' in (state / "last-update.json").read_text()


def test_update_run_by_the_automatic_updater_keeps_the_same_guarantees(sandbox: Sandbox) -> None:
    """auto-update.sh holds the lock, runs under umask 077 and calls update.sh --yes --auto."""
    prepare(sandbox)
    outside = stage(sandbox)
    proc = sandbox.run(
        "scripts/update.sh",
        "--yes",
        "--auto",
        "v0.9.0",
        umask="077",
        extra_env={"SELFHOSTR_UPDATE_LOCK_HELD": "1"},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    check_readable(sandbox, outside)
    assert mode(sandbox.root / ".suckerpot-state/last-update.json") == 0o600


def test_update_under_the_usual_umask_changes_nothing_for_the_caller(sandbox: Sandbox) -> None:
    prepare(sandbox)
    outside = stage(sandbox)
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    check_readable(sandbox, outside)
    assert mode(sandbox.root / ".suckerpot-state/last-update.json") == 0o600


def test_rollback_under_umask_077_leaves_a_readable_checkout(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.write_env(ENV.replace("v0.8.0", "v0.9.0"))
    write_state(sandbox)
    # restore-db.sh has its own tests; here it is replaced by a recorder.
    (sandbox.root / "scripts" / "restore-db.sh").write_text('echo "restore-db $*" >> "$SHIM_LOG"\n')
    outside = stage(sandbox)
    proc = sandbox.run("scripts/rollback.sh", "--yes", umask="077")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"git checkout --quiet --detach {OLD}" in sandbox.calls()
    check_readable(sandbox, outside)
    assert mode(sandbox.root / ".suckerpot-state/last-update.json") == 0o600


def test_env_migrate_repairs_a_checkout_an_older_update_made_under_umask_077(
    sandbox: Sandbox,
) -> None:
    """The update that is running may be an older update.sh: env-migrate.sh is the first new script."""
    prepare(sandbox)
    outside = stage(sandbox)
    # The checkout already happened (and left the new files unreadable).
    for rel in ("scripts/backup-service.sh", "db/migrations/versions/0032_reputation_keep.py"):
        make(sandbox, rel, 0o700 if rel.endswith(".sh") else 0o600)
    (sandbox.root / "db").chmod(0o700)
    proc = sandbox.run("scripts/env-migrate.sh", umask="077")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert mode(sandbox.root / "scripts/backup-service.sh") == 0o755
    assert mode(sandbox.root / "db/migrations/versions/0032_reputation_keep.py") == 0o644
    assert mode(sandbox.root / "db") & 0o055 == 0o055
    assert mode(sandbox.root / "config/old.yaml") == 0o644
    assert mode(sandbox.root / ".env") == 0o600
    for rel, perm in PRIVATE_FILES.items():
        assert mode(sandbox.root / rel) == perm, rel
    assert mode(outside) == 0o600


def test_install_under_umask_077_repairs_a_clone_and_keeps_env_private(sandbox: Sandbox) -> None:
    outside = stage(sandbox)
    for rel in ("scripts/backup-service.sh", "db/migrations/versions/0032_reputation_keep.py"):
        make(sandbox, rel, 0o700 if rel.endswith(".sh") else 0o600)
    proc = sandbox.run(
        "scripts/install.sh",
        "--yes",
        "--source",
        "--sensors",
        "ssh",
        "--admin-password-stdin",
        stdin=PASSWORD + "\n",
        umask="077",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert mode(sandbox.root / ".env") == 0o600
    assert mode(sandbox.root / "scripts/backup-service.sh") == 0o755
    assert mode(sandbox.root / "db/migrations/versions/0032_reputation_keep.py") == 0o644
    assert mode(sandbox.root / "config/old.yaml") == 0o644
    assert mode(outside) == 0o600
    assert mode(sandbox.root / "hub/secrets/token") == 0o600


# ----------------------------------------------------------------------- static

# Commands that write the checkout, or read it to build an image.
RISKY = re.compile(
    r"\bgit\s+(checkout|pull)\b|\bdocker\s+build\b|\bdocker\s+compose\b.*(\bbuild\b|--build\b)"
)
SCRIPTS = ["update.sh", "rollback.sh", "install.sh", "auto-update.sh"]


@pytest.mark.parametrize("name", SCRIPTS)
def test_no_checkout_pull_or_build_runs_under_umask_077(name: str) -> None:
    private = False
    for number, line in enumerate((ROOT / "scripts" / name).read_text().splitlines(), 1):
        code = line.strip()
        if code.startswith("#"):
            continue
        found = re.match(r"umask\s+(\S+)", code)
        if found:
            private = found.group(1) == "077"
            continue
        if RISKY.search(code):
            assert "with_public_umask" in code or not private, f"{name}:{number}: {code}"


def test_the_commands_that_write_or_read_the_checkout_go_through_with_public_umask() -> None:
    wanted = {
        "update.sh": [
            "with_public_umask git pull --ff-only --quiet",
            'with_public_umask git checkout --quiet --detach "$target_commit"',
            "with_public_umask docker compose build",
        ],
        "rollback.sh": [
            'with_public_umask git checkout --quiet "$from_branch"',
            'with_public_umask git checkout --quiet --detach "$from_ref"',
            "with_public_umask docker compose build",
        ],
        "install.sh": ["with_public_umask docker compose up -d --build"],
    }
    for name, fragments in wanted.items():
        text = (ROOT / "scripts" / name).read_text()
        for fragment in fragments:
            assert fragment in text, (name, fragment)


def test_the_umask_is_restored_after_the_private_part_of_update_and_install() -> None:
    for name in ("update.sh", "install.sh"):
        code = [
            x.strip()
            for x in (ROOT / "scripts" / name).read_text().splitlines()
            if not x.strip().startswith("#")
        ]
        assert "caller_umask=$(umask)" in code, name
        assert 'umask "$caller_umask"' in code, name
        assert code.index("umask 077") > code.index("caller_umask=$(umask)"), name


def test_fix_tracked_modes_is_called_after_every_checkout() -> None:
    update = (ROOT / "scripts/update.sh").read_text()
    assert update.index("fix_tracked_modes") > update.index("with_public_umask git checkout")
    rollback = (ROOT / "scripts/rollback.sh").read_text()
    assert rollback.index("fix_tracked_modes") > rollback.index("with_public_umask git checkout")
    # The first script of the new checkout that an (older) running update.sh calls.
    assert "fix_tracked_modes" in (ROOT / "scripts/env-migrate.sh").read_text()
    assert os.access(ROOT / "scripts/lib/env.sh", os.R_OK)
