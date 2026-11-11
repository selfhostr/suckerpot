"""The loop of scripts/backup-service.sh: a failed dump is retried soon, a good one restores the
hourly rhythm. Runs the real script with fake `pg_dump`, `sleep` and `df` first on PATH, in a
temporary backup folder: no database, no real waiting."""

import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "backup-service.sh"

# Fails for the first SHIM_FAILS calls, then writes a small dump.
PG_DUMP = """#!/bin/sh
n=$(cat "$SHIM_DIR/dump-calls" 2> /dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$SHIM_DIR/dump-calls"
if [ "$n" -le "$SHIM_FAILS" ]; then
  echo "pg_dump: error: connection refused" >&2
  exit 1
fi
echo "dump-bytes"
"""

# Records the delay, then fails once SHIM_SLEEPS sleeps were asked, which ends the loop (set -e).
SLEEP = """#!/bin/sh
echo "$1" >> "$SHIM_DIR/sleeps"
n=$(wc -l < "$SHIM_DIR/sleeps")
[ "$n" -lt "$SHIM_SLEEPS" ] || exit 1
"""

# Plenty of free space, so make_room never prunes or refuses.
DF = """#!/bin/sh
printf 'Filesystem 1024-blocks Used Available Capacity Mounted\\nfake 9999999999 1 9999999999 1%% /\\n'
"""


def _shim(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _loop(
    tmp_path: Path, fails: int, sleeps: int
) -> tuple[list[int], subprocess.CompletedProcess[str]]:
    """Runs the service loop until `sleeps` sleeps were requested; returns the sleep delays."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    backups = tmp_path / "backups"
    backups.mkdir()
    _shim(bin_dir / "pg_dump", PG_DUMP)
    _shim(bin_dir / "sleep", SLEEP)
    _shim(bin_dir / "df", DF)
    script = tmp_path / "backup-service.sh"
    text = SCRIPT.read_text()
    text = text.replace("DIR=/backups", f"DIR={backups}")
    text = text.replace("LOCK=/tmp/backup.lock", f"LOCK={tmp_path}/lock")
    script.write_text(text)
    env = {
        "PATH": f"{bin_dir}:/usr/local/bin:/usr/bin:/bin",
        "SHIM_DIR": str(tmp_path),
        "SHIM_FAILS": str(fails),
        "SHIM_SLEEPS": str(sleeps),
        "POSTGRES_HOST": "db",
        "POSTGRES_PORT": "5432",
        "POSTGRES_USER": "u",
        "POSTGRES_DB": "d",
        "POSTGRES_PASSWORD": "dummy",
    }
    proc = subprocess.run(  # noqa: S603
        ["/bin/sh", str(script)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    sleeps_file = tmp_path / "sleeps"
    delays = [int(x) for x in sleeps_file.read_text().split()] if sleeps_file.exists() else []
    return delays, proc


def test_a_failed_first_dump_is_retried_within_a_minute(tmp_path: Path) -> None:
    delays, proc = _loop(tmp_path, fails=1, sleeps=2)
    assert delays[0] == 30
    assert len(list((tmp_path / "backups").glob("suckerpot-*.dump"))) == 1
    assert "pg_dump failed" in proc.stderr
    assert "backup: wrote suckerpot-" in proc.stdout


def test_after_a_success_the_next_check_is_hourly(tmp_path: Path) -> None:
    delays, _ = _loop(tmp_path, fails=1, sleeps=3)
    assert delays == [30, 3600, 3600]


def test_repeated_failures_back_off_and_are_capped_at_the_hour(tmp_path: Path) -> None:
    delays, _ = _loop(tmp_path, fails=99, sleeps=10)
    assert delays == [30, 60, 120, 240, 480, 960, 1920, 3600, 3600, 3600]


def test_a_healthy_start_checks_hourly(tmp_path: Path) -> None:
    delays, _ = _loop(tmp_path, fails=0, sleeps=2)
    assert delays == [3600, 3600]
