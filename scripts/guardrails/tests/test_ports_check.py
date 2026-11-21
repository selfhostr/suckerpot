"""Port reachability check: scripts/lib/ports-check.sh, ports_check_filter.py, the install prompt.

The check reads the database (a fake `docker compose exec -T db`), filters the addresses with
scripts/lib/ports_check_filter.py (run by the fake `exec -T ingest python`) and makes no network
call. The SQL was also run against a real PostgreSQL by hand.
"""

import importlib.util
import re
import sys
from typing import Any

import pytest
from conftest import ROOT, Sandbox
from test_install import add_participant_files, p_real, wrap_docker

LIB = ROOT / "scripts/lib/ports-check.sh"
FILTER = ROOT / "scripts/lib/ports_check_filter.py"

DB_ROWS = (
    '  "compose exec -T -e PGOPTIONS="*" db sh -c"*)\n'
    '    echo "docker $*" >> "$SHIM_LOG"\n'
    '    cat > "$SHIM_DIR/db-sql"\n'
    '    [ ! -f "$SHIM_DIR/db-fail" ] || exit 1\n'
    '    cat "$SHIM_DIR/db-rows" 2>/dev/null; exit 0 ;;\n'
    '  "compose exec -T ingest python -I -c"*)\n'
    '    echo "docker compose exec -T ingest python -I -c <filter>" >> "$SHIM_LOG"\n'
    '    exec "$SHIM_PYTHON" -I -c "$8" ;;'
)


def _load_filter() -> Any:
    spec = importlib.util.spec_from_file_location("ports_check_filter", FILTER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FILTER_MODULE = _load_filter()


# RFC 1918 handling is the standard library's `is_global`; no private range is listed anywhere.
@pytest.mark.parametrize(
    "addr",
    [
        "127.0.0.1",
        "100.64.0.1",
        "169.254.1.1",
        "0.0.0.1",
        "198.51.100.7",
        "203.0.113.9",
        "192.0.2.1",
        "fc00::1",
        "fe80::1",
        "::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
        "::ffff:198.51.100.7",
        "224.0.0.1",
        "ff02::1",
        "not-an-address",
        "",
    ],
)
def test_special_sources_never_count(addr: str) -> None:
    assert FILTER_MODULE.is_public(addr) is False, addr


@pytest.mark.parametrize(
    "addr", ["8.8.8.8", "8.8.4.4", "1.1.1.1", "2606:4700::1111", "::ffff:8.8.4.4"]
)
def test_public_sources_count(addr: str) -> None:
    assert FILTER_MODULE.is_public(addr) is True, addr


def test_count_is_distinct_public_addresses_per_sensor() -> None:
    lines = [
        "ssh 8.8.8.8",
        "ssh 8.8.8.8",
        "ssh 8.8.4.4",
        "ssh 127.0.0.1",
        "web 1.1.1.1",
        "web fe80::1",
        "telnet 203.0.113.9",
        "bad line here",
        "onlyone",
        "bad;sensor 8.8.8.8",
        "",
    ]
    assert FILTER_MODULE.count_public(lines) == {"ssh": 2, "web": 1}


def test_the_sql_is_read_only_and_the_timestamp_validated() -> None:
    text = LIB.read_text()
    assert "ports_check_valid_ts" in text
    assert "-e PGOPTIONS='-c default_transaction_read_only=on'" in text
    assert "BEGIN READ ONLY;" in text and "COMMIT;" in text
    assert "LIMIT 50000" in text
    # The addresses are filtered in the ingest container, not in SQL, and never printed.
    assert "python -I -c" in text
    assert "print(sensor, n)" in FILTER.read_text()


def test_the_check_makes_no_network_call() -> None:
    for rel in (
        "scripts/lib/ports-check.sh",
        "scripts/lib/ports_check_filter.py",
        "scripts/participant.sh",
    ):
        code = "\n".join(
            line
            for line in (ROOT / rel).read_text().splitlines()
            if not line.lstrip().startswith("#")
        )
        assert not re.search(r"\b(curl|wget|nc|ncat|netcat|nslookup|dig)\b", code), rel
        assert "/dev/tcp" not in code and "/dev/udp" not in code, rel
        if rel.endswith("ports-check.sh"):
            assert not re.search(r"https?://", code), rel
    # install.sh: only the new block, between its two markers.
    install = (ROOT / "scripts/install.sh").read_text()
    block = install.split("Does the internet already reach the sensors?", 1)[1].split(
        "\nexit 0", 1
    )[0]
    assert not re.search(r"\b(curl|wget|nc|ping)\b|/dev/tcp", block)


@pytest.fixture
def psb(sandbox: Sandbox) -> Sandbox:
    add_participant_files(sandbox)
    sandbox.env["SHIM_PYTHON"] = sys.executable
    return sandbox


@pytest.fixture
def installed(psb: Sandbox) -> Sandbox:
    psb.env["SHIM_PYTHON"] = sys.executable
    rc, out = p_real(psb)
    assert rc == 0, out
    wrap_docker(psb, DB_ROWS)
    return psb


def _check(sb: Sandbox, *args: str) -> tuple[int, str]:
    proc = sb.run("scripts/participant.sh", "ports-check", *args)
    return proc.returncode, proc.stdout + proc.stderr


def test_reached_exits_0_and_prints_counts_only(installed: Sandbox) -> None:
    (installed.shim / "db-rows").write_text(
        "ssh 8.8.8.8\nssh 8.8.4.4\nssh 127.0.0.1\nweb 100.64.0.1\n"
    )
    rc, out = _check(installed, "--wait", "0")
    assert rc == 0, out
    assert "Ports are open: the internet reaches this machine." in out
    assert "reached from the internet (2)" in out
    assert re.search(r"web\s+no traffic yet", out)
    assert "SIP" in out  # the note about quiet services
    assert "8.8.8.8" not in out and "8.8.4.4" not in out


def test_nothing_reached_exits_3_with_the_warning(installed: Sandbox) -> None:
    rc, out = _check(installed, "--wait", "0")
    assert rc == 3, out
    assert "No connection from the internet has reached your sensors yet." in out
    assert "DMZ that is not active" in out
    assert "no traffic yet" in out


def test_wait_polls_until_the_deadline(installed: Sandbox) -> None:
    before = len(installed.calls())
    rc, _ = _check(installed, "--wait", "30")
    assert rc == 3
    queries = [c for c in installed.calls()[before:] if " db sh -c" in c]
    assert len(queries) == 4  # now, +10, +20, +30 seconds (sleep is a fake)


def test_unreadable_database_exits_2(installed: Sandbox) -> None:
    (installed.shim / "db-fail").write_text("")
    rc, out = _check(installed, "--wait", "0")
    assert rc == 2
    assert "Could not read the database" in out


def test_closed_local_ports_are_reported(installed: Sandbox) -> None:
    (installed.shim / "ss-output").write_text("tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n")
    rc, out = _check(installed, "--wait", "0")
    assert rc == 3
    assert "not listening on this machine" in out
    assert "port 80 (web)" in out
    assert "port 22 (ssh)" not in out


@pytest.mark.parametrize(
    "args",
    [
        ["--wait", "x"],
        ["--wait"],
        ["--since", "yesterday"],
        ["--since", "2026-01-01'; DROP"],
        ["--bogus"],
    ],
)
def test_bad_arguments_are_refused_before_any_query(installed: Sandbox, args: list[str]) -> None:
    before = len(installed.calls())
    rc, _ = _check(installed, *args)
    assert rc == 64
    assert not [c for c in installed.calls()[before:] if " db sh -c" in c]


def test_since_is_passed_to_the_query(installed: Sandbox) -> None:
    rc, out = _check(installed, "--wait", "0", "--since", "2026-11-04T10:00:00Z")
    assert rc == 3
    assert "since 2026-11-04T10:00:00Z" in out


# -------------------------------------------------------------------------- the install prompt


def _install(sb: Sandbox, *extra: str, answers: str | None = None) -> tuple[int, str, str]:
    env = {}
    if answers is not None:
        tty = sb.root / "answers"
        tty.write_text(answers)
        env["SELFHOSTR_TTY"] = str(tty)
    proc = sb.run(
        "scripts/install.sh",
        "--participant",
        "--version",
        "v0.8.0",
        "--sensors",
        "ssh,web",
        *extra,
        extra_env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_yes_never_asks_and_prints_the_recheck_command(psb: Sandbox) -> None:
    wrap_docker(psb, DB_ROWS)
    rc, out, err = _install(psb, "--yes")
    assert rc == 0, err
    assert "Ports not reachable yet" not in out + err
    assert "No connection from the internet has reached your sensors yet." in out
    assert "Check again any time: ./scripts/participant.sh ports-check" in out
    assert "short probation period" in out
    assert "14 days" not in out


def test_install_does_not_fail_when_the_database_cannot_be_read(psb: Sandbox) -> None:
    wrap_docker(psb, DB_ROWS)
    (psb.shim / "db-fail").write_text("")
    rc, out, _ = _install(psb, "--yes")
    assert rc == 0
    assert "Check again any time" in out


def test_reachable_ports_do_not_prompt(psb: Sandbox) -> None:
    wrap_docker(psb, DB_ROWS)
    (psb.shim / "db-rows").write_text("web 1.1.1.1\n")
    rc, out, err = _install(psb, answers="y\n")
    assert rc == 0, err
    assert "Ports are open" in out
    assert "Ports not reachable yet" not in err
    assert "Check again any time" not in out


def test_the_install_does_not_ask_to_recheck(psb: Sandbox) -> None:
    """Phase C: one check, then the command for later; no recheck question."""
    wrap_docker(psb, DB_ROWS)
    rc, out, err = _install(psb, answers="y\n")
    assert rc == 0, err
    assert "Ports not reachable yet" not in err
    assert "Check again any time: ./scripts/participant.sh ports-check" in out


def test_prompt_ends_on_end_of_input(psb: Sandbox) -> None:
    wrap_docker(psb, DB_ROWS)
    rc, out, _ = _install(psb, answers="y\n")
    assert rc == 0
    assert "Check again any time" in out


def test_dry_run_skips_the_check(psb: Sandbox) -> None:
    proc = psb.run(
        "scripts/install.sh",
        "--participant",
        "--yes",
        "--dry-run",
        "--env-out",
        str(psb.root / "o.env"),
        "--sensors",
        "ssh,web",
    )
    assert proc.returncode == 0, proc.stderr
    assert "internet reaches your sensors" not in proc.stdout
    assert psb.docker_calls() == []


def test_only_private_sources_means_nothing_reached(installed: Sandbox) -> None:
    (installed.shim / "db-rows").write_text("ssh 127.0.0.1\nweb fe80::1\nssh ::ffff:127.0.0.1\n")
    rc, out = _check(installed, "--wait", "0")
    assert rc == 3, out


def test_the_real_read_only_mechanism_reaches_the_database_container(installed: Sandbox) -> None:
    before = len(installed.calls())
    rc, _ = _check(installed, "--wait", "0")
    assert rc == 3
    query = next(c for c in installed.calls()[before:] if " db sh -c" in c)
    # `docker compose exec` does not forward the caller's environment: the option is a -e flag.
    assert "exec -T -e PGOPTIONS=-c default_transaction_read_only=on db sh -c" in query
    sql = (installed.shim / "db-sql").read_text()
    assert sql.startswith("BEGIN READ ONLY;\n") and sql.rstrip().endswith("COMMIT;")


def test_a_bad_poll_interval_falls_back_to_10_seconds(installed: Sandbox) -> None:
    for bad in ("0", "abc", "-3", "1.5", ""):
        before = len(installed.calls())
        proc = installed.run(
            "scripts/participant.sh",
            "ports-check",
            "--wait",
            "30",
            extra_env={"PORTS_CHECK_INTERVAL": bad},
        )
        assert proc.returncode == 3, bad
        queries = [c for c in installed.calls()[before:] if " db sh -c" in c]
        assert len(queries) == 4, bad
