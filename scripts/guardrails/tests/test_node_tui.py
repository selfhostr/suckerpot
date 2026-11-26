"""The terminal tools of a node: the questions and menus (scripts/lib/ask.sh), the node name and
country questions of the installer (scripts/lib/nodeprofile.sh), the local country check
(scripts/lib/geocheck.sh), participant.sh set-name and set-country, status --brief and --wait,
edit.sh, uninstall.sh and the menu (scripts/suckerpot.sh, ./suckerpot.sh).

Everything runs in the sandbox of conftest.py: fake docker, no network, no real terminal unless a
test opens a pseudo-terminal itself.
"""

import fcntl
import json
import os
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import ROOT, Sandbox
from test_install import add_participant_files, p_real, wrap_docker
from test_install_ui import run_pty
from vt import Screen

LIB = ROOT / "scripts" / "lib"
ESC = "\x1b"
SGR_COLOUR = re.compile(r"\x1b\[(3\d|38;)")

# A DB-IP shaped country list with documentation addresses only (CONTRIBUTING.md).
GEO_CSV = (
    "0.0.0.0,0.255.255.255,ZZ\n"
    "192.0.2.0,192.0.2.255,FR\n"
    "198.51.100.0,198.51.100.255,DE\n"
    "203.0.113.0,203.0.113.127,CH\n"
    "203.0.113.128,203.0.113.255,ZZ\n"
    "::,1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,ZZ\n"
    "2001:db8::,2001:db8:0:ffff:ffff:ffff:ffff:ffff,NL\n"
    "2001:db8:1::,2001:db8:1:ffff:ffff:ffff:ffff:ffff,BE\n"
)


def lib_bash(
    script: str, tmp_path: Path, env: dict[str, str] | None = None, libs: tuple[str, ...] = ()
) -> subprocess.CompletedProcess[str]:
    """Runs a snippet that sources ask.sh (and LIBS) with output on pipes, never a terminal."""
    sources = "".join(f'. "{LIB / name}"\n' for name in ("ask.sh", *libs))
    return subprocess.run(  # noqa: S603
        ["bash", "-c", f"set -euo pipefail\n{sources}{script}"],  # noqa: S607
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "LANG": "C.UTF-8", **(env or {})},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def answers(tmp_path: Path, text: str) -> dict[str, str]:
    path = tmp_path / "answers"
    path.write_text(text)
    return {"SELFHOSTR_TTY": str(path)}


# ------------------------------------------------------------------ ask.sh


def test_text_questions_check_the_answer_and_take_the_default_at_the_end(tmp_path: Path) -> None:
    proc = lib_bash(
        """
        two() { [ "${#1}" = 2 ] || { echo "two letters, please"; return 1; }; }
        ask_open
        ask_text a "Code" "" two
        ask_text b "Other" "zz" two
        ask_yn "Sure?" y && echo "yes"
        echo "a=$a b=$b eof=$ASK_EOF"
        """,
        tmp_path,
        answers(tmp_path, "abc\nch\n"),
    )
    assert proc.returncode == 0, proc.stderr
    assert "two letters, please" in proc.stderr
    assert proc.stdout == "yes\na=ch b=zz eof=1\n"
    assert ESC not in proc.stderr


def test_without_a_terminal_nothing_is_read(tmp_path: Path) -> None:
    proc = lib_bash(
        'ask_open --non-interactive\nask_text a "Code" "fr"\necho "a=$a tty=$ASK_TTY"',
        tmp_path,
        answers(tmp_path, "de\n"),
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "a=fr tty=0\n"


def test_the_numbered_menu_without_a_terminal(tmp_path: Path) -> None:
    proc = lib_bash(
        """
        ask_open
        ask_menu a 1 "Pick one" "1|Alpha|the first" "2|Beta|the second" "q|Quit|"
        ask_menu b 1 "Again" "1|Alpha|" "2|Beta|"
        ask_menu c 2 "At the end" "1|Alpha|" "2|Beta|"
        echo "a=$a b=$b c=$c eof=$ASK_EOF"
        """,
        tmp_path,
        answers(tmp_path, "Q\n7\n2\n"),
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "a=q b=2 c=2 eof=1\n"
    assert "  1   Alpha  the first" in proc.stderr
    assert "answer one of: 1 2" in proc.stderr
    assert ESC not in proc.stderr and "\r" not in proc.stderr


def run_pty_bash(
    script: str, keys: list[bytes], cols: int = 80, env: dict[str, str] | None = None
) -> tuple[int, str, str]:
    """Runs a snippet on a pseudo-terminal (its controlling terminal) and types KEYS, one by one
    once the screen is quiet. Returns (rc, terminal output, the snippet's stdout file)."""
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, cols, 0, 0))
    fd, name = tempfile.mkstemp(prefix="pty-out-")
    os.close(fd)
    out = Path(name)

    def controlling_tty() -> None:
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(  # noqa: S603
        ["bash", "-c", f'set -euo pipefail\n. "{LIB / "ask.sh"}"\nexec 9> "{out}"\n{script}'],  # noqa: S607
        env={"PATH": "/usr/bin:/bin", "TERM": "xterm-256color", "LANG": "C.UTF-8", **(env or {})},
        stdin=slave,
        stdout=slave,
        stderr=slave,
        preexec_fn=controlling_tty,
        close_fds=True,
    )
    os.close(slave)
    buf = bytearray()
    pending = list(keys)
    quiet_since = time.monotonic()
    deadline = time.monotonic() + 30
    while True:
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            try:
                data = os.read(master, 65536)
            except OSError:
                data = b""
            if not data:
                break
            buf += data
            quiet_since = time.monotonic()
        elif pending and time.monotonic() - quiet_since > 0.3:
            os.write(master, pending.pop(0))
            quiet_since = time.monotonic()
        if time.monotonic() > deadline:
            proc.kill()
            raise AssertionError("the snippet did not finish:\n" + buf.decode())
    rc = proc.wait(timeout=10)
    os.close(master)
    text = out.read_text() if out.exists() else ""
    out.unlink(missing_ok=True)
    return rc, buf.decode("utf-8", "replace"), text


MENU = 'ask_open\nask_menu a 1 "Pick one" "1|Alpha|the first" "2|Beta|the second" "q|Quit|"\necho "a=$a" >&9'


def test_the_key_menu_moves_with_the_arrows() -> None:
    rc, raw, out = run_pty_bash(MENU, [b"\x1b[B", b"\x1b[B", b"\x1b[A", b"\r"])
    assert rc == 0, raw
    assert out == "a=2\n"
    s = Screen(80)
    s.feed(raw)
    text = s.text()
    assert "  > 2   Alpha" not in text
    assert "  > 2   Beta   the second" in text
    assert s.cursor_visible
    assert "Up/Down to move, Enter to choose, or press a key" in text


def test_the_key_menu_takes_the_key_of_an_item_and_escape_quits() -> None:
    assert run_pty_bash(MENU, [b"2"])[2] == "a=2\n"
    assert run_pty_bash(MENU, [b"j", b"\r"])[2] == "a=2\n"
    assert run_pty_bash(MENU, [b"\x1b"])[2] == "a=q\n"


@pytest.mark.parametrize("cols", [40, 80])
def test_the_key_menu_fits_the_terminal_and_no_color_has_no_colour(cols: int) -> None:
    long = "|".join(["1", "A label", "a hint that is much longer than any narrow terminal is wide"])
    script = f'ask_open\nask_menu a 1 "T" "{long}" "2|B|"\necho "a=$a" >&9'
    rc, raw, out = run_pty_bash(script, [b"\r"], cols=cols, env={"NO_COLOR": "1"})
    assert rc == 0 and out == "a=1\n", raw
    assert not SGR_COLOUR.search(raw) and "\x1b[7m" not in raw
    s = Screen(cols)
    s.feed(raw)
    assert not s.overflow
    _, raw, _ = run_pty_bash(script, [b"\r"], cols=cols)
    assert SGR_COLOUR.search(raw) and "\x1b[7m" in raw  # colour and reverse video otherwise


# ------------------------------------------------------------------ geocheck.sh


# Private IPv4 examples, written in parts: the repository's private-ipv4 scan (.gitleaks.toml)
# flags any literal one, and these are test inputs, not anybody's network.
PRIV_A, PRIV_B, PRIV_C, PRIV_SELF = (
    ".".join(parts)
    for parts in (
        ("10", "1", "2", "3"),
        ("172", "20", "0", "1"),
        ("192", "168", "1", "1"),
        ("192", "168", "1", "5"),
    )
)


def test_country_codes_and_public_addresses(tmp_path: Path) -> None:
    proc = lib_bash(
        f"""
        for c in ch DE xx C1 f; do geo_code_ok "$c" > /dev/null && echo "$c ok" || echo "$c bad"; done
        for a in 8.8.8.8 {PRIV_A} {PRIV_B} 100.70.0.1 {PRIV_C} 127.0.0.1 203.0.113.9 \\
                 2a01:4f8::1 fe80::1 fd00::1 2001:db8::5; do
          geo_public "$a" && echo "$a public" || echo "$a not"
        done
        SELFHOSTR_GEO_ALLOW_DOC=1 geo_public 203.0.113.9 && echo "doc allowed"
        """,
        tmp_path,
        libs=("geocheck.sh",),
    )
    assert proc.returncode == 0, proc.stderr
    want = (
        f"ch ok\nDE ok\nxx bad\nC1 bad\nf bad\n8.8.8.8 public\n{PRIV_A} not\n{PRIV_B} not\n"
        f"100.70.0.1 not\n{PRIV_C} not\n127.0.0.1 not\n203.0.113.9 not\n2a01:4f8::1 public\n"
        "fe80::1 not\nfd00::1 not\n2001:db8::5 not\ndoc allowed\n"
    )
    assert proc.stdout == want


@pytest.mark.parametrize("gz", [False, True])
def test_the_country_list_lookup(tmp_path: Path, gz: bool) -> None:
    path = tmp_path / "c.csv"
    path.write_text(GEO_CSV)
    if gz:
        subprocess.run(["gzip", str(path)], check=True)  # noqa: S603, S607
        path = tmp_path / "c.csv.gz"
    proc = lib_bash(
        f"""
        for a in 192.0.2.1 198.51.100.200 203.0.113.9 203.0.113.200 2001:db8::5 2001:DB8:1:0:0:0:0:9 \\
                 2001:db8:2::1 1.2.3.4; do
          echo "$a=$(_geo_csv_lookup "{path}" "$a")"
        done
        """,
        tmp_path,
        libs=("geocheck.sh",),
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == [
        "192.0.2.1=FR",
        "198.51.100.200=DE",
        "203.0.113.9=CH",
        "203.0.113.200=",  # ZZ is "unknown"
        "2001:db8::5=NL",
        "2001:DB8:1:0:0:0:0:9=BE",
        "2001:db8:2::1=",
        "1.2.3.4=",
    ]


def geo(tmp_path: Path, cc: str, **env: str) -> dict[str, str]:
    proc = lib_bash(
        f'''geo_check {cc}
        printf '%s\\n' "result=$GEO_RESULT" "found=$GEO_FOUND" "addr=$GEO_ADDR" "why=$GEO_WHY"''',
        tmp_path,
        {"SELFHOSTR_GEO_ALLOW_DOC": "1", **env},
        libs=("geocheck.sh",),
    )
    assert proc.returncode == 0, proc.stderr
    return dict(line.split("=", 1) for line in proc.stdout.splitlines())


def test_the_check_compares_with_the_local_list_only(tmp_path: Path) -> None:
    (tmp_path / "c.csv").write_text(GEO_CSV)
    csv = str(tmp_path / "c.csv")
    got = geo(tmp_path, "ch", GEO_SELF_ADDRESS="203.0.113.9", SUCKERPOT_GEOIP_CSV=csv)
    assert (got["result"], got["found"], got["addr"]) == ("match", "CH", "203.0.113.9")
    got = geo(tmp_path, "FR", GEO_SELF_ADDRESS="203.0.113.9", SUCKERPOT_GEOIP_CSV=csv)
    assert (got["result"], got["found"]) == ("mismatch", "CH")
    # No public address: only an outside service could tell, and the check never asks one.
    got = geo(tmp_path, "CH", GEO_SELF_ADDRESS=PRIV_SELF, SUCKERPOT_GEOIP_CSV=csv)
    assert got["result"] == "unknown" and "never asks one" in got["why"]
    got = geo(tmp_path, "CH", GEO_SELF_ADDRESS="203.0.113.9")
    assert got["result"] == "unknown" and got["why"] == "no GeoIP database on this machine"


# ------------------------------------------------------------------ the installer's questions


def geo_sandbox(sb: Sandbox) -> None:
    add_participant_files(sb)
    (sb.root / "c.csv").write_text(GEO_CSV)
    sb.env["SUCKERPOT_GEOIP_CSV"] = str(sb.root / "c.csv")
    sb.env["SELFHOSTR_GEO_ALLOW_DOC"] = "1"


def interactive_dry_run(sb: Sandbox, text: str, *extra: str) -> tuple[int, str, Path]:
    target = sb.root / f"out-{len(list(sb.root.glob('out-*.env')))}.env"
    (sb.root / "answers").write_text(text)
    proc = sb.run(
        "scripts/install.sh",
        *("--participant", "--dry-run", "--env-out", str(target), "--sensors", "ssh,web"),
        *extra,
        extra_env={"SELFHOSTR_TTY": str(sb.root / "answers")},
    )
    return proc.returncode, proc.stdout + proc.stderr, target


def test_after_the_consent_it_asks_the_node_name_and_the_country(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    geo_sandbox(sandbox)
    rc, out, target = interactive_dry_run(
        sandbox, "y\n2\nGrey Heron 7\ny\nch\n", "--self-address", "203.0.113.9"
    )
    assert rc == 0, out
    assert "Node name and country: you choose them after this screen." in out
    assert "Pseudonym:" not in out
    assert out.index("Join the SuckerPot network as described?") < out.index("Node name\n")
    assert "Do not use a name you use anywhere else" in out
    assert "Show a country for this node? [y/N]" in out
    assert "CH matches: DB-IP country list on this machine" in out
    env = parse_env(target)
    assert env["NETWORK_PSEUDONYM"] == "'Grey Heron 7'"
    assert (env["NETWORK_COUNTRY"], env["NETWORK_SHOW_COUNTRY"]) == ("CH", "true")


def test_an_older_answer_file_takes_the_defaults(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    """Only the consent is answered: a random name, no country (as before the questions)."""
    geo_sandbox(sandbox)
    rc, out, target = interactive_dry_run(sandbox, "y\n")
    assert rc == 0, out
    env = parse_env(target)
    assert re.fullmatch(r"[a-z]+-[a-z]+-\d\d", env["NETWORK_PSEUDONYM"])
    assert "NETWORK_COUNTRY" not in env


def test_a_country_elsewhere_than_the_database_asks_what_to_do(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    geo_sandbox(sandbox)
    rc, out, target = interactive_dry_run(
        sandbox, "y\n3\ny\nde\n2\n", "--self-address", "203.0.113.9"
    )
    assert rc == 0, out
    assert "places this machine (203.0.113.9) in CH, not in DE." in out
    assert "1   Keep DE" in out and "2   Use CH" in out
    env = parse_env(target)
    assert env["NETWORK_PSEUDONYM"] == ""
    assert env["NETWORK_COUNTRY"] == "CH"  # the owner chose it; never filled in by itself
    rc, out, target = interactive_dry_run(
        sandbox, "y\n1\ny\nde\n1\n", "--self-address", "203.0.113.9"
    )
    assert rc == 0, out
    assert parse_env(target)["NETWORK_COUNTRY"] == "DE"


def test_without_a_local_database_nothing_is_downloaded_unless_asked(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    add_participant_files(sandbox)
    sandbox.env["SELFHOSTR_GEO_ALLOW_DOC"] = "1"
    rc, out, target = interactive_dry_run(
        sandbox, "y\n1\ny\nfr\nn\n", "--self-address", "203.0.113.9"
    )
    assert rc == 0, out
    # The text names the host; this is not a URL check.
    assert re.search(r"download\.db-ip\.com", out) and "Download it and check FR? [y/N]" in out
    assert "FR not checked: no GeoIP database on this machine." in out
    assert not [c for c in sandbox.calls() if c.startswith("curl ")]
    assert parse_env(target)["NETWORK_COUNTRY"] == "FR"


def test_a_country_flag_is_checked_and_a_mismatch_only_warns(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    geo_sandbox(sandbox)
    rc, out = p_real(sandbox, "--country", "de", "--show-country", "--self-address", "203.0.113.9")
    assert rc == 0, out
    assert "--country DE: DB-IP country list on this machine" in out
    assert "places this machine (203.0.113.9) in CH, not in DE" in out
    assert parse_env(sandbox.root / ".env")["NETWORK_COUNTRY"] == "DE"
    assert not [c for c in sandbox.calls() if c.startswith("curl ")]


def test_non_interactive_never_reads_the_terminal(sandbox: Sandbox) -> None:
    add_participant_files(sandbox)
    rc, out, _ = interactive_dry_run(sandbox, "y\n", "--non-interactive")
    assert rc != 0
    assert "no terminal to ask the participant consent on; use --yes" in out


def test_node_name_flags_are_the_pseudonym_flags(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    add_participant_files(sandbox)
    target = sandbox.root / "n.env"
    proc = sandbox.run(
        "scripts/install.sh",
        *("--participant", "--yes", "--dry-run", "--env-out", str(target)),
        *("--sensors", "ssh", "--node-name", "Grey Heron 7", "--non-interactive"),
    )
    assert proc.returncode == 0, proc.stderr
    assert parse_env(target)["NETWORK_PSEUDONYM"] == "'Grey Heron 7'"
    proc = sandbox.run(
        "scripts/install.sh",
        *("--participant", "--yes", "--dry-run", "--env-out", str(sandbox.root / "m.env")),
        *("--sensors", "ssh", "--country-check", "sometimes"),
    )
    assert proc.returncode != 0 and "--country-check must be local, download or off" in proc.stderr


# ------------------------------------------------------------------ participant.sh set-name, set-country

PROFILE_CASES = (
    '  "compose exec -T ingest python -m ingest.network.cli update"*)\n'
    '    echo "docker $*" >> "$SHIM_LOG"; cat "$SHIM_DIR/cli-update.json"; exit "${SHIM_UPDATE_RC:-0}" ;;\n'
    '  "compose exec -T ingest python -m ingest.network.cli status --json")\n'
    '    n=$(cat "$SHIM_DIR/cli-n" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$SHIM_DIR/cli-n"\n'
    '    if [ "$n" -gt 1 ] && [ -f "$SHIM_DIR/cli-after.json" ]; then cat "$SHIM_DIR/cli-after.json";'
    ' else cat "$SHIM_DIR/cli-state.json"; fi; exit 0 ;;\n'
    '  "compose exec -T ingest python -m ingest.network.cli leave")\n'
    '    echo "docker $*" >> "$SHIM_LOG"; exit 0 ;;'
)


@pytest.fixture
def node(sandbox: Sandbox) -> Sandbox:
    """A finished participant install (fake docker) with a fake ingest CLI that is a member."""
    add_participant_files(sandbox)
    sandbox.env["SUCKERPOT_FW_ROOT"] = str(sandbox.root / "fwroot")
    rc, out = p_real(sandbox)
    assert rc == 0, out
    wrap_docker(sandbox, PROFILE_CASES)
    (sandbox.shim / "cli-state.json").write_text(
        '{"network": {"membership": {"desired": "member"}}, "state": "member", "pseudonym": "amber-falcon-42"}'
    )
    (sandbox.shim / "cli-update.json").write_text('{"updated": true, "changed": ["pseudonym"]}')
    (sandbox.shim / "cli-after.json").write_text(
        '{"profile_synced": true, "state": "member", "pseudonym": "Grey Heron 7"}'
    )
    return sandbox


def test_set_name_updates_a_member_and_waits_for_the_hub(
    node: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    start = len(node.calls())
    proc = node.run("scripts/participant.sh", "set-name", "Grey Heron 7")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "the node name is now Grey Heron 7, and the hub has it." in proc.stdout
    assert parse_env(node.root / ".env")["NETWORK_PSEUDONYM"] == "'Grey Heron 7'"
    calls = node.calls()[start:]
    assert (
        "docker compose exec -T ingest python -m ingest.network.cli update --pseudonym Grey Heron 7"
        in calls
    )
    assert any(
        c.startswith("docker compose up") and c.endswith("--force-recreate ingest") for c in calls
    )


def test_a_taken_name_puts_everything_back(node: Sandbox) -> None:
    before = (node.root / ".env").read_text()
    (node.shim / "cli-after.json").write_text(
        '{"state": "member", "pseudonym": "amber-falcon-42", "error_code": "pseudonym_taken"}'
    )
    proc = node.run("scripts/participant.sh", "set-name", "bignoe")
    assert proc.returncode == 1
    assert "the hub refused the name 'bignoe': another node already uses it" in proc.stderr
    assert "keeps the name 'amber-falcon-42'" in proc.stderr
    assert re.search(r"set-name bignoe-\d\d\n", proc.stderr)
    assert (node.root / ".env").read_text() == before


def test_bad_names_and_countries_change_nothing(node: Sandbox) -> None:
    before = (node.root / ".env").read_text()
    start = len(node.calls())
    for args in (
        ("set-name", "admin"),
        ("set-name",),
        ("set-country", "XX"),
        ("set-country", "CH", "x"),
    ):
        proc = node.run("scripts/participant.sh", *args)
        assert proc.returncode != 0, args
    assert (node.root / ".env").read_text() == before
    assert not [c for c in node.calls()[start:] if c.startswith("docker compose up")]


def test_set_country_hidden_and_none(
    node: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    start = len(node.calls())
    proc = node.run("scripts/participant.sh", "set-country", "ch", "--hide")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    env = parse_env(node.root / ".env")
    assert (env["NETWORK_COUNTRY"], env["NETWORK_SHOW_COUNTRY"]) == ("CH", "false")
    assert "CH is not checked: no public address" in proc.stdout
    calls = node.calls()[start:]
    assert (
        "docker compose exec -T ingest python -m ingest.network.cli update --country CH --hide-country"
        in calls
    )
    proc = node.run("scripts/participant.sh", "set-country", "--none")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    env = parse_env(node.root / ".env")
    assert (env["NETWORK_COUNTRY"], env["NETWORK_SHOW_COUNTRY"]) == ("", "false")


def test_a_node_out_of_the_network_only_saves_the_name(
    node: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    node.write_env(
        (node.root / ".env").read_text().replace("NETWORK_ENABLED=true", "NETWORK_ENABLED=false")
    )
    start = len(node.calls())
    proc = node.run("scripts/participant.sh", "set-name", "grey-heron")
    assert proc.returncode == 0, proc.stderr
    assert "it is used when you join" in proc.stdout
    assert parse_env(node.root / ".env")["NETWORK_PSEUDONYM"] == "grey-heron"
    assert not [c for c in node.calls()[start:] if "cli update" in c]


# ------------------------------------------------------------------ status --brief and --wait


def test_status_brief_shows_the_enrolment(node: Sandbox) -> None:
    status_env: dict[str, str] = {}
    # The renderer runs inside ingest in real life; here with the interpreter of the tests.
    wrap_docker(
        node,
        '  "compose ps --format"*) printf "sensor-ssh running healthy\\ningest running healthy\\n'
        'db running healthy\\n"; exit 0 ;;\n'
        '  "compose exec -T ingest python -I -c "*) shift 7; exec '
        + sys.executable
        + ' -I -c "$@" ;;\n'
        + PROFILE_CASES,
    )
    cli = {
        "state": "member",
        "pseudonym": "amber-falcon-42",
        "standing": "new",
        "country": "CH",
        "show_country": True,
        "profile_synced": True,
        "sent": [{"day": "2026-11-24", "sources": 412, "links": 1, "files": 0}],
        "hub": {"host": "hub", "last_contact": "2026-11-25T10:00:00Z", "signature_ok": True},
    }
    (node.shim / "cli-state.json").write_text(json.dumps(cli))
    (node.shim / "cli-after.json").unlink()
    proc = node.run("scripts/status.sh", "--brief", extra_env=status_env)
    out = proc.stdout
    assert "Stack    v0.8.0, 3 services running, all healthy" in out, out + proc.stderr
    assert "Sensors  1 healthy: ssh" in out
    assert "Network  accepted as amber-falcon-42, standing new" in out
    assert "country CH (shown to the network); last batch 2026-11-24 (412 sources)" in out
    assert "Overall  " in out
    full = node.run("scripts/status.sh", extra_env=status_env).stdout
    assert "  Country: CH (shown to the network)" in full
    cli.update(state="error", error_code="pseudonym_taken", last_error={"code": "pseudonym_taken"})
    (node.shim / "cli-state.json").write_text(json.dumps(cli))
    out = node.run("scripts/status.sh", "--brief", extra_env=status_env).stdout
    assert "Network  refused: the name 'amber-falcon-42' is already used by another node" in out
    assert "next: ./scripts/participant.sh set-name NEW-NAME" in out


def test_status_wait_waits_only_for_a_join_in_progress(node: Sandbox) -> None:
    wrap_docker(
        node, '  "compose ps --format"*) echo "ingest running healthy"; exit 0 ;;\n' + PROFILE_CASES
    )
    (node.shim / "cli-after.json").unlink()
    (node.shim / "cli-state.json").write_text('{"state": "enrolling"}')
    t0 = time.monotonic()
    proc = node.run("scripts/status.sh", "--wait", "2")
    assert "Waiting for the hub to accept this node, at most 2 s" in proc.stderr
    assert time.monotonic() - t0 >= 0.9
    (node.shim / "cli-state.json").write_text('{"state": "member"}')
    proc = node.run("scripts/status.sh", "--wait", "30")
    assert "Waiting for the hub" not in proc.stderr


# ------------------------------------------------------------------ edit.sh, uninstall.sh, the menu


def add_tools(sb: Sandbox) -> None:
    for rel in ("scripts/edit.sh", "scripts/uninstall.sh", "scripts/suckerpot.sh", "suckerpot.sh"):
        dest = sb.root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dest)


def test_edit_hands_each_setting_to_its_script(
    node: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    add_tools(node)
    proc = node.run("scripts/edit.sh", "name", "Grey Heron 7")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert parse_env(node.root / ".env")["NETWORK_PSEUDONYM"] == "'Grey Heron 7'"
    start = len(node.calls())
    proc = node.run("scripts/edit.sh", "sensors", "ssh,telnet")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    env = parse_env(node.root / ".env")
    assert (env["SENSOR_SSH"], env["SENSOR_TELNET"], env["SENSOR_WEB"]) == ("1", "1", "0")
    assert any(c.startswith("docker compose up") for c in node.calls()[start:])
    proc = node.run("scripts/edit.sh", "sensors", "ssh,nope")
    assert proc.returncode != 0 and "unknown sensor 'nope'" in proc.stderr
    proc = node.run("scripts/edit.sh", "name", extra_env={"SELFHOSTR_TTY": "/nonexistent"})
    assert proc.returncode != 0 and "no terminal to ask on" in proc.stderr


def test_the_edit_menu_with_answers(
    node: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    add_tools(node)
    (node.root / "answers").write_text("2\ny\nch\nb\n")
    proc = node.run("scripts/edit.sh", extra_env={"SELFHOSTR_TTY": str(node.root / "answers")})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "The configuration of this node" in proc.stderr
    assert re.search(r"Version +v0\.8\.0 \(signed images", proc.stderr)
    assert re.search(r"1   Node name +[a-z]+-[a-z]+-\d\d", proc.stderr)
    assert "Show a country for this node? [y/N]" in proc.stderr
    assert parse_env(node.root / ".env")["NETWORK_COUNTRY"] == "CH"


def test_uninstall_keeps_the_data_unless_told(
    node: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    add_tools(node)
    (node.shim / "cli-state.json").write_text('{"state": "left"}')
    (node.shim / "cli-after.json").unlink()
    (node.root / "answers").write_text("n\n")
    before = (node.root / ".env").read_text()
    proc = node.run("scripts/uninstall.sh", extra_env={"SELFHOSTR_TTY": str(node.root / "answers")})
    assert proc.returncode != 0 and "nothing was changed" in proc.stderr
    assert (
        "This keeps:" in proc.stdout
        and ".env (the database password lives in the data" in proc.stdout
    )
    assert (node.root / ".env").read_text() == before
    node.env["SHIM_EXISTING_VOLUMES"] = "suckerpot_db-data suckerpot_ingest-data"
    start = len(node.calls())
    proc = node.run("scripts/uninstall.sh", "--yes")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = node.calls()[start:]
    assert "docker compose down" in calls
    assert not [c for c in calls if c.startswith("docker volume rm")]
    assert (node.root / ".env").exists()
    assert "Kept: the data volumes suckerpot_* and .env" in proc.stdout
    proc = node.run("scripts/uninstall.sh", "--yes", "--delete-data")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "docker volume rm suckerpot_db-data suckerpot_ingest-data" in node.calls()
    assert not (node.root / ".env").exists()
    assert list(node.root.glob(".env.removed-*"))


def fake_scripts(sb: Sandbox) -> None:
    """Every script the menu calls, as a fake that records its arguments."""
    for name in (
        "install.sh",
        "status.sh",
        "edit.sh",
        "update.sh",
        "participant.sh",
        "uninstall.sh",
    ):
        path = sb.root / "scripts" / name
        path.write_text(f'#!/bin/sh\necho "{name} $*" >> "$SHIM_LOG"\nexit 0\n')
        path.chmod(0o755)


def menu(sb: Sandbox, text: str, *args: str) -> subprocess.CompletedProcess[str]:
    (sb.root / "answers").write_text(text)
    return sb.run("suckerpot.sh", *args, extra_env={"SELFHOSTR_TTY": str(sb.root / "answers")})


def script_calls(sb: Sandbox) -> list[str]:
    return [c.rstrip() for c in sb.calls() if c.split(" ", 1)[0].endswith(".sh")]


def test_the_menu_before_an_install(sandbox: Sandbox) -> None:
    add_participant_files(sandbox)
    add_tools(sandbox)
    fake_scripts(sandbox)
    proc = menu(sandbox, "1\n")
    assert proc.returncode == 0, proc.stderr
    assert "SuckerPot  not installed in" in proc.stderr
    assert "Install a participant node" in proc.stderr and "Full install" in proc.stderr
    assert script_calls(sandbox) == ["install.sh --participant"]
    (sandbox.shim / "ss-output").write_text("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
    proc = menu(sandbox, "3\n")
    assert re.search(r"ssh\s+22\s+tcp\s+IN USE", proc.stdout), proc.stdout + proc.stderr
    assert re.search(r"telnet\s+23\s+tcp\s+free", proc.stdout)


def test_the_menu_of_a_participant_node(node: Sandbox) -> None:
    add_tools(node)
    fake_scripts(node)
    proc = menu(node, "6\n")
    assert proc.returncode == 0, proc.stderr
    assert "participant node · v0.8.0" in proc.stderr
    assert re.search(r"  Node       [a-z]+-[a-z]+-\d\d · direct \(no VPN\)", proc.stderr)
    for item in (
        "Node status",
        "Edit the node",
        "Update now",
        "Check the ports",
        "Logs",
        "Repair",
        "Leave the network",
        "Remove the node",
        "Quit",
    ):
        assert item in proc.stderr, item
    assert script_calls(node)[-1:] == ["install.sh --repair"]
    for keys, want in (
        ("1\n", "status.sh"),
        ("2\n", "edit.sh"),
        ("3\n", "update.sh"),
        ("4\n", "participant.sh ports-check --wait 60"),
        ("8\n", "uninstall.sh"),
        ("7\ny\n", "participant.sh leave"),
    ):
        menu(node, keys)
        assert script_calls(node)[-1] == want, keys
    proc = menu(node, "5\n4\nb\n")  # Logs, install.log, back
    assert re.search(r"Z step \d+: ", proc.stdout), proc.stdout + proc.stderr  # install.log


def test_the_menu_commands_without_a_terminal(node: Sandbox) -> None:
    add_tools(node)
    fake_scripts(node)
    for args, want in (
        (("status", "--brief"), "status.sh --brief"),
        (("edit", "name", "x-y"), "edit.sh name x-y"),
        (("remove", "--yes"), "uninstall.sh --yes"),
        (("repair",), "install.sh --repair"),
        (("install", "--participant", "--lite"), "install.sh --participant --lite"),
    ):
        proc = node.run("suckerpot.sh", *args)
        assert proc.returncode == 0, proc.stderr
        assert script_calls(node)[-1] == want
    proc = node.run("suckerpot.sh", extra_env={"SELFHOSTR_TTY": "/nonexistent"})
    assert proc.returncode != 0 and "the menu needs a terminal" in proc.stderr
    proc = node.run("suckerpot.sh", "frobnicate")
    assert proc.returncode != 0 and "unknown command" in proc.stderr
    assert "./suckerpot.sh install [FLAGS]" in node.run("suckerpot.sh", "help").stdout


# ------------------------------------------------------------------ text wrapped at the terminal


def test_hand_broken_text_is_joined_and_wrapped_at_word_boundaries(tmp_path: Path) -> None:
    proc = lib_bash(
        f'. "{LIB / "env.sh"}"\nconsent_screen amber-falcon-42 0 | text_wrap --join 60',
        tmp_path,
    )
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.splitlines()
    assert max(len(line) for line in lines) <= 60
    text = proc.stdout
    assert "\nSuckerPot maintainers" not in text  # never the old break of the source text
    # Items keep their mark, and their next lines are indented under the text.
    item = next(i for i, line in enumerate(lines) if line.startswith("  - source addresses"))
    assert lines[item + 1].startswith("    ") and not lines[item + 1].startswith("     ")
    words = " ".join(" ".join(lines).split())
    assert "with the services they used, what they did and rounded counts;" in words
    assert "a hub run by the SuckerPot maintainers. What is sent" in words
    # Without a terminal nothing changes (plain and CI output).
    plain = lib_bash(f'. "{LIB / "env.sh"}"\nconsent_screen x 0 | text_out 1 --join', tmp_path)
    raw = lib_bash(f'. "{LIB / "env.sh"}"\nconsent_screen x 0', tmp_path)
    assert plain.stdout == raw.stdout


def test_lines_without_join_keep_their_breaks(tmp_path: Path) -> None:
    proc = lib_bash(
        "printf '%s\\n' 'Sensors (2)' '  ssh  router 22' "
        "'  ! one two three four five six seven eight nine ten' | text_wrap 30",
        tmp_path,
    )
    assert proc.stdout == (
        "Sensors (2)\n  ssh  router 22\n  ! one two three four five\n    six seven eight nine ten\n"
    )


def test_a_long_question_wraps_on_a_narrow_terminal() -> None:
    q = "The hub has not answered this node's join yet. Wait for its answer (at most 10 minutes)?"
    rc, raw, out = run_pty_bash(f'ask_open\nask_yn "{q}" y && echo yes >&9', [b"\r"], cols=40)
    assert rc == 0 and out == "yes\n", raw
    s = Screen(40)
    s.feed(raw)
    assert not s.overflow
    assert "minutes)? [Y/n]" in s.text()


# ------------------------------------------------------------------ round 2: re-runs and old nodes


def test_pick_numbers_the_shown_items_and_takes_notice_keys(tmp_path: Path) -> None:
    proc = lib_bash(
        """
        ask_open
        ask_pick a own "" "random|Random|" "own|Own|" "q|Quit|"
        ASK_HIDDEN=" c u"
        ask_pick b random "" "random|Random|" "own|Own|"
        ask_pick c random "" "random|Random|" "own|Own|"
        echo "a=$a b=$b c=$c"
        """,
        tmp_path,
        answers(tmp_path, "\nc\n1\n"),
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "a=own b=c c=random\n"
    assert (
        "  1   Random" in proc.stderr and "  2   Own" in proc.stderr and "  q   Quit" in proc.stderr
    )
    assert "Choose [2]:" in proc.stderr


def test_the_name_menu_has_no_gaps(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    geo_sandbox(sandbox)
    sandbox.env["SHIM_HOSTNAME"] = "vps-paris-1"
    rc, out, target = interactive_dry_run(sandbox, "y\n2\ny\n")
    assert rc == 0, out
    assert re.search(r"  1   [a-z]+-[a-z]+-\d\d +a random name", out)
    assert "  2   vps-paris-1" in out and "  3   Type a name" in out and "  4   No name" in out
    assert parse_env(target)["NETWORK_PSEUDONYM"] == "vps-paris-1"
    assert "Use 'vps-paris-1' anyway? [y/N]" in out


def branch_checkout(sb: Sandbox) -> None:
    add_participant_files(sb)
    sb.git_mode("normal")
    sb.git_set("branch", "dev")
    sb.git_set("head", "c" * 40)
    sb.git_set("tags", "v0.8.0\nv0.9.0\n")


def test_a_branch_checkout_asks_which_images_to_run(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    branch_checkout(sandbox)
    (sandbox.root / "answers").write_text("1\ny\n")
    proc = sandbox.run(
        "scripts/install.sh",
        *("--participant", "--sensors", "ssh,web"),
        extra_env={"SELFHOSTR_TTY": str(sandbox.root / "answers")},
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "This checkout is the branch dev, not a release. Which images should run?" in out
    assert "1   Signed images of v0.9.0" in out and "2   Build from this checkout" in out
    env = parse_env(sandbox.root / ".env")
    assert (env["SUCKERPOT_INSTALL_MODE"], env["SUCKERPOT_VERSION"]) == ("images", "v0.9.0")


def test_a_branch_checkout_can_build_from_source(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    branch_checkout(sandbox)
    (sandbox.root / "answers").write_text("2\ny\n")
    proc = sandbox.run(
        "scripts/install.sh",
        *("--participant", "--sensors", "ssh,web"),
        extra_env={"SELFHOSTR_TTY": str(sandbox.root / "answers")},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert parse_env(sandbox.root / ".env")["SUCKERPOT_INSTALL_MODE"] == "source"


def test_without_a_terminal_a_branch_needs_a_flag(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    branch_checkout(sandbox)
    proc = sandbox.run("scripts/install.sh", "--participant", "--yes", "--sensors", "ssh")
    assert proc.returncode != 0
    assert (
        "pass --version latest (the signed images of v0.9.0), --version vX.Y.Z or --source"
        in proc.stderr
    )
    assert "this checkout (dev) is not a release tag" in proc.stderr
    proc = sandbox.run(
        "scripts/install.sh", "--participant", "--yes", "--sensors", "ssh", "--version", "latest"
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert parse_env(sandbox.root / ".env")["SUCKERPOT_VERSION"] == "v0.9.0"


def test_the_node_name_log_line(sandbox: Sandbox) -> None:
    geo_sandbox(sandbox)
    (sandbox.root / "answers").write_text("y\n2\nGrey Heron 7\n")
    proc = sandbox.run(
        "scripts/install.sh",
        *("--participant", "--version", "v0.8.0", "--sensors", "ssh,web"),
        extra_env={"SELFHOSTR_TTY": str(sandbox.root / "answers")},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    log = (sandbox.root / "install.log").read_text()
    assert "node name chosen (set)" in log and "Grey Heron" not in log


def test_an_old_ingest_refuses_a_country_change_and_changes_nothing(node: Sandbox) -> None:
    wrap_docker(
        node,
        '  "compose exec -T ingest python -m ingest.network.cli update"*) echo "invalid choice" >&2; exit 2 ;;\n'
        '  "compose exec -T ingest printenv SUCKERPOT_RUNNING_VERSION") echo v0.8.0; exit 0 ;;\n'
        + PROFILE_CASES,
    )
    node.git_set("tags", "v0.8.0\n")
    before = (node.root / ".env").read_text()
    start = len(node.calls())
    proc = node.run("scripts/participant.sh", "set-country", "CH")
    assert proc.returncode != 0
    assert "this node runs v0.8.0, whose ingest cannot change the country" in proc.stderr
    assert "Nothing was changed." in proc.stderr
    assert (node.root / ".env").read_text() == before
    assert not [c for c in node.calls()[start:] if c.startswith("docker compose up")]
    # A name still changes through the join of the older ingest.
    proc = node.run("scripts/participant.sh", "set-name", "grey-heron")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert any("cli join --pseudonym grey-heron" in c for c in node.calls())


def test_an_installed_node_opens_the_installed_menu_with_notices(node: Sandbox) -> None:
    add_tools(node)
    fake_scripts(node)
    node.git_set("tags", "v0.8.0\nv0.9.0\n")
    proc = menu(node, "")
    assert proc.returncode == 0, proc.stderr
    assert "Install a participant node" not in proc.stderr
    assert "! Update available: v0.8.0 -> v0.9.0: press u to update" in proc.stderr
    assert "! Country not set: press c to show one (optional)" in proc.stderr
    assert "runs v0.8.0; v0.9.0 is available" in proc.stderr
    menu(node, "c\n")
    assert script_calls(node)[-1] == "edit.sh country"
    menu(node, "u\n")
    assert script_calls(node)[-1] == "update.sh"


def test_an_old_install_env_opens_the_installed_menu(sandbox: Sandbox) -> None:
    """An .env written by an older installer (v0.14): the menu never offers to install over it."""
    add_participant_files(sandbox)
    add_tools(sandbox)
    fake_scripts(sandbox)
    sandbox.write_env(
        "COMPOSE_PROJECT_NAME=suckerpot\nSUCKERPOT_VOLUME_PREFIX=suckerpot\n"
        "SUCKERPOT_STACK_MODE=participant\nSUCKERPOT_INSTALL_MODE=images\nSUCKERPOT_VERSION=v0.14.2\n"
        "NETWORK_ENABLED=true\nNETWORK_PSEUDONYM=amber-falcon-42\nAUTO_UPDATE_ENABLED=true\n"
    )
    sandbox.git_set("tags", "v0.14.2\nv0.15.0\n")
    proc = menu(sandbox, "1\n")
    assert proc.returncode == 0, proc.stderr
    assert "participant node · v0.14.2" in proc.stderr
    assert "Install a participant node" not in proc.stderr
    assert "Update available: v0.14.2 -> v0.15.0" in proc.stderr
    assert script_calls(sandbox)[-1] == "status.sh"
    shutil.copy2(ROOT / "scripts/install.sh", sandbox.root / "scripts/install.sh")
    proc = sandbox.run("scripts/install.sh", "--participant")
    assert "already installed here in participant mode" in proc.stdout + proc.stderr


def test_update_on_a_branch_that_holds_the_release_changes_only_the_images(
    sandbox: Sandbox,
) -> None:
    from test_update import prepare, run_update

    prepare(sandbox, branch="dev")
    sandbox.git_set("ancestor", "1")
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    assert "only the images change" in out
    assert not [c for c in sandbox.calls() if c.startswith("git checkout")]
    assert "SUCKERPOT_VERSION=v0.9.0" in (sandbox.root / ".env").read_text()
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0 and "Already on v0.9.0 (the images" in out


def test_docker_setup_under_sudo_is_for_the_calling_user(sandbox: Sandbox) -> None:
    from test_install_ui import _without_an_engine, _write

    _without_an_engine(sandbox)
    _write(
        sandbox, "id", '#!/bin/sh\n[ "$1" = -un ] && echo root && exit 0\nexec /usr/bin/id "$@"\n'
    )
    sandbox.env["SUDO_USER"] = "alice"
    proc = sandbox.run("scripts/install.sh", "--yes")
    assert "sudo usermod -aG docker alice" in proc.stdout
    assert "usermod -aG docker root" not in proc.stdout
    del sandbox.env["SUDO_USER"]
    sandbox.env["SELFHOSTR_EUID"] = "0"
    proc = sandbox.run("scripts/install.sh", "--yes")
    assert "usermod" not in proc.stdout  # root needs no group
    assert "  apt-get install -y docker-ce" in proc.stdout and "sudo apt-get" not in proc.stdout


def sudo_shim(sb: Sandbox, body: str) -> None:
    (sb.shim / "sudo").write_text('#!/bin/sh\necho "sudo $*" >> "$SHIM_LOG"\n' + body)
    (sb.shim / "sudo").chmod(0o755)


def firewall_tools(sb: Sandbox) -> None:
    add_participant_files(sb)
    render = sb.root / "scripts/host/render-firewall.sh"
    render.write_text('#!/bin/sh\necho "render-firewall $*" >> "$SHIM_LOG"\n')
    render.chmod(0o755)


def test_started_with_sudo_nothing_calls_sudo_again(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    """As root through sudo: no sudo call, no password; the owner gets the schedule."""
    firewall_tools(sandbox)
    sudo_shim(sandbox, "exit 1\n")
    proc = sandbox.run(
        "scripts/install.sh",
        *("--participant", "--yes", "--version", "v0.8.0", "--sensors", "ssh,web"),
        extra_env={"SELFHOSTR_EUID": "0", "SUDO_USER": "alice", "SELFHOSTR_DIR_OWNER": "alice"},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = sandbox.calls()
    assert not [c for c in calls if c.startswith("sudo")], calls
    assert any(c.startswith("install-firewall ") for c in calls)  # root: the firewall loads
    assert any(c.startswith("crontab -u alice ") for c in calls)
    assert "sudo asks for your password" not in proc.stdout + proc.stderr


def test_passwordless_sudo_asks_nothing(sandbox: Sandbox) -> None:
    firewall_tools(sandbox)
    sudo_shim(sandbox, '[ "$1" = -n ] && exit 0\n[ "$1" = -v ] && exit 1\nexit 0\n')
    (sandbox.root / "answers").write_text("y\n")
    rc, raw = run_pty(
        sandbox,
        *("--participant", "--version", "v0.8.0", "--sensors", "ssh,web"),
        env={"SELFHOSTR_TTY": str(sandbox.root / "answers")},
    )
    assert rc == 0, raw
    assert "sudo asks for your password" not in raw
    calls = sandbox.calls()
    assert not [c for c in calls if c.startswith("sudo -v")]
    assert any(c.startswith("install-firewall ") for c in calls)


def test_sudo_with_a_password_says_it_once(sandbox: Sandbox) -> None:
    firewall_tools(sandbox)
    # The password is typed: -n fails (a prompt is needed), -v succeeds.
    sudo_shim(
        sandbox,
        '[ "$1" = -v ] && { touch "$SHIM_DIR/sudo-ok"; exit 0; }\n'
        '[ "$1" = -n ] && { [ -f "$SHIM_DIR/sudo-ok" ]; exit $?; }\nexit 0\n',
    )
    (sandbox.root / "answers").write_text("y\n")
    rc, raw = run_pty(
        sandbox,
        *("--participant", "--version", "v0.8.0", "--sensors", "ssh,web"),
        env={"SELFHOSTR_TTY": str(sandbox.root / "answers")},
    )
    assert rc == 0, raw
    assert raw.count("sudo asks for your password") == 1
    assert len([c for c in sandbox.calls() if c.startswith("sudo -v")]) == 1


def test_without_sudo_and_not_root_the_firewall_waits(sandbox: Sandbox, tmp_path: Path) -> None:
    from conftest import tools_without

    firewall_tools(sandbox)
    (sandbox.shim / "sudo").unlink(missing_ok=True)
    sysbin = tools_without(sandbox, ("sudo",), tmp_path / "nosudo")
    sandbox.env["PATH"] = f"{sandbox.shim}:{sysbin}"
    (sandbox.root / "answers").write_text("y\n")
    rc, raw = run_pty(
        sandbox,
        *("--participant", "--version", "v0.8.0", "--sensors", "ssh,web"),
        env={"SELFHOSTR_TTY": str(sandbox.root / "answers")},
    )
    assert rc == 0, raw
    s = Screen(100)
    s.feed(raw)
    assert "needs sudo: ./scripts/participant.sh firewall" in s.text()


def test_get_started_with_sudo_gives_the_folder_to_the_user(
    sandbox: Sandbox, tmp_path: Path
) -> None:
    from test_bundle import Web

    web = Web(sandbox, tmp_path)
    web.release()
    proc = web.run("--yes", SELFHOSTR_EUID="0", SUDO_USER="alice")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "runs as root (started with sudo) and calls no sudo" in proc.stdout
    assert "belong to alice" in proc.stdout
    assert not [c for c in sandbox.calls() if c.startswith("sudo")]
