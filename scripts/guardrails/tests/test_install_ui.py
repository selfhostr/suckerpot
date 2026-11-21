"""The installer's display (scripts/lib/ui.sh, docs/dev/design/installer-ux.md).

Plain mode (no terminal, TERM=dumb, --plain) must print what the installer always printed: the
guardrails and the participant end-to-end test read it. The golden files pin it. The rich mode
(a terminal) is run on a real pseudo-terminal and replayed on a tiny terminal emulator (vt.py).
Refresh the golden files with UPDATE_GOLDEN=1 after a deliberate change, and review the diff.
"""

import fcntl
import os
import re
import select
import struct
import subprocess
import termios
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import ROOT, Sandbox
from test_install import PASSWORD, SECRET_NAMES, add_participant_files, wrap_docker
from vt import Screen

GOLDEN = Path(__file__).parent / "fixtures" / "install-plain"
UI = ROOT / "scripts" / "lib" / "ui.sh"
ESC = "\x1b"


# ------------------------------------------------------------------ helpers


def normalise(text: str, sb: Sandbox) -> str:
    text = text.replace(str(sb.root), "<root>").replace(str(sb.shim), "<shim>")
    text = re.sub(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", "<time>", text)
    text = re.sub(r"Pseudonym: [a-z]+(-[a-z]+)*-\d+", "Pseudonym: <pseudonym>", text)
    text = re.sub(r"from \d\d:\d\d local time", "from <hh:mm> local time", text)
    text = re.sub(r"daily at \d\d:\d\d local time", "daily at <hh:mm> local time", text)
    return re.sub(r"(password manager now\): )\S+", r"\1<password>", text)


def check_golden(name: str, text: str) -> None:
    path = GOLDEN / f"{name}.txt"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    assert path.exists(), f"missing golden file {path}: run with UPDATE_GOLDEN=1"
    assert text == path.read_text(), f"plain output differs from {path.name}"


def quiet_firewall(sb: Sandbox) -> None:
    """Participant installs: a firewall renderer and sudo that behave the same on every host."""
    add_participant_files(sb)
    render = sb.root / "scripts/host/render-firewall.sh"
    render.write_text('#!/bin/sh\necho "render-firewall $*" >> "$SHIM_LOG"\n')
    render.chmod(0o755)
    for name, text in {"sudo": "#!/bin/sh\nexit 1\n", "id": "#!/bin/sh\necho 1000\n"}.items():
        path = sb.shim / name
        path.write_text(text)
        path.chmod(0o755)


def run_pty(
    sb: Sandbox,
    *args: str,
    cols: int = 100,
    rows: int = 40,
    env: dict[str, str] | None = None,
    interrupt_when: Callable[[], bool] | None = None,
    timeout: float = 90,
) -> tuple[int, str]:
    """Runs install.sh on a pseudo-terminal that is its controlling terminal. Returns (rc, output)."""
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    full_env = {**sb.env, "TERM": "xterm-256color", "LANG": "C.UTF-8", **(env or {})}

    def controlling_tty() -> None:
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(  # noqa: S603
        ["bash", str(sb.root / "scripts/install.sh"), *args],  # noqa: S607
        cwd=sb.root,
        env=full_env,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        preexec_fn=controlling_tty,
        close_fds=True,
    )
    os.close(slave)
    buf = bytearray()
    sent = False
    deadline = time.monotonic() + timeout
    while True:
        ready, _, _ = select.select([master], [], [], 0.1)
        if ready:
            try:
                data = os.read(master, 65536)
            except OSError:
                data = b""
            if not data:
                break
            buf += data
        if interrupt_when is not None and not sent and interrupt_when():
            os.write(master, b"\x03")
            sent = True
        if time.monotonic() > deadline:
            proc.kill()
            raise AssertionError("install.sh did not finish on the terminal:\n" + buf.decode())
    rc = proc.wait(timeout=30)
    os.close(master)
    return rc, buf.decode("utf-8", "replace")


def screen(raw: str, cols: int) -> Screen:
    s = Screen(cols)
    s.feed(raw)
    return s


def list_lines(text: str) -> list[str]:
    """The lines of the step list and the bar."""
    marks = "✓✗·\u2013━╸⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"  # \u2013: the skipped mark
    return [line for line in text.splitlines() if line[:2] == "  " and line[2:3] in marks]


def ui_bash(script: str, env: dict[str, str], tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """Runs a snippet that sources ui.sh, with output on pipes (no terminal)."""
    return subprocess.run(  # noqa: S603
        ["bash", "-c", f'set -euo pipefail\n. "{UI}"\n{script}'],  # noqa: S607
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), **env},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


# ------------------------------------------------------------------ ui.sh on its own


def test_without_a_terminal_ui_is_plain_and_tees_into_the_log(tmp_path: Path) -> None:
    proc = ui_bash(
        """
        ui_init log.txt 0
        ui_plan "a|Alpha|1" "b|Beta|1"
        ui_begin a
        ui_run -- sh -c 'echo out; echo err >&2; exit 3' || echo "rc=$?"
        ui_end
        """,
        {"TERM": "xterm-256color", "LANG": "C.UTF-8"},
        tmp_path,
    )
    assert proc.returncode == 0, proc.stderr
    assert ESC not in proc.stdout + proc.stderr
    assert "\r" not in proc.stdout + proc.stderr
    assert "out" in proc.stdout and "err" in proc.stdout and "rc=3" in proc.stdout
    log = (tmp_path / "log.txt").read_text()
    assert "+ sh -c" in log and "out" in log and "err" in log
    assert oct((tmp_path / "log.txt").stat().st_mode & 0o777) == "0o600"


@pytest.mark.parametrize(
    ("env", "want", "unwanted"),
    [
        ({"TERM": "xterm-256color", "COLORTERM": "truecolor"}, "38;2;167;139;250", "38;5;"),
        ({"TERM": "tmux-256color"}, "38;5;141", "38;2;"),
        ({"TERM": "xterm"}, "\x1b[35m", "38;5;"),
        ({"TERM": "xterm-256color", "NO_COLOR": "1"}, "\x1b[?25l", r"\x1b\[(3[0-7]|38;)"),
    ],
)
def test_colour_tiers_follow_the_terminal(
    tmp_path: Path, env: dict[str, str], want: str, unwanted: str
) -> None:
    proc = ui_bash(
        'ui_init "" 0\nui_plan "a|Alpha|1"\nui_begin a\nui_done ok\nui_end',
        {"SUCKERPOT_UI": "rich", "LANG": "C.UTF-8", "COLUMNS": "80", **env},
        tmp_path,
    )
    assert proc.returncode == 0, proc.stderr
    assert want in proc.stdout
    assert not re.search(unwanted, proc.stdout)
    assert "Alpha" in proc.stdout


def test_without_utf8_the_display_is_ascii(tmp_path: Path) -> None:
    proc = ui_bash(
        'ui_init "" 0\nui_header ctx\nui_plan "a|Alpha|1" "b|Beta|1"\nui_begin a\nui_end',
        {"SUCKERPOT_UI": "rich", "LANG": "C", "TERM": "xterm", "COLUMNS": "80"},
        tmp_path,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.isascii()
    assert "+ Alpha" in screen(proc.stdout, 80).text()


@pytest.mark.parametrize("cols", [30, 50, 80, 120])
def test_no_line_of_the_list_is_wider_than_the_terminal(tmp_path: Path, cols: int) -> None:
    proc = ui_bash(
        """
        ui_init "" 0
        ui_header "participant node · a long context line that does not fit a narrow terminal"
        ui_plan "a|Check this machine|1" "b|Verify and download images|5" "c|Start SuckerPot|5"
        ui_begin a
        ui_detail "a very long detail that would wrap on any terminal narrower than one hundred columns"
        ui_begin b
        ui_end
        """,
        {"SUCKERPOT_UI": "rich", "LANG": "C.UTF-8", "TERM": "xterm-256color", "COLUMNS": str(cols)},
        tmp_path,
    )
    assert proc.returncode == 0, proc.stderr
    s = screen(proc.stdout, cols)
    assert not s.overflow, s.text()
    assert s.cursor_visible


def test_the_failure_screen_shows_the_log_tail_and_the_fix(tmp_path: Path) -> None:
    proc = ui_bash(
        """
        ui_init log.txt 0
        ui_plan "a|Alpha|1" "b|Beta|1"
        ui_begin a
        ui_run -- sh -c 'for i in $(seq 1 30); do echo "line $i"; done'
        ui_begin b
        UI_FAIL_LOGLINE="FAILED: it broke"
        ui_fail "it broke" "do this, then run again"
        """,
        {"SUCKERPOT_UI": "rich", "LANG": "C.UTF-8", "TERM": "xterm-256color", "COLUMNS": "80"},
        tmp_path,
    )
    assert proc.returncode == 1
    text = screen(proc.stdout, 80).text()
    assert "✗ Beta" in text and "✓ Alpha" in text
    assert "✗ it broke" in text
    assert "│ line 30" in text and "│ line 16" in text and "line 15" not in text
    assert "Fix   do this, then run again" in text
    assert f"Log   {tmp_path}/log.txt" in text
    assert (tmp_path / "log.txt").read_text().endswith("FAILED: it broke\n")


def test_plain_failure_keeps_the_prefix_and_names_the_log(tmp_path: Path) -> None:
    proc = ui_bash(
        'UI_PREFIX=install\nui_init log.txt 0\nui_fail "it broke"',
        {"TERM": "dumb"},
        tmp_path,
    )
    assert proc.returncode == 1
    assert proc.stderr == f"install: it broke\n      log: {tmp_path}/log.txt\n"


# ------------------------------------------------------------------ plain mode: golden output


def test_plain_full_install(sandbox: Sandbox) -> None:
    proc = sandbox.run(
        "scripts/install.sh",
        *("--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh,web"),
    )
    assert proc.returncode == 0, proc.stderr
    check_golden("full-yes", normalise(proc.stdout + "--- stderr\n" + proc.stderr, sandbox))


def test_plain_participant_install(sandbox: Sandbox) -> None:
    quiet_firewall(sandbox)
    proc = sandbox.run(
        "scripts/install.sh",
        *("--participant", "--yes", "--version", "v0.8.0", "--sensors", "ssh,web"),
    )
    assert proc.returncode == 0, proc.stderr
    check_golden("participant-yes", normalise(proc.stdout + "--- stderr\n" + proc.stderr, sandbox))


def test_plain_failed_start(sandbox: Sandbox) -> None:
    sandbox.env["SHIM_UP_RC"] = "1"
    proc = sandbox.run(
        "scripts/install.sh",
        *("--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh,web"),
    )
    assert proc.returncode == 1
    check_golden(
        "full-failed-start", normalise(proc.stdout + "--- stderr\n" + proc.stderr, sandbox)
    )


def test_plain_dry_run(sandbox: Sandbox) -> None:
    proc = sandbox.run(
        "scripts/install.sh",
        *("--yes", "--dry-run", "--env-out", str(sandbox.root / "out.env")),
    )
    assert proc.returncode == 0, proc.stderr
    check_golden("dry-run", normalise(proc.stdout + "--- stderr\n" + proc.stderr, sandbox))


@pytest.mark.parametrize("how", ["--plain", "TERM=dumb"])
def test_plain_on_a_terminal(sandbox: Sandbox, how: str) -> None:
    args = ["--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh,web"]
    env = {}
    if how == "--plain":
        args.append("--plain")
    else:
        env["TERM"] = "dumb"
    rc, raw = run_pty(sandbox, *args, env=env)
    assert rc == 0, raw
    assert ESC not in raw
    assert "[9/10] Starting SuckerPot (this can take several minutes)" in raw
    assert "SuckerPot is running." in raw


# ------------------------------------------------------------------ rich mode on a terminal


def test_rich_full_install(sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]) -> None:
    rc, raw = run_pty(
        sandbox, "--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh,web", cols=90
    )
    assert rc == 0, raw
    s = screen(raw, 90)
    text = s.text()
    assert s.cursor_visible
    assert "[1/10]" not in text  # the numbered lines are for plain mode
    for row in (
        "✓ Check this machine",
        "✓ Settings and secrets",
        "✓ Admin account",
        "✓ Data volumes and checks",
        "✓ Verify and download images",
        "✓ Start SuckerPot",
        "✓ Dashboard answers",
    ):
        assert row in text, text
    assert "100%" in text
    assert "SuckerPot is running." in text
    assert "Dashboard   http://127.0.0.1:8443" in text
    printed = re.findall(r"password .*: (\S+)", text)
    assert len(printed) == 1 and len(printed[0]) >= 24
    for line in list_lines(text):
        assert len(line) < 90, line
    # The verbose output went to the log, and nothing secret reached the screen or the log.
    log = (sandbox.root / "install.log").read_text()
    assert "check-ports: ok" in log and "check-ports: ok" not in text
    env = parse_env(sandbox.root / ".env")
    for name in SECRET_NAMES:
        assert env[name] not in raw and env[name] not in log
    assert printed[0] not in log


def test_rich_participant_install(sandbox: Sandbox) -> None:
    quiet_firewall(sandbox)
    rc, raw = run_pty(
        sandbox, "--participant", "--yes", "--version", "v0.8.0", "--sensors", "ssh,web"
    )
    assert rc == 0, raw
    text = screen(raw, 100).text()
    assert "SuckerPot participant mode (experimental preview)" in text  # the consent stays whole
    assert "--yes was given: this counts as your agreement" in text
    assert "✓ Automatic updates" in text
    assert (
        "\u2013 Host firewall                needs sudo: ./scripts/participant.sh firewall" in text
    )
    assert "✓ Sensor reachability" in text
    assert "SuckerPot is running in participant mode (v0.8.0)." in text
    assert "Never forward the admin SSH port of this machine." in text
    assert "./scripts/participant.sh ports-check" in text


def test_no_color_keeps_the_live_display(sandbox: Sandbox) -> None:
    rc, raw = run_pty(
        sandbox,
        *("--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh,web"),
        env={"NO_COLOR": "1"},
    )
    assert rc == 0, raw
    assert "\x1b[?25l" in raw and "\x1b[J" in raw
    assert not re.search(r"\x1b\[(3\d|38;)", raw)
    assert "✓ Start SuckerPot" in screen(raw, 100).text()


def test_rich_failure_screen(sandbox: Sandbox) -> None:
    rc, raw = run_pty(
        sandbox,
        *("--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh,web"),
        env={"SHIM_UP_RC": "1"},
    )
    assert rc == 1, raw
    s = screen(raw, 100)
    text = s.text()
    assert s.cursor_visible
    assert "✗ Start SuckerPot" in text
    assert "✗ the stack did not become healthy" in text
    assert "│ + dc up -d --no-build --pull never --wait --wait-timeout 600" in text
    assert "Fix   when the cause is fixed: ./scripts/install.sh --repair" in text
    assert f"Log   {sandbox.root}/install.log" in text
    assert "FAILED: the stack did not become healthy" in (sandbox.root / "install.log").read_text()


def test_ctrl_c_restores_the_terminal_and_keeps_the_log(sandbox: Sandbox) -> None:
    pidfile = sandbox.shim / "up.pid"
    wrap_docker(
        sandbox,
        f'  "compose up"*) echo $$ > "{pidfile}"; exec /bin/sleep 60 ;;',
    )
    rc, raw = run_pty(
        sandbox,
        *("--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh,web"),
        interrupt_when=pidfile.exists,
    )
    assert rc == 130, raw
    s = screen(raw, 100)
    assert s.cursor_visible
    text = s.text()
    assert "✗ Start SuckerPot              interrupted" in text
    assert f"Interrupted. Log: {sandbox.root}/install.log" in text
    assert (sandbox.root / "install.log").exists()
    assert not (sandbox.root / ".env.tmp").exists()
    pid = int(pidfile.read_text())
    time.sleep(0.5)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_the_questions_are_never_hidden(sandbox: Sandbox) -> None:
    answers = sandbox.root / "answers"
    answers.write_text("source\nssh,telnet\nl\nowner\n" + PASSWORD + "\n" + PASSWORD + "\n\n\n\n\n")
    rc, raw = run_pty(sandbox, env={"SELFHOSTR_TTY": str(answers)}, cols=200)
    assert rc == 0, raw
    text = screen(raw, 200).text()
    for question in ("Install mode: images (download) or source", "Admin user name [admin]:"):
        assert question in text
    assert "Join the SuckerPot network? [y/N]" in text
    assert PASSWORD not in raw
    assert "✓ Dashboard answers" in text
