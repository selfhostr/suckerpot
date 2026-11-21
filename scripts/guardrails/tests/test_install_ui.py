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
import shutil
import struct
import subprocess
import tempfile
import termios
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import ROOT, Sandbox
from test_install import SECRET_NAMES, add_participant_files, wrap_docker
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
    assert proc.stdout == "out\nrc=3\n"  # stderr stays on stderr
    assert proc.stderr == "err\n"
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


def streams(proc: subprocess.CompletedProcess[str], sb: Sandbox) -> str:
    """stdout and stderr, each on its own: plain mode keeps them apart, as before."""
    return normalise("--- stdout\n" + proc.stdout + "--- stderr\n" + proc.stderr, sb)


FULL = ("--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh,web")


@pytest.mark.parametrize(
    ("name", "env", "rc"),
    [
        ("full-yes", {}, 0),
        # The failures end with one more line than before: "      log: <path>" (on stderr).
        ("full-failed-start", {"SHIM_UP_RC": "1"}, 1),
        ("full-failed-signature", {"SHIM_COSIGN_NODIGEST": "1"}, 1),
        ("full-failed-dashboard", {"SHIM_CURL_RC": "7"}, 1),
    ],
)
def test_plain_full_install(sandbox: Sandbox, name: str, env: dict[str, str], rc: int) -> None:
    sandbox.env.update(env)
    proc = sandbox.run("scripts/install.sh", *FULL)
    assert proc.returncode == rc, proc.stderr
    check_golden(name, streams(proc, sandbox))


def test_plain_keeps_the_stderr_of_commands_on_stderr(sandbox: Sandbox) -> None:
    sandbox.env["SHIM_COSIGN_NODIGEST"] = "1"
    proc = sandbox.run("scripts/install.sh", *FULL)
    assert proc.returncode == 1
    assert "  FAILED  api (no single verified digest" in proc.stderr
    assert "FAILED  api" not in proc.stdout
    assert "FAILED  api" in (sandbox.root / "install.log").read_text()


def test_plain_participant_install(sandbox: Sandbox) -> None:
    quiet_firewall(sandbox)
    proc = sandbox.run(
        "scripts/install.sh",
        *("--participant", "--yes", "--version", "v0.8.0", "--sensors", "ssh,web"),
    )
    assert proc.returncode == 0, proc.stderr
    check_golden("participant-yes", streams(proc, sandbox))


def test_plain_dry_run(sandbox: Sandbox) -> None:
    proc = sandbox.run(
        "scripts/install.sh",
        *("--yes", "--dry-run", "--env-out", str(sandbox.root / "out.env")),
    )
    assert proc.returncode == 0, proc.stderr
    check_golden("dry-run", streams(proc, sandbox))


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
    assert "full install" in text.splitlines()[2]  # the header names the mode
    assert "SuckerPot is running." in text
    assert "    Dashboard   http://127.0.0.1:8443" in text
    assert "    Network     not joined" in text
    # The password stands alone on the line under its label, never cut.
    printed = re.findall(r"password manager now\):\n    (\S+)\n", text)
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
    """Phase C: the type question is the one screen of a full install, above the list."""
    answers = sandbox.root / "answers"
    answers.write_text("2\n")
    rc, raw = run_pty(
        sandbox, "--images", "--version", "v0.8.0", env={"SELFHOSTR_TTY": str(answers)}, cols=100
    )
    assert rc == 0, raw
    text = screen(raw, 100).text()
    assert "  What do you want to install?" in text
    assert "    1  Participant node   Sensors only. Joins the SuckerPot network." in text
    assert "    2  Full install       Sensors, dashboard, VPN egress, reports." in text
    assert "  Choose 1 or 2 [1]:" in text
    assert text.index("Choose 1 or 2") < text.index("✓ Check this machine")
    assert "Join the SuckerPot network? [y/N]" not in text
    assert "    Network     not joined" in text
    assert "✓ Dashboard answers" in text


# ------------------------------------------------------------------ review fixes


def _not_root() -> None:
    if os.geteuid() == 0:
        pytest.skip("root reads files whatever their mode")


def test_an_unexpected_error_shows_the_failure_screen(sandbox: Sandbox) -> None:
    """set -e stops the script on a failed cp: the screen says so, with the log tail."""
    _not_root()
    (sandbox.root / ".env.example").chmod(0)
    rc, raw = run_pty(sandbox, *FULL)
    assert rc == 1, raw
    s = screen(raw, 100)
    text = s.text()
    assert s.cursor_visible
    assert "✗ Admin account                stopped" in text
    assert "✗ Stopped by an unexpected error (exit 1)" in text
    assert "Permission denied" in text
    assert f"Log   {sandbox.root}/install.log" in text
    assert not (sandbox.root / ".env.tmp").exists()


def test_a_log_that_cannot_be_written_still_shows_the_failure(sandbox: Sandbox) -> None:
    """Like a full disk: every write to install.log fails, the screen still explains."""
    (sandbox.root / "install.log").mkdir()  # no write to it can succeed
    rc, raw = run_pty(sandbox, *FULL)
    assert rc != 0, raw
    s = screen(raw, 100)
    text = s.text()
    assert s.cursor_visible
    assert "! cannot write install.log: Is a directory; output is not logged" in text
    assert "Stopped by an unexpected error" in text
    assert "The last lines of the log" not in text  # no promise of lines it cannot show
    assert "No log lines are available" in text
    assert "Log   not written" in text


def test_ctrl_c_stops_a_shell_function_at_once(sandbox: Sandbox) -> None:
    """dashboard_wait is a loop in the installer: Ctrl-C must not wait for its 10 tries."""
    marker = sandbox.shim / "curl-started"
    curl = sandbox.shim / "curl"
    curl.write_text(f'#!/bin/sh\ntouch "{marker}"\n/bin/sleep 5\nexit 7\n')
    curl.chmod(0o755)
    start = time.monotonic()
    rc, raw = run_pty(sandbox, *FULL, interrupt_when=marker.exists)
    assert rc == 130, raw
    assert time.monotonic() - start < 25
    text = screen(raw, 100).text()
    assert "✗ Dashboard answers            interrupted" in text


def _run_and_signal(
    sb: Sandbox, sig: int, pidfile: Path
) -> tuple[int, float, subprocess.Popen[bytes]]:
    """Starts install.sh on a terminal, sends SIG to the installer alone once compose up runs."""
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))

    def controlling_tty() -> None:
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(  # noqa: S603
        ["bash", str(sb.root / "scripts/install.sh"), *FULL],  # noqa: S607
        cwd=sb.root,
        env={**sb.env, "TERM": "xterm-256color", "LANG": "C.UTF-8"},
        stdin=slave,
        stdout=slave,
        stderr=slave,
        preexec_fn=controlling_tty,
        close_fds=True,
    )
    os.close(slave)
    deadline = time.monotonic() + 60
    while not pidfile.exists():
        select.select([master], [], [], 0.1)
        try:
            os.read(master, 65536)
        except OSError:
            break
        assert time.monotonic() < deadline, "compose up never started"
    start = time.monotonic()
    os.kill(proc.pid, sig)
    while proc.poll() is None and time.monotonic() - start < 30:
        if select.select([master], [], [], 0.1)[0]:
            try:
                os.read(master, 65536)
            except OSError:
                break
    rc = proc.wait(timeout=30)
    os.close(master)
    return rc, time.monotonic() - start, proc


def _gone(pid: int) -> bool:
    for _ in range(20):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    return False


def test_term_stops_the_running_command_at_once(sandbox: Sandbox) -> None:
    pidfile = sandbox.shim / "up.pid"
    wrap_docker(sandbox, f'  "compose up"*) echo $$ > "{pidfile}"; exec /bin/sleep 60 ;;')
    rc, took, _ = _run_and_signal(sandbox, 15, pidfile)
    assert rc == 143
    assert took < 10
    assert _gone(int(pidfile.read_text()))


def test_the_spinner_does_not_outlive_a_killed_installer(sandbox: Sandbox) -> None:
    # Pipes, not a terminal: a dying session leader would send SIGHUP and hide the bug.
    pidfile = sandbox.shim / "up.pid"
    wrap_docker(sandbox, f'  "compose up"*) echo $$ > "{pidfile}"; exec /bin/sleep 60 ;;')
    proc = subprocess.Popen(  # noqa: S603
        ["bash", str(sandbox.root / "scripts/install.sh"), *FULL],  # noqa: S607
        cwd=sandbox.root,
        env={**sandbox.env, "SUCKERPOT_UI": "rich", "TERM": "xterm", "LANG": "C.UTF-8"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 60
    while not pidfile.exists():
        assert time.monotonic() < deadline, "compose up never started"
        time.sleep(0.1)
    proc.kill()
    proc.wait(timeout=10)
    # The subshell that runs the command itself (the parent of the fake compose) may stay until
    # the command ends: SIGKILL cannot be caught. Only the spinner must go.
    stat = Path(f"/proc/{pidfile.read_text().strip()}/stat").read_text()
    command_shell = stat.rsplit(") ", 1)[1].split()[1]
    script = str(sandbox.root / "scripts/install.sh")
    deadline = time.monotonic() + 5
    while True:
        left = []
        for cmdline in Path("/proc").glob("[0-9]*/cmdline"):
            try:
                if (
                    script in cmdline.read_bytes().decode(errors="replace")
                    and cmdline.parent.name != command_shell
                ):
                    left.append(cmdline.parent.name)
            except OSError:
                continue
        if not left or time.monotonic() > deadline:
            break
        time.sleep(0.2)
    for pid in [*left, command_shell, pidfile.read_text().strip()]:
        try:
            os.kill(int(pid), 9)
        except ProcessLookupError, ValueError:
            pass
    assert not left, f"processes of the installer still run: {left}"


def test_every_numbered_step_has_a_row() -> None:
    text = (ROOT / "scripts/install.sh").read_text()
    m = re.search(r"^STEP_ROW=\((.*)\)$", text, re.MULTILINE)
    assert m
    keys = {int(k) for k in re.findall(r"\[(\d+)\]=", m.group(1))}
    assert keys == set(range(1, 9))


def test_the_final_screen_fits_a_narrow_terminal(sandbox: Sandbox) -> None:
    rc, raw = run_pty(sandbox, *FULL, cols=60)
    assert rc == 0, raw
    text = screen(raw, 60).text()
    final = text[text.index("SuckerPot is running.") :].splitlines()
    log_path = f"{sandbox.root}/install.log"
    for line in final:
        if line.strip() != log_path:  # a path is never cut
            assert len(line) < 60, line
    assert re.search(r"now\):\n    \S{24,}\n", text)


def test_a_failed_schedule_is_not_shown_as_done(sandbox: Sandbox) -> None:
    quiet_firewall(sandbox)
    (sandbox.shim / "crontab").write_text(
        '#!/bin/sh\ncase "$1" in -l) echo "no crontab for user" >&2; exit 1 ;; esac\nexit 1\n'
    )
    (sandbox.shim / "systemctl").write_text("#!/bin/sh\nexit 1\n")
    (sandbox.shim / "systemctl").chmod(0o755)
    rc, raw = run_pty(sandbox, "--participant", "--yes", "--version", "v0.8.0", "--sensors", "ssh")
    assert rc == 0, raw
    text = screen(raw, 100).text()
    assert "\u2013 Automatic updates            not scheduled" in text
    assert "✓ Automatic updates" not in text


def test_a_missing_log_folder_prints_no_shell_error(tmp_path: Path) -> None:
    proc = ui_bash("ui_init missing/log.txt 0\necho done", {"TERM": "dumb"}, tmp_path)
    assert proc.returncode == 0
    assert proc.stdout == "done\n"
    assert proc.stderr == ""


def test_consent_and_prompts_are_indented_like_the_screen(sandbox: Sandbox) -> None:
    quiet_firewall(sandbox)
    answers = sandbox.root / "answers"
    answers.write_text("y\n")
    rc, raw = run_pty(
        sandbox,
        *("--participant", "--version", "v0.8.0", "--sensors", "ssh,web"),
        env={"SELFHOSTR_TTY": str(answers)},
        cols=120,
    )
    assert rc == 0, raw
    text = screen(raw, 120).text()
    assert "\n  SuckerPot participant mode (experimental preview)\n" in text
    assert "\n    - source addresses seen by your sensors" in text  # wording unchanged
    assert "\n  Join the SuckerPot network as described? [y/N]" in text
    # The firewall is on by default: no question, sudo asks in the open (decision O7).
    assert "Install the host firewall now?" not in text
    assert "  The host firewall needs root rights: sudo asks for your password." in text
    assert "\u2013 Host firewall                sudo failed" in text


def _admin_port(sb: Sandbox) -> str:
    proc = subprocess.run(
        ["bash", "-c", ". scripts/lib/env.sh; . scripts/lib/firewall.sh; fw_admin_port"],  # noqa: S607
        cwd=sb.root,
        env=sb.env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return proc.stdout


def test_the_admin_port_probe_ignores_the_host(sandbox: Sandbox) -> None:
    """The sandbox hides ssh.socket, sshd and /etc/ssh: the probe falls back to its default."""
    add_participant_files(sandbox)
    assert _admin_port(sandbox) == "22 default\n"
    # Its own sshd_config in SELFHOSTR_SSH_DIR is read, the host's /etc/ssh is not.
    (Path(sandbox.env["SELFHOSTR_SSH_DIR"]) / "sshd_config").write_text("Port 2201\n")
    assert _admin_port(sandbox) == "2201 sshd_config\n"


# ------------------------------------------------------------------ phase C: fewer questions


def _write(sb: Sandbox, name: str, text: str) -> None:
    path = sb.shim / name
    path.write_text(text)
    path.chmod(0o755)


def _participant_tools(sb: Sandbox, uid: str, sudo_rc: int) -> None:
    """A firewall renderer and loader that only record, and sudo/id that behave as asked."""
    add_participant_files(sb)
    for rel, body in (
        ("scripts/host/render-firewall.sh", 'echo "render-firewall $*" >> "$SHIM_LOG"\n'),
        ("scripts/host/install-firewall.sh", 'echo "install-firewall $*" >> "$SHIM_LOG"\n'),
    ):
        path = sb.root / rel
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)
    _write(sb, "sudo", f'#!/bin/sh\necho "sudo $*" >> "$SHIM_LOG"\nexit {sudo_rc}\n')
    _write(sb, "id", f'#!/bin/sh\n[ "$1" = -u ] && echo {uid} && exit 0\nexec /usr/bin/id "$@"\n')


def test_the_firewall_is_installed_without_a_question(sandbox: Sandbox) -> None:
    """Decision O7: on by default; sudo may ask for its password, the installer asks nothing."""
    _participant_tools(sandbox, "1000", 0)
    answers = sandbox.root / "answers"
    answers.write_text("y\n")
    proc = sandbox.run(
        "scripts/install.sh",
        *("--participant", "--version", "v0.8.0", "--sensors", "ssh,web"),
        extra_env={"SELFHOSTR_TTY": str(answers)},
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "Install the host firewall now?" not in out
    assert any(c.startswith("install-firewall ") for c in sandbox.calls())


def test_no_firewall_skips_it_and_records_the_choice(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    _participant_tools(sandbox, "0", 0)
    proc = sandbox.run(
        "scripts/install.sh",
        *("--participant", "--yes", "--version", "v0.8.0", "--sensors", "ssh,web"),
        "--no-firewall",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Skipped (--no-firewall)" in proc.stdout
    assert not any(c.startswith("install-firewall ") for c in sandbox.calls())
    assert parse_env(sandbox.root / ".env")["SUCKERPOT_NO_FIREWALL"] == "1"


def test_a_participant_without_a_terminal_needs_yes(sandbox: Sandbox) -> None:
    add_participant_files(sandbox)
    proc = sandbox.run(
        "scripts/install.sh",
        *("--participant", "--dry-run", "--env-out", str(sandbox.root / "x.env")),
        extra_env={"SELFHOSTR_TTY": "/nonexistent/tty"},
    )
    assert proc.returncode != 0
    assert "no terminal to ask the participant consent on; use --yes" in proc.stderr


def test_update_check_and_self_address_are_flags_of_a_full_install(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    target = sandbox.root / "f.env"
    proc = sandbox.run(
        "scripts/install.sh",
        *("--yes", "--dry-run", "--env-out", str(target)),
        *("--update-check", "--self-address", "203.0.113.9"),
    )
    assert proc.returncode == 0, proc.stderr
    env = parse_env(target)
    assert env["UPDATE_CHECK_ENABLED"] == "true"
    assert env["INDICATORS_IGNORE"] == "203.0.113.9"
    default = sandbox.root / "d.env"
    proc = sandbox.run("scripts/install.sh", "--yes", "--dry-run", "--env-out", str(default))
    assert parse_env(default)["UPDATE_CHECK_ENABLED"] == "false"
    add_participant_files(sandbox)
    proc = sandbox.run(
        "scripts/install.sh",
        *("--participant", "--yes", "--dry-run", "--env-out", str(sandbox.root / "p.env")),
        "--update-check",
    )
    assert proc.returncode != 0 and "--update-check" in proc.stderr


def test_plain_output_ends_with_a_result_line(sandbox: Sandbox) -> None:
    proc = sandbox.run("scripts/install.sh", *FULL)
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.splitlines()
    assert lines[-2] == "[10/10] ok"
    assert lines[-1] == (
        f"result: ok type=full version=v0.8.0 engine=docker log={sandbox.root}/install.log"
    )
    assert "[1/10] ok" in lines and "[9/10] ok" in lines
    sandbox.env["SHIM_UP_RC"] = "1"
    (sandbox.root / ".env").unlink()
    proc = sandbox.run("scripts/install.sh", *FULL)
    assert proc.returncode == 1
    assert proc.stdout.splitlines()[-2:] == [
        "[9/10] failed",
        f"result: failed step=9 log={sandbox.root}/install.log",
    ]


DOCKER_KEY_DEB = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"

# A fake gpg for the key steps: one key in the throwaway keyring, an export, and FPR as its key.
GPG_SHIM = """#!/bin/sh
case "$*" in
  *--list-keys* | *--show-keys*) echo "pub:u:4096:1:8D81803C0EBFCD88:"; echo "fpr:::::::::FPR:" ;;
  *--export*) echo "-----BEGIN PGP PUBLIC KEY BLOCK-----" ;;
esac
exit 0
"""


def _without_an_engine(
    sb: Sandbox, os_release: str = "ID=debian\nVERSION_CODENAME=trixie\n"
) -> None:
    """PATH without docker, podman and docker-compose, whatever the host has installed."""
    for name in ("docker", "podman", "docker-compose"):
        (sb.shim / name).rename(sb.shim / f"{name}.later")
    sysbin = sb.shim.parent / "sysbin"
    sysbin.mkdir(exist_ok=True)
    for folder in ("/usr/bin", "/bin"):
        for entry in os.listdir(folder):
            link = sysbin / entry
            if entry in ("docker", "podman", "docker-compose") or link.exists():
                continue
            link.symlink_to(Path(folder) / entry)
    sb.env["PATH"] = f"{sb.shim}:{sysbin}"
    osr = sb.shim / "os-release"
    osr.write_text(os_release)
    sb.env["SELFHOSTR_OS_RELEASE"] = str(osr)
    sb.env["USER"] = "tester"  # when this uid has no name (a container)
    # curl writes an empty file where -o says; gpg reports the pinned key; sudo only records.
    _write(
        sb,
        "curl",
        '#!/bin/sh\necho "curl $*" >> "$SHIM_LOG"\n'
        'while [ $# -gt 0 ]; do [ "$1" = -o ] && : > "$2"; shift; done\n',
    )
    _write(sb, "gpg", GPG_SHIM.replace("FPR", DOCKER_KEY_DEB))
    _write(sb, "sudo", '#!/bin/sh\necho "sudo $*" >> "$SHIM_LOG"\ncat > /dev/null &\nexit 0\n')
    # sg: the probe succeeds; the second run gets docker back on PATH and really runs.
    later = sb.shim / "later"
    later.mkdir(exist_ok=True)
    for name in ("docker", "podman", "docker-compose"):
        (later / name).symlink_to(sb.shim / f"{name}.later")
    _write(
        sb,
        "sg",
        '#!/bin/sh\necho "sg $*" >> "$SHIM_LOG"\n'
        '[ "$3" = true ] && exit "${SHIM_SG_RC:-0}"\n'
        'PATH="$SHIM_DIR/later:$PATH" exec sh -c "$3"\n',
    )


def _user() -> str:
    who = subprocess.run(["id", "-un"], capture_output=True, text=True, check=False)  # noqa: S607
    name = who.stdout.strip()
    return name if re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", name) else "tester"


def test_without_docker_the_commands_come_from_docker_s_repository(sandbox: Sandbox) -> None:
    """Decision O4, without a pipe to a shell: the key is checked, then the package manager."""
    _without_an_engine(sandbox)
    proc = sandbox.run("scripts/install.sh", "--yes")
    assert proc.returncode == 1, proc.stderr  # nothing was installed
    out = proc.stdout
    assert "These commands install it from Docker's own package repository" in out
    assert (
        "curl -fsSL https://download.docker.com/linux/debian/gpg -o .suckerpot-state/docker-download.gpg"
        in out
    )
    assert f"= {DOCKER_KEY_DEB}" in out
    assert "https://download.docker.com/linux/debian trixie stable" in out
    assert (
        "sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin" in out
    )
    assert f"sudo usermod -aG docker {_user()}" in out
    assert "| sudo sh" not in out and "get.docker.com" not in out
    assert out.splitlines()[-1].startswith("result: stopped reason=docker-missing step=1 ")
    assert not [c for c in sandbox.calls() if c.startswith(("curl", "sudo", "sg"))]


def test_fedora_and_rhel_use_the_rpm_repository_and_its_key(sandbox: Sandbox) -> None:
    _without_an_engine(sandbox, "ID=rocky\nVERSION_ID=10\n")
    proc = sandbox.run("scripts/install.sh", "--yes")
    assert proc.returncode == 1, proc.stderr  # nothing was installed
    assert "https://download.docker.com/linux/centos/docker-ce.repo" in proc.stdout
    assert "= 060A61C51B558A7F742B77AAC52FEB6B621E9F35" in proc.stdout
    assert (
        "sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin"
        in proc.stdout
    )


def test_an_unknown_distribution_only_gets_the_docs_link(sandbox: Sandbox) -> None:
    _without_an_engine(sandbox, "ID=arch\n")
    proc = sandbox.run("scripts/install.sh", "--yes")
    assert proc.returncode == 1, proc.stderr  # nothing was installed
    assert "https://docs.docker.com/engine/install/" in proc.stdout
    assert "sudo apt-get" not in proc.stdout


def test_a_no_answer_runs_nothing(sandbox: Sandbox) -> None:
    _without_an_engine(sandbox)
    answers = sandbox.root / "answers"
    answers.write_text("n\n")
    proc = sandbox.run("scripts/install.sh", "--full", extra_env={"SELFHOSTR_TTY": str(answers)})
    assert proc.returncode == 1, proc.stderr  # nothing was installed
    assert "Run them now? sudo asks for your password. [Y/n]" in proc.stderr
    assert "Run them yourself, log out and back in" in proc.stdout
    assert not [c for c in sandbox.calls() if c.startswith(("curl", "sudo", "sg"))]


def test_a_failed_key_check_stops_before_the_package_manager(sandbox: Sandbox) -> None:
    _without_an_engine(sandbox)
    _write(sandbox, "gpg", GPG_SHIM.replace("FPR", "0" * 40))
    answers = sandbox.root / "answers"
    answers.write_text("y\n")
    proc = sandbox.run("scripts/install.sh", "--full", extra_env={"SELFHOSTR_TTY": str(answers)})
    assert proc.returncode == 1
    assert "this command failed (see the log): ( g=$(mktemp -d)" in proc.stderr
    calls = sandbox.calls()
    assert not any("docker-ce" in c or "keyrings" in c for c in calls)


def test_sg_failing_says_to_log_in_again(sandbox: Sandbox) -> None:
    _without_an_engine(sandbox)
    sandbox.env["SHIM_SG_RC"] = "1"
    answers = sandbox.root / "answers"
    answers.write_text("y\n")
    proc = sandbox.run("scripts/install.sh", "--full", extra_env={"SELFHOSTR_TTY": str(answers)})
    assert proc.returncode == 1, proc.stderr  # nothing was installed
    assert "Docker is installed. Log out and back in, then run the installer again." in proc.stdout
    assert "sg could not start a shell in the docker group" in proc.stdout
    assert proc.stdout.splitlines()[-1].startswith("result: stopped reason=relogin ")
    assert [c for c in sandbox.calls() if c.startswith("sg ")] == ["sg docker -c true"]


def test_the_second_run_under_sg_draws_on_the_terminal(sandbox: Sandbox) -> None:
    """After the install, the run under sg must show its screen and the password on the terminal."""
    _without_an_engine(sandbox)
    answers = sandbox.root / "answers"
    answers.write_text("y\n")
    rc, raw = run_pty(
        sandbox,
        *("--full", "--images", "--version", "v0.8.0"),
        env={"SELFHOSTR_TTY": str(answers)},
    )
    assert rc == 0, raw
    text = screen(raw, 100).text()
    assert "Docker is installed. The installer starts again in the docker group" in text
    calls = sandbox.calls()
    assert (
        "sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin"
        in calls
    )
    sg = [c for c in calls if c.startswith("sg docker -c SELFHOSTR_DOCKER_INSTALLED=1 bash ")]
    assert len(sg) == 1 and sg[0].endswith("--full --images --version v0.8.0 ")
    # The second run's final screen, with the password shown once, is on the terminal.
    assert "SuckerPot is running." in text
    printed = re.findall(r"now\):\n    (\S+)\n", text)
    assert len(printed) == 1
    assert printed[0] not in (sandbox.root / "install.log").read_text()


def test_a_strange_codename_is_never_put_in_a_command(sandbox: Sandbox) -> None:
    _without_an_engine(sandbox, 'ID=debian\nVERSION_CODENAME="trixie stable; rm -rf /"\n')
    proc = sandbox.run("scripts/install.sh", "--yes")
    assert proc.returncode == 1
    assert "https://docs.docker.com/engine/install/" in proc.stdout
    assert "rm -rf" not in proc.stdout


def _gpg(home: Path, *args: str, stdin: str | None = None) -> str:
    return subprocess.run(  # noqa: S603
        ["gpg", "--homedir", str(home), "--batch", *args],  # noqa: S607
        input=stdin,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _throwaway_key(home: Path, name: str) -> str:
    home.mkdir(mode=0o700, exist_ok=True)
    _gpg(
        home,
        *("--pinentry-mode", "loopback", "--passphrase", ""),
        *("--quick-gen-key", f"{name} <{name}@example.org>", "ed25519"),
    )
    fpr = [line for line in _gpg(home, "--with-colons", "--list-keys").splitlines()]
    return next(line.split(":")[9] for line in fpr if line.startswith("fpr:"))


@pytest.mark.skipif(shutil.which("gpg") is None, reason="needs a real gpg")
def test_only_the_pinned_key_reaches_the_package_manager(sandbox: Sandbox, tmp_path: Path) -> None:
    """Real gpg, throwaway keys: the download with an extra key is refused."""
    # Short folders: gpg-agent puts its socket there, and a socket path has a length limit.
    short = Path(tempfile.mkdtemp(prefix="gpg"))
    pinned_home, extra_home = short / "p", short / "e"
    pinned = _throwaway_key(pinned_home, "pinned")
    _throwaway_key(extra_home, "extra")
    alone = _gpg(pinned_home, "--export", "--armor")
    both = alone + _gpg(extra_home, "--export", "--armor")
    _without_an_engine(sandbox)
    (sandbox.shim / "gpg").unlink()  # the real one, from the host
    # The throwaway key replaces the pinned one only in test mode, which also wants an sp-it name.
    sandbox.env["SELFHOSTR_DOCKER_KEY_DEB"] = pinned
    sandbox.env["SELFHOSTR_TEST_INSTALL"] = "1"
    project = ("--project", "sp-it-participant-abcdef12", "--prefix", "sp-it-participant-abcdef12")
    served = sandbox.shim / "served-key"
    _write(
        sandbox,
        "curl",
        '#!/bin/sh\necho "curl $*" >> "$SHIM_LOG"\n'
        f'while [ $# -gt 0 ]; do [ "$1" = -o ] && cp "{served}" "$2"; shift; done\n',
    )
    answers = sandbox.root / "answers"
    answers.write_text("y\n")
    for text, ok in ((alone, True), (both, False)):
        served.write_text(text)
        (sandbox.shim / "calls.log").unlink(missing_ok=True)
        proc = sandbox.run(
            "scripts/install.sh", "--full", *project, extra_env={"SELFHOSTR_TTY": str(answers)}
        )
        calls = sandbox.calls()
        installed = "sudo install -m 0644 .suckerpot-state/docker.asc /etc/apt/keyrings/docker.asc"
        if ok:
            assert installed in calls, proc.stdout + proc.stderr
            export = (sandbox.root / ".suckerpot-state/docker.asc").read_text()
            keys = subprocess.run(
                ["gpg", "--batch", "--with-colons", "--show-keys"],  # noqa: S607
                input=export,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            assert keys.count("\npub:") + keys.startswith("pub:") == 1
            assert pinned in keys
        else:
            assert proc.returncode == 1
            assert installed not in calls
            assert not any("docker-ce" in c for c in calls)
        (sandbox.root / ".suckerpot-state/docker.asc").unlink(missing_ok=True)


def test_the_test_key_hook_is_ignored_outside_test_mode(sandbox: Sandbox) -> None:
    """A real run never lets an environment variable replace Docker's pinned fingerprint."""
    _without_an_engine(sandbox)
    sandbox.env["SELFHOSTR_DOCKER_KEY_DEB"] = "A" * 40
    sandbox.env["SELFHOSTR_DOCKER_KEY_RPM"] = "B" * 40
    proc = sandbox.run("scripts/install.sh", "--yes")
    assert proc.returncode == 1
    assert "are for the tests only (SELFHOSTR_TEST_INSTALL=1): ignored" in proc.stderr
    assert f"= {DOCKER_KEY_DEB}" in proc.stdout
    assert "A" * 40 not in proc.stdout
    sandbox.env["SELFHOSTR_TEST_INSTALL"] = "1"
    proc = sandbox.run(
        "scripts/install.sh",
        *(
            "--yes",
            "--project",
            "sp-it-participant-abcdef12",
            "--prefix",
            "sp-it-participant-abcdef12",
        ),
    )
    assert proc.returncode == 1
    assert "= " + "A" * 40 in proc.stdout
