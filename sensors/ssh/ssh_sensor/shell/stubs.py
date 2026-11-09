"""Binaries that exist in the fake filesystem but have no real emulation.

A real box answers a bare ``tar`` or ``git`` with a usage error, not silence. Each entry here
returns the cheapest truthful response: a usage line and a non-zero status without usable
arguments, the "file not found" error for a missing operand, and quiet success otherwise.
Names that are not in the filesystem at all never get here (``command not found``, 127).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from ssh_sensor.shell.core import CmdIO, parse_flags

if TYPE_CHECKING:
    from ssh_sensor.shell.interp import Shell

Stub = Callable[["Shell", CmdIO], int]

_TRY = "Try '{0} --help' for more information.\n"


def _missing(name: str, msg: str) -> Stub:
    """``name`` needs an operand: without one print ``msg`` plus the hint and exit 1."""

    def run(sh: Shell, io: CmdIO) -> int:
        _, _, operands = parse_flags(io.args)
        if operands:
            return 0
        io.error(f"{name}: {msg}\n" + _TRY.format(name))
        return 1

    return run


def _bare(text: str, status: int) -> Stub:
    """Print ``text`` (to stderr, or stdout for status 0) when called without arguments."""

    def run(sh: Shell, io: CmdIO) -> int:
        if io.args:
            return 0
        (io.write if status == 0 else io.error)(text)
        return status

    return run


def _tar(sh: Shell, io: CmdIO) -> int:
    args = ["-" + io.args[0], *io.args[1:]] if io.args and io.args[0][0] != "-" else io.args
    flags, values, operands = parse_flags(args, "CfzjJ")
    if not io.args:
        io.error(
            "tar: You must specify one of the '-Acdtrux', '--delete' or '--test-label' options\n"
            "Try 'tar --help' or 'tar --usage' for more information.\n"
        )
        return 2
    path = values.get("f") or (operands[0] if operands else "")
    if flags & {"x", "t"} and path:
        try:
            exists = sh.fs.exists(sh.abspath(path))
        except Exception:
            exists = False
        if not exists:
            io.error(f"tar: {path}: Cannot open: No such file or directory\n")
            io.error("tar: Error is not recoverable: exiting now\n")
            return 2
    return 0


def _dd(sh: Shell, io: CmdIO) -> int:
    count = bs = 0
    for arg in io.args:
        key, _, value = arg.partition("=")
        if key in ("count", "bs") and value.isascii() and value.isdigit() and len(value) < 8:
            if key == "count":
                count = int(value)
            else:
                bs = int(value)
    blocks = count if count else 0
    total = blocks * (bs or 512)
    io.error(
        f"{blocks}+0 records in\n{blocks}+0 records out\n"
        f"{total} bytes ({total} B) copied, 0.000312 s, {max(total, 1) // 312} kB/s\n"
    )
    return 0


def _find(sh: Shell, io: CmdIO) -> int:
    operands = [a for a in io.args if not a.startswith(("-", "(", "!"))][:1]
    start = io.args[0] if io.args and not io.args[0].startswith("-") else "."
    if not io.args:
        io.write(".\n")
        return 0
    if operands and not sh.fs.exists(sh.abspath(start)):
        io.error(f"find: ‘{start}’: No such file or directory\n")
        return 1
    return 0


_OPENSSL_SUBS = frozenset("rand enc dgst x509 req genrsa s_client verify version passwd".split())


def _openssl(sh: Shell, io: CmdIO) -> int:
    if not io.args:
        return 0  # reads commands from an empty stdin and exits
    sub = io.args[0]
    if sub == "version":
        io.write("OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)\n")
        return 0
    if sub not in _OPENSSL_SUBS:
        io.error(f"Invalid command '{sub}'; type \"help\" for a list.\n")
        return 1
    if len(io.args) == 1:
        io.error(f"Usage: {sub} [options]\nUse -help for summary.\n")
        return 1
    return 0


_GIT_USAGE = (
    "usage: git [-v | --version] [-h | --help] [-C <path>] [-c <name>=<value>]\n"
    "           [--exec-path[=<path>]] [--html-path] [--man-path] [--info-path]\n"
    "           [-p | --paginate | -P | --no-pager] [--no-replace-objects] [--bare]\n"
    "           [--git-dir=<path>] [--work-tree=<path>] [--namespace=<name>]\n"
    "           [--config-env=<name>=<envvar>] <command> [<args>]\n"
)
_GIT_REPO = frozenset("status log diff pull push add commit checkout branch fetch show".split())


def _git(sh: Shell, io: CmdIO) -> int:
    if not io.args:
        io.error(_GIT_USAGE + "\nThese are common Git commands used in various situations:\n")
        return 1
    sub = io.args[0]
    if sub in ("--version", "version"):
        io.write("git version 2.43.0\n")
        return 0
    if sub in _GIT_REPO:
        io.error("fatal: not a git repository (or any of the parent directories): .git\n")
        return 128
    if sub == "clone":
        name = (io.args[-1].rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")) or "repo"
        io.error(f"Cloning into '{name}'...\n")
        io.error("fatal: unable to access the repository: Could not resolve host\n")
        return 128
    if sub.startswith("-"):
        return 0
    io.error(f"git: '{sub}' is not a git command. See 'git --help'.\n")
    return 1


def _root_only(name: str, usage: str) -> Stub:
    def run(sh: Shell, io: CmdIO) -> int:
        if not sh.is_root:
            io.error(f"{name}: Permission denied.\n")
            return 1
        if not io.args:
            io.error(usage)
            return 2
        return 0

    return run


def _iptables(sh: Shell, io: CmdIO) -> int:
    if not sh.is_root:
        io.error(
            "iptables v1.8.10 (nf_tables): Could not fetch rule set generation id: "
            "Permission denied (you must be root)\n"
        )
        return 4
    if not io.args:
        io.error(
            "iptables v1.8.10 (nf_tables): no command specified\n"
            "Try `iptables -h' or 'iptables --help' for more information.\n"
        )
        return 2
    return 0


def _sshd(sh: Shell, io: CmdIO) -> int:
    io.error("sshd re-exec requires execution with an absolute path\n")
    return 1


def _dmesg(sh: Shell, io: CmdIO) -> int:
    if not sh.is_root:
        io.error("dmesg: read kernel buffer failed: Operation not permitted\n")
        return 1
    io.write(f"[    0.000000] Linux version {sh.profile.kernel} (buildd@lcy02-amd64-103)\n")
    io.write(
        "[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz root=/dev/root ro console=tty1\n"
    )
    return 0


def _mount(sh: Shell, io: CmdIO) -> int:
    if io.args:
        return 0 if sh.is_root else 1
    io.write(
        "/dev/root on / type ext4 (rw,relatime,discard,errors=remount-ro)\n"
        "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
        "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n"
        "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n"
    )
    return 0


def _basename(sh: Shell, io: CmdIO) -> int:
    _, _, operands = parse_flags(io.args)
    if not operands:
        io.error("basename: missing operand\n" + _TRY.format("basename"))
        return 1
    name = operands[0].rstrip("/").rsplit("/", 1)[-1] or (
        "/" if operands[0].startswith("/") else ""
    )
    if len(operands) > 1 and name.endswith(operands[1]) and name != operands[1]:
        name = name[: -len(operands[1])]
    io.write(name + "\n")
    return 0


def _dirname(sh: Shell, io: CmdIO) -> int:
    _, _, operands = parse_flags(io.args)
    if not operands:
        io.error("dirname: missing operand\n" + _TRY.format("dirname"))
        return 1
    for path in operands[:64]:
        trimmed = path.rstrip("/")
        head = trimmed.rpartition("/")[0]
        io.write((head.rstrip("/") or "/" if "/" in trimmed else ".") + "\n")
    return 0


def _seq(sh: Shell, io: CmdIO) -> int:
    _, _, operands = parse_flags(io.args)
    nums: list[int] = []
    for op in operands:
        digits = op.lstrip("-")
        if not (digits.isascii() and digits.isdigit() and len(digits) < 9):
            io.error(f"seq: invalid floating point argument: ‘{op}’\n")
            io.error(_TRY.format("seq"))
            return 1
        nums.append(int(op))
    if not nums:
        io.error("seq: missing operand\n" + _TRY.format("seq"))
        return 1
    first, step, last = (
        (1, 1, nums[0])
        if len(nums) == 1
        else ((nums[0], 1, nums[1]) if len(nums) == 2 else (nums[0], nums[1], nums[2]))
    )
    if step == 0:
        io.error("seq: invalid Zero increment value: ‘0’\n")
        return 1
    cur, emitted = first, 0
    while (cur <= last if step > 0 else cur >= last) and emitted < 10000 and not io.full:
        io.write(f"{cur}\n")
        cur += step
        emitted += 1
    return 0


def _readlink(sh: Shell, io: CmdIO) -> int:
    _, _, operands = parse_flags(io.args)
    if not operands:
        io.error("readlink: missing operand\n" + _TRY.format("readlink"))
        return 1
    try:
        node = sh.fs.stat(sh.fs.resolve(sh.cwd, operands[0], follow_last=False))
    except Exception:
        node = None
    if node is None or node.kind != "l":
        return 1
    io.write(node.target + "\n")
    return 0


def _du(sh: Shell, io: CmdIO) -> int:
    _, _, operands = parse_flags(io.args)
    status = 0
    for path in operands[:16] or ["."]:
        node = sh.fs.stat(sh.abspath(path))
        if node is None:
            io.error(f"du: cannot access '{path}': No such file or directory\n")
            status = 1
        else:
            io.write(f"{max(4, -(-node.length // 4096) * 4)}\t{path}\n")
    return status


_STUBS: dict[str, Stub] = {
    "tar": _tar,
    "dd": _dd,
    "find": _find,
    "openssl": _openssl,
    "git": _git,
    "useradd": _root_only("useradd", "Usage: useradd [options] LOGIN\n       useradd -D\n"),
    "userdel": _root_only("userdel", "Usage: userdel [options] LOGIN\n"),
    "usermod": _root_only("usermod", "Usage: usermod [options] LOGIN\n"),
    "fdisk": _root_only("fdisk", "Usage:\n fdisk [options] <disk>    change partition table\n"),
    "iptables": _iptables,
    "sshd": _sshd,
    "dmesg": _dmesg,
    "mount": _mount,
    "basename": _basename,
    "dirname": _dirname,
    "seq": _seq,
    "readlink": _readlink,
    "du": _du,
    "ln": _missing("ln", "missing file operand"),
    "gzip": _bare(
        "gzip: compressed data not written to a terminal. Use -f to force compression.\n"
        "For help, type: gzip -h\n",
        1,
    ),
    "unzip": _bare(
        "UnZip 6.00 of 20 April 2009, by Debian. Original by Info-ZIP.\n\n"
        "Usage: unzip [-Z] [-opts[modifiers]] file[.zip] [list] [-x xlist] [-d exdir]\n",
        0,
    ),
    "gpg": _bare(
        "gpg: WARNING: no command supplied.  Trying to guess what you mean ...\n"
        "gpg: no valid OpenPGP data found.\ngpg: processing message failed: Unknown system error\n",
        2,
    ),
}


def run_stub(sh: Shell, name: str, io: CmdIO) -> int:
    """Behaviour of an installed binary without a real implementation."""
    stub = _STUBS.get(name)
    return stub(sh, io) if stub is not None else 0
