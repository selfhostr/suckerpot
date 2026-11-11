"""Download tools. They NEVER fetch anything: they record a ``download_attempt`` and print
believable output, then drop a tiny stub file into the fake filesystem."""

from __future__ import annotations

import ipaddress
import posixpath
import re
from urllib.parse import SplitResult, urlsplit

from suckerpot_common import EventType

from ssh_sensor.shell.core import CmdIO, PendingEvent, parse_flags
from ssh_sensor.shell.fs import FSError
from ssh_sensor.shell.interp import Shell
from ssh_sensor.shell.payload import Payload, payload_for

MAX_URLS = 8
# Top-level names that never resolve on the public internet (RFC 2606, RFC 6761, mDNS, Tor).
_DEAD_TLDS = frozenset({"invalid", "test", "example", "localhost", "local", "onion", "lan"})
_LABEL_RE = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
_IP_ECHO_HOSTS = (
    "ifconfig.me",
    "icanhazip.com",
    "ipinfo.io",
    "api.ipify.org",
    "checkip.amazonaws.com",
)


def _split(url: str) -> SplitResult:
    """``urlsplit`` that never raises: a malformed URL (``http://[x``) splits as empty."""
    try:
        return urlsplit(url)
    except ValueError:
        return urlsplit("")


def _normalize_url(raw: str) -> str:
    raw = raw.strip()[:2048]
    return raw if "://" in raw else "http://" + raw


def _record(sh: Shell, url: str, tool: str, io: CmdIO) -> None:
    sh.pending.append(
        PendingEvent(EventType.download_attempt, {"url": url, "tool": tool, "command": io.cmdline})
    )


def _drop(sh: Shell, io: CmdIO, path: str, url: str) -> Payload:
    """Create the fake downloaded file. Its type and size depend on the URL."""
    payload = payload_for(sh.profile.payload_key, url)
    if not sh.fs.may_write(path, sh.user.name, sh.user.home):
        raise FSError("Permission denied")
    sh.fs.write(
        path,
        payload.content,
        append=False,
        owner=sh.user.name,
        tag=payload.tag,
        size=payload.size,
    )
    return payload


def host_exists(host: str) -> bool:
    """False for a host name that cannot resolve: malformed, no dot, or a reserved TLD."""
    host = host.rstrip(".").lower()
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2 or labels[-1] in _DEAD_TLDS:
        return False
    if all(part.isdigit() for part in labels):
        return False  # a dotted quad that is not a valid address
    return all(_LABEL_RE.match(part) for part in labels)


def _is_loopback(host: str) -> bool:
    """``localhost`` or a literal loopback address (127.0.0.0/8, ::1), never a name."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _human(n: int) -> str:
    """wget's legible size: ``512``, ``5.3K``, ``14K``, ``1.2M``."""
    value = float(n)
    for unit in ("", "K", "M", "G"):
        if value < 1024 or unit == "G":
            if not unit:
                return str(n)
            return f"{value:.1f}{unit}" if value < 10 else f"{value:.0f}{unit}"
        value /= 1024
    return str(n)


def _local_name(sh: Shell, url: str, directory: str, default: str = "index.html") -> str:
    name = posixpath.basename(_split(url).path) or default
    name = re.sub(r"[^A-Za-z0-9._@+-]", "_", name)[:100] or default
    path = posixpath.join(directory, name)
    n = 0
    while sh.fs.exists(path):
        n += 1
        path = posixpath.join(directory, f"{name}.{n}")
    return path


def _stamp(sh: Shell) -> str:
    import time

    t = time.gmtime(sh.now())
    return (
        f"{t.tm_year}-{t.tm_mon:02d}-{t.tm_mday:02d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"
    )


def _wait(sh: Shell, seconds: float) -> None:
    if sh.cfg.command_delay:
        sh.delay += seconds


def cmd_wget(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "OPTtUoeiw")
    urls = [_normalize_url(o) for o in operands][:MAX_URLS]
    if not urls:
        io.error(
            "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.\n"
        )
        return 1
    quiet = "q" in flags
    out_name = values.get("O")
    directory = sh.abspath(values["P"]) if "P" in values else sh.cwd
    status = 0
    for url in urls:
        _record(sh, url, "wget", io)
        parts = _split(url)
        try:
            host = parts.hostname or ""
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError:
            host, port = "", 80
        if not host_exists(host) and not _is_loopback(host):
            if not quiet:
                shown = host or url
                io.error(
                    f"--{_stamp(sh)}--  {url}\n"
                    f"Resolving {shown} ({shown})... failed: Name or service not known.\n"
                    f"wget: unable to resolve host address ‘{shown}’\n"
                )
            status = 4
            continue
        if _is_loopback(host):
            if not quiet:
                io.error(
                    f"--{_stamp(sh)}--  {url}\n"
                    f"Resolving {host} ({host})... 127.0.0.1\n"
                    f"Connecting to {host} ({host})|127.0.0.1|:{port}... "
                    "failed: Connection refused.\n"
                )
            status = 4
            continue
        dest_shown = out_name or posixpath.basename(parts.path) or "index.html"
        try:
            if out_name == "-":
                payload = payload_for(sh.profile.payload_key, url)
                dest_shown = "STDOUT"
            else:
                dest = sh.abspath(out_name) if out_name else _local_name(sh, url, directory)
                payload = _drop(sh, io, dest, url)
                dest_shown = posixpath.basename(dest)
            size = payload.size
        except FSError as exc:
            io.error(f"{dest_shown}: {exc}\n")
            status = 1
            continue
        ip = sh.profile.resolve(host)
        speed = f"{0.8 + sh.profile._num('wget-speed|' + url, 40) / 10:.1f}"
        if not quiet:
            io.error(
                f"--{_stamp(sh)}--  {url}\n"
                f"Resolving {host} ({host})... {ip}\n"
                f"Connecting to {host} ({host})|{ip}|:{port}... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: {size} ({_human(size)}) [{payload.mime}]\n"
                f"Saving to: ‘{dest_shown}’\n\n"
                f"{dest_shown:<24} 100%[===================>] {size:>5}  --.-KB/s    in 0s\n\n"
                f"{_stamp(sh)} ({speed} MB/s) - ‘{dest_shown}’ saved [{size}/{size}]\n\n"
            )
        _wait(sh, 1.0)
    return status


def cmd_curl(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "oHdXAmubeTx")
    urls = [_normalize_url(o) for o in operands if "." in o or "://" in o or "/" in o][:MAX_URLS]
    if not urls:
        io.error("curl: try 'curl --help' or 'curl --manual' for more information\n")
        return 2
    status = 0
    for url in urls:
        _record(sh, url, "curl", io)
        try:
            host = _split(url).hostname or ""
            port = _split(url).port or (443 if url.startswith("https") else 80)
        except ValueError:
            host, port = "", 80
        quiet = ("s" in flags or "silent" in flags) and "S" not in flags
        if not host_exists(host) and not _is_loopback(host):
            if not quiet:
                io.error(f"curl: (6) Could not resolve host: {host or url}\n")
            status = 6
            continue
        if _is_loopback(host):
            if not quiet:
                io.error(
                    f"curl: (7) Failed to connect to {host} port {port} after 0 ms: "
                    "Couldn't connect to server\n"
                )
            status = 7
            continue
        saves = "o" in values or "O" in flags or "remote-name" in flags
        if saves:
            try:
                dest = sh.abspath(values["o"]) if "o" in values else _local_name(sh, url, sh.cwd)
                size = _drop(sh, io, dest, url).size
            except FSError as exc:
                io.error(f"curl: (23) Failure writing output to destination: {exc}\n")
                status = 23
                continue
            if "s" not in flags and "silent" not in flags:
                io.error(
                    "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                    "                                 Dload  Upload   Total   Spent    Left  Speed\n"
                    f"100 {size:>5}  100 {size:>5}    0     0  {size * 7:>6}      0 --:--:-- --:--:-- --:--:-- {size * 7:>6}\n"
                )
        elif host in _IP_ECHO_HOSTS:
            io.write(sh.profile.public_ip + "\n")
        _wait(sh, 1.0)
    return status


def cmd_tftp(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "lrc")
    host = ""
    remote = values.get("r", "")
    if "c" in values and operands:  # tftp host -c get file
        host = operands[0] if values["c"] == "get" and len(operands) > 1 else operands[0]
        remote = remote or (operands[-1] if len(operands) > 1 else "")
        if values["c"] != "get":
            remote = operands[0]
    elif operands:
        host = operands[-1]
    elif io.args:
        host = io.args[0]
    if not host:
        io.error("usage: tftp [-h] [-g|-p] [-l FILE] [-r FILE] HOST [PORT]\n")
        return 1
    remote = remote or "file"
    url = f"tftp://{host}/{remote.lstrip('/')}"
    _record(sh, url, "tftp", io)
    local = values.get("l") or posixpath.basename(remote)
    try:
        _drop(sh, io, sh.abspath(local), url)
    except FSError as exc:
        io.error(f"tftp: can't open '{local}': {exc}\n")
        return 1
    _wait(sh, 1.0)
    return 0


def cmd_ftpget(sh: Shell, io: CmdIO) -> int:
    _, values, operands = parse_flags(io.args, "upPv")
    if len(operands) < 2:
        io.error("ftpget: short read\n")
        return 1
    host, local = operands[0], operands[1]
    remote = operands[2] if len(operands) > 2 else local
    url = f"ftp://{host}/{remote.lstrip('/')}"
    _record(sh, url, "ftpget", io)
    try:
        _drop(sh, io, sh.abspath(local), url)
    except FSError as exc:
        io.error(f"ftpget: can't open '{local}': {exc}\n")
        return 1
    _wait(sh, 1.0)
    return 0


def _is_remote_spec(arg: str) -> bool:
    """``[user@]host:path``: a colon before any slash or whitespace. Linear scan, no regex."""
    head, colon, _ = arg.partition(":")
    return bool(
        colon
        and head
        and not arg.startswith("-")
        and "/" not in head
        and not any(c.isspace() for c in head)
    )


def cmd_scp(sh: Shell, io: CmdIO) -> int:
    _, _, operands = parse_flags(io.args, "PiloFJS")
    remote = next((o for o in operands if _is_remote_spec(o)), "")
    if not remote:
        io.error(
            "usage: scp [-346ABCOpqRrsTvx] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
        )
        return 1
    host, _, path = remote.partition(":")
    from_remote = operands.index(remote) < len(operands) - 1
    if from_remote:
        _record(sh, f"scp://{host}/{path.lstrip('/')}", "scp", io)
    hostname = host.rpartition("@")[2]
    _wait(sh, 2.0)
    io.error(
        f"ssh: connect to host {hostname} port 22: Connection timed out\nscp: Connection closed\n"
    )
    return 255


def cmd_busybox(sh: Shell, io: CmdIO) -> int:
    from ssh_sensor.shell.commands import COMMANDS

    if not io.args:
        io.write(
            "BusyBox v1.36.1 (Ubuntu 1:1.36.1-6ubuntu3.1) multi-call binary.\n"
            "BusyBox is copyrighted by many authors between 1998-2015.\n"
            "Licensed under GPLv2. See source distribution for detailed\ncopyright notices.\n\n"
            "Usage: busybox [function [arguments]...]\n"
            "   or: busybox --list[-full]\n"
            "   or: function [arguments]...\n"
        )
        return 0
    applet = io.args[0]
    if applet in COMMANDS and applet != "busybox":
        return sh.run_argv(io.args, io)
    io.error(f"{applet}: applet not found\n")
    return 127


def cmd_sh(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "c")
    if "c" in values:
        text, status = sh.run_nested(values["c"], io.stdin, limit=io.room)
        io.write(text)
        return status
    if operands:
        try:
            from ssh_sensor.shell.util import read_text

            content = read_text(sh, sh.abspath(operands[0]))
        except FSError as exc:
            io.error(
                f"sh: 0: cannot open {operands[0]}: {exc}\n"
                if False
                else f"{io.cmdline.split()[0]}: {operands[0]}: {exc}\n"
            )
            return 127
        return sh.run_script(content, io)
    if io.stdin:
        return sh.run_script(io.stdin, io)
    return 0
