"""Static guard for the shared package: no code execution, no outbound connections of its own.

The Redis publisher is the one allowed network path: it goes through the ``redis`` client, which
this package never drives with a raw connect call.
"""

from __future__ import annotations

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "suckerpot_common"
BANNED_CALLS = {"eval", "exec", "compile", "breakpoint", "input"}
BANNED_OS = {"system", "popen", "fork", "forkpty", "startfile"}


def test_no_eval_or_exec() -> None:
    hits = []
    for path in sorted(PKG.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name) and fn.id in BANNED_CALLS:
                    hits.append(f"{path.name}:{node.lineno} {fn.id}()")
                if isinstance(fn, ast.Attribute) and fn.attr in BANNED_OS | {"eval", "exec"}:
                    hits.append(f"{path.name}:{node.lineno} .{fn.attr}()")
    assert hits == []


def test_no_file_writes() -> None:
    """The shared package never touches the filesystem: it only builds events and XADDs them."""
    markers = ("write_text(", "write_bytes(", "os.open(", "os.fdopen(", "open(")
    offenders = [
        f"{p.name}: {m}" for p in sorted(PKG.rglob("*.py")) for m in markers if m in p.read_text()
    ]
    assert offenders == []


def test_only_the_publisher_imports_redis() -> None:
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name == "publisher.py":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module]
            offenders += [f"{path.name} {m}" for m in mods if m.split(".")[0] == "redis"]
    assert offenders == []


# --- Shared hardening checks (the same block is in every sensor's test_static.py) ---------------
# AST based: process spawning in every flavour, dynamic imports and attribute indirection that
# would hide them, and any outbound connection primitive. Names are checked wherever they
# appear (called, passed to run_in_executor or functools.partial, assigned), not only when called.
_H_MODULES = {
    "subprocess", "_posixsubprocess", "asyncio.subprocess", "pty", "ctypes", "_ctypes",
    "builtins", "importlib", "posix", "pickle", "marshal", "runpy",
}  # fmt: skip
_H_SPAWN_ATTRS = {
    "create_subprocess_exec", "create_subprocess_shell", "subprocess_exec", "subprocess_shell",
    "import_module", "__import__", "system", "popen", "fork", "forkpty", "startfile",
}  # fmt: skip
_H_OS_PREFIXES = ("exec", "spawn", "posix_spawn")
_H_SPAWN_BASES = {"os", "posix", "subprocess", "asyncio"}
_H_INDIRECT_BASES = {"os", "posix", "builtins", "subprocess", "asyncio", "sys", "importlib"}
_H_OUT_MODULES = {
    "urllib.request", "urllib3", "http.client", "httpx", "requests", "aiohttp", "ftplib",
    "smtplib", "telnetlib", "poplib", "imaplib", "xmlrpc.client",
}  # fmt: skip
_H_OUT_ATTRS = {
    "open_connection", "open_unix_connection", "create_connection", "create_unix_connection",
    "connect", "connect_ex", "sock_connect", "getaddrinfo", "gethostbyname", "gethostbyaddr",
    "getnameinfo", "socketpair",
}  # fmt: skip
# Package-relative path of the one file that may connect (to 127.0.0.1, container healthcheck).
_H_OUT_EXEMPT = {"healthcheck.py"}


def _h_mod_hit(name: str, banned: set[str]) -> bool:
    return any(name == m or name.startswith(m + ".") for m in banned)


def _h_spawn_name(base: str, attr: str) -> bool:
    return (
        attr in _H_SPAWN_ATTRS
        or (base in ("os", "posix") and attr.startswith(_H_OS_PREFIXES))
        or (base == "asyncio" and attr == "subprocess")
    )


def _hardening_violations(root: Path = PKG, outbound: bool = False) -> list[str]:
    found: list[str] = []
    banned = _H_OUT_MODULES if outbound else _H_MODULES
    attrs = _H_OUT_ATTRS if outbound else _H_SPAWN_ATTRS
    for path in sorted(root.rglob("*.py")):
        if outbound and path.relative_to(root).as_posix() in _H_OUT_EXEMPT:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        aliases: dict[str, str] = {}  # local name -> module, for `import os as o`
        # local name -> (module, name) for `from module import name`
        imported: dict[str, tuple[str, str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    aliases[a.asname or a.name.split(".")[0]] = a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for a in node.names:
                    imported[a.asname or a.name] = (node.module, a.name)
        for node in ast.walk(tree):
            where = f"{path.name}:{getattr(node, 'lineno', 0)}"
            if isinstance(node, ast.Import):
                found += [
                    f"{where} import {a.name}" for a in node.names if _h_mod_hit(a.name, banned)
                ]
            elif isinstance(node, ast.ImportFrom) and node.module:
                if _h_mod_hit(node.module, banned):
                    found.append(f"{where} from {node.module}")
                for a in node.names:
                    mod = node.module.split(".")[0]
                    star = not outbound and a.name == "*" and mod in _H_SPAWN_BASES
                    spawn_os = not outbound and mod in _H_SPAWN_BASES and _h_spawn_name(mod, a.name)
                    if (
                        _h_mod_hit(f"{node.module}.{a.name}", banned)
                        or a.name in attrs
                        or spawn_os
                        or star
                    ):
                        found.append(f"{where} from {node.module} import {a.name}")
            elif isinstance(node, ast.Call):
                fn = node.func
                if (
                    outbound
                    and (getattr(fn, "attr", getattr(fn, "id", "")) == "create_datagram_endpoint")
                    and any(k.arg == "remote_addr" for k in node.keywords)
                ):
                    found.append(f"{where} create_datagram_endpoint(remote_addr=...)")
                if not outbound and isinstance(fn, ast.Name) and fn.id == "getattr" and node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Name) and first.id in _H_INDIRECT_BASES:
                        found.append(f"{where} getattr({first.id}, ...)")
                    if (
                        len(node.args) > 1
                        and isinstance(node.args[1], ast.Constant)
                        and node.args[1].value in _H_SPAWN_ATTRS
                    ):
                        found.append(f"{where} getattr(..., {node.args[1].value!r})")
            elif isinstance(node, ast.Attribute):
                base = node.value.id if isinstance(node.value, ast.Name) else ""
                base = aliases.get(base, base)
                if node.attr in attrs and base != "EventType":  # EventType.connect is an enum
                    found.append(f"{where} {base}.{node.attr}")
                elif not outbound and base in _H_SPAWN_BASES and _h_spawn_name(base, node.attr):
                    found.append(f"{where} {base}.{node.attr}")
                elif not outbound and node.attr in ("__builtins__", "__import__"):
                    found.append(f"{where} __builtins__/__import__ reference")
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                src = imported.get(node.id)
                if node.id in attrs:
                    found.append(f"{where} {node.id}")
                elif not outbound and node.id in ("__builtins__", "__import__"):
                    found.append(f"{where} __builtins__/__import__ reference")
                elif not outbound and src and src[0].split(".")[0] in _H_SPAWN_BASES:
                    if _h_spawn_name(src[0].split(".")[0], src[1]):
                        found.append(f"{where} {node.id} (from {src[0]} import {src[1]})")
    return found


def test_hardening_no_spawn_or_dynamic_import() -> None:
    assert _hardening_violations() == []


def test_hardening_no_outbound_connections() -> None:
    assert _hardening_violations(outbound=True) == []


def test_hardening_guard_detects_violations(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text(
        "import asyncio, functools, os, pty, ctypes, builtins\n"
        "import os as o\n"
        "from importlib import import_module\n"
        "async def f(loop, name, cmd):\n"
        "    await asyncio.create_subprocess_exec('x')\n"
        "    await asyncio.create_subprocess_shell('x')\n"
        "    await loop.subprocess_exec(None, 'x')\n"
        "    os.posix_spawnp('x', ['x'], {})\n"
        "    os.execvp('x', ['x'])\n"
        "    os.spawnl(0, 'x')\n"
        "    os.popen('x')\n"
        "    getattr(os, name)('x')\n"
        "    getattr(builtins, name)\n"
        "    __import__(name)\n"
        "    await loop.run_in_executor(None, os.system, cmd)\n"
        "    run = functools.partial(os.execv, '/bin/sh', ['sh'])\n"
        "    alias = o.fork\n"
    )
    spawn = _hardening_violations(tmp_path)
    for needle in (
        "import pty", "import ctypes", "import builtins", "from importlib",
        "create_subprocess_exec", "create_subprocess_shell", ".subprocess_exec",
        "os.posix_spawnp", "os.execvp", "os.spawnl", ".popen", "getattr(os",
        "getattr(builtins", "__import__", "os.system", "os.execv", "os.fork",
    ):  # fmt: skip
        assert any(needle in v for v in spawn), (needle, spawn)
    # A reference passed around is caught as well as a call.
    assert any(v.startswith("bad.py:15") and "os.system" in v for v in spawn)
    assert any(v.startswith("bad.py:16") and "os.execv" in v for v in spawn)
    (tmp_path / "bad.py").write_text(
        "from os import *\nexecv('/bin/sh', ['sh'])\n"
        "from os import execv as run\nrun('/bin/sh', ['sh'])\n"
    )
    star = _hardening_violations(tmp_path)
    assert any("import *" in v for v in star)
    assert any("run (from os import execv)" in v for v in star)
    (tmp_path / "bad.py").write_text(
        "import socket, urllib.request, http.client, httpx, requests, aiohttp\n"
        "import asyncssh\n"
        "async def f(loop, sock, addr):\n"
        "    await asyncio.open_connection('192.0.2.1', 1)\n"
        "    socket.create_connection(('192.0.2.1', 1))\n"
        "    socket.socket().connect(('192.0.2.1', 1))\n"
        "    await asyncssh.connect('192.0.2.1')\n"
        "    await asyncssh.create_connection(None, '192.0.2.1')\n"
        "    await loop.create_connection(None, '192.0.2.1', 1)\n"
        "    await loop.run_in_executor(None, sock.connect, addr)\n"
        "    socket.gethostbyaddr('192.0.2.1')\n"
        "    socket.getnameinfo(addr, 0)\n"
        "    await loop.create_datagram_endpoint(None, remote_addr=('192.0.2.1', 53))\n"
    )
    out = _hardening_violations(tmp_path, outbound=True)
    for needle in (
        "urllib.request", "http.client", "httpx", "requests", "aiohttp", ".open_connection",
        ".create_connection", ".connect", "gethostbyaddr", "getnameinfo", "remote_addr",
    ):  # fmt: skip
        assert any(needle in v for v in out), (needle, out)
    assert any(v.startswith("bad.py:10") and ".connect" in v for v in out)
    # Only the package-relative healthcheck.py is exempt, not one in a subfolder.
    sub = tmp_path / "sub"
    sub.mkdir()
    probe = "import socket\nsocket.create_connection(('127.0.0.1', 1))\n"
    (sub / "healthcheck.py").write_text(probe)
    (tmp_path / "bad.py").unlink()
    assert _hardening_violations(tmp_path, outbound=True) != []
    (tmp_path / "healthcheck.py").write_text(probe)
    (sub / "healthcheck.py").unlink()
    assert _hardening_violations(tmp_path, outbound=True) == []
