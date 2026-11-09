"""Static guard: the package must never contain code-execution or process-spawning primitives."""

from __future__ import annotations

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "rdp_sensor"
BANNED_CALLS = {"eval", "exec", "compile", "__import__", "breakpoint", "input"}
BANNED_MODULES = {
    "subprocess",
    "pickle",
    "cPickle",
    "marshal",
    "shelve",
    "ctypes",
    "pty",
    "code",
    "codeop",
    "multiprocessing",
    "runpy",
    "importlib",
    "dill",
    "cloudpickle",
    "shlex_exec",
}
BANNED_OS = {
    "system",
    "popen",
    "execv",
    "execve",
    "execl",
    "execle",
    "execlp",
    "execvp",
    "execvpe",
    "spawnl",
    "spawnv",
    "spawnlp",
    "spawnvp",
    "fork",
    "forkpty",
    "posix_spawn",
    "startfile",
}


def _violations(root: Path = PKG) -> list[str]:
    found: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            where = f"{path.relative_to(root)}:{getattr(node, 'lineno', 0)}"
            if isinstance(node, ast.Import):
                found += [
                    f"{where} import {a.name}"
                    for a in node.names
                    if a.name.split(".")[0] in BANNED_MODULES
                ]
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in BANNED_MODULES:
                    found.append(f"{where} from {node.module}")
                if node.module == "os":
                    found += [
                        f"{where} from os import {a.name}"
                        for a in node.names
                        if a.name in BANNED_OS
                    ]
            elif isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name) and fn.id in BANNED_CALLS:
                    found.append(f"{where} {fn.id}()")
                if isinstance(fn, ast.Attribute) and fn.attr in BANNED_OS | {"eval", "exec"}:
                    found.append(f"{where} .{fn.attr}()")
    return found


def test_no_code_execution_primitives() -> None:
    assert _violations() == []


def test_guard_detects_violations(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text(
        "import subprocess\nimport os\nos.system('x')\neval('1')\ncompile('1', '', 'eval')\n"
    )
    assert len(_violations(tmp_path)) == 4


def test_no_write_outside_data_path() -> None:
    """The only file writes are the identity files (secret, key, certificate) in identity.py."""
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name == "identity.py":
            continue
        text = path.read_text()
        for marker in ("write_text(", "write_bytes(", "os.open(", "os.fdopen(", "open("):
            if marker in text:
                offenders.append(f"{path.name}: {marker}")
    assert offenders == []


def test_no_network_clients() -> None:
    """The sensor never initiates connections (no fetching, no callbacks)."""
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name == "healthcheck.py":  # connects to 127.0.0.1 only
            continue
        text = path.read_text()
        for marker in (
            "open_connection(",
            "create_connection(",
            "urllib",
            "http.client",
            "requests",
        ):
            if marker in text:
                offenders.append(f"{path.name}: {marker}")
    assert offenders == []


def test_no_giveaways_in_package() -> None:
    for path in sorted(PKG.rglob("*.py")):
        text = path.read_text().lower()
        assert "honeypot" not in text, path
        assert "selfhostr" not in text, path


# --- Shared hardening checks (the same block is in every sensor's test_static.py) ---------------
# AST based: process spawning in every flavour, dynamic imports and attribute indirection that
# would hide them, and any outbound connection primitive.
_H_MODULES = {
    "subprocess", "_posixsubprocess", "asyncio.subprocess", "pty", "ctypes", "_ctypes",
    "builtins", "importlib", "posix", "pickle", "marshal", "runpy",
}  # fmt: skip
_H_SPAWN_ATTRS = {
    "create_subprocess_exec", "create_subprocess_shell", "subprocess_exec", "subprocess_shell",
    "import_module", "__import__", "system", "popen", "fork", "forkpty", "startfile",
}  # fmt: skip
_H_OS_PREFIXES = ("exec", "spawn", "posix_spawn")
_H_INDIRECT_BASES = {"os", "posix", "builtins", "subprocess", "asyncio", "sys", "importlib"}
_H_OUT_MODULES = {
    "urllib.request", "urllib3", "http.client", "httpx", "requests", "aiohttp", "ftplib",
    "smtplib", "telnetlib", "poplib", "imaplib", "xmlrpc.client",
}  # fmt: skip
_H_OUT_ATTRS = {
    "open_connection", "open_unix_connection", "create_connection", "create_unix_connection",
    "connect", "connect_ex", "sock_connect", "getaddrinfo", "gethostbyname", "socketpair",
}  # fmt: skip
_H_OUT_EXEMPT = {"healthcheck.py"}  # connects to 127.0.0.1 only, from the container healthcheck


def _h_mod_hit(name: str, banned: set[str]) -> bool:
    return any(name == m or name.startswith(m + ".") for m in banned)


def _hardening_violations(root: Path = PKG, outbound: bool = False) -> list[str]:
    found: list[str] = []
    banned = _H_OUT_MODULES if outbound else _H_MODULES
    attrs = _H_OUT_ATTRS if outbound else _H_SPAWN_ATTRS
    for path in sorted(root.rglob("*.py")):
        if outbound and path.name in _H_OUT_EXEMPT:
            continue
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            where = f"{path.name}:{getattr(node, 'lineno', 0)}"
            if isinstance(node, ast.Import):
                found += [
                    f"{where} import {a.name}" for a in node.names if _h_mod_hit(a.name, banned)
                ]
            elif isinstance(node, ast.ImportFrom) and node.module:
                if _h_mod_hit(node.module, banned):
                    found.append(f"{where} from {node.module}")
                for a in node.names:
                    spawn_os = (
                        not outbound
                        and node.module in ("os", "posix")
                        and a.name.startswith(_H_OS_PREFIXES)
                    )
                    if _h_mod_hit(f"{node.module}.{a.name}", banned) or a.name in attrs or spawn_os:
                        found.append(f"{where} from {node.module} import {a.name}")
            elif isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name):
                    if fn.id in attrs:
                        found.append(f"{where} {fn.id}()")
                    if not outbound and fn.id == "getattr" and node.args:
                        first = node.args[0]
                        if isinstance(first, ast.Name) and first.id in _H_INDIRECT_BASES:
                            found.append(f"{where} getattr({first.id}, ...)")
                        if (
                            len(node.args) > 1
                            and isinstance(node.args[1], ast.Constant)
                            and node.args[1].value in _H_SPAWN_ATTRS
                        ):
                            found.append(f"{where} getattr(..., {node.args[1].value!r})")
                elif isinstance(fn, ast.Attribute):
                    if fn.attr in attrs:
                        found.append(f"{where} .{fn.attr}()")
                    base = fn.value.id if isinstance(fn.value, ast.Name) else ""
                    if not outbound and base in ("os", "posix"):
                        if fn.attr.startswith(_H_OS_PREFIXES):
                            found.append(f"{where} {base}.{fn.attr}()")
            elif not outbound and isinstance(node, ast.Name | ast.Attribute):
                if getattr(node, "id", getattr(node, "attr", "")) in ("__builtins__", "__import__"):
                    found.append(f"{where} __builtins__/__import__ reference")
    return found


def test_hardening_no_spawn_or_dynamic_import() -> None:
    assert _hardening_violations() == []


def test_hardening_no_outbound_connections() -> None:
    assert _hardening_violations(outbound=True) == []


def test_hardening_guard_detects_violations(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text(
        "import asyncio, os, pty, ctypes, builtins\n"
        "from importlib import import_module\n"
        "async def f(loop, name):\n"
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
    )
    spawn = _hardening_violations(tmp_path)
    for needle in (
        "import pty", "import ctypes", "import builtins", "from importlib",
        "create_subprocess_exec", "create_subprocess_shell", ".subprocess_exec()",
        "os.posix_spawnp", "os.execvp", "os.spawnl", ".popen()", "getattr(os",
        "getattr(builtins", "__import__",
    ):  # fmt: skip
        assert any(needle in v for v in spawn), (needle, spawn)
    (tmp_path / "bad.py").write_text(
        "import socket, urllib.request, http.client, httpx, requests, aiohttp\n"
        "import asyncssh\n"
        "async def f(loop):\n"
        "    await asyncio.open_connection('192.0.2.1', 1)\n"
        "    socket.create_connection(('192.0.2.1', 1))\n"
        "    socket.socket().connect(('192.0.2.1', 1))\n"
        "    await asyncssh.connect('192.0.2.1')\n"
        "    await asyncssh.create_connection(None, '192.0.2.1')\n"
        "    await loop.create_connection(None, '192.0.2.1', 1)\n"
    )
    out = _hardening_violations(tmp_path, outbound=True)
    for needle in (
        "urllib.request", "http.client", "httpx", "requests", "aiohttp", ".open_connection()",
        ".create_connection()", ".connect()",
    ):  # fmt: skip
        assert any(needle in v for v in out), (needle, out)
