"""Static guarantees of the collector package (docs/dev/design/m21.md sections 3.3, 5.5 and 6.4).

An AST walk over the package source (calls and imports only, so comments may mention these names):

* no direct HTTP client or socket outside ``suckerpot_egress`` (invariant I3);
* nothing ever executes a file: no ``subprocess``, ``os.system``, ``os.exec*``, ``os.spawn*``,
  ``eval`` or ``exec``; the single allowed spawn is the analysis child in ``runner.py``;
* no ``chmod`` with an execute bit;
* the analyzer-side modules (store, runner, child, analyzer) import no HTTP or egress code.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parent.parent / "collector"

FORBIDDEN_CALLS = {
    "httpx.AsyncClient", "httpx.Client", "httpx.get", "httpx.post", "httpx.request",
    "httpx.stream", "socket.create_connection", "socket.socket", "socket.getaddrinfo",
    "socket.gethostbyname", "smtplib.SMTP", "smtplib.SMTP_SSL", "urllib.request.urlopen",
    "asyncio.open_connection", "asyncio.open_unix_connection",
    "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "os.system", "os.popen", "os.execv", "os.execve", "os.execl",
    "os.execlp", "os.execvp", "os.posix_spawn", "os.spawnl", "os.spawnv", "os.fork",
    "eval", "exec", "compile", "__import__", "ctypes.CDLL", "importlib.import_module",
}  # fmt: skip
FORBIDDEN_ATTRS = {
    "getaddrinfo", "create_connection", "open_connection", "create_subprocess_shell", "sock_connect",
}  # fmt: skip
FORBIDDEN_MODULES = {
    "urllib.request", "aiohttp", "requests", "urllib3", "http.client", "subprocess", "ctypes",
    "pickle", "marshal", "shelve",
}  # fmt: skip
# (relative path, dotted call): the one place a process is started.
ALLOW = {("runner.py", "asyncio.create_subprocess_exec")}
# These modules run in the no-network analyzer path and must not import any HTTP client.
OFFLINE_MODULES = {"store.py", "runner.py", "analysis_child.py", "analyzer.py", "validate.py"}
HTTP_MODULES = {"httpx", "suckerpot_egress", "socket", "ssl"}
CHMOD_CALLS = {"os.chmod", "os.fchmod", "os.lchmod", "Path.chmod"}


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _aliases(tree: ast.AST) -> dict[str, str]:
    """Local name to the dotted module path it stands for (``import httpx as h``, ``from m import n``)."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def _resolved(node: ast.AST, aliases: dict[str, str]) -> str:
    name = _dotted(node)
    head, _, rest = name.partition(".")
    if head in aliases:
        return aliases[head] + ("." + rest if rest else "")
    return name


def _has_exec_bit(node: ast.Call) -> bool:
    for arg in node.args[1:] or node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, int) and arg.value & 0o111:
            return True
    return False


def scan_source(source: str, rel: str = "<memory>") -> list[str]:
    problems: list[str] = []
    tree = ast.parse(source)
    aliases = _aliases(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _resolved(node.func, aliases)
            attr = name.rsplit(".", 1)[-1]
            if (name in FORBIDDEN_CALLS or attr in FORBIDDEN_ATTRS) and (rel, name) not in ALLOW:
                problems.append(f"{rel}:{node.lineno}: call to {name}")
            if name in CHMOD_CALLS and _has_exec_bit(node):
                problems.append(f"{rel}:{node.lineno}: chmod with an execute bit")
            if attr == "create_subprocess_exec" and (rel, name) not in ALLOW:
                problems.append(f"{rel}:{node.lineno}: process spawn")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if alias.name in FORBIDDEN_MODULES or top in FORBIDDEN_MODULES:
                    problems.append(f"{rel}:{node.lineno}: import {alias.name}")
                if rel in OFFLINE_MODULES and top in HTTP_MODULES:
                    problems.append(f"{rel}:{node.lineno}: network import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            top = mod.split(".")[0]
            if mod in FORBIDDEN_MODULES or top in FORBIDDEN_MODULES:
                problems.append(f"{rel}:{node.lineno}: import from {mod}")
            if rel in OFFLINE_MODULES and top in HTTP_MODULES:
                problems.append(f"{rel}:{node.lineno}: network import from {mod}")
    return problems


def test_package_is_clean() -> None:
    problems: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        problems += scan_source(path.read_text(encoding="utf-8"), str(path.relative_to(PACKAGE)))
    assert problems == []


def test_the_scan_fails_on_planted_violations() -> None:
    for bad in (
        "import httpx\nhttpx.AsyncClient()",
        "import socket\nsocket.create_connection(('x', 1))",
        "import subprocess\nsubprocess.run(['x'])",
        "import os\nos.system('x')",
        "eval('1')",
        "import os\nos.chmod('f', 0o755)",
        "import os\nos.fchmod(3, 0o500)",
        "import asyncio\nasyncio.create_subprocess_exec('x')",
        "import asyncio\nasyncio.create_subprocess_shell('x')",
        "import os\nos.execv('/x', [])",
        "from httpx import AsyncClient\nAsyncClient()",
        "import httpx as h\nh.AsyncClient()",
        "from socket import create_connection\ncreate_connection(('x', 1))",
        "import asyncio as a\na.open_connection('h', 1)",
        "from asyncio import open_connection\nopen_connection('h', 1)",
        "async def f(loop, s):\n    await loop.sock_connect(s, ('h', 1))",
        "from subprocess import run\nrun(['x'])",
        "from os import system\nsystem('x')",
        "import os as o\no.chmod('f', 0o755)",
    ):
        assert scan_source(bad, "evil.py"), bad
    assert scan_source("import httpx\n", "analyzer.py")  # offline module importing a client
    assert scan_source("import asyncio\nasyncio.create_subprocess_exec('x')", "runner.py") == []
    assert scan_source("import os\nos.fchmod(3, 0o400)", "store.py") == []


def test_every_python_file_is_scanned() -> None:
    names = {p.name for p in PACKAGE.rglob("*.py")}
    assert OFFLINE_MODULES <= names
    assert "service.py" in names


@pytest.mark.parametrize("module", sorted(OFFLINE_MODULES))
def test_offline_modules_exist(module: str) -> None:
    assert (PACKAGE / module).is_file()
