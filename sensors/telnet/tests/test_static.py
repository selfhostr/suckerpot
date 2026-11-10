"""Static guard: the package must never contain code-execution or process-spawning primitives."""

from __future__ import annotations

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "telnet_sensor"
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
    """The only writes are the profile secret file in secret.py."""
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name == "secret.py":
            continue
        text = path.read_text()
        for marker in ("write_text(", "write_bytes(", "os.open(", "os.fdopen(", "open("):
            if marker in text:
                offenders.append(f"{path.name}: {marker}")
    assert offenders == []


def test_product_name_never_appears_in_package() -> None:
    for path in sorted(PKG.rglob("*.py")):
        assert "selfhostr" not in path.read_text().lower(), path


# --- Shared hardening checks (the same block is in every sensor's test_static.py) ---------------
# AST based: process spawning in every flavour, dynamic imports and attribute indirection that
# would hide them, and any outbound connection primitive. Names are checked wherever they
# appear (called, passed to run_in_executor or functools.partial, assigned), on any base
# expression, not only when called on `os`.
_H_MODULES = {
    "subprocess", "_posixsubprocess", "asyncio.subprocess", "pty", "ctypes", "_ctypes",
    "builtins", "importlib", "posix", "pickle", "_pickle", "marshal", "runpy", "timeit",
    "pydoc", "code", "codeop",
}  # fmt: skip
_H_OS_EXEC = {  # every exec / spawn flavour of os and posix
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "posix_spawn", "posix_spawnp",
}  # fmt: skip
_H_SPAWN_ATTRS = {
    "create_subprocess_exec", "create_subprocess_shell", "subprocess_exec", "subprocess_shell",
    "import_module", "__import__", "system", "popen", "fork", "forkpty", "startfile",
    "resolve_name", "set_executable", *_H_OS_EXEC,
}  # fmt: skip
_H_SPAWN_BASES = {"os", "posix", "subprocess", "asyncio"}
# Modules whose attributes must not be reached through getattr / vars / __dict__.
_H_GETATTR_MODS = {
    "os", "posix", "subprocess", "socket", "asyncio", "ssl", "sys", "builtins", "importlib",
}  # fmt: skip
_H_OUT_MODULES = {
    "urllib.request", "urllib3", "http.client", "httpx", "requests", "aiohttp", "ftplib",
    "smtplib", "telnetlib", "poplib", "imaplib", "xmlrpc.client",
}  # fmt: skip
_H_OUT_ATTRS = {
    "open_connection", "open_unix_connection", "create_connection", "create_unix_connection",
    "connect", "connect_ex", "sock_connect", "getaddrinfo", "gethostbyname", "gethostbyaddr",
    "getnameinfo", "socketpair", "connect_reverse", "listen_reverse", "scp",
    "get_server_host_key",
}  # fmt: skip
# Package-relative path of the one file that may connect: the container healthcheck, to a
# literal loopback address only, and imported by no other module.
_H_OUT_EXEMPT = {"healthcheck.py"}
_H_LOOPBACK = ("127.0.0.1", "localhost")


def _h_mod_hit(name: str, banned: set[str]) -> bool:
    return any(name == m or name.startswith(m + ".") for m in banned)


def _h_top(expr: ast.expr, aliases: dict[str, str]) -> str:
    """Top-level module a name or dotted attribute chain refers to ('' if it is not one)."""
    while isinstance(expr, ast.Attribute):
        expr = expr.value
    return aliases.get(expr.id, "") if isinstance(expr, ast.Name) else ""


def _h_eventtype_ok(tree: ast.Module) -> bool:
    """True when `EventType` is bound exactly once in the file, by the real enum (imported from
    suckerpot_common or defined as an Enum class): `EventType.connect` is then an enum member."""
    good = bad = 0
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and n.id == "EventType" and not isinstance(n.ctx, ast.Load):
            bad += 1
        elif isinstance(n, ast.arg) and n.arg == "EventType":
            bad += 1
        elif isinstance(n, ast.ExceptHandler) and n.name == "EventType":
            bad += 1
        elif isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == "EventType":
            bad += 1
        elif isinstance(n, ast.ClassDef) and n.name == "EventType":
            enum = any(getattr(b, "id", "") in ("StrEnum", "Enum") for b in n.bases)
            good, bad = (good + 1, bad) if enum and n in tree.body else (good, bad + 1)
        elif isinstance(n, ast.Import):
            bad += sum((a.asname or a.name.split(".")[0]) == "EventType" for a in n.names)
        elif isinstance(n, ast.ImportFrom):
            for a in n.names:
                if (a.asname or a.name) != "EventType":
                    continue
                real = n.level == 0 and a.name == "EventType" and a.asname in (None, "EventType")
                if real and (n.module or "").split(".")[0] == "suckerpot_common":
                    good += 1
                else:
                    bad += 1
    return good == 1 and bad == 0


def _h_health_violations(tree: ast.Module, name: str) -> list[str]:
    """The healthcheck may connect, but only to a literal loopback address."""
    found: list[str] = []
    called = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    net = _H_OUT_ATTRS | {"sendto"}
    for n in ast.walk(tree):
        where = f"{name}:{getattr(n, 'lineno', 0)}"
        if isinstance(n, ast.Attribute) and n.attr in net and id(n) not in called:
            found.append(f"{where} {ast.unparse(n)} (reference, not a call)")
        elif isinstance(n, ast.Call):
            fn = n.func
            attr = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if attr not in net:
                continue
            at = 1 if attr == "sendto" else 0
            arg = n.args[at] if len(n.args) > at else None
            if isinstance(arg, ast.Tuple) and arg.elts:
                arg = arg.elts[0]
            if not (isinstance(arg, ast.Constant) and arg.value in _H_LOOPBACK):
                found.append(f"{where} {attr}() target is not a literal loopback address")
    return found


def _hardening_violations(root: Path = PKG, outbound: bool = False) -> list[str]:
    found: list[str] = []
    banned = _H_OUT_MODULES if outbound else _H_MODULES
    attrs = _H_OUT_ATTRS if outbound else _H_SPAWN_ATTRS
    dunder = ("__builtins__", "__import__")
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        tree = ast.parse(path.read_text(), filename=str(path))
        if outbound and rel in _H_OUT_EXEMPT:
            found += _h_health_violations(tree, rel)
            continue
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
        evt_ok = _h_eventtype_ok(tree)
        called = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
        for node in ast.walk(tree):
            where = f"{path.name}:{getattr(node, 'lineno', 0)}"
            if isinstance(node, ast.Import):
                found += [
                    f"{where} import {a.name}" for a in node.names if _h_mod_hit(a.name, banned)
                ]
                if outbound:
                    found += [
                        f"{where} import {a.name} (the healthcheck is imported nowhere)"
                        for a in node.names
                        if a.name.split(".")[-1] == "healthcheck"
                    ]
            elif isinstance(node, ast.ImportFrom):
                modname = node.module or ""  # empty for `from . import name`
                if _h_mod_hit(modname, banned):
                    found.append(f"{where} from {modname}")
                mod = modname.split(".")[0]
                for a in node.names:
                    star = (
                        not outbound and a.name == "*" and mod in _H_SPAWN_BASES | _H_GETATTR_MODS
                    )
                    sysmod = not outbound and mod == "sys" and a.name == "modules"
                    health = outbound and "healthcheck" in (modname.split(".")[-1], a.name)
                    if (
                        _h_mod_hit(f"{modname}.{a.name}", banned)
                        or a.name in attrs
                        or star
                        or sysmod
                        or health
                    ):
                        found.append(f"{where} from {modname} import {a.name}")
            elif isinstance(node, ast.Call):
                fn = node.func
                fname = getattr(fn, "attr", getattr(fn, "id", ""))
                if outbound:
                    if fname == "create_datagram_endpoint" and any(
                        k.arg == "remote_addr" for k in node.keywords
                    ):
                        found.append(f"{where} create_datagram_endpoint(remote_addr=...)")
                    continue
                if isinstance(fn, ast.Name) and fn.id in ("getattr", "vars") and node.args:
                    top = _h_top(node.args[0], aliases)
                    first = node.args[0]
                    direct = isinstance(first, ast.Name) and first.id in _H_GETATTR_MODS
                    if fn.id == "vars":
                        mods = _H_GETATTR_MODS | {m.split(".")[0] for m in _H_MODULES}
                        if top in mods or direct:
                            found.append(f"{where} vars({ast.unparse(first)})")
                        continue
                    name_arg = node.args[1] if len(node.args) > 1 else None
                    const = (
                        name_arg.value
                        if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str)
                        else None
                    )
                    if const in _H_SPAWN_ATTRS | _H_OUT_ATTRS:
                        found.append(f"{where} getattr(..., {const!r})")
                    elif (top in _H_GETATTR_MODS or direct) and const is None:
                        found.append(f"{where} getattr({ast.unparse(first)}, <not a constant>)")
                imp = imported.get(fn.id) if isinstance(fn, ast.Name) else None
                from_op = imp is not None and imp[0] == "operator"
                via_attr = isinstance(fn, ast.Attribute) and _h_top(fn.value, aliases) == "operator"
                is_op = (fname in ("attrgetter", "methodcaller") and via_attr) or (
                    from_op and imp is not None and imp[1] in ("attrgetter", "methodcaller")
                )
                if is_op:
                    for arg in node.args:
                        text = arg.value if isinstance(arg, ast.Constant) else None
                        if not isinstance(text, str) or any(
                            part in _H_SPAWN_ATTRS | _H_OUT_ATTRS for part in text.split(".")
                        ):
                            found.append(f"{where} operator.{fname}({ast.unparse(arg)})")
            elif isinstance(node, ast.Attribute):
                top = _h_top(node.value, aliases)
                base = ast.unparse(node.value)
                if node.attr in attrs and not (base == "EventType" and evt_ok):
                    found.append(f"{where} {ast.unparse(node)}")
                elif not outbound:
                    if node.attr == "modules" and top == "sys":
                        found.append(f"{where} sys.modules")
                    elif node.attr == "__dict__" and (
                        top in _H_GETATTR_MODS | {m.split(".")[0] for m in _H_MODULES}
                    ):
                        found.append(f"{where} {base}.__dict__")
                    elif node.attr in dunder or (top == "asyncio" and node.attr == "subprocess"):
                        found.append(f"{where} {ast.unparse(node)}")
            elif isinstance(node, ast.Name):
                src = imported.get(node.id)
                if not outbound and node.id in dunder:  # any context: load, store, delete
                    found.append(f"{where} {node.id}")
                elif isinstance(node.ctx, ast.Load) and node.id in attrs and id(node) not in called:
                    found.append(f"{where} {node.id}")
                elif isinstance(node.ctx, ast.Load) and node.id in attrs:
                    found.append(f"{where} {node.id}()")
                elif isinstance(node.ctx, ast.Load) and src and src[1] in attrs:
                    found.append(f"{where} {node.id} (from {src[0]} import {src[1]})")
    return found


def test_hardening_no_spawn_or_dynamic_import() -> None:
    assert _hardening_violations() == []


def test_hardening_no_outbound_connections() -> None:
    assert _hardening_violations(outbound=True) == []


def _h_case(tmp_path: Path, files: dict[str, str], outbound: bool = False) -> list[str]:
    case = tmp_path / f"case{len(list(tmp_path.iterdir()))}"
    for name, text in files.items():
        (case / name).parent.mkdir(parents=True, exist_ok=True)
        (case / name).write_text(text)
    return _hardening_violations(case, outbound=outbound)


def test_hardening_guard_detects_spawn_and_import_bypasses(tmp_path: Path) -> None:
    bad = [
        ("import pty", "import pty"), ("import ctypes", "import ctypes"),
        ("import builtins", "import builtins"), ("import timeit", "import timeit"),
        ("import _pickle", "import _pickle"), ("import pydoc", "import pydoc"),
        ("import runpy", "import runpy"), ("import code", "import code"),
        ("import codeop", "import codeop"), ("from importlib import import_module", "importlib"),
        ("import asyncio\nasyncio.create_subprocess_exec('x')", "create_subprocess_exec"),
        ("import asyncio\nasyncio.create_subprocess_shell('x')", "create_subprocess_shell"),
        ("loop.subprocess_exec(None, 'x')", "subprocess_exec"),
        ("import os\nos.posix_spawnp('x', ['x'], {})", "posix_spawnp"),
        ("import os\nos.execvp('x', ['x'])", "execvp"),
        ("import os\nos.spawnl(0, 'x')", "spawnl"), ("import os\nos.popen('x')", "popen"),
        ("import os\ngetattr(os, name)('x')", "getattr(os"),
        ("import builtins\ngetattr(builtins, name)", "getattr(builtins"),
        ("__import__(name)", "__import__"),
        ("import os\nloop.run_in_executor(None, os.system, cmd)", "os.system"),
        ("import os, functools\nfunctools.partial(os.execv, '/bin/sh', ['sh'])", "os.execv"),
        ("import os as o\nalias = o.fork", "o.fork"),
        ("from os import *\nexecv('/bin/sh', ['sh'])", "import *"),
        ("from os import execv as run\nrun('/bin/sh', ['sh'])", "run (from os import execv)"),
        # getattr through an import alias or a computed name
        ("import os as o\ngetattr(o, n)", "getattr(o"),
        ("import socket\ngetattr(socket, 'conn' + 'ect')", "getattr(socket"),
        ("import ssl\ngetattr(ssl, n)", "getattr(ssl"),
        ("import sys\ngetattr(sys, n)", "getattr(sys"),
        ("import subprocess as sp\ngetattr(sp, n)", "getattr(sp"),
        ("x = getattr(thing, 'system')", "getattr(..., 'system')"),
        # exec / spawn on any base, and sys.modules
        ("import shutil\nshutil.os.execv('x', ['x'])", "shutil.os.execv"),
        ("import sys\nsys.modules['os'].posix_spawnp('x', ['x'], {})", "sys.modules"),
        ("from sys import modules", "from sys import modules"),
        ("anything.spawnvpe(0, 'x', ['x'], {})", "spawnvpe"),
        # other ways to reach banned things
        ("import pkgutil\npkgutil.resolve_name('os:system')", "resolve_name"),
        ("import operator\noperator.attrgetter(name)", "operator.attrgetter"),
        ("import operator\noperator.methodcaller('system', 'x')", "operator.methodcaller"),
        ("from operator import attrgetter as ag\nag(name)", "operator.ag"),
        ("import multiprocessing\nmultiprocessing.set_executable(x)", "set_executable"),
        ("import os\nvars(os)", "vars(os)"), ("import os\nx = os.__dict__", "os.__dict__"),
        ("import builtins as b\nx = b.__dict__", "b.__dict__"),
        # the dunder names in every context
        ("__builtins__ = {}", "__builtins__"), ("del __import__", "__import__"),
        ("print(__builtins__)", "__builtins__"),
    ]  # fmt: skip
    for source, needle in bad:
        hits = _h_case(tmp_path, {"bad.py": source + "\n"})
        assert any(needle in v for v in hits), (source, hits)
    good = [
        "import socket\nx = getattr(socket, 'AF_INET')",
        "import operator\nf = operator.attrgetter('a.b')",
        "import os\nx = os.environ",
        "from suckerpot_common.models import EventType\nx = EventType.disconnect",
    ]
    for source in good:
        assert _h_case(tmp_path, {"ok.py": source + "\n"}) == [], source


def test_hardening_guard_detects_outbound_bypasses(tmp_path: Path) -> None:
    ev = "from suckerpot_common.models import EventType\n"
    bad = [
        ("import socket, urllib.request, http.client, httpx, requests, aiohttp", "urllib.request"),
        ("import http.client", "http.client"), ("import httpx", "httpx"),
        ("import requests", "requests"), ("import aiohttp", "aiohttp"),
        ("asyncio.open_connection('192.0.2.1', 1)", ".open_connection"),
        ("socket.create_connection(('192.0.2.1', 1))", ".create_connection"),
        ("socket.socket().connect(('192.0.2.1', 1))", ".connect"),
        ("await loop.run_in_executor(None, sock.connect, addr)", "sock.connect"),
        ("socket.gethostbyaddr('192.0.2.1')", "gethostbyaddr"),
        ("socket.getnameinfo(addr, 0)", "getnameinfo"),
        ("loop.create_datagram_endpoint(None, remote_addr=('192.0.2.1', 53))", "remote_addr"),
        # asyncssh client entry points
        ("import asyncssh\nasyncssh.connect('192.0.2.1')", "asyncssh.connect"),
        ("import asyncssh\nasyncssh.create_connection(None, '192.0.2.1')", "create_connection"),
        ("import asyncssh\nasyncssh.connect_reverse('192.0.2.1')", "connect_reverse"),
        ("import asyncssh\nasyncssh.listen_reverse()", "listen_reverse"),
        ("import asyncssh\nasyncssh.scp('a', 'b')", "asyncssh.scp"),
        ("import asyncssh\nasyncssh.get_server_host_key('192.0.2.1')", "get_server_host_key"),
        # EventType is only exempt when it is the real enum, bound once
        ("from socket import socket as EventType\nEventType.connect(s, addr)", "EventType.connect"),
        ("from socket import socket\nEventType = socket\nEventType.connect(s)", "Type.connect"),
        (ev + "EventType = sock\nEventType.connect(a)", "EventType.connect"),
        (ev + "for EventType in socks:\n    EventType.connect(a)", "EventType.connect"),
        (ev + "def f(EventType):\n    EventType.connect(a)", "EventType.connect"),
        (ev + "import socket as EventType\nEventType.connect(a)", "EventType.connect"),
        ("from other import EventType\nEventType.connect(a)", "EventType.connect"),
    ]  # fmt: skip
    for source, needle in bad:
        hits = _h_case(tmp_path, {"bad.py": source + "\n"}, outbound=True)
        assert any(needle in v for v in hits), (source, hits)
    real = "from suckerpot_common.models import EventType\nx = EventType.connect\n"
    assert _h_case(tmp_path, {"ok.py": real}, outbound=True) == []


def test_hardening_guard_pins_the_healthcheck(tmp_path: Path) -> None:
    probe = "import socket\nsocket.create_connection(('127.0.0.1', 1))\n"
    # Only the package-relative healthcheck.py may connect, not one in a subfolder.
    assert _h_case(tmp_path, {"healthcheck.py": probe}, outbound=True) == []
    assert _h_case(tmp_path, {"sub/healthcheck.py": probe}, outbound=True) != []
    # Its targets must be literal loopback addresses.
    host = "import socket\nsocket.create_connection((host, 1))\n"
    assert _h_case(tmp_path, {"healthcheck.py": host}, outbound=True) != []
    elsewhere = "import socket\nsocket.create_connection(('192.0.2.1', 1))\n"
    assert _h_case(tmp_path, {"healthcheck.py": elsewhere}, outbound=True) != []
    udp = "sock.sendto(b'x', ('127.0.0.1', 9))\nsock.connect = sock.connect\n"
    assert _h_case(tmp_path, {"healthcheck.py": udp}, outbound=True) != []
    assert (
        _h_case(tmp_path, {"healthcheck.py": "sock.sendto(b'x', ('localhost', 9))\n"}, True) == []
    )
    # No other module may import it.
    for imp in (
        "import healthcheck",
        "from . import healthcheck",
        "from pkg.healthcheck import main",
    ):
        files = {"healthcheck.py": probe, "other.py": imp + "\n"}
        assert any(v.startswith("other.py") for v in _h_case(tmp_path, files, outbound=True)), imp
