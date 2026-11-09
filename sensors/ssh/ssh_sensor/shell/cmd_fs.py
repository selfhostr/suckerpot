"""Filesystem commands: ls, cd, cat, mkdir, rm, ..."""

from __future__ import annotations

import posixpath
import re

from ssh_sensor.shell.core import CmdIO, parse_flags
from ssh_sensor.shell.fs import FSError, Node
from ssh_sensor.shell.interp import Shell
from ssh_sensor.shell.util import (
    can_access,
    iter_lines,
    ls_date,
    mode_string,
    read_text,
    write_lines,
)

_OCTAL = re.compile(r"^[0-7]{3,4}$")
_SYMBOLIC = re.compile(r"^([ugoa]*)([-+=])([rwxXst]*)$")


def _err(sh: Shell, io: CmdIO, cmd: str, name: str, msg: str) -> None:
    io.error(f"{cmd}: {name}: {msg}\n")


Row = tuple[str, str, str, str, str, str, str]


def _long_row(sh: Shell, name: str, node: Node, human: bool) -> Row:
    size = 4096 if node.kind == "d" else node.length
    if node.kind == "l":
        size = len(node.target)
    shown = f"{name} -> {node.target}" if node.kind == "l" else name
    links = 2 if node.kind == "d" else 1
    return (
        mode_string(node),
        str(links),
        node.owner,
        node.group,
        _human(size) if human else str(size),
        ls_date(node.mtime, sh.now()),
        shown,
    )


def _format_rows(rows: list[Row]) -> list[str]:
    """Pad columns to the widest entry, like ls does."""
    if not rows:
        return []
    w_links = max(len(r[1]) for r in rows)
    w_owner = max(len(r[2]) for r in rows)
    w_group = max(len(r[3]) for r in rows)
    w_size = max(len(r[4]) for r in rows)
    return [
        f"{m} {ln:>{w_links}} {o:<{w_owner}} {g:<{w_group}} {sz:>{w_size}} {d} {n}"
        for m, ln, o, g, sz, d, n in rows
    ]


def _human(size: int) -> str:
    value = float(size)
    for unit in ("", "K", "M", "G"):
        if value < 1024:
            return f"{value:.0f}{unit}" if value >= 10 or not unit else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}T"


def _columns(names: list[str], width: int = 80) -> str:
    if not names:
        return ""
    col = max(len(n) for n in names) + 2
    ncols = max(1, width // col)
    nrows = -(-len(names) // ncols)
    rows = []
    for r in range(nrows):
        cells = [names[r + c * nrows] for c in range(ncols) if r + c * nrows < len(names)]
        rows.append("".join(c.ljust(col) for c in cells[:-1]) + cells[-1])
    return "\n".join(rows) + "\n"


def cmd_ls(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args)
    long = "l" in flags
    show_all = "a" in flags
    almost = "A" in flags
    human = "h" in flags
    one = "1" in flags or io.piped_out or not sh.tty
    status = 0
    targets = operands or ["."]
    files: list[tuple[str, Node]] = []
    dirs: list[tuple[str, str]] = []
    for target in targets:
        try:
            path = sh.abspath(target)
        except FSError as exc:
            io.error(f"ls: cannot access '{target}': {exc}\n")
            status = 2
            continue
        node = sh.fs.stat(path)
        if node is None:
            io.error(f"ls: cannot access '{target}': No such file or directory\n")
            status = 2
        elif node.kind == "d" and "d" not in flags:
            dirs.append((target, path))
        else:
            files.append((target, node))
    chunks: list[str] = []
    if files:
        if long:
            chunks.append(
                "\n".join(_format_rows([_long_row(sh, n, nd, human) for n, nd in files])) + "\n"
            )
        else:
            chunks.append(
                ("\n".join(n for n, _ in files) + "\n") if one else _columns([n for n, _ in files])
            )
    multi = len(targets) > 1
    for target, path in dirs:
        node = sh.fs.stat(path)
        assert node is not None
        if not can_access(sh, node, "r"):
            io.error(f"ls: cannot open directory '{target}': Permission denied\n")
            status = 2
            continue
        names = sorted(sh.fs.listdir(path), key=lambda n: (n.lstrip(".").lower(), n))
        if not (show_all or almost):
            names = [n for n in names if not n.startswith(".")]
        header = f"{target}:\n" if multi else ""
        if long:
            rows = []
            blocks = 0
            entries = (
                [(".", node), ("..", sh.fs.stat(posixpath.dirname(path)) or node)]
                if show_all
                else []
            )
            for n in names:
                child = sh.fs.stat(posixpath.join(path, n))
                if child is not None:
                    entries.append((n, child))
            for n, child in entries:
                blocks += 4 * (-(-(child.length) // 4096) if child.kind == "f" else 1)
                rows.append(_long_row(sh, n, child, human))
            chunks.append(
                header
                + f"total {blocks}\n"
                + "\n".join(_format_rows(rows))
                + ("\n" if rows else "")
            )
        else:
            listing = ([".", ".."] + names) if show_all else names
            body = ("\n".join(listing) + "\n" if listing else "") if one else _columns(listing)
            chunks.append(header + body)
    io.write("\n".join(chunks))
    return status


def cmd_cd(sh: Shell, io: CmdIO) -> int:
    target = io.args[0] if io.args else sh.env.get("HOME", "/")
    if target == "-":
        target = sh.prev_cwd
        io.write(target + "\n")
    elif target.startswith("~"):
        target = sh.env.get("HOME", "/") + target[1:]
    try:
        path = sh.abspath(target)
    except FSError as exc:
        io.error(f"{sh.error_prefix()}cd: {target}: {exc}\n")
        return 1
    node = sh.fs.stat(path)
    if node is None:
        io.error(f"{sh.error_prefix()}cd: {target}: No such file or directory\n")
        return 1
    if node.kind != "d":
        io.error(f"{sh.error_prefix()}cd: {target}: Not a directory\n")
        return 1
    if not can_access(sh, node, "x"):
        io.error(f"{sh.error_prefix()}cd: {target}: Permission denied\n")
        return 1
    sh.prev_cwd = sh.cwd
    sh.cwd = path
    sh.env["PWD"] = path
    return 0


def cmd_pwd(sh: Shell, io: CmdIO) -> int:
    io.write(sh.cwd + "\n")
    return 0


def cmd_cat(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args)
    status = 0
    if not operands:
        operands = ["-"]
    for name in operands:
        if name == "-":
            text = io.stdin or ""
        else:
            try:
                text = read_text(sh, sh.abspath(name))
            except FSError as exc:
                io.error(f"cat: {name}: {exc}\n")
                status = 1
                continue
        if io.full:
            break
        if "n" in flags:
            # numbered line by line, stopping at the output budget (never a whole copy)
            write_lines(io, (f"{i:>6}\t{line}" for i, line in enumerate(iter_lines(text), 1)))
        else:
            io.write(text[: io.room])
    return status


def cmd_mkdir(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args, "m")
    if not operands:
        io.error("mkdir: missing operand\n")
        return 1
    status = 0
    for name in operands:
        try:
            path = sh.abspath(name)
            if not sh.fs.may_write(path, sh.user.name, sh.user.home):
                raise FSError("Permission denied")
            if "p" in flags:
                parts = [p for p in path.split("/") if p]
                built = ""
                for part in parts:
                    built += "/" + part
                    if not sh.fs.exists(built):
                        sh.fs.mkdir(built, sh.user.name)
            else:
                sh.fs.mkdir(path, sh.user.name)
        except FSError as exc:
            io.error(f"mkdir: cannot create directory '{name}': {exc}\n")
            status = 1
    return status


def cmd_touch(sh: Shell, io: CmdIO) -> int:
    _, _, operands = parse_flags(io.args)
    status = 0
    for name in operands:
        try:
            path = sh.abspath(name)
            if not sh.fs.may_write(path, sh.user.name, sh.user.home):
                raise FSError("Permission denied")
            sh.fs.touch(path, sh.user.name)
        except FSError as exc:
            io.error(f"touch: cannot touch '{name}': {exc}\n")
            status = 1
    return status


def cmd_rm(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args)
    recursive = bool(flags & {"r", "R", "recursive"})
    force = "f" in flags or "force" in flags
    if not operands and not force:
        io.error("rm: missing operand\n")
        return 1
    status = 0
    for name in operands:
        try:
            path = sh.abspath(name)
            node = sh.fs.stat(path)
            if node is None:
                if not force:
                    io.error(f"rm: cannot remove '{name}': No such file or directory\n")
                    status = 1
                continue
            if path == "/" and recursive:
                io.error("rm: it is dangerous to operate recursively on '/'\n")
                io.error("rm: use --no-preserve-root to override this failsafe\n")
                status = 1
                continue
            if not sh.fs.may_write(path, sh.user.name, sh.user.home):
                raise FSError("Permission denied")
            if node.kind == "d":
                if not recursive:
                    io.error(f"rm: cannot remove '{name}': Is a directory\n")
                    status = 1
                    continue
                sh.fs.remove_tree(path)
            else:
                sh.fs.remove(path)
        except FSError as exc:
            if not force:
                io.error(f"rm: cannot remove '{name}': {exc}\n")
                status = 1
    return status


def cmd_rmdir(sh: Shell, io: CmdIO) -> int:
    status = 0
    for name in parse_flags(io.args)[2]:
        try:
            path = sh.abspath(name)
            if not sh.fs.is_dir(path):
                raise FSError(
                    "Not a directory" if sh.fs.exists(path) else "No such file or directory"
                )
            sh.fs.remove(path)
        except FSError as exc:
            io.error(f"rmdir: failed to remove '{name}': {exc}\n")
            status = 1
    return status


def _apply_mode(node: Node, spec: str) -> int | None:
    if _OCTAL.match(spec):
        return int(spec, 8)
    mode = node.mode
    for clause in spec.split(","):
        m = _SYMBOLIC.match(clause)
        if not m:
            return None
        who, op, perms = m.groups()
        who = who or "a"
        bits = 0
        for ch, val in (("r", 4), ("w", 2), ("x", 1), ("X", 1)):
            if ch in perms:
                bits |= val
        mask = 0
        for w, shift in (("u", 6), ("g", 3), ("o", 0)):
            if w in who or "a" in who:
                mask |= bits << shift
        if op == "+":
            mode |= mask
        elif op == "-":
            mode &= ~mask
        else:
            mode = (mode & ~0o777) | mask
    return mode


def cmd_chmod(sh: Shell, io: CmdIO) -> int:
    _, _, operands = parse_flags(io.args)
    if len(operands) < 2:
        io.error("chmod: missing operand\n")
        return 1
    spec, names = operands[0], operands[1:]
    status = 0
    for name in names:
        try:
            path = sh.abspath(name)
            node = sh.fs.stat(path)
            if node is None:
                raise FSError("No such file or directory")
            if not sh.is_root and node.owner != sh.user.name:
                io.error(f"chmod: changing permissions of '{name}': Operation not permitted\n")
                status = 1
                continue
            new = _apply_mode(node, spec)
            if new is None:
                io.error(f"chmod: invalid mode: '{spec}'\n")
                return 1
            sh.fs.chmod(path, new)
        except FSError as exc:
            io.error(f"chmod: cannot access '{name}': {exc}\n")
            status = 1
    return status


def cmd_chown(sh: Shell, io: CmdIO) -> int:
    _, _, operands = parse_flags(io.args)
    if len(operands) < 2:
        io.error("chown: missing operand\n")
        return 1
    if not sh.is_root:
        io.error(f"chown: changing ownership of '{operands[1]}': Operation not permitted\n")
        return 1
    return 0


def cmd_mv(sh: Shell, io: CmdIO) -> int:
    _, _, operands = parse_flags(io.args)
    if len(operands) < 2:
        io.error("mv: missing file operand\n")
        return 1
    return _transfer(sh, io, "mv", operands)


def cmd_cp(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args)
    if len(operands) < 2:
        io.error("cp: missing file operand\n")
        return 1
    return _transfer(sh, io, "cp", operands, recursive=bool(flags & {"r", "R", "a"}))


def _transfer(sh: Shell, io: CmdIO, cmd: str, operands: list[str], recursive: bool = False) -> int:
    *sources, dest = operands
    status = 0
    try:
        dest_path = sh.abspath(dest)
    except FSError as exc:
        io.error(f"{cmd}: cannot stat '{dest}': {exc}\n")
        return 1
    dest_is_dir = sh.fs.is_dir(dest_path)
    if len(sources) > 1 and not dest_is_dir:
        io.error(f"{cmd}: target '{dest}' is not a directory\n")
        return 1
    for src in sources:
        try:
            src_path = sh.abspath(src)
            node = sh.fs.stat(src_path)
            if node is None:
                io.error(f"{cmd}: cannot stat '{src}': No such file or directory\n")
                status = 1
                continue
            if node.kind == "d" and not (cmd == "cp" and recursive):
                io.error(
                    f"{cmd}: -r not specified; omitting directory '{src}'\n"
                    if cmd == "cp"
                    else f"{cmd}: cannot move '{src}': Operation not permitted\n"
                )
                status = 1
                continue
            target = (
                posixpath.join(dest_path, posixpath.basename(src_path))
                if dest_is_dir
                else dest_path
            )
            if not sh.fs.may_write(target, sh.user.name, sh.user.home):
                raise FSError("Permission denied")
            if node.kind == "d":
                continue
            if cmd == "cp":
                sh.fs.copy(src_path, target, sh.user.name)
            else:
                sh.fs.rename(src_path, target)
        except FSError as exc:
            io.error(
                f"{cmd}: cannot {'create regular file' if cmd == 'cp' else 'move'} '{dest}': {exc}\n"
            )
            status = 1
    return status


def cmd_stat(sh: Shell, io: CmdIO) -> int:
    status = 0
    for name in parse_flags(io.args)[2]:
        try:
            path = sh.abspath(name)
        except FSError:
            continue
        node = sh.fs.stat(path)
        if node is None:
            io.error(f"stat: cannot statx '{name}': No such file or directory\n")
            status = 1
            continue
        size = 4096 if node.kind == "d" else node.length
        kind = {"d": "directory", "l": "symbolic link"}.get(node.kind, "regular file")
        io.write(
            f"  File: {name}\n  Size: {size:<10}\tBlocks: {-(-size // 512):<10} IO Block: 4096   {kind}\n"
            f"Access: ({node.mode & 0o7777:04o}/{mode_string(node)})  Uid: ({'0' if node.owner == 'root' else '1000':>5}"
            f"/{node.owner:>8})   Gid: ({'0' if node.group == 'root' else '1000':>5}/{node.group:>8})\n"
        )
    return status
