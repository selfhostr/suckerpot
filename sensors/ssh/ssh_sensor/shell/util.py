"""Helpers shared by command implementations."""

from __future__ import annotations

import fnmatch
import itertools
import re
import time
from collections.abc import Callable, Iterable, Iterator

from ssh_sensor.shell.core import CmdIO
from ssh_sensor.shell.fs import FSError, Node
from ssh_sensor.shell.interp import Shell

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
MAX_LINES = 5000
MAX_LINE_CHARS = 2000
# Largest text a command reads from one file, and over all its inputs together. Files are
# already bounded by the fake filesystem cap (1 MiB); this bounds decoding and line splitting.
MAX_TEXT_INPUT = 1024 * 1024


def ls_date(ts: int, now: float) -> str:
    t = time.gmtime(ts)
    if abs(now - ts) < 180 * 86400:
        return f"{MONTHS[t.tm_mon - 1]} {t.tm_mday:2d} {t.tm_hour:02d}:{t.tm_min:02d}"
    return f"{MONTHS[t.tm_mon - 1]} {t.tm_mday:2d}  {t.tm_year}"


def mode_string(node: Node) -> str:
    kind = {"d": "d", "l": "l"}.get(node.kind, "-")
    bits = ""
    for shift, special, ch_special in ((6, 0o4000, "s"), (3, 0o2000, "s"), (0, 0o1000, "t")):
        triple = (node.mode >> shift) & 7
        r = "r" if triple & 4 else "-"
        w = "w" if triple & 2 else "-"
        x_set = bool(triple & 1)
        if node.mode & special:
            x = ch_special if x_set else ch_special.upper()
        else:
            x = "x" if x_set else "-"
        bits += r + w + x
    return kind + bits


def can_access(sh: Shell, node: Node, want: str) -> bool:
    if sh.is_root:
        return want != "x" or bool(node.mode & 0o111) or node.kind == "d"
    shift = 6 if node.owner == sh.user.name else 0
    bit = {"r": 4, "w": 2, "x": 1}[want]
    return bool((node.mode >> shift) & bit)


def read_text(sh: Shell, path: str, limit: int = MAX_TEXT_INPUT) -> str:
    """Read at most ``limit`` bytes of a file as text, with permission checks; raises FSError."""
    node = sh.fs.stat(path)
    if node is None:
        raise FSError("No such file or directory")
    if node.kind == "d":
        raise FSError("Is a directory")
    if not can_access(sh, node, "r"):
        raise FSError("Permission denied")
    data = sh.fs.read(path, max(0, limit))
    return (data if len(data) <= limit else data[: max(0, limit)]).decode("utf-8", "replace")


def iter_lines(text: str) -> Iterator[str]:
    """Lazily yield the lines of ``text``, each sliced to MAX_LINE_CHARS straight from ``text``
    (a 1 MB line never becomes a 1 MB string). A trailing newline does not add an empty line."""
    pos, end_of_text = 0, len(text)
    while pos < end_of_text:
        nl = text.find("\n", pos)
        end = end_of_text if nl < 0 else nl
        yield text[pos : min(end, pos + MAX_LINE_CHARS)]
        pos = end + 1


def split_lines(text: str, max_lines: int = MAX_LINES) -> list[str]:
    """At most ``max_lines`` lines of at most MAX_LINE_CHARS characters each. Never splits the
    whole text: it walks the newlines and stops at the line cap."""
    return list(itertools.islice(iter_lines(text), max(0, max_lines)))


def write_lines(io: CmdIO, lines: Iterable[str]) -> None:
    """Write ``line + "\n"`` for each line, stopping as soon as the output budget is used."""
    for line in lines:
        if io.full:
            return
        io.write(line)
        io.write("\n")


def join_lines(lines: list[str]) -> str:
    return "\n".join(lines) + "\n" if lines else ""


_POSIX_CLASSES = {
    "digit": "0-9",
    "alpha": "a-zA-Z",
    "alnum": "a-zA-Z0-9",
    "upper": "A-Z",
    "lower": "a-z",
    "space": " \t",
    "punct": "!-/:-@[-`{-~",
}


def _regex_to_glob(alt: str, extended: bool) -> tuple[bool, bool, str]:
    """Translate a (very) restricted regex into an fnmatch pattern. Returns (^, $, glob)."""
    anchor_start = alt.startswith("^")
    if anchor_start:
        alt = alt[1:]
    anchor_end = alt.endswith("$") and not alt.endswith("\\$")
    if anchor_end:
        alt = alt[:-1]
    out: list[str] = []
    i = 0
    while i < len(alt):
        ch = alt[i]
        if ch == "\\" and i + 1 < len(alt):
            nxt = alt[i + 1]
            i += 2
            if nxt in "<>bB":
                continue
            if nxt in "dswDSW":
                out.append("?")
                continue
            out.append(f"[{nxt}]")
            continue
        if ch == "[":
            end = alt.find("]", i + 2)
            if end > 0:
                cls = alt[i + 1 : end]
                cls = re.sub(r"\[:(\w+):\]", lambda m: _POSIX_CLASSES.get(m.group(1), ""), cls)
                if cls.startswith("^"):
                    cls = "!" + cls[1:]
                out.append(f"[{cls}]" if cls else "?")
                i = end + 1
                continue
        if ch == ".":
            out.append("?")
        elif ch == "*":
            if out:
                out[-1] = "*"
            else:
                out.append("*")
        elif ch == "+" and extended:
            out.append("*")
        elif ch == "?" and extended:
            if out:
                out[-1] = "*"
        elif ch in "(){}" and extended:
            pass
        elif ch in "*?[":
            out.append(f"[{ch}]")
        else:
            out.append(ch)
        i += 1
    return anchor_start, anchor_end, "".join(out)


def make_matcher(
    pattern: str, *, fixed: bool = False, icase: bool = False, extended: bool = False
) -> Callable[[str], bool]:
    """Line matcher for grep/awk. Linear-time by construction: never uses ``re`` on attacker
    patterns, only a restricted regex-to-glob translation."""
    pattern = pattern[:200]
    if fixed:
        needle = pattern.lower() if icase else pattern
        return lambda line: needle in (line.lower() if icase else line)[:MAX_LINE_CHARS]
    sep = "|" if extended else "\\|"
    matchers: list[tuple[bool, bool, str]] = []
    for alt in pattern.split(sep)[:8]:
        a_start, a_end, glob = _regex_to_glob(alt, extended)
        matchers.append((a_start, a_end, glob.lower() if icase else glob))

    def match(line: str) -> bool:
        subject = (line.lower() if icase else line)[:MAX_LINE_CHARS]
        for a_start, a_end, glob in matchers:
            full = ("" if a_start else "*") + glob + ("" if a_end else "*")
            if fnmatch.fnmatchcase(subject, full):
                return True
        return False

    return match


def fmt_date(ts: float) -> str:
    t = time.gmtime(ts)
    return (
        f"{DAYS[t.tm_wday]} {MONTHS[t.tm_mon - 1]} {t.tm_mday:2d} "
        f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} UTC {t.tm_year}"
    )


def human_size(kb: int) -> str:
    size = float(kb)
    for unit in ("K", "M", "G", "T"):
        if size < 1024 or unit == "T":
            return f"{size:.0f}{unit}" if size >= 10 or unit == "K" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.0f}T"
