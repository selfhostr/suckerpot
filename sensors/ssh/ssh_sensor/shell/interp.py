"""Shell state, word expansion and execution against the fake filesystem.

This module never touches the real system: commands are Python functions that read and write
the in-memory ``FakeFS``. Command substitution only runs a short allow-list of read-only
emulated commands and is otherwise replaced by an empty string.
"""

from __future__ import annotations

import fnmatch
import logging
import posixpath
import re
import secrets
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from ssh_sensor.config import Config
from ssh_sensor.shell.arith import ArithError, evaluate
from ssh_sensor.shell.baseimage import Profile
from ssh_sensor.shell.core import (
    MAX_IO_CHARS,
    CmdIO,
    PendingEvent,
    ShellExit,
    join_bounded,
    parse_uint,
)
from ssh_sensor.shell.fs import BaseImage, FakeFS, FSError
from ssh_sensor.shell.parser import Command, ParseError, Pipeline, Word, parse
from ssh_sensor.shell.procfs import cwd_links, proc_nodes
from ssh_sensor.shell.stubs import run_stub

log = logging.getLogger("ssh_sensor.shell")
MAX_BUDGET = 200
MAX_VARS = 256
MAX_VAR_BYTES = 64 * 1024
MAX_VALUE = 4096
MAX_HISTORY_BYTES = 64 * 1024
MAX_WORD = 64 * 1024
MAX_DEPTH = 3
MAX_FIELDS = 256
MAX_SUBST_OUTPUT = 4096
MAX_ARGV_CHARS = 128 * 1024  # total size of one command's expanded words (bash: E2BIG)
MAX_SCRIPT_LINES = 200
_ERROR_LOG_INTERVAL = 60.0
_last_traceback: dict[str, float] = {}


def _log_internal_error(exc: BaseException) -> None:
    """Full traceback at most once per minute per exception type, otherwise one line.

    An attacker who finds an input that trips an emulation bug must not be able to flood the
    logs with tracebacks."""
    name = type(exc).__name__
    now = time.monotonic()
    last = _last_traceback.get(name)
    if last is None or now - last >= _ERROR_LOG_INTERVAL:
        if last is None and len(_last_traceback) >= 64:
            _last_traceback.pop(next(iter(_last_traceback)))
        _last_traceback[name] = now
        log.warning("shell internal error", exc_info=exc)
    else:
        log.warning("shell internal error: %s (traceback rate-limited)", name)


_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=")
_VAR_RE = re.compile(r"\$(?:\{([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*|[?$#@*!0-9]))")
_BIN_DIRS = ("/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin")
_SUBST_ALLOWED = frozenset(
    "uname whoami hostname pwd id nproc date echo basename dirname cat grep wc head tail cut "
    "awk tr sort uniq uptime which free ls lscpu printf".split()
)


class LineTimeout(Exception):
    """The command line used up its CPU time budget."""


@dataclass(slots=True)
class Result:
    chunks: list[tuple[bool, str]]
    status: int
    delay: float = 0.0
    exit: bool = False

    @property
    def output(self) -> str:
        """Everything the terminal would show, stdout and stderr interleaved."""
        return "".join(text for _, text in self.chunks)


@dataclass(slots=True)
class UserInfo:
    name: str
    uid: int
    gid: int
    home: str
    shell: str


def parse_passwd(text: str) -> dict[str, UserInfo]:
    users: dict[str, UserInfo] = {}
    for line in text.splitlines():
        parts = line.split(":")
        uid, gid = parse_uint(parts[2]) if len(parts) > 3 else None, None
        if len(parts) >= 7:
            gid = parse_uint(parts[3])
        if uid is not None and gid is not None:
            users[parts[0]] = UserInfo(parts[0], uid, gid, parts[5], parts[6])
    return users


@dataclass
class Shell:
    cfg: Config
    base: BaseImage
    profile: Profile
    username: str
    client_ip: str
    client_port: int
    term: str = "xterm"
    shared_fs: FakeFS | None = None
    tty: bool = True
    interactive: bool = True
    now: Callable[[], float] = time.time
    fs: FakeFS = field(init=False)
    user: UserInfo = field(init=False)
    cwd: str = field(init=False)
    env: dict[str, str] = field(init=False)
    shell_vars: dict[str, str] = field(default_factory=dict)
    history: list[str] = field(default_factory=list)
    pending: list[PendingEvent] = field(default_factory=list)
    crontab: list[str] = field(default_factory=list)
    last_status: int = 0
    delay: float = 0.0
    started: float = field(init=False)
    pid: int = 1873
    _term: list[tuple[bool, str]] = field(default_factory=list)
    _term_len: int = 0
    _term_cap: int = 0
    _deadline: float = 0.0
    _history_bytes: int = 0
    _truncated: bool = False
    _budget: int = MAX_BUDGET
    _depth: int = 0
    _expand_failed: bool = False
    prev_cwd: str = "/"
    user_stack: list[UserInfo] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.started = self.now()
        self.fs = self.shared_fs or FakeFS(
            self.base,
            max_bytes=self.cfg.max_fs_bytes,
            max_nodes=self.cfg.max_fs_nodes,
            now=int(self.started),
        )
        self.user = self._setup_user(self.username)
        self.cwd = self.user.home
        self.pid = 1873 + (hash(self.client_ip) & 0x3FF)
        self.fs.seed(proc_nodes(self))
        self.set_cwd(self.cwd)
        self.env = {
            "SHELL": "/bin/bash",
            "PWD": self.cwd,
            "LOGNAME": self.user.name,
            "HOME": self.user.home,
            "LANG": "en_US.UTF-8",
            "TERM": self.term if self.tty else "dumb",
            "USER": self.user.name,
            "SHLVL": "1",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games",
            "SSH_CLIENT": f"{self.client_ip} {self.client_port} 22",
            "SSH_CONNECTION": f"{self.client_ip} {self.client_port} {self.profile.ip} 22",
            "XDG_SESSION_ID": "14",
            "XDG_RUNTIME_DIR": f"/run/user/{self.user.uid}",
            "MAIL": f"/var/mail/{self.user.name}",
            "_": "/usr/bin/env",
        }
        if self.tty:
            self.env["SSH_TTY"] = "/dev/pts/0"
        self._term_cap = self.cfg.max_output_per_line
        try:
            raw = self.fs.read(f"{self.user.home}/.bash_history")[-MAX_HISTORY_BYTES:]
            hist = raw.decode("utf-8", "replace")
            self.history = [h[:MAX_VALUE] for h in hist.splitlines()[-500:]]
            self._history_bytes = sum(len(h) + 1 for h in self.history)
        except FSError:
            self.history = []

    def set_cwd(self, path: str) -> None:
        """Change directory; ``/proc/self/cwd`` and ``/proc/<pid>/cwd`` follow it."""
        self.cwd = path
        self.fs.seed(cwd_links(self))

    # ---- user handling -------------------------------------------------------------------
    def _setup_user(self, name: str) -> UserInfo:
        users = parse_passwd(self.fs.read("/etc/passwd").decode())
        if name in users:
            return users[name]
        safe = re.sub(r"[^A-Za-z0-9_-]", "", name)[:32] or "user"
        if safe in users:
            return users[safe]
        uid = 1001 + len([u for u in users.values() if u.uid >= 1000])
        info = UserInfo(safe, uid, uid, f"/home/{safe}", "/bin/bash")
        line = f"{safe}:x:{uid}:{uid}:,,,:{info.home}:/bin/bash\n"
        try:
            self.fs.write("/etc/passwd", line.encode(), append=True, owner="root")
            self.fs.mkdir(info.home, safe, 0o750)
        except FSError:
            pass
        return info

    @property
    def is_root(self) -> bool:
        return self.user.uid == 0

    def set_user(self, name: str) -> bool:
        """Switch identity (``su``/``sudo -u``). Returns False for unknown users."""
        users = parse_passwd(self.fs.read("/etc/passwd").decode())
        if name not in users:
            return False
        self.user = users[name]
        self.env.update(USER=name, LOGNAME=name, HOME=self.user.home)
        return True

    # ---- paths ---------------------------------------------------------------------------
    def abspath(self, path: str) -> str:
        return self.fs.resolve(self.cwd, path)

    def display_cwd(self) -> str:
        home = self.user.home
        if self.cwd == home:
            return "~"
        if self.cwd.startswith(home + "/"):
            return "~" + self.cwd[len(home) :]
        return self.cwd

    def prompt(self) -> str:
        sign = "#" if self.is_root else "$"
        host = self.profile.hostname
        if not self.tty:
            return ""
        return (
            f"\x1b[01;32m{self.user.name}@{host}\x1b[00m:\x1b[01;34m{self.display_cwd()}"
            f"\x1b[00m{sign} "
        )

    def can_read(self, path: str) -> bool:
        node = self.fs.stat(path)
        if node is None:
            return True
        if self.is_root or node.mode & 0o004:
            return True
        return node.owner == self.user.name and bool(node.mode & 0o400)

    # ---- output --------------------------------------------------------------------------
    def _to_terminal(self, text: str, err: bool = False) -> None:
        if not text:
            return
        room = self._term_cap - self._term_len
        if room <= 0:
            self._truncated = True
            return
        if len(text) > room:
            text = text[:room]
            self._truncated = True
        self._term.append((err, text))
        self._term_len += len(text)

    # ---- resource limits -----------------------------------------------------------------
    def tick(self) -> None:
        """Abort the current command line once it has used its CPU time budget."""
        if time.monotonic() > self._deadline:
            raise LineTimeout

    def clear_history(self) -> None:
        self.history.clear()
        self._history_bytes = 0

    def private_bytes(self) -> int:
        """Approximate memory held by this shell (variables, history, crontab)."""
        return (
            sum(len(k) + len(v) for k, v in self.env.items())
            + sum(len(k) + len(v) for k, v in self.shell_vars.items())
            + self._history_bytes
            + sum(len(c) for c in self.crontab)
        )

    def set_var(self, name: str, value: str, *, export: bool = False) -> bool:
        """Set a shell variable within the per-shell caps. Returns False when refused."""
        value = value[:MAX_VALUE]
        name = name[:128]
        known = name in self.shell_vars or name in self.env
        if not known and len(self.shell_vars) + len(self.env) >= MAX_VARS:
            return False
        old = len(self.shell_vars.get(name, "")) + len(self.env.get(name, ""))
        extra = len(value) * (2 if export else 1) - old
        vars_bytes = sum(len(k) + len(v) for k, v in self.shell_vars.items()) + sum(
            len(k) + len(v) for k, v in self.env.items()
        )
        if vars_bytes + extra > MAX_VAR_BYTES:
            return False
        self.shell_vars[name] = value
        if export or name in self.env:
            self.env[name] = value
        return True

    def error_prefix(self) -> str:
        return "bash: " if self.interactive else "bash: line 1: "

    # ---- expansion -----------------------------------------------------------------------
    def lookup(self, name: str) -> str:
        if name == "?":
            return str(self.last_status)
        if name == "$":
            return str(self.pid + 1)  # the session's bash, as ps lists it
        if name in ("#", "@", "*", "!"):
            return "0" if name == "#" else ""
        if name == "0":
            return "-bash" if self.interactive else "bash"
        if name.isascii() and name.isdigit():
            return ""
        if name in self.shell_vars:
            return self.shell_vars[name]
        if name == "HOSTNAME":
            return self.profile.hostname
        if name == "UID" or name == "EUID":
            return str(self.user.uid)
        if name == "RANDOM":
            return str(secrets.randbelow(32768))
        return self.env.get(name, "")

    def _expand_vars(self, text: str, limit: int = MAX_WORD) -> str:
        """Expand ``$var``, ``${...}``, ``$(...)`` and backquotes; at most ``limit`` chars.

        The running total is checked after every piece, so the result never exceeds the cap
        by more than one (already bounded) piece before it is cut."""
        out: list[str] = []
        i = 0
        total = 0
        limit = min(limit, MAX_WORD)
        while i < len(text) and total < limit:
            ch = text[i]
            piece: str
            if ch == "\x00" and i + 1 < len(text):
                piece = text[i + 1]
                i += 2
            elif ch == "$" and text[i + 1 : i + 3] == "((":
                end = self._match_paren(text, i)
                if text[end - 2 : end] == "))" and end - i >= 5:
                    piece = self._arith(text[i + 3 : end - 2])
                else:  # "$( (cmd) )": a command substitution that starts with a subshell
                    piece = self._substitute(text[i + 2 : end - 1])
                i = end
            elif ch == "$" and text[i + 1 : i + 2] == "(":
                end = self._match_paren(text, i)
                piece = self._substitute(text[i + 2 : end - 1])
                i = end
            elif ch == "`" and text.find("`", i + 1) > 0:
                end = text.find("`", i + 1)
                piece = self._substitute(text[i + 1 : end])
                i = end + 1
            elif ch == "$" and (m := _VAR_RE.match(text, i)) is not None:
                piece = self._var_value(m.group(1) if m.group(1) is not None else m.group(2))
                i = m.end()
            else:
                # copy the whole run of literal text up to the next special character at once
                nxt = min(
                    (j for j in (text.find(c, i + 1) for c in "$`\x00") if j >= 0),
                    default=len(text),
                )
                piece = text[i : min(nxt, i + limit - total)]
                i = nxt if len(piece) == nxt - i else i + len(piece)
            if total + len(piece) > limit:
                piece = piece[: limit - total]
            out.append(piece)
            total += len(piece)
        return "".join(out)

    @staticmethod
    def _match_paren(text: str, i: int) -> int:
        depth = 0
        for j in range(i + 1, len(text)):
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
                if depth == 0:
                    return j + 1
        return len(text)

    def _var_value(self, expr: str) -> str:
        if expr.startswith("#") and len(expr) > 1:
            return str(len(self.lookup(expr[1:])))
        for sep in (":-", ":=", "-", "="):
            if sep in expr:
                name, _, default = expr.partition(sep)
                value = self.lookup(name)
                return value if value else self._expand_vars(default, MAX_VALUE)
        return self.lookup(expr.split(":")[0].split("%")[0].split("#")[0])

    def _arith(self, expr: str) -> str:
        """Value of ``$(( expr ))``; an invalid expression expands to nothing (bash aborts)."""
        try:
            return str(evaluate(self._expand_vars(expr, 512), self.lookup))
        except ArithError as exc:
            self._to_terminal(f"{self.error_prefix()}{expr.strip()[:64]}: {exc}\n", True)
            self._expand_failed = True
            return ""

    def _substitute(self, inner: str) -> str:
        """Run an allow-listed, read-only pipeline and return its output, else empty."""
        if self._depth >= MAX_DEPTH or len(inner) > 512:
            return ""
        try:
            items = parse(inner)
        except ParseError:
            return ""
        for item in items:
            for cmd in item.pipeline.commands:
                if cmd.redirs or not cmd.words:
                    return ""
                if cmd.words[0].literal not in _SUBST_ALLOWED:
                    return ""
        text, _ = self.run_nested(inner, limit=MAX_SUBST_OUTPUT + 64)
        return text.rstrip("\n")[:MAX_SUBST_OUTPUT]

    def expand_string(self, word: Word) -> str:
        """Expand without splitting or globbing (redirection targets, assignments)."""
        parts: list[str] = []
        total = 0
        for idx, seg in enumerate(word.segments):
            if total >= MAX_WORD:
                break
            text = seg.text
            if seg.quote == "single":
                piece = text[: MAX_WORD - total]
            else:
                if seg.quote == "none" and idx == 0 and text.startswith("~"):
                    rest = text[1:]
                    if not rest or rest.startswith("/"):
                        text = self.env.get("HOME", "/") + rest
                piece = self._expand_vars(text, MAX_WORD - total)
            parts.append(piece)
            total += len(piece)
        return "".join(parts)

    def expand_fields(self, word: Word) -> list[str]:
        fields: list[str] = []
        cur: list[str] = []
        has = False
        globbable = False
        total = 0  # all fields of one word together stay within MAX_WORD
        for idx, seg in enumerate(word.segments):
            if total >= MAX_WORD:
                break
            text = seg.text
            if seg.quote == "single":
                cur.append(text[: MAX_WORD - total])
                total += len(cur[-1])
                has = True
                continue
            if seg.quote == "none" and idx == 0 and text.startswith("~"):
                rest = text[1:]
                if not rest or rest.startswith("/"):
                    text = self.env.get("HOME", "/") + rest
            expanded = self._expand_vars(text, MAX_WORD - total)
            total += len(expanded)
            if seg.quote == "double":
                cur.append(expanded)
                has = True
                continue
            if any(c in text for c in "*?["):
                globbable = True
            if "$" not in text and "`" not in text:
                cur.append(expanded)
                has = has or bool(expanded)
                continue
            for k, piece in enumerate(re.split(r"\s+", expanded)):
                if k > 0 and has:
                    fields.append("".join(cur))
                    cur, has = [], False
                if piece:
                    cur.append(piece)
                    has = True
        if has:
            fields.append("".join(cur))
        if globbable:
            out: list[str] = []
            for f in fields:
                matches = self.glob(f)
                out.extend(matches if matches else [f])
                if len(out) > MAX_FIELDS:
                    break
            return out[:MAX_FIELDS]
        return fields

    def glob(self, pattern: str) -> list[str]:
        if not any(c in pattern for c in "*?["):
            return []
        absolute = pattern.startswith("/")
        parts = [p for p in pattern.split("/") if p]
        results = ["/" if absolute else ""]
        for part in parts:
            nxt: list[str] = []
            for base in results:
                if not any(c in part for c in "*?["):
                    nxt.append(posixpath.join(base, part) if base else part)
                    continue
                directory = base or "."
                try:
                    names = self.fs.listdir(self.fs.resolve(self.cwd, directory))
                except FSError:
                    continue
                for name in names:
                    if name.startswith(".") and not part.startswith("."):
                        continue
                    if fnmatch.fnmatchcase(name, part):
                        nxt.append(posixpath.join(base, name) if base else name)
            results = nxt[:MAX_FIELDS]
        return sorted(r for r in results if r not in ("", "/") and self.fs.exists(self.abspath(r)))

    # ---- execution -----------------------------------------------------------------------
    def run_line(self, line: str) -> Result:
        """Run one command line from the terminal (or an exec request)."""
        self._term, self._term_len, self._truncated = [], 0, False
        self._term_cap = self.cfg.max_output_per_line
        self._budget = MAX_BUDGET
        self._deadline = time.monotonic() + self.cfg.line_budget
        self.delay = 0.0
        exit_requested = False
        status = 0
        if self.interactive and line.strip():
            self.history.append(line)
            self._history_bytes += len(line) + 1
            while self.history and (
                self._history_bytes > MAX_HISTORY_BYTES or len(self.history) > 1000
            ):
                self._history_bytes -= len(self.history.pop(0)) + 1
            if not self.history:
                self._history_bytes = 0
        try:
            status = self._run_items(line)
        except ShellExit as exc:
            status = exc.status
            exit_requested = True
        except LineTimeout:
            self._to_terminal("Killed\n", True)
            status = 137
        except RecursionError:
            self._to_terminal(
                f"{self.error_prefix()}fork: retry: Resource temporarily unavailable\n", True
            )
            status = 2
        except Exception as exc:
            # Never let an emulation bug kill the session or hide the command from the logs.
            _log_internal_error(exc)
            self._to_terminal(
                f"{self.error_prefix()}fork: retry: Resource temporarily unavailable\n", True
            )
            status = 2
        self.last_status = status
        if self._truncated:
            self._term.append((True, "\n[output truncated]\n"))
        return Result(self._term, status, min(self.delay, 3.0), exit_requested)

    def run_nested(
        self, line: str, stdin: str | None = None, *, limit: int | None = None
    ) -> tuple[str, int]:
        """Run ``line`` capturing everything it prints (used by ``sh -c`` and substitution).

        The capture is bounded while it is produced: at most ``limit`` characters (and never
        more than one command line's terminal cap) are kept."""
        if self._depth >= MAX_DEPTH:
            return f"{self.error_prefix()}fork: retry: Resource temporarily unavailable\n", 1
        cap = self.cfg.max_output_per_line if limit is None else max(0, limit)
        cap = min(cap, self.cfg.max_output_per_line)
        saved = (self._term, self._term_len, self._term_cap, self._stdin_hint(), self._truncated)
        self._term, self._term_len, self._term_cap = [], 0, cap
        self._depth += 1
        self._nested_stdin = stdin
        try:
            status = self._run_items(line)
        except ShellExit as exc:  # `exit` inside a child shell only ends that child
            status = exc.status
        finally:
            self._depth -= 1
            text = "".join(t for _, t in self._term)
            child_truncated = self._truncated
            self._term, self._term_len, self._term_cap, self._nested_stdin, self._truncated = saved
            # a child cut by the caller's own limit is not a terminal truncation
            self._truncated = self._truncated or (child_truncated and limit is None)
        return text, status

    _nested_stdin: str | None = None

    def _stdin_hint(self) -> str | None:
        return self._nested_stdin

    def _run_items(self, line: str) -> int:
        try:
            items = parse(line)
        except ParseError as exc:
            self._to_terminal(
                f"bash: {exc}\n" if self.interactive else f"bash: line 1: {exc}\n", True
            )
            return 2
        status = self.last_status if self._depth else 0
        for item in items:
            if item.op == "&&" and status != 0:
                continue
            if item.op == "||" and status == 0:
                continue
            status = self._run_pipeline(item.pipeline)
            self.last_status = status
        return status

    def _run_pipeline(self, pipeline: Pipeline) -> int:
        stdin: str | None = self._nested_stdin if self._depth else None
        status = 0
        last_index = len(pipeline.commands) - 1
        for idx, cmd in enumerate(pipeline.commands):
            stdout, status = self._run_simple(cmd, stdin, piped_out=idx < last_index)
            stdin = stdout
        return status

    def _run_simple(self, cmd: Command, stdin: str | None, *, piped_out: bool) -> tuple[str, int]:
        self._budget -= 1
        self.tick()
        if self._budget < 0:
            self._to_terminal(
                f"{self.error_prefix()}fork: retry: Resource temporarily unavailable\n", True
            )
            raise ShellExit(1)
        words = list(cmd.words)
        assigns: list[tuple[str, str]] = []
        while words:
            first = words[0].segments[0].text if words[0].segments else ""
            m = _ASSIGN_RE.match(first) if words[0].segments[0].quote == "none" else None
            if not m:
                break
            value_word = Word(
                (type(words[0].segments[0])(first[m.end() :], "none"), *words[0].segments[1:])
            )
            assigns.append((m.group(1), self.expand_string(value_word)))
            words.pop(0)
        fields: list[str] = []
        argv_chars = 0
        for w in words:
            expanded = self.expand_fields(w)
            argv_chars += sum(len(f) + 1 for f in expanded)
            if argv_chars > MAX_ARGV_CHARS:
                name = fields[0] if fields else (expanded[0] if expanded else "")
                self._to_terminal(
                    f"{self.error_prefix()}{name[:64]}: Argument list too long\n", True
                )
                return "", 126
            fields.extend(expanded)
        if self._expand_failed:  # a bad $(( )): bash abandons the command
            self._expand_failed = False
            return "", 1
        if not fields:
            for name, value in assigns:
                if not self.set_var(name, value):
                    self._to_terminal(
                        f"{self.error_prefix()}{name}: cannot allocate memory\n", True
                    )
                    return "", 1
            return "", 0

        err_to_out = any(r.op in ("2>&1",) for r in cmd.redirs)
        out_to_err = any(r.op == "1>&2" for r in cmd.redirs)
        out_file: tuple[str, bool] | None = None
        err_file: tuple[str, bool] | None = None
        both_file: tuple[str, bool] | None = None
        stdin_text = stdin
        for redir in cmd.redirs:
            if redir.target is None:
                continue
            target = self.expand_string(redir.target)
            if target.startswith("/dev/tcp/") or target.startswith("/dev/udp/"):
                self._to_terminal(f"{self.error_prefix()}{target}: Connection refused\n", True)
                return "", 1
            path = self.abspath(target) if target else ""
            if redir.op == "<":
                try:
                    if not self.fs.exists(path):
                        raise FSError("No such file or directory")
                    if not self.can_read(path):
                        raise FSError("Permission denied")
                    stdin_text = self.fs.read(path).decode("utf-8", "replace")
                except FSError as exc:
                    self._to_terminal(f"{self.error_prefix()}{target}: {exc}\n", True)
                    return "", 1
                continue
            append = redir.op in (">>", "2>>")
            err = self._prepare_target(path, target, append)
            if err:
                self._to_terminal(err, True)
                return "", 1
            if redir.op in (">", ">>"):
                out_file = (path, append)
            elif redir.op in ("2>", "2>>"):
                err_file = (path, append)
            elif redir.op == "&>":
                both_file = (path, append)

        io = CmdIO(args=fields[1:], stdin=stdin_text, piped_out=piped_out or out_file is not None)
        io.cmdline = " ".join(fields)
        try:
            status = self.dispatch(fields[0], io)
        except ShellExit:
            # keep what the command printed (e.g. an error message) before ending the shell
            self._to_terminal(join_bounded(io.err, self._term_room() + 1), True)
            self._to_terminal(join_bounded(io.out, self._term_room() + 1))
            raise
        # io.out and io.err share one MAX_IO_CHARS budget, so every join below is bounded by
        # it; output that only goes to the terminal is joined up to the terminal room only.
        out_parts, err_parts = io.out, io.err
        if err_to_out:
            out_parts, err_parts = [*out_parts, *err_parts], []
        if out_to_err:
            out_parts, err_parts = [], [*err_parts, *out_parts]
        if both_file is not None:
            self._write_target(
                both_file[0], join_bounded(out_parts + err_parts, MAX_IO_CHARS), both_file[1]
            )
            return "", status
        if err_file is not None:
            self._write_target(err_file[0], join_bounded(err_parts, MAX_IO_CHARS), err_file[1])
            err_parts = []
        self._to_terminal(join_bounded(err_parts, self._term_room() + 1), True)
        if out_file is not None:
            self._write_target(out_file[0], join_bounded(out_parts, MAX_IO_CHARS), out_file[1])
            return "", status
        if piped_out:
            return join_bounded(out_parts, MAX_IO_CHARS), status
        self._to_terminal(join_bounded(out_parts, self._term_room() + 1))
        return "", status

    def _term_room(self) -> int:
        return max(0, self._term_cap - self._term_len)

    def _prepare_target(self, path: str, shown: str, append: bool) -> str:
        if path == "/dev/null":
            return ""
        prefix = self.error_prefix()
        if not path or path == "/":
            return f"{prefix}{shown or ''}: No such file or directory\n"
        try:
            if not self.fs.may_write(path, self.user.name, self.user.home) and not self.is_root:
                raise FSError("Permission denied")
            if self.fs.is_dir(path):
                raise FSError("Is a directory")
            if not append or not self.fs.exists(path):
                self.fs.write(path, b"", append=False, owner=self.user.name)
        except FSError as exc:
            return f"{prefix}{shown}: {exc}\n"
        return ""

    def _write_target(self, path: str, text: str, append: bool) -> None:
        if path == "/dev/null" or (not text and not append):
            return
        try:
            if len(text) > self.fs.free_bytes:  # chars <= bytes: refuse before encoding
                raise FSError("No space left on device")
            self.fs.write(path, text.encode(), append=True, owner=self.user.name)
        except FSError as exc:
            self._to_terminal(f"{self.error_prefix()}{path}: {exc}\n", True)

    def dispatch(self, name: str, io: CmdIO) -> int:
        from ssh_sensor.shell.commands import COMMANDS

        if "/" in name:
            return self._run_path(name, io)
        fn = COMMANDS.get(name)
        if fn is not None:
            return fn(self, io)
        if name in self.base.binaries:
            return run_stub(self, name, io)
        io.error(f"{self.error_prefix()}{name}: command not found\n")
        return 127

    def run_argv(self, argv: list[str], io: CmdIO) -> int:
        """Run an already-split command (sudo, nohup, xargs, busybox...) with ``io``'s streams."""
        if not argv:
            return 0
        inner = CmdIO(args=argv[1:], stdin=io.stdin, piped_out=io.piped_out)
        inner.cmdline = " ".join(argv)
        status = self.dispatch(argv[0], inner)
        io.absorb(inner)  # within io's budget (extending the lists directly would bypass it)
        return status

    def _run_path(self, name: str, io: CmdIO) -> int:
        from ssh_sensor.shell.commands import COMMANDS

        directory, _, base = name.rpartition("/")
        norm_dir = posixpath.normpath(directory or "/")
        if norm_dir in _BIN_DIRS and base in COMMANDS:
            return COMMANDS[base](self, io)
        prefix = self.error_prefix()
        try:
            path = self.abspath(name)
        except FSError as exc:
            io.error(f"{prefix}{name}: {exc}\n")
            return 126
        node = self.fs.stat(path)
        if node is None:
            io.error(f"{prefix}{name}: No such file or directory\n")
            return 127
        if node.kind == "d":
            io.error(f"{prefix}{name}: Is a directory\n")
            return 126
        if not node.mode & 0o111 or not self.can_read(path):
            io.error(f"{prefix}{name}: Permission denied\n")
            return 126
        if node.content.startswith(b"\x7fELF"):
            digest = sum(path.encode()) % 3
            if digest == 0:
                io.error(f"{prefix}{name}: cannot execute binary file: Exec format error\n")
                return 126
            if self.interactive:
                io.error("Segmentation fault (core dumped)\n")
            else:
                io.error(f"{prefix}{self.pid + 7} Segmentation fault (core dumped) {name}\n")
            return 139
        content = self.fs.read(path, 64 * 1024)
        return self.run_script(content.decode("utf-8", "replace"), io)

    def run_script(self, text: str, io: CmdIO) -> int:
        """Interpret a text file (created inside the fake fs) line by line, bounded."""
        status = 0
        for count, line in enumerate(_script_lines(text)):
            if count >= MAX_SCRIPT_LINES or io.full:
                break
            if line.startswith("#"):
                continue
            out, status = self.run_nested(line, limit=io.room)
            io.write(out)
        return status

    def source_lines(self) -> int:
        return self._budget


def _script_lines(text: str) -> Iterator[str]:
    """Lines of a script, lazily (a 1 MB script is never split whole), each <= MAX_VALUE."""
    pos = 0
    while pos < len(text):
        nl = text.find("\n", pos)
        end = len(text) if nl < 0 else nl
        yield text[pos : min(end, pos + MAX_VALUE)].rstrip("\r")
        pos = end + 1


def tilde_home(user: UserInfo) -> str:
    return user.home
