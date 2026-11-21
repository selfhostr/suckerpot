"""The only door to the owner's mailbox (design M26, section 4.2).

``SafeMailbox`` owns the imaplib connection and exposes a handful of methods. Nothing else in
this package touches IMAP, and the wrapper itself can do exactly this and nothing more:

    CAPABILITY, STARTTLS, LOGIN, SELECT/EXAMINE, UID SEARCH, UID FETCH (BODY.PEEK only),
    UID STORE +FLAGS.SILENT with the "seen" flag (the one flag ever written), UID MOVE, LIST,
    LOGOUT.

Mail is never removed, added, renamed or answered, and no access right is touched.
``mark_seen`` and ``move`` are the only methods that change the mailbox. The connection leaves
through the VPN tunnel (``suckerpot_egress``); with the gate closed nothing is created. Server
answers are never logged or stored: failures become constant codes (``MailboxError.code``).

Blocking: callers run these methods in a thread (``asyncio.to_thread``). A timer shuts the socket
down after ``deadline_s`` whatever the server drips, and each operation gets what is left of it.
"""

from __future__ import annotations

import contextlib
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Final, Protocol

from suckerpot_egress import ImapError, TunnelIMAP4, TunnelIMAP4_SSL
from suckerpot_egress.imap import format_since, internaldate_to_utc

from ingest.egress import EgressClosed, EgressGate

from .parse import HEADER_FIELDS

IO_TIMEOUT_S: Final = 15.0
DEFAULT_DEADLINE_S: Final = 120.0
HEADER_BATCH: Final = 25
HEADER_LIMIT: Final = 65_536
MAX_FOLDERS: Final = 50
MAX_FOLDER_LEN: Final = 100
SEEN: Final = "(\\Seen)"  # the only flag ever written
FLAG_COMMAND: Final = "+FLAGS.SILENT"
ALLOWED_UID_COMMANDS: Final = frozenset({"SEARCH", "FETCH", "STORE", "MOVE"})

_FOLDER_OK: Final = re.compile(rf"^[ -~]{{1,{MAX_FOLDER_LEN}}}$")
_FOLDER_BAD: Final = frozenset('"\\*%')
_LIST_LINE: Final = re.compile(rb'^\((?P<flags>[^)]*)\) (?:"[^"]*"|NIL) (?P<name>.+)$')
_UID: Final = re.compile(rb"\bUID (\d+)")
_SIZE: Final = re.compile(rb"\bRFC822\.SIZE (\d+)")
_UIDVALIDITY: Final = re.compile(rb"\[UIDVALIDITY (\d+)\]")


class MailboxError(Exception):
    """A mailbox operation failed. ``code`` is a constant; nothing else is attached."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ImapProfile:
    """The ``report_imap`` row with its password decrypted (ingest is the only reader)."""

    host: str
    port: int
    security: str  # ssl | starttls
    username: str
    folder: str
    processed_action: str  # mark_read | move
    move_folder: str | None
    poll_minutes: int
    since: date
    enabled: bool = True
    password: str = field(default="", repr=False)
    trusted_authserv_id: str | None = None  # the only Authentication-Results we believe


@dataclass(frozen=True, slots=True)
class Selected:
    uidvalidity: int
    exists: int


@dataclass(frozen=True, slots=True)
class HeaderItem:
    uid: int
    size: int
    internal_date: datetime | None
    headers: bytes
    oversize: bool


class Mailbox(Protocol):
    """What the poller needs; ``SafeMailbox`` is the real one, tests bring a fake."""

    move_supported: bool

    def connect(self) -> None: ...
    def login(self) -> None: ...
    def select(self, folder: str, *, readonly: bool = False) -> Selected: ...
    def search_new(self, last_uid: int, since: date, limit: int) -> list[int]: ...
    def search_last(self, exists: int, limit: int) -> list[int]: ...
    def fetch_headers(self, uids: list[int]) -> list[HeaderItem]: ...
    def fetch_partial(self, uid: int, size: int) -> bytes: ...
    def mark_seen(self, uid: int) -> None: ...
    def move(self, uid: int, folder: str) -> bool: ...
    def list_folders(self) -> list[str]: ...
    def logout(self) -> None: ...


def valid_folder(name: str) -> bool:
    """Printable ASCII, 1 to 100 characters, none of the quote, backslash, ``*`` or ``%``."""
    return bool(_FOLDER_OK.match(name)) and not set(name) & _FOLDER_BAD


def _quoted(name: str) -> str:
    if not valid_folder(name):
        raise MailboxError("no_folder")
    return f'"{name}"'


class SafeMailbox:
    def __init__(
        self,
        gate: EgressGate,
        profile: ImapProfile,
        *,
        deadline_s: float = DEFAULT_DEADLINE_S,
    ) -> None:
        self._gate = gate
        self._profile = profile
        self._deadline_s = deadline_s
        self._imap: Any = None
        self._started = time.monotonic()
        self._expired = threading.Event()
        self._timer: threading.Timer | None = None
        self.move_supported = False

    # -- plumbing ------------------------------------------------------------------------

    def _left(self) -> float:
        return max(0.5, self._deadline_s - (time.monotonic() - self._started))

    def _expire(self) -> None:
        self._expired.set()
        sock = getattr(self._imap, "sock", None)
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                sock.close()

    def _arm(self) -> Any:
        if self._expired.is_set():
            raise TimeoutError
        if self._imap is None:
            raise MailboxError("protocol")
        sock = getattr(self._imap, "sock", None)
        if sock is not None:
            sock.settimeout(min(IO_TIMEOUT_S, self._left()))
        return self._imap

    def _fail(self, exc: BaseException, default: str) -> MailboxError:
        """A constant code for what went wrong. Server text is dropped here."""
        if isinstance(exc, MailboxError):
            return exc
        if isinstance(exc, EgressClosed):
            return MailboxError("egress_closed")
        if self._expired.is_set() or isinstance(exc, TimeoutError):
            return MailboxError("timeout")
        if isinstance(exc, ssl.SSLError):
            return MailboxError("tls_failed")
        if isinstance(exc, OSError | EOFError):
            return MailboxError("network")
        if isinstance(exc, ImapError):
            return MailboxError(default)
        return MailboxError("protocol")

    def _uid(self, command: str, *args: str) -> Any:
        """The single place a UID command is sent. A fixed vocabulary; STORE may only set \\Seen."""
        if command not in ALLOWED_UID_COMMANDS:
            raise MailboxError("protocol")
        if command == "STORE" and args[1:] != (FLAG_COMMAND, SEEN):
            raise MailboxError("protocol")
        imap = self._arm()
        typ, data = imap.uid(command, *args)
        if typ != "OK":
            raise MailboxError("protocol")
        return data

    # -- connection ----------------------------------------------------------------------

    def connect(self) -> None:
        profile = self._profile
        self._started = time.monotonic()
        timer = threading.Timer(self._deadline_s, self._expire)
        timer.daemon = True
        self._timer = timer
        try:
            self._gate.require_open()  # EgressClosed before any client, socket or tunnel exists
            timer.start()
            context = ssl.create_default_context()  # certificate chain and host name verified
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            timeout = min(IO_TIMEOUT_S, self._left())
            if profile.security == "ssl":
                self._imap = TunnelIMAP4_SSL(
                    self._gate, profile.host, profile.port, ssl_context=context, timeout=timeout
                )
            else:
                self._imap = TunnelIMAP4(self._gate, profile.host, profile.port, timeout=timeout)
                if "STARTTLS" not in self._imap.capabilities:
                    raise MailboxError("tls_failed")  # never LOGIN in clear
                self._arm()
                self._imap.starttls(ssl_context=context)
            self.move_supported = "MOVE" in self._imap.capabilities
        except Exception as exc:
            self._close_quietly()
            raise self._fail(exc, "tls_failed") from None

    def login(self) -> None:
        try:
            self._arm().login(self._profile.username, self._profile.password)
        except Exception as exc:
            raise self._fail(exc, "auth_failed") from None

    def select(self, folder: str, *, readonly: bool = False) -> Selected:
        try:
            imap = self._arm()
            typ, data = imap.select(_quoted(folder), readonly=readonly)
            if typ != "OK":
                raise MailboxError("no_folder")
            exists = int(data[0]) if data and data[0] else 0
            found = None
            for line in imap.untagged_responses.get("OK", []):
                found = _UIDVALIDITY.search(line if isinstance(line, bytes) else b"")
                if found:
                    break
            raw = imap.untagged_responses.get("UIDVALIDITY", [])
            validity = int(raw[0]) if raw else (int(found.group(1)) if found else 0)
            return Selected(validity, exists)
        except Exception as exc:
            raise self._fail(exc, "no_folder") from None

    def logout(self) -> None:
        self._close_quietly(logout=True)

    def _close_quietly(self, *, logout: bool = False) -> None:
        if self._timer is not None:
            self._timer.cancel()
        imap, self._imap = self._imap, None
        if imap is None:
            return
        if logout:
            with contextlib.suppress(Exception):
                imap.logout()
        sock = getattr(imap, "sock", None)
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.close()

    # -- reading -------------------------------------------------------------------------

    def search_new(self, last_uid: int, since: date, limit: int) -> list[int]:
        """UIDs above ``last_uid`` received since ``since``, oldest first, at most ``limit``.
        Never ``UNSEEN``: the owner may already have read the mail."""
        try:
            stamp = format_since(datetime(since.year, since.month, since.day))
            data = self._uid("SEARCH", "UID", f"{last_uid + 1}:*", "SINCE", stamp)
            found = sorted({int(x) for x in (data[0] or b"").split() if x.isdigit()})
            return [u for u in found if u > last_uid][:limit]
        except Exception as exc:
            raise self._fail(exc, "protocol") from None

    def search_last(self, exists: int, limit: int) -> list[int]:
        """UIDs of the last ``limit`` messages of a folder holding ``exists`` (by sequence
        number, so the answer stays small whatever the folder size)."""
        if exists <= 0 or limit <= 0:
            return []
        try:
            data = self._uid("SEARCH", f"{max(1, exists - limit + 1)}:{exists}")
            found = sorted({int(x) for x in (data[0] or b"").split() if x.isdigit()})
        except Exception as exc:
            raise self._fail(exc, "protocol") from None
        return found[-limit:]

    def fetch_headers(self, uids: list[int]) -> list[HeaderItem]:
        """Size, date and a bounded set of header fields. ``BODY.PEEK``: nothing is marked."""
        items: list[HeaderItem] = []
        try:
            for start in range(0, len(uids), HEADER_BATCH):
                batch = uids[start : start + HEADER_BATCH]
                spec = (
                    f"(UID RFC822.SIZE INTERNALDATE "
                    f"BODY.PEEK[HEADER.FIELDS ({HEADER_FIELDS})]<0.{HEADER_LIMIT}>)"
                )
                data = self._uid("FETCH", ",".join(map(str, batch)), spec)
                items.extend(_header_items(data))
        except Exception as exc:
            raise self._fail(exc, "protocol") from None
        return sorted(items, key=lambda i: i.uid)

    def fetch_partial(self, uid: int, size: int) -> bytes:
        """The first ``size`` bytes of a message. ``.PEEK``: fetching never sets ``\\Seen``."""
        try:
            data = self._uid("FETCH", str(uid), f"(BODY.PEEK[]<0.{max(1, size)}>)")
        except Exception as exc:
            raise self._fail(exc, "protocol") from None
        for part in data:
            if isinstance(part, tuple) and isinstance(part[1], bytes):
                return part[1][:size]
        return b""

    def list_folders(self) -> list[str]:
        """Folder names for the move target. At most 50, printable ASCII only (test only)."""
        try:
            typ, data = self._arm().list('""', '"*"')
        except Exception as exc:
            raise self._fail(exc, "protocol") from None
        if typ != "OK":
            raise MailboxError("protocol")
        names: list[str] = []
        for line in data:
            found = _LIST_LINE.match(line) if isinstance(line, bytes) else None
            if found is None or b"\\noselect" in found["flags"].lower():
                continue
            name = found["name"].strip().strip(b'"').decode("ascii", errors="ignore")
            if valid_folder(name) and name not in names:
                names.append(name)
            if len(names) >= MAX_FOLDERS:
                break
        return names

    # -- the only writes -----------------------------------------------------------------

    def mark_seen(self, uid: int) -> None:
        """Set ``\\Seen``. The only flag this class ever writes."""
        try:
            self._uid("STORE", str(uid), FLAG_COMMAND, SEEN)
        except Exception as exc:
            raise self._fail(exc, "protocol") from None

    def move(self, uid: int, folder: str) -> bool:
        """``UID MOVE`` (RFC 6851) when the server has it; otherwise the mail is only marked as
        read and False is returned (the caller records ``move_supported = false``)."""
        if not self.move_supported:
            self.mark_seen(uid)
            return False
        try:
            self._uid("MOVE", str(uid), _quoted(folder))
        except Exception as exc:
            err = self._fail(exc, "no_move_folder")
            raise MailboxError("no_move_folder" if err.code == "protocol" else err.code) from None
        return True


def _header_items(data: list[Any]) -> list[HeaderItem]:
    """Read the answer of a header FETCH. Each message is a ``(prefix, literal)`` tuple, then a
    trailing bytes element that may hold attributes the server put after the literal."""
    items: list[HeaderItem] = []
    for i, part in enumerate(data):
        if not isinstance(part, tuple) or not isinstance(part[0], bytes):
            continue
        tail = data[i + 1] if i + 1 < len(data) and isinstance(data[i + 1], bytes) else b""
        meta = part[0] + b" " + tail
        uid, size = _UID.search(meta), _SIZE.search(meta)
        if uid is None:
            continue
        literal = part[1] if isinstance(part[1], bytes) else b""
        items.append(
            HeaderItem(
                uid=int(uid.group(1)),
                size=int(size.group(1)) if size else 0,
                internal_date=internaldate_to_utc(meta),
                headers=literal[:HEADER_LIMIT],
                oversize=len(literal) >= HEADER_LIMIT,
            )
        )
    return items
