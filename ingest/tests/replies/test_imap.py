"""SafeMailbox: the wire vocabulary, the gate, TLS and the codes. No connection is ever opened."""

from __future__ import annotations

import ssl
from datetime import UTC, date, datetime
from typing import Any, ClassVar

import pytest
from suckerpot_egress import ImapError

from ingest.replies import imap as imap_mod
from ingest.replies.imap import (
    ImapProfile,
    MailboxError,
    SafeMailbox,
    _header_items,
    valid_folder,
)

from ..helpers import fake_gate


class FakeSock:
    def __init__(self) -> None:
        self.timeouts: list[float] = []
        self.closed = False
        self.shut = False

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def shutdown(self, how: int) -> None:
        self.shut = True

    def close(self) -> None:
        self.closed = True


class FakeImap:
    instances: ClassVar[list[FakeImap]] = []
    caps: ClassVar[tuple[str, ...]] = ("IMAP4REV1", "STARTTLS", "MOVE")
    fail: ClassVar[dict[str, BaseException]] = {}
    answers: ClassVar[dict[str, Any]] = {}

    def __init__(self, gate: Any, host: str, port: int, **kw: Any) -> None:
        self.host, self.port, self.kw = host, port, kw
        self.capabilities = type(self).caps
        self.sock = FakeSock()
        self.calls: list[tuple[Any, ...]] = []
        self.untagged_responses: dict[str, list[Any]] = {"UIDVALIDITY": [b"777"]}
        type(self).instances.append(self)

    def _go(self, name: str, *args: Any) -> None:
        self.calls.append((name, *args))
        if name in type(self).fail:
            raise type(self).fail[name]

    def starttls(self, ssl_context: Any = None) -> None:
        self._go("starttls")

    def login(self, user: str, password: str) -> tuple[str, list[bytes]]:
        self._go("login", user, password)
        return "OK", [b"done"]

    def select(self, mailbox: str, readonly: bool = False) -> tuple[str, list[bytes]]:
        self._go("select", mailbox, readonly)
        return "OK", [b"3"]

    def uid(self, command: str, *args: str) -> tuple[str, Any]:
        self._go("uid", command, *args)
        return "OK", type(self).answers.get(command, [None])

    def list(self, directory: str, pattern: str) -> tuple[str, list[bytes]]:
        self._go("list", directory, pattern)
        return "OK", type(self).answers.get("LIST", [])

    def logout(self) -> None:
        self._go("logout")


@pytest.fixture(autouse=True)
def fakes(monkeypatch: pytest.MonkeyPatch) -> type[FakeImap]:
    FakeImap.instances = []
    FakeImap.caps = ("IMAP4REV1", "STARTTLS", "MOVE")
    FakeImap.fail = {}
    FakeImap.answers = {}
    monkeypatch.setattr(imap_mod, "TunnelIMAP4", FakeImap)
    monkeypatch.setattr(imap_mod, "TunnelIMAP4_SSL", FakeImap)
    return FakeImap


def profile(**over: Any) -> ImapProfile:
    base: dict[str, Any] = {
        "host": "imap.example.org",
        "port": 143,
        "security": "starttls",
        "username": "reporter",
        "folder": "INBOX",
        "processed_action": "mark_read",
        "move_folder": None,
        "poll_minutes": 15,
        "since": date(2026, 11, 1),
        "password": "hunter2-sample",
    }
    base.update(over)
    return ImapProfile(**base)


def opened(**over: Any) -> tuple[SafeMailbox, FakeImap]:
    box = SafeMailbox(fake_gate(), profile(**over))
    box.connect()
    return box, FakeImap.instances[-1]


def verbs(client: FakeImap) -> list[Any]:
    return [c[0] if c[0] != "uid" else f"UID {c[1]}" for c in client.calls]


# --- the gate and TLS ----------------------------------------------------------------------


def test_a_closed_gate_creates_no_client() -> None:
    box = SafeMailbox(fake_gate(open_=False), profile())
    with pytest.raises(MailboxError) as exc:
        box.connect()
    assert exc.value.code == "egress_closed"
    assert FakeImap.instances == []


def test_starttls_is_done_before_login() -> None:
    box, client = opened()
    box.login()
    assert verbs(client)[:2] == ["starttls", "login"]
    assert client.calls[1][1:] == ("reporter", "hunter2-sample")
    assert box.move_supported


def test_a_server_without_starttls_is_refused_and_never_sees_the_password() -> None:
    FakeImap.caps = ("IMAP4REV1",)
    box = SafeMailbox(fake_gate(), profile())
    with pytest.raises(MailboxError) as exc:
        box.connect()
    assert exc.value.code == "tls_failed"
    assert "login" not in verbs(FakeImap.instances[-1])


def test_implicit_tls_gets_a_verifying_context() -> None:
    box, client = opened(security="ssl", port=993)
    context = client.kw["ssl_context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert "starttls" not in verbs(client)
    box.logout()


def test_no_move_capability() -> None:
    FakeImap.caps = ("IMAP4REV1", "STARTTLS")
    box, _ = opened()
    assert not box.move_supported


# --- the wire vocabulary -------------------------------------------------------------------


def test_select_quotes_the_folder_and_reads_uidvalidity() -> None:
    box, client = opened(folder="INBOX/Abuse")
    selected = box.select("INBOX/Abuse")
    assert (selected.uidvalidity, selected.exists) == (777, 3)
    assert client.calls[-1] == ("select", '"INBOX/Abuse"', False)
    box.select("INBOX", readonly=True)
    assert client.calls[-1] == ("select", '"INBOX"', True)


@pytest.mark.parametrize(
    "name", ['a"b', "a\\b", "a*b", "a%b", "a\r\nb", "", "x" * 101, "dossier é"]
)
def test_a_bad_folder_name_is_refused(name: str) -> None:
    assert not valid_folder(name)
    box, _ = opened()
    with pytest.raises(MailboxError) as exc:
        box.select(name)
    assert exc.value.code == "no_folder"


def test_search_never_uses_unseen_and_filters_old_uids() -> None:
    box, client = opened()
    FakeImap.answers["SEARCH"] = [b"40 41 5 42 x 43"]
    found = box.search_new(40, date(2026, 11, 1), 3)
    assert found == [41, 42, 43]
    cmd = client.calls[-1]
    assert cmd[:2] == ("uid", "SEARCH")
    assert cmd[2:] == ("UID", "41:*", "SINCE", "01-Nov-2026")
    assert "UNSEEN" not in " ".join(map(str, client.calls))
    assert box.search_new(0, date(2026, 11, 1), 2) == [5, 40]


def test_search_last_asks_for_a_bounded_sequence_range() -> None:
    box, client = opened()
    FakeImap.answers["SEARCH"] = [b"90 91 x 99"]
    assert box.search_last(120, 20) == [90, 91, 99]
    assert client.calls[-1] == ("uid", "SEARCH", "101:120")
    assert box.search_last(5, 20) == [90, 91, 99]
    assert client.calls[-1] == ("uid", "SEARCH", "1:5")
    calls = len(client.calls)
    assert box.search_last(0, 20) == [] and len(client.calls) == calls


def test_headers_are_fetched_with_peek_in_bounded_batches() -> None:
    box, client = opened()
    FakeImap.answers["FETCH"] = [None]
    box.fetch_headers(list(range(1, 61)))
    fetches = [c for c in client.calls if c[:2] == ("uid", "FETCH")]
    assert [len(c[2].split(",")) for c in fetches] == [25, 25, 10]
    for call in fetches:
        spec = call[3]
        assert "BODY.PEEK[HEADER.FIELDS (FROM SUBJECT" in spec and "<0.65536>" in spec
        assert "BODY[" not in spec.replace("BODY.PEEK[", "")  # never a non-peek fetch
        assert "RFC822.SIZE" in spec and "INTERNALDATE" in spec


def test_a_partial_body_is_fetched_with_peek_and_capped() -> None:
    box, client = opened()
    FakeImap.answers["FETCH"] = [(b"5 (UID 9 BODY[]<0> {9}", b"123456789"), b")"]
    assert box.fetch_partial(9, 4) == b"1234"
    assert client.calls[-1][2:] == ("9", "(BODY.PEEK[]<0.4>)")


def test_mark_seen_writes_only_the_seen_flag() -> None:
    box, client = opened()
    box.mark_seen(41)
    assert client.calls[-1] == ("uid", "STORE", "41", "+FLAGS.SILENT", "(\\Seen)")


@pytest.mark.parametrize(
    "args",
    [
        ("STORE", "1", "+FLAGS", "(\\Deleted)"),
        ("STORE", "1", "+FLAGS.SILENT", "(\\Deleted)"),
        ("STORE", "1", "-FLAGS.SILENT", "(\\Seen)"),
        ("EXPUNGE",),
        ("COPY", "1", '"x"'),
        ("APPEND",),
    ],
)
def test_nothing_else_can_be_sent(args: tuple[str, ...]) -> None:
    box, client = opened()
    before = len(client.calls)
    with pytest.raises(MailboxError):
        box._uid(*args)
    assert len(client.calls) == before  # refused before the wire


def test_move_uses_uid_move_with_a_quoted_folder() -> None:
    box, client = opened()
    assert box.move(41, "INBOX/Done") is True
    assert client.calls[-1] == ("uid", "MOVE", "41", '"INBOX/Done"')


def test_move_without_the_capability_marks_seen_instead() -> None:
    FakeImap.caps = ("IMAP4REV1", "STARTTLS")
    box, client = opened()
    assert box.move(41, "INBOX/Done") is False
    assert client.calls[-1] == ("uid", "STORE", "41", "+FLAGS.SILENT", "(\\Seen)")


def test_move_to_a_missing_folder_has_its_own_code() -> None:
    box, _ = opened()
    FakeImap.fail["uid"] = ImapError("NO folder missing: secret server text")
    with pytest.raises(MailboxError) as exc:
        box.move(41, "Missing")
    assert exc.value.code == "no_move_folder"
    assert "secret" not in str(exc.value)


def test_list_folders_is_sanitised_and_capped() -> None:
    box, _ = opened()
    lines = [
        b'(\\HasNoChildren) "/" "INBOX"',
        b'(\\Noselect) "/" "[Gmail]"',
        b'(\\HasNoChildren) "/" "bad\\"name"',
    ]
    lines += [f'(\\HasNoChildren) "/" "F{i}"'.encode() for i in range(80)]
    FakeImap.answers["LIST"] = lines
    names = box.list_folders()
    assert names[0] == "INBOX" and "[Gmail]" not in names and len(names) == 50
    assert all(valid_folder(n) for n in names)


# --- errors become constant codes ----------------------------------------------------------


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (ImapError("NO [AUTHENTICATIONFAILED] secret server text"), "auth_failed"),
        (ssl.SSLCertVerificationError("bad cert for imap.example.org"), "tls_failed"),
        (TimeoutError("slow"), "timeout"),
        (ConnectionResetError("reset"), "network"),
        (EOFError(), "network"),
    ],
)
def test_login_errors(exc: BaseException, code: str) -> None:
    box, _ = opened()
    FakeImap.fail["login"] = exc
    with pytest.raises(MailboxError) as raised:
        box.login()
    assert raised.value.code == code
    assert "secret" not in str(raised.value) and "example.org" not in str(raised.value)


def test_select_failure_is_no_folder() -> None:
    box, _ = opened()
    FakeImap.fail["select"] = ImapError("NO nothing there")
    with pytest.raises(MailboxError) as raised:
        box.select("INBOX")
    assert raised.value.code == "no_folder"


def test_the_deadline_shuts_the_socket_and_ends_the_poll() -> None:
    box, client = opened()
    box._expire()
    assert client.sock.shut and client.sock.closed
    with pytest.raises(MailboxError) as raised:
        box.search_new(0, date(2026, 11, 1), 5)
    assert raised.value.code == "timeout"


def test_every_operation_gets_a_socket_timeout() -> None:
    box, client = opened()
    box.mark_seen(1)
    assert client.sock.timeouts and max(client.sock.timeouts) <= imap_mod.IO_TIMEOUT_S


def test_logout_always_closes() -> None:
    box, client = opened()
    box.logout()
    assert "logout" in verbs(client) and client.sock.closed
    box.logout()  # twice is fine


# --- parsing a header FETCH ----------------------------------------------------------------


def test_header_items() -> None:
    when = 'INTERNALDATE "01-Nov-2026 09:30:00 +0100"'
    data: list[Any] = [
        (
            f"1 (UID 41 RFC822.SIZE 2048 {when} BODY[HEADER.FIELDS (FROM)]<0> {{20}}".encode(),
            b"From: a@example.net\r\n",
        ),
        b")",
        (b"2 (BODY[HEADER.FIELDS (FROM)]<0> {5}", b"X: y\r\n"),
        b" UID 42 RFC822.SIZE 99)",
        (b"3 (UID 43 BODY[HEADER.FIELDS (FROM)]<0> {10}", b"A" * imap_mod.HEADER_LIMIT),
        b")",
        b"not a tuple",
    ]
    items = _header_items(data)
    assert [(i.uid, i.size) for i in items] == [(41, 2048), (42, 99), (43, 0)]
    assert items[0].internal_date == datetime(2026, 11, 1, 8, 30, tzinfo=UTC)
    assert items[0].headers.startswith(b"From:") and not items[0].oversize
    assert items[2].oversize
    assert _header_items([None, b")"]) == []
