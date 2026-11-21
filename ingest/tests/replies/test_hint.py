"""The provider-name hint: only the top-most Authentication-Results counts, and only a valid name
ever leaves the parser. "Test connection" reads recent headers with PEEK and reports the hint."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import date

from ingest.features import FeatureSettings
from ingest.replies.config import RepliesSettings
from ingest.replies.imap import HeaderItem, ImapProfile, MailboxError, Selected
from ingest.replies.parse import authserv_hint, authserv_sample, top_authserv_id
from ingest.replies.worker import HINT_MESSAGES, ReplyWorker

from ..helpers import fake_gate


def head(*results: str, sender: str = "example.net") -> bytes:
    lines = [f"Authentication-Results: {r}\r\n" for r in results]
    return ("".join(lines) + f"From: abuse@{sender}\r\nSubject: Hi\r\n\r\n").encode()


def senders(n: int, *results: str, start: int = 0) -> list[bytes]:
    """``n`` blocks, each from its own sender domain."""
    return [head(*results, sender=f"d{start + i}.example.net") for i in range(n)]


def test_only_the_top_most_header_counts() -> None:
    assert top_authserv_id(head("MX.Example.ORG; dkim=pass", "forged.example.net; dkim=pass")) == (
        "mx.example.org"
    )
    assert top_authserv_id(head()) is None


def test_a_value_that_is_not_a_name_is_dropped() -> None:
    for bad in (
        "<script>; dkim=pass",
        "spf=pass (sender IP) smtp.mailfrom=example.net",
        "x" * 300,
        "; dkim=pass",
        "mx_1.example.org",
    ):
        assert top_authserv_id(head(bad)) is None
    assert top_authserv_id(b"\xff\xfe garbage") is None


def hint(blocks: list[bytes]) -> dict[str, object] | None:
    return authserv_hint(authserv_sample(b) for b in blocks)


def test_the_sample_is_the_name_and_the_sender_domain() -> None:
    assert authserv_sample(head("mx.example.org", sender="Example.NET")) == (
        "mx.example.org",
        "example.net",
    )
    assert authserv_sample(b"\xff garbage") == ("", "")


def test_a_forged_lower_header_does_not_win() -> None:
    blocks = senders(3, "mx.example.org", "evil.example.net")
    blocks += [head("evil.example.net")]
    assert hint(blocks) == {"id": "mx.example.org", "seen": 3, "of": 4}
    assert hint([head(), head("bad!value; dkim=pass")]) is None


def test_the_normal_case_gives_a_hint() -> None:
    assert hint(senders(18, "mx.example.org") + [head()] * 2) == {
        "id": "mx.example.org",
        "seen": 18,
        "of": 20,
    }


def test_a_single_sender_forging_a_name_gives_no_hint() -> None:
    # The provider adds no header of its own: the top-most one is the sender's.
    assert hint([head("spam.example.com", sender="spam.example.com")] * 20) is None
    assert hint([head("spam.example.com", sender="spam.example.com")] * 10 + [head()] * 2) is None


def test_three_senders_under_half_of_the_messages_give_no_hint() -> None:
    assert hint(senders(3, "mx.example.org") + senders(4, start=10)) is None
    assert hint(senders(3, "mx.example.org") + senders(3, start=10)) is not None  # exactly half


def test_two_sender_domains_are_not_enough() -> None:
    blocks = [head("mx.example.org", sender=f"d{i % 2}.example.net") for i in range(10)]
    assert hint(blocks) is None


@dataclass
class Box:
    blocks: list[bytes]
    fail: str | None = None
    move_supported: bool = True
    calls: list[str] = field(default_factory=list)

    def connect(self) -> None: ...
    def login(self) -> None: ...

    def select(self, folder: str, *, readonly: bool = False) -> Selected:
        assert readonly  # the test never opens the folder read-write
        return Selected(1, len(self.blocks))

    def search_new(self, last_uid: int, since: date, limit: int) -> list[int]:
        raise AssertionError

    def search_last(self, exists: int, limit: int) -> list[int]:
        self.calls.append(f"search_last {exists} {limit}")
        if self.fail:
            raise MailboxError(self.fail)
        return list(range(1, exists + 1))[-limit:]

    def fetch_headers(self, uids: list[int]) -> list[HeaderItem]:
        self.calls.append("fetch_headers")
        return [HeaderItem(u, 100, None, self.blocks[u - 1], False) for u in uids]

    def fetch_partial(self, uid: int, size: int) -> bytes:
        raise AssertionError

    def mark_seen(self, uid: int) -> None:
        raise AssertionError

    def move(self, uid: int, folder: str) -> bool:
        raise AssertionError

    def list_folders(self) -> list[str]:
        return ["INBOX"]

    def logout(self) -> None: ...


PROFILE = ImapProfile(
    "imap.example.org", 993, "ssl", "reports", "INBOX", "mark_read", None, 15, date(2026, 1, 1)
)


def run_test(box: Box) -> tuple[dict[str, object], str | None]:
    worker = ReplyWorker(
        FeatureSettings(replies_enabled=True),
        replies=RepliesSettings(),
        gate=fake_gate(),
        mailbox_factory=lambda profile, gate, deadline: box,
    )
    return asyncio.run(worker._test(PROFILE))


def test_the_connection_test_reports_the_most_common_provider() -> None:
    blocks = senders(18, "mx.example.org; dkim=pass") + senders(7, "other.example.net", start=50)
    box = Box(blocks)
    result, code = run_test(box)
    assert code is None and result["ok"] is True
    assert result["authserv_hint"] == {"id": "mx.example.org", "seen": 13, "of": HINT_MESSAGES}
    assert box.calls == [f"search_last 25 {HINT_MESSAGES}", "fetch_headers"]


def test_a_failed_header_read_only_drops_the_hint() -> None:
    result, code = run_test(Box([head("mx.example.org")], fail="protocol"))
    assert code is None and result["ok"] is True and result["authserv_hint"] is None


def test_an_empty_folder_has_no_hint() -> None:
    box = Box([])
    result, _ = run_test(box)
    assert result["authserv_hint"] is None
