"""What a reply teaches about the desk: web form only, dead address (units; the database part
is in ``test_worker_integration``)."""

from __future__ import annotations

import pytest

from ingest.replies.desk import form_url_of, hard_bounce, host_of_url, user_unknown
from ingest.replies.parse import ParsedReply, parse_message

from . import mails


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "Please use https://support.example.net/abuse-form to report.",
            "https://support.example.net/abuse-form",
        ),
        ("Form: <https://support.example.net/f?x=1>.", "https://support.example.net/f?x=1"),
        ("See (https://support.example.net/form).", "https://support.example.net/form"),
        # The first usable link wins; a bad one before it is skipped.
        (
            "https://user:pw@evil.example.net/x then https://ok.example.org/f",
            "https://ok.example.org/f",
        ),
        ("Only http://support.example.net/form here", None),
        ("javascript:alert(1) and https://192.0.2.7/form", None),
        ("https://exa mple.net/", None),
        ("no link at all", None),
        ("https://" + "a" * 600 + ".example.net/", None),
    ],
)
def test_form_url_of(text: str, expected: str | None) -> None:
    assert form_url_of(text) == expected


def test_hard_bounce_and_user_unknown() -> None:
    gone = parse_message(mails.dsn(status="5.1.1"))
    assert hard_bounce(gone) and user_unknown(gone)
    blocked = parse_message(mails.dsn(status="5.7.1"))
    assert hard_bounce(blocked) and not user_unknown(blocked)
    delayed = parse_message(mails.dsn(action="delayed", status="4.4.1"))
    assert not hard_bounce(delayed)


def test_a_bounce_without_a_status_is_read_from_its_text() -> None:
    text = ParsedReply(body="550 User not found\r\n")
    assert hard_bounce(text) and user_unknown(text)
    assert hard_bounce(ParsedReply(body="550 Message blocked")) is True
    assert not user_unknown(ParsedReply(body="550 Message blocked"))
    assert not hard_bounce(ParsedReply(body="Thanks for your report"))


def test_a_code_inside_a_sentence_or_the_quoted_report_is_not_a_bounce() -> None:
    assert not hard_bounce(ParsedReply(body="We saw 1550 sessions from your host\r\n"))
    assert not hard_bounce(ParsedReply(body="Thanks, looking at it.\r\n> 550 User not found\r\n"))
    assert not hard_bounce(
        ParsedReply(body="Thanks.\r\n\r\n-----Original message-----\r\n550 User not found\r\n")
    )
    assert not hard_bounce(ParsedReply(body="Ports 5500 and 550 were hit"))
    assert hard_bounce(ParsedReply(body="Delivery failed\r\n554 5.7.1 blocked\r\n"))


def test_host_of_url() -> None:
    assert host_of_url("https://support.example.net:8443/a?b") == "support.example.net"
