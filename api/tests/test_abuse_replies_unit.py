"""M26 helpers that need no database: what a viewer may see, the outcome shape, the validators."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from api.abuse_core import reply_args
from api.abuse_imap import ImapBody, authserv_hint, mailbox_is_shared, valid_folder
from api.abuse_outcomes import _bucket_start, _next_bucket, _window, no_answer_days, to_out
from api.abuse_replies import (
    ImportJson,
    ReplyPatch,
    _multipart_file,
    mask_reference,
    reply_out,
)

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
REPORT = uuid.UUID("33333333-3333-4333-8333-333333333333")


def reply(**over: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "id": 7,
        "source": "imap",
        "received_at": NOW,
        "date_header": None,
        "from_address": "desk@example.net",
        "from_domain": "example.net",
        "subject": "Re: report",
        "auth": "none",
        "report_id": 5,
        "match_method": "token",
        "verified": True,
        "classification": "human_reply",
        "classification_source": "rule",
        "rule_id": None,
        "ticket_id": None,
        "dsn_status": None,
        "truncated": False,
        "attachments": {"count": 1, "types": ["application/pdf"], "bytes": 10},
        "excerpt": "We looked into it.",
        "excerpt_purged_at": None,
        "reviewed_at": None,
        "reviewed_by": None,
    }
    base.update(over)
    return SimpleNamespace(**base)


def test_a_viewer_sees_the_domain_but_not_the_address_or_the_excerpt() -> None:
    row = reply(reviewed_by="admin")
    viewer = reply_out(row, REPORT, admin=False)  # type: ignore[arg-type]
    assert viewer.from_domain == "example.net"
    assert viewer.from_address is None and viewer.excerpt is None and viewer.reviewed_by is None
    dumped = viewer.model_dump_json()
    assert "desk@" not in dumped and "looked into" not in dumped
    owner = reply_out(row, REPORT, admin=True)  # type: ignore[arg-type]
    assert owner.from_address == "desk@example.net" and owner.excerpt == "We looked into it."
    assert owner.report == str(REPORT) and owner.reviewed_by == "admin"


@pytest.mark.parametrize(
    ("over", "waiting"),
    [
        ({}, False),
        ({"report_id": None}, True),
        ({"verified": False}, True),
        ({"classification": "bounce"}, True),
        ({"verified": False, "reviewed_at": NOW}, False),
        ({"report_id": None, "reviewed_at": NOW}, False),
    ],
)
def test_needs_review(over: dict[str, Any], waiting: bool) -> None:
    assert reply_out(reply(**over), None, admin=True).needs_review is waiting  # type: ignore[arg-type]


def test_a_purged_excerpt_is_flagged() -> None:
    out = reply_out(reply(excerpt=None, excerpt_purged_at=NOW), None, admin=True)  # type: ignore[arg-type]
    assert out.excerpt is None and out.excerpt_purged is True


def test_odd_attachment_data_cannot_break_the_answer() -> None:
    out = reply_out(reply(attachments={"types": list("abcdefghijklmnop")}), None, admin=False)  # type: ignore[arg-type]
    assert out.attachments.count == 0 and len(out.attachments.types) == 10


# ---- patch and import bodies -----------------------------------------------------------------


def test_patch_bodies_refuse_unknown_fields_and_classes() -> None:
    assert ReplyPatch.model_validate({"report": None}).model_fields_set == {"report"}
    for bad in (
        {"surprise": 1},
        {"classification": "angry"},
        {"report": "nope"},
        {"ticket_id": "x" * 65},
    ):
        with pytest.raises(ValidationError):
            ReplyPatch.model_validate(bad)


def test_import_bodies() -> None:
    assert ImportJson.model_validate({"raw": "Subject: x"}).report is None
    for bad in ({"raw": ""}, {"raw": "x" * 262_145}, {"raw": "x", "extra": 1}):
        with pytest.raises(ValidationError):
            ImportJson.model_validate(bad)


def test_the_multipart_reader() -> None:
    body = (
        b'--B\r\nContent-Disposition: form-data; name="report"\r\n\r\n'
        + str(REPORT).encode()
        + b'\r\n--B\r\nContent-Disposition: form-data; name="file"; filename="a.eml"\r\n'
        b"Content-Type: message/rfc822\r\n\r\nSubject: hi\r\n\r\nbody\r\n--B--\r\n"
    )
    file, report = _multipart_file("multipart/form-data; boundary=B", body)
    assert file is not None and file.startswith(b"Subject: hi") and report == str(REPORT)
    assert _multipart_file("multipart/form-data; boundary=B", b"garbage") == (None, None)
    assert _multipart_file("multipart/form-data", b"x") == (None, None)
    quoted = _multipart_file('multipart/form-data; boundary="B"', body)
    assert quoted[0] is not None and quoted[0].endswith(b"body")  # message/rfc822 stays bytes
    # A file name is not a field name.
    tricky = (
        b'--B\r\nContent-Disposition: form-data; name="x"; filename="file"\r\n\r\nno\r\n--B--\r\n'
    )
    assert _multipart_file("multipart/form-data; boundary=B", tricky) == (None, None)


# ---- the profile -----------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["INBOX", "INBOX/Abuse replies", "Archive.2026", "a" * 100])
def test_folder_names(name: str) -> None:
    assert valid_folder(name)


@pytest.mark.parametrize(
    "name", ["", 'a"b', "a\\b", "a*", "a%", "a\r\nb", "a\x00b", "é", "a" * 101]
)
def test_bad_folder_names(name: str) -> None:
    assert not valid_folder(name)


def profile_body(**over: Any) -> dict[str, Any]:
    return {
        "host": "imap.example.org",
        "port": 993,
        "security": "ssl",
        "username": "reports@example.org",
        "current_password": "x",
    } | over


def test_the_profile_body() -> None:
    body = ImapBody.model_validate(profile_body())
    assert (
        body.folder == "INBOX" and body.poll_minutes == 15 and body.processed_action == "mark_read"
    )
    assert "password" not in repr(ImapBody.model_validate(profile_body(password="hunter2-sample")))
    for bad in (
        {"security": "plain"},
        {"poll_minutes": 4},
        {"poll_minutes": 1441},
        {"port": 0},
        {"processed_action": "delete"},
        {"extra_field": 1},
        {"username": ""},
    ):
        with pytest.raises(ValidationError):
            ImapBody.model_validate(profile_body(**bad))


# ---- outcomes --------------------------------------------------------------------------------


def outcome_row(**over: Any) -> SimpleNamespace:
    base = {
        "auto_outcome": "none",
        "manual_outcome": None,
        "needs_review": False,
        "reply_count": 0,
        "first_reply_at": None,
        "first_human_at": None,
        "ticket_at": None,
        "resolved_at": None,
        "rejected_at": None,
        "bounced_at": None,
        "ticket_id": None,
        "manual_at": None,
        "manual_by": None,
        "note": None,
    }
    return SimpleNamespace(**(base | over))


def test_the_effective_outcome_prefers_the_owner() -> None:
    sent = NOW - timedelta(days=2)
    out = to_out(outcome_row(auto_outcome="auto_ack", manual_outcome="resolved"), sent, NOW)
    assert (out.effective, out.auto, out.manual) == ("resolved", "auto_ack", "resolved")
    assert to_out(outcome_row(auto_outcome="auto_ack"), sent, NOW).effective == "auto_ack"


def test_no_answer() -> None:
    assert to_out(None, NOW - timedelta(days=15), NOW).no_answer is True
    assert to_out(None, NOW - timedelta(days=5), NOW).no_answer is False
    assert (
        to_out(outcome_row(auto_outcome="auto_ack"), NOW - timedelta(days=30), NOW).no_answer
        is False
    )
    assert (
        to_out(outcome_row(manual_outcome="none"), NOW - timedelta(days=30), NOW).no_answer is True
    )
    assert to_out(None, None, NOW).no_answer is False


def test_the_delay_to_the_first_reply() -> None:
    sent = NOW - timedelta(days=1)
    out = to_out(outcome_row(first_reply_at=sent + timedelta(hours=2)), sent, NOW)
    assert out.first_reply_after_s == 7200


def test_the_no_answer_period_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    assert no_answer_days() == 14
    monkeypatch.setenv("ABUSE_NO_ANSWER_DAYS", "30")
    assert no_answer_days() == 30
    for bad in ("0", "x", "9999", ""):
        monkeypatch.setenv("ABUSE_NO_ANSWER_DAYS", bad)
        assert no_answer_days() == 14


def test_the_window() -> None:
    assert _window(None, NOW) is not None
    start, end = _window(NOW - timedelta(days=730), NOW)  # type: ignore[misc]
    assert end - start == timedelta(days=730)
    assert _window(NOW - timedelta(days=731), NOW) is None
    assert _window(NOW, NOW) is None
    assert _window(NOW + timedelta(days=1), NOW) is None


def test_buckets() -> None:
    wed = datetime(2026, 11, 4, 15, 30, tzinfo=UTC)
    assert _bucket_start(wed, "week") == datetime(2026, 11, 2, tzinfo=UTC)
    assert _bucket_start(wed, "month") == datetime(2026, 11, 1, tzinfo=UTC)
    assert _next_bucket(datetime(2026, 11, 2, tzinfo=UTC), "week") == datetime(
        2026, 11, 9, tzinfo=UTC
    )
    assert _next_bucket(datetime(2026, 11, 1, tzinfo=UTC), "month") == datetime(
        2026, 12, 1, tzinfo=UTC
    )
    assert _next_bucket(datetime(2026, 12, 1, tzinfo=UTC), "month") == datetime(
        2027, 1, 1, tzinfo=UTC
    )


def test_a_viewer_never_sees_the_reply_token_in_a_subject() -> None:
    row = reply(subject="Re: Abuse report (ref 3f9a1c7b2e4d) for 198.51.100.23")
    viewer = reply_out(row, REPORT, admin=False)  # type: ignore[arg-type]
    assert "3f9a1c7b2e4d" not in viewer.model_dump_json()
    assert viewer.subject and "198.51.100.23" in viewer.subject and "ref" in viewer.subject
    owner = reply_out(row, REPORT, admin=True)  # type: ignore[arg-type]
    assert owner.subject and "3f9a1c7b2e4d" in owner.subject
    assert mask_reference(None) is None
    assert "0123456789ab" not in (mask_reference("REF: 0123456789ab and ref#0123456789ab") or "")


def test_a_viewer_render_carries_no_reply_token() -> None:
    row = SimpleNamespace(reply_token="3f9a1c7b2e4d")  # gitleaks:allow
    bundle = SimpleNamespace(reference_style="subject_and_body")
    assert reply_args(row, bundle, admin=True) == {  # type: ignore[arg-type]
        "reply_token": "3f9a1c7b2e4d",  # gitleaks:allow
        "reference_style": "subject_and_body",
    }
    assert reply_args(row, bundle, admin=False) == {  # type: ignore[arg-type]
        "reply_token": None,
        "reference_style": "off",
    }


def test_free_mail_mailboxes_are_flagged() -> None:
    assert mailbox_is_shared("imap.gmail.com", "reports@example.org")
    assert mailbox_is_shared("mail.example.org", "me@outlook.com")
    assert not mailbox_is_shared("imap.example.org", "reports@example.org")


def test_only_a_valid_provider_hint_is_passed_on() -> None:
    good = {"id": "MX.Example.org", "seen": 18, "of": 20}
    assert authserv_hint(good) == {"id": "mx.example.org", "seen": 18, "of": 20}
    for bad in (
        None,
        "mx.example.org",
        {"id": "<b>x</b>", "seen": 1, "of": 1},
        {"id": "mx example", "seen": 1, "of": 1},
        {"id": "x" * 256, "seen": 1, "of": 1},
        {"id": "mx.example.org", "seen": 3, "of": 2},
        {"id": "mx.example.org", "seen": 0, "of": 2},
        {"id": "mx.example.org", "seen": "1", "of": 2},
    ):
        assert authserv_hint(bad) is None
