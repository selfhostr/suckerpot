"""M26: the reply token (O6). Random, printed in the subject, never in an export."""

from __future__ import annotations

import base64
import json
import re
import uuid

import pytest

from suckerpot_reporting import (
    GuardContext,
    ReferenceStyle,
    RenderUnavailable,
    ReportSettings,
    SelfTerms,
    guard_message,
    message_subject,
    new_reply_token,
    render_csv,
    render_eml,
    render_mail,
    render_misp,
    render_stix,
    render_text,
    report_stem,
    stix_dumps,
)
from tests.conftest import SEED, SESSION_ID, SETTINGS, make_evidence, make_export

TOKEN = "3f9a1c7b2e4d"  # gitleaks:allow (a sample token)
HEX12 = re.compile(r"^[0-9a-f]{12}$")


def test_new_reply_token_format_and_uniqueness() -> None:
    draws = {new_reply_token() for _ in range(10_000)}
    assert len(draws) == 10_000
    assert all(HEX12.match(t) for t in draws)


def test_the_token_is_not_derived_from_any_id() -> None:
    assert TOKEN not in SEED.hex and new_reply_token() != SEED.hex[:12]


def test_subject_without_a_placeholder_gets_a_suffix() -> None:
    subject = message_subject(make_evidence(), SETTINGS, reply_token=TOKEN)
    assert subject.endswith(f" (ref {TOKEN})")
    assert subject.startswith("Attack from ")


def test_subject_with_the_placeholder_is_not_doubled() -> None:
    cfg = ReportSettings(
        reply_contact="reports@example.org", subject_template="Abuse {value} [{ref}]"
    )
    subject = message_subject(make_evidence(), cfg, reply_token=TOKEN)
    assert subject.endswith(f"[ref {TOKEN}]")
    assert subject.count(TOKEN) == 1


def test_off_and_missing_token_leave_the_subject_alone() -> None:
    plain = message_subject(make_evidence(), SETTINGS)
    assert TOKEN not in plain
    assert (
        message_subject(make_evidence(), SETTINGS, reply_token=TOKEN, reference_style="off")
        == plain
    )
    cfg = ReportSettings(reply_contact="reports@example.org", subject_template="A {value} {ref}")
    assert "ref" not in message_subject(
        make_evidence(), cfg, reply_token=TOKEN, reference_style="off"
    )


def test_a_long_subject_keeps_the_token() -> None:
    cfg = ReportSettings(reply_contact="reports@example.org", subject_template="x" * 200)
    subject = message_subject(make_evidence(), cfg, reply_token=TOKEN)
    assert len(subject) <= 150 and subject.endswith(f"(ref {TOKEN})")


def test_the_demo_prefix_and_the_token_coexist() -> None:
    subject = message_subject(make_evidence(demo=True), SETTINGS, reply_token=TOKEN)
    assert subject.startswith("DEMO, DO NOT SEND: ") and TOKEN in subject


@pytest.mark.parametrize(
    "bad", ["ABCDEF123456", "3f9a1c7b2e4", "3f9a1c7b2e4dd", "not-a-token!", ""]
)
def test_a_malformed_token_is_refused(bad: str) -> None:
    with pytest.raises(RenderUnavailable):
        message_subject(make_evidence(), SETTINGS, reply_token=bad)


def test_an_unknown_style_is_refused() -> None:
    with pytest.raises(RenderUnavailable):
        message_subject(make_evidence(), SETTINGS, reply_token=TOKEN, reference_style="body")  # type: ignore[arg-type]


def test_the_body_line_only_with_subject_and_body() -> None:
    plain = render_text(make_evidence(), SETTINGS, reply_token=TOKEN)
    assert "Ref:" not in plain.body and TOKEN not in plain.body
    both = render_text(
        make_evidence(), SETTINGS, reply_token=TOKEN, reference_style="subject_and_body"
    )
    assert both.body.rstrip().endswith(f"Ref: {TOKEN}")
    assert TOKEN in both.subject
    off = render_text(make_evidence(), SETTINGS, reply_token=TOKEN, reference_style="off")
    assert TOKEN not in off.body and TOKEN not in off.subject


def test_defaults_keep_todays_output() -> None:
    assert render_text(make_evidence(), SETTINGS) == render_text(
        make_evidence(), SETTINGS, reply_token=None, reference_style="subject"
    )


def test_the_token_stays_out_of_every_export_and_name() -> None:
    evidence = make_evidence()
    single = render_mail(evidence, SETTINGS, reply_token=TOKEN, reference_style="subject_and_body")
    assert single.layout == "report"
    assert TOKEN in single.subject and TOKEN in single.body  # the human part only
    for att in single.attachments:  # the XARF JSON part and the evidence CSV
        assert TOKEN not in att.content, att.name
        assert TOKEN not in att.name
    parsed = json.loads(single.attachments[0].content)
    payload = base64.b64decode(parsed["evidence"][0]["payload"]).decode()
    assert TOKEN not in json.dumps(parsed) and TOKEN not in payload
    assert TOKEN not in (single.feedback or "")
    assert TOKEN not in render_csv(evidence).content
    data = make_export()
    assert TOKEN not in stix_dumps(render_stix(data))
    assert TOKEN not in json.dumps(render_misp(data), default=str)
    assert TOKEN not in report_stem(uuid.uuid4())


def test_the_multi_subject_summary_also_carries_it_in_the_subject_only() -> None:
    msg = render_mail(make_evidence(), SETTINGS, reply_token=TOKEN)
    assert TOKEN in msg.subject
    for att in msg.attachments:
        assert TOKEN not in att.content


def test_the_eml_has_the_token_in_the_subject_header_only() -> None:
    msg = render_text(make_evidence(), SETTINGS, reply_token=TOKEN)
    raw = render_eml(msg).decode("ascii")
    head, _, body = raw.partition("\r\n\r\n")
    assert f"(ref {TOKEN})" in head and TOKEN not in body


def test_the_guard_passes_a_message_with_a_token(terms: SelfTerms, ctx: GuardContext) -> None:
    styles: tuple[ReferenceStyle, ...] = ("subject", "subject_and_body")
    for style in styles:
        msg = render_text(make_evidence(), SETTINGS, reply_token=TOKEN, reference_style=style)
        result = guard_message(msg, terms, ctx=ctx)
        assert result.ok, result.codes


def test_the_guard_fails_when_a_seed_or_a_session_id_stands_in_for_the_token(
    terms: SelfTerms,
) -> None:
    ctx = GuardContext(internal_ids=frozenset({SESSION_ID, SEED.hex}), allow_documentation=True)
    for leak in (SEED.hex, SESSION_ID):
        cfg = ReportSettings(
            reply_contact="reports@example.org", subject_template="Abuse {value} (ref " + leak + ")"
        )
        msg = render_text(make_evidence(), cfg)
        result = guard_message(msg, terms, ctx=ctx)
        assert not result.ok and "internal_id" in result.codes, leak
    # The same facts with a real token are clean.
    assert guard_message(
        render_text(make_evidence(), SETTINGS, reply_token=TOKEN), terms, ctx=ctx
    ).ok
