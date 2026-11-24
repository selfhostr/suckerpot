"""Reply classification: every default rule, precedence, ticket extraction, the loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from ingest.replies.parse import ParsedReply, parse_message
from ingest.replies.rules import (
    ReplyRules,
    TicketRule,
    find_ticket,
    load_reply_rules,
    parse_chars,
)
from ingest.tagging.engine import RuleError

from . import mails
from .mails import mail

RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "replies"


@pytest.fixture(scope="module")
def rules() -> ReplyRules:
    return load_reply_rules(RULES_DIR)


def classify(rules: ReplyRules, raw: bytes, *, matched: bool = True) -> tuple[str, str | None]:
    verdict = rules.classify(parse_message(raw), matched=matched)
    return verdict.outcome, verdict.rule_id


def test_the_shipped_rules_load(rules: ReplyRules) -> None:
    assert [r.priority for r in rules.rules] == sorted(r.priority for r in rules.rules)
    assert {r.outcome for r in rules.rules} == {
        "bounce",
        "resolved",
        "rejected",
        "ticket_opened",
        "auto_ack",
        "human_reply",
        "unknown",
    }
    assert rules.description("auto-ack") == "An automatic acknowledgement."


def test_bounce_by_dsn_and_by_daemon(rules: ReplyRules) -> None:
    assert classify(rules, mails.dsn()) == ("bounce", "bounce-dsn")
    # A delay notice is not a bounce.
    assert classify(rules, mails.dsn(action="delayed"))[0] != "bounce"
    daemon = mail(from_="postmaster@example.net", subject="Mail delivery failed: returning message")
    assert classify(rules, daemon) == ("bounce", "bounce-daemon")


@pytest.mark.parametrize(
    "phrase",
    [
        "the address has been suspended",
        "The server HAS BEEN TERMINATED today",
        "we have taken action against the customer",
        "traffic is null-routed now",
        "the issue has been resolved",
        "the reported address has been blocked",
        "the host is no longer reachable",
    ],
)
def test_resolved(rules: ReplyRules, phrase: str) -> None:
    assert classify(rules, mail(body=f"Hello,\r\n\r\n{phrase}.\r\n")) == (
        "resolved",
        "resolved-action-taken",
    )


def test_resolved_by_subject(rules: ReplyRules) -> None:
    assert classify(rules, mail(subject="Case 4411 resolved"))[0] == "resolved"


@pytest.mark.parametrize(
    ("phrase", "rule"),
    [
        ("this is not our customer", "not-our-customer"),
        ("the range is not hosted by us", "not-our-customer"),
        ("we have insufficient evidence", "insufficient-evidence"),
        ("please use our web form", "form-required"),
        ("Please submit via our portal", "form-required"),
        ("Reports sent to this email address will not be processed", "form-required"),
        ("Please submit your report using webform", "form-required"),
        ("This email inbox is not monitored", "form-required-unmonitored"),
        (
            "We require you to submit all tickets via our online client support portal",
            "form-required",
        ),
    ],
)
def test_rejected(rules: ReplyRules, phrase: str, rule: str) -> None:
    assert classify(rules, mail(body=f"{phrase}\r\n")) == ("rejected", rule)


def test_ticket_opened_by_an_automatic_message_with_an_id(rules: ReplyRules) -> None:
    raw = mail(
        subject="[#48213] We received your report",
        extra={"Auto-Submitted": "auto-replied"},
        body="Thanks. Your ticket has been created.\r\n",
    )
    parsed = parse_message(raw)
    assert rules.extract_ticket(parsed) == "48213"
    assert rules.classify(parsed, matched=True).outcome == "ticket_opened"
    assert rules.classify(parsed, matched=True).ticket_id == "48213"


def test_an_auto_acknowledgement_with_a_ticket_number_is_a_ticket(rules: ReplyRules) -> None:
    raw = mail(
        subject="Automatic reply: your report",
        extra={"Auto-Submitted": "auto-generated"},
        body="Ticket #AB-1234 was opened.\r\n",
    )
    assert classify(rules, raw)[0] == "ticket_opened"
    # Without a number the same mail is only an acknowledgement.
    plain = mail(subject="Automatic reply: your report", extra={"Auto-Submitted": "auto-replied"})
    assert classify(rules, plain) == ("auto_ack", "auto-ack")


@pytest.mark.parametrize(
    "raw",
    [
        mail(extra={"Auto-Submitted": "auto-replied"}),
        mail(extra={"X-Autoreply": "yes"}),
        mail(extra={"Precedence": "auto_reply"}),
        mail(extra={"Precedence": "bulk"}),
        mail(subject="Out of Office"),
        mail(subject="Automatische Antwort: Abuse"),
        mail(subject="Réponse automatique : abus"),
        mail(subject="Respuesta automática"),
        mail(subject="Automatisch antwoord"),
        mail(subject="Resposta automática"),
        mail(body="This is an automated message.\r\n"),
        mail(body="Please do not reply to this mailbox.\r\n"),
    ],
)
def test_auto_ack(rules: ReplyRules, raw: bytes) -> None:
    assert classify(rules, raw) == ("auto_ack", "auto-ack")


def test_a_human_answer_that_says_terminated_is_resolved(rules: ReplyRules) -> None:
    raw = mail(body="Hi, thanks for the report. The service was terminated this morning.\r\n")
    assert classify(rules, raw)[0] == "resolved"


def test_precedence_bounce_then_resolved_then_rejected_then_ticket_then_ack(
    rules: ReplyRules,
) -> None:
    both = mail(
        subject="Automatic reply",
        extra={"Auto-Submitted": "auto-replied"},
        body="The account has been suspended. This is not our customer. Ticket #7788.\r\n",
    )
    assert classify(rules, both)[0] == "resolved"
    rejected = mail(
        extra={"Auto-Submitted": "auto-replied"},
        body="Not our customer. Ticket #7788 opened. This is an automated message.\r\n",
    )
    assert classify(rules, rejected)[0] == "rejected"


def test_fallbacks(rules: ReplyRules) -> None:
    human = mail(body="Hi, could you tell me which log lines you saw? Thanks!\r\n")
    assert classify(rules, human) == ("human_reply", None)
    assert classify(rules, mail(body="ok\r\n")) == ("unknown", None)  # too short
    assert classify(rules, mail(from_="nobody", body="x" * 50)) == ("unknown", None)


def test_the_matched_field_is_available_to_rules(tmp_path: Path) -> None:
    (tmp_path / "10.yaml").write_text(
        "rules:\n  - id: r1\n    outcome: rejected\n    priority: 5\n"
        "    when: {field: matched, equals: false}\n"
    )
    rules = load_reply_rules(tmp_path)
    parsed = ParsedReply(from_domain="example.net", body="x" * 40)
    assert rules.classify(parsed, matched=False).outcome == "rejected"
    assert rules.classify(parsed, matched=True).outcome == "human_reply"


# --- ticket extraction ---------------------------------------------------------------------

GENERIC = TicketRule(
    "t", ("ticket #", "case:", "[#"), ("subject", "body"), 4, 32, parse_chars("A-Za-z0-9-_")
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Your Ticket #48213 is open", "48213"),
        ("Case: INC-0042-X, thanks", "inc-0042-x"),
        ("[#99120] re: report", "99120"),
        ("ticket # 1234567", "1234567"),
        ("case: closed", None),  # no digit
        ("ticket #12", None),  # too short
        ("ticket #" + "9" * 80, None),  # too long
        ("nothing here", None),
    ],
)
def test_find_ticket(text: str, expected: str | None) -> None:
    assert find_ticket(text, GENERIC) == expected


def test_parse_chars() -> None:
    chars = parse_chars("A-Za-z0-9-_")
    assert {"A", "Z", "a", "0", "9", "-", "_"} <= chars and "." not in chars and " " not in chars
    with pytest.raises(RuleError):
        parse_chars("z-a")


# --- the loader refuses a bad file ---------------------------------------------------------

GOOD = "rules:\n  - id: r\n    outcome: rejected\n    priority: 5\n    when: {field: body, contains: x}\n"


def write(tmp_path: Path, content: str) -> Path:
    (tmp_path / "10-x.yaml").write_text(content)
    return tmp_path


@pytest.mark.parametrize(
    "content",
    [
        "rules: not-a-list\n",
        "unknown_key: []\n",
        GOOD.replace("outcome: rejected", "outcome: pwned"),
        GOOD.replace("priority: 5", "priority: 0"),
        GOOD.replace("priority: 5", "priority: 1000"),
        GOOD.replace("priority: 5", "priority: high"),
        GOOD.replace("body", "data.input"),  # a tagging field, not a reply field
        GOOD.replace("contains: x", "regex: x"),  # no regular expressions
        GOOD.replace("contains: x", "contains: 5"),
        GOOD.replace("    priority: 5\n", "    priority: 5\n    extra: 1\n"),
        GOOD + GOOD.split("rules:\n")[1],  # duplicate id
        "rules:\n  - outcome: rejected\n    priority: 1\n    when: {field: body, contains: x}\n",
        "tickets:\n  - id: t\n    after: []\n",
        "tickets:\n  - id: t\n    after: [x]\n    fields: [headers]\n",
        "tickets:\n  - id: t\n    after: [x]\n    min_len: 9\n    max_len: 3\n",
        "tickets:\n  - id: t\n    after: [x]\n    surprise: true\n",
        "{{{{ not yaml",
    ],
)
def test_the_loader_refuses(tmp_path: Path, content: str) -> None:
    with pytest.raises(RuleError):
        load_reply_rules(write(tmp_path, content))


def test_too_many_rules(tmp_path: Path) -> None:
    items = "".join(
        f"  - id: r{i}\n    outcome: rejected\n    priority: 5\n"
        f"    when: {{field: body, contains: x}}\n"
        for i in range(201)
    )
    with pytest.raises(RuleError):
        load_reply_rules(write(tmp_path, "rules:\n" + items))


def test_a_good_file_loads(tmp_path: Path) -> None:
    assert len(load_reply_rules(write(tmp_path, GOOD)).rules) == 1


def test_the_tagging_loader_ignores_the_replies_folder() -> None:
    from ingest.tagging.engine import load_rules

    load_rules(RULES_DIR.parent)  # rules/replies/ is a subfolder: not read as tagging rules


def test_a_delayed_notice_is_neither_an_acknowledgement_nor_a_bounce(rules: ReplyRules) -> None:
    delayed = mails.dsn(action="delayed", status="4.4.1", extra={"Auto-Submitted": "auto-replied"})
    assert classify(rules, delayed) == ("unknown", "delayed-dsn")
    # The text-only form: no machine-readable part, only the subject.
    text_only = mail(
        from_="MAILER-DAEMON <mailer-daemon@mx.example.org>",
        subject="Delayed Mail (still being retried)",
        extra={"Auto-Submitted": "auto-replied"},
        in_reply_to=None,
    )
    assert classify(rules, text_only) == ("unknown", "delayed-dsn")
    # A real failure still bounces.
    assert classify(rules, mails.dsn()) == ("bounce", "bounce-dsn")


def test_forwarding_the_case_to_the_customer_is_not_a_resolution(rules: ReplyRules) -> None:
    raw = mail(
        extra={"Auto-Submitted": "auto-replied"},
        body="We have forwarded the case details to our end customer.\r\n",
    )
    assert classify(rules, raw) == ("human_reply", "forwarded-to-customer")
    # ... unless the same mail also says the provider acted.
    acted = mail(body="We forwarded the case details to our customer. It has been suspended.\r\n")
    assert classify(rules, acted)[0] == "resolved"


def test_logged_and_being_investigated_is_a_ticket(rules: ReplyRules) -> None:
    raw = mail(
        extra={"Auto-Submitted": "auto-replied"},
        body="Your report has been logged as 90417 and is being investigated.\r\n",
    )
    parsed = parse_message(raw)
    assert rules.extract_ticket(parsed) == "90417"
    assert classify(rules, raw) == ("ticket_opened", "ticket-opened")
    # Without a readable id the two phrases still make a ticket.
    no_id = mail(body="Your report has been logged as pending and is being investigated.\r\n")
    assert classify(rules, no_id) == ("ticket_opened", "ticket-logged")
    # One phrase alone is not enough.
    assert (
        classify(rules, mail(body="The case is being investigated by our team, thanks.\r\n"))[0]
        == "human_reply"
    )


QUOTED = (
    "> Abuse report: the address 198.51.100.23 has been suspended in our logs,\r\n"
    "> please use our web form if this is wrong, ticket #99887 is being investigated.\r\n"
)


@pytest.mark.parametrize(
    "body",
    [
        "Thanks, we will look.\r\n\r\n" + QUOTED,
        "Thanks, we will look.\r\n\r\n----- Original message -----\r\n"
        "From: reports@example.org\r\n"
        "The host has been terminated and has been blocked. Please use our web form.\r\n",
        "Thanks, we will look.\r\n\r\nOn Sat, 31 Oct 2026 10:00, reports@example.org wrote:\r\n"
        "The host has been suspended. This is not our customer.\r\n",
        "Thanks, we will look.\r\n\r\n-----Original Message-----\r\n"
        "The service was terminated. The case has been logged as 5512 and is being investigated.\r\n",
    ],
)
def test_our_own_quoted_report_never_triggers_a_rule(rules: ReplyRules, body: str) -> None:
    assert classify(rules, mail(body=body)) == ("human_reply", None)


def test_a_signature_or_an_acknowledgement_is_not_a_web_form_request(rules: ReplyRules) -> None:
    ack = mail(
        subject="[#123] We received your report",
        extra={"Auto-Submitted": "auto-replied"},
        body="This mailbox is not monitored. Your ticket #123 was created.\r\n",
    )
    assert classify(rules, ack)[0] != "rejected"
    signature = mail(
        body="Thanks, we will look.\r\n\r\nFor sales use our web form or the contact form.\r\n"
    )
    assert classify(rules, signature) == ("human_reply", None)
    plain = mail(body="Mail to the old address will not be processed after the move, sorry.\r\n")
    assert classify(rules, plain)[0] != "rejected"


def test_a_ticket_acknowledgement_that_names_a_portal_is_not_a_web_form_request(
    rules: ReplyRules,
) -> None:
    ack = mail(
        extra={"Auto-Submitted": "auto-replied"},
        body="You can follow your ticket #123 via our portal.\r\n",
    )
    assert classify(rules, ack)[0] != "rejected"
    only = mail(body="Reports must go through our portal, nothing else is read.\r\n")
    assert classify(rules, only) == ("rejected", "form-required-portal")


# --- web forms: form only, form preferred, neither -----------------------------------------

ACK = {"Auto-Submitted": "auto-replied"}


@pytest.mark.parametrize(
    ("body", "rule"),
    [
        # A ticket portal that refuses mail, wrapped at 72 columns.
        (
            "Your email to our support system could not be accepted because we require\r\n"
            "you to submit all\r\ntickets via our online client support portal. You can do\r\n"
            "this at the URL below.\r\n\r\nhttps://billing.example.net//submitticket.php\r\n",
            "form-required",
        ),
        ("We no longer accept reports by email.", "form-required"),
        ("We no longer accept abuse reports by e-mail.", "form-required"),
        ("Abuse reports must be submitted through https://example.net/abuse", "form-required"),
        ("Please use our web form at https://example.net/abuse", "form-required"),
        ("Please use the form at https://example.net/abuse", "form-required"),
        ("Kindly use the form at\r\nhttps://example.net/abuse", "form-required"),
        ("Please submit your report through our online form.", "form-required"),
        ("Please submit via our portal.", "form-required"),
        ("We only accept reports via https://example.net/abuse", "form-required"),
        # Refused outright: a polite "we encourage" next to it does not soften it.
        (
            "We no longer accept reports by email. We encourage you to use our abuse form.",
            "form-required",
        ),
        ("This mailbox is not monitored.", "form-required-unmonitored"),
        ("This abuse inbox is no longer monitored.", "form-required-unmonitored"),
        ("Reports go through our portal only.", "form-required-portal"),
    ],
)
def test_form_only(rules: ReplyRules, body: str, rule: str) -> None:
    assert classify(rules, mail(body=body + "\r\n")) == ("rejected", rule)


def test_form_only_wins_over_an_automatic_header(rules: ReplyRules) -> None:
    raw = mail(extra=ACK, body="We require you to submit all tickets via our portal.\r\n")
    assert classify(rules, raw) == ("rejected", "form-required")


PREFERRED_ACK = (
    "THIS IS AN AUTOMATED MESSAGE - PLEASE DO NOT REPLY.\r\n\r\n"
    "We have received your abuse report and it has been forwarded to our systems for\r\n"
    "analysis. For faster processing and better tracking: While we accept email reports,\r\n"
    "we highly encourage you to submit your report via our dedicated abuse form\r\n"
    "(https://abuse.example.net/report).\r\n"
)


@pytest.mark.parametrize(
    ("body", "extra"),
    [
        (PREFERRED_ACK, None),
        (PREFERRED_ACK, ACK),
        ("Thank you for your report. You can also use our web form next time.", None),
        ("We have received your report. If you prefer, use the form at example.net.", None),
        ("Thanks. Alternatively, reports can be filed via our portal.", ACK),
    ],
)
def test_form_preferred_is_an_acknowledgement(
    rules: ReplyRules, body: str, extra: dict[str, str] | None
) -> None:
    assert classify(rules, mail(body=body + "\r\n", extra=extra)) == ("auto_ack", "form-preferred")


@pytest.mark.parametrize(
    "raw",
    [
        # A person answers and mentions the form: still a human reply, never a refusal.
        mail(body="We will look into it. You can also use our web form next time.\r\n"),
        # A form in a signature.
        mail(body="Thanks, we will look.\r\n\r\nFor sales use our contact form.\r\n"),
        # "information" or "platform" is not a form.
        mail(extra=ACK, body="We have received your report. You can also send information.\r\n"),
        mail(extra=ACK, body="We have received your report. Alternatively visit our platform.\r\n"),
        # A no-reply sender of an acknowledgement.
        mail(
            extra=ACK,
            body="We have received your report. This mailbox is not monitored, do not reply.\r\n",
        ),
        mail(body="Please do not reply to this email, this address is not monitored.\r\n"),
    ],
)
def test_neither_form_only_nor_form_preferred(rules: ReplyRules, raw: bytes) -> None:
    outcome, rule = classify(rules, raw)
    assert outcome != "rejected"
    assert rule not in ("form-required", "form-required-portal", "form-required-unmonitored")
    assert rule != "form-preferred"


@pytest.mark.parametrize(
    "body",
    [
        "We are only the registrar. Please use the form at https://example.net/abuse for "
        "domain matters; content complaints go to the hosting provider.",
        "This is not our customer. Please contact the hosting provider. Domain complaints "
        "can be filed via our web form.",
        "We are the registrar for this domain. Abuse reports must be submitted through the "
        "hosting provider.",
    ],
)
def test_a_registrar_that_sends_you_elsewhere_is_not_a_form_only_desk(
    rules: ReplyRules, body: str
) -> None:
    assert classify(rules, mail(body=body + "\r\n")) == ("rejected", "not-our-customer")


def test_a_ticket_acknowledgement_that_suggests_the_form_stays_a_ticket(rules: ReplyRules) -> None:
    raw = mail(
        extra=ACK,
        subject="[#48213] We received your report",
        body="Your ticket has been created. You can also use our web form next time.\r\n",
    )
    assert classify(rules, raw)[0] == "ticket_opened"


def test_a_phrase_cut_by_a_line_break_still_matches(rules: ReplyRules) -> None:
    raw = mail(body="Sorry, we no\r\nlonger   accept\treports by email.\r\n")
    assert classify(rules, raw) == ("rejected", "form-required")


PORTAL_REFUSAL = (
    "Your email to our support system could not be accepted because we require you to submit "
    "all tickets via our online client support portal. You can do this at the URL below. "
    "https://billing.example.net//submitticket.php"
)


def _wrap(text: str, width: int) -> str:
    lines, line = [], ""
    for word in text.split(" "):
        if line and len(line) + 1 + len(word) > width:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}" if line else word
    return "\r\n".join([*lines, line]) + "\r\n"


@pytest.mark.parametrize("width", [40, 50, 60, 66, 72, 76, 78, 1000])
@pytest.mark.parametrize(
    "extra",
    [
        {"Auto-Submitted": "auto-replied"},
        {"Auto-Submitted": "auto-generated", "Precedence": "bulk"},
        {"X-Autoreply": "yes", "X-Autorespond": "yes"},
        {"Precedence": "auto_reply"},
    ],
)
def test_an_automatic_portal_refusal_is_form_only_however_it_wraps(
    rules: ReplyRules, width: int, extra: dict[str, str]
) -> None:
    """Automatic headers never turn a refusal into a receipt (field case: the auto-ack rule won
    when the mail wrapped "submit all / tickets")."""
    raw = mail(subject="Support ticket not opened", extra=extra, body=_wrap(PORTAL_REFUSAL, width))
    assert classify(rules, raw) == ("rejected", "form-required")


def test_an_automatic_portal_refusal_in_html_is_form_only(rules: ReplyRules) -> None:
    html = (
        "<p>Your email to our support system could not be accepted because we require you to "
        "submit all<br>\r\ntickets via our online client support portal. You can do this at the"
        " URL below.</p><p><a href='https://billing.example.net//submitticket.php'>"
        "https://billing.example.net//submitticket.php</a></p>"
    )
    raw = mail(
        extra={"Auto-Submitted": "auto-replied"},
        ctype="text/html; charset=utf-8",
        body=html + "\r\n",
    )
    assert classify(rules, raw) == ("rejected", "form-required")


@pytest.mark.parametrize("extra", [ACK, {"X-Autoreply": "yes"}, {"Precedence": "bulk"}])
def test_an_automatic_form_preferred_ack_stays_a_receipt(
    rules: ReplyRules, extra: dict[str, str]
) -> None:
    assert classify(rules, mail(extra=extra, body=PREFERRED_ACK)) == ("auto_ack", "form-preferred")
