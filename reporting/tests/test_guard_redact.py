"""Planted-leak and clean corpora against the redaction pass and the identity guard."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from suckerpot_reporting import (
    Activity,
    Evidence,
    ExportData,
    ExportItem,
    GuardContext,
    RedactionContext,
    SelfTermRow,
    SelfTerms,
    Subject,
    guard,
    guard_message,
    load_self_terms,
    redact,
    render_csv,
    render_eml,
    render_misp,
    render_stix,
    render_text,
    render_xarf,
)
from suckerpot_reporting.legacy import legacy_hit
from tests.conftest import (
    EXPORT_ID,
    OWNER_DOMAIN,
    SEED,
    SELF_ADDRESS,
    SETTINGS,
    SUBJECT_IP,
    make_activity,
    make_evidence,
    t,
)

CORPUS = Path(__file__).parent / "corpus"
PLANTED: list[dict[str, Any]] = yaml.safe_load((CORPUS / "planted.yaml").read_text())["cases"]
CLEAN: list[str] = yaml.safe_load((CORPUS / "clean.yaml").read_text())["cases"]
IDS = [c["id"] for c in PLANTED]


def _generated_cases() -> list[dict[str, Any]]:
    """Base64 of the dotted form at the three alignments."""
    out = []
    for k in range(3):
        enc = base64.b64encode(b"A" * k + SELF_ADDRESS.encode() + b"/x").decode()
        out.append(
            {
                "id": f"base64_align_{k}",
                "text": f"echo {enc} | base64 -d | sh",
                "codes": ["self_address"],
                "secret": enc.lower(),
            }
        )
    return out


def _b64_cases() -> list[dict[str, Any]]:
    """Base64 of a self name and of the self IPv6 address, at the three alignments."""
    out = []
    for label, value, code in (
        ("name", OWNER_DOMAIN, "owner_domain"),
        ("v6", "2001:db8:1234::77", "self_address"),
        ("v6_exploded", "2001:0db8:1234:0000:0000:0000:0000:0077", "self_address"),
    ):
        for k in range(3):
            enc = base64.b64encode(b"A" * k + value.encode() + b"/x").decode()
            out.append(
                {
                    "id": f"base64_{label}_{k}",
                    "text": f"echo {enc} | base64 -d",
                    "codes": [code],
                    "secret": enc.lower(),
                }
            )
    return out


ALL = PLANTED + _generated_cases() + _b64_cases()


def _ctx_for(case: dict[str, Any], base: GuardContext) -> GuardContext:
    return GuardContext(internal_ids=base.internal_ids, allow_documentation=not case.get("doc"))


# --- (a) redaction removes the leak -------------------------------------------------------


@pytest.mark.parametrize("case", ALL, ids=lambda c: c["id"])
def test_redaction_removes_planted_leak(
    case: dict[str, Any], rctx: RedactionContext, terms: SelfTerms, ctx: GuardContext
) -> None:
    out = redact(case["text"], rctx)
    assert case["secret"] not in out.text.lower()
    assert out.text.isascii()
    # the redacted text must pass the guard, documentation addresses included
    verdict = guard(out.text, terms, ctx=GuardContext(ctx.internal_ids, allow_documentation=True))
    assert verdict.ok, verdict.codes
    assert out.lines_dropped + out.addresses_masked >= 1


# --- (b) planted straight into every renderer, the guard fails with the expected code -----


def _renderings(text: str) -> dict[str, tuple[Any, str]]:
    evidence = make_evidence(text=text[:200])
    msg = render_text(evidence, SETTINGS)
    x = render_xarf(evidence, SETTINGS)
    return {
        "text": (msg, "msg"),
        "xarf": (x, "msg"),
        "eml": (render_eml(msg), "eml"),
        "eml_xarf": (render_eml(x), "eml"),
        "csv": (render_csv(evidence).content, "csv"),
    }


@pytest.mark.parametrize("case", ALL, ids=lambda c: c["id"])
def test_guard_fails_on_every_renderer(
    case: dict[str, Any], terms: SelfTerms, ctx: GuardContext
) -> None:
    gctx = _ctx_for(case, ctx)
    expected = set(case["codes"])
    for name, (artefact, kind) in _renderings(case["text"]).items():
        if kind == "msg":
            result = guard_message(artefact, terms, ctx=gctx)
        else:
            result = guard(artefact, terms, fmt="eml" if kind == "eml" else "csv", ctx=gctx)
        assert not result.ok, name
        assert expected <= set(result.codes), (name, result.codes)


def _export_with(value: str, **kw: Any) -> ExportData:
    item = ExportItem(
        role="payload_host",
        type="url",
        value=value[:1000],
        first_seen=t(15, 0),
        last_seen=t(15, 0),
        **kw,
    )
    return ExportData(
        export_id=EXPORT_ID,
        id_seed=SEED,
        created=t(18, 0),
        description="Test indicators",
        items=(item,),
    )


@pytest.mark.parametrize("case", ALL, ids=lambda c: c["id"])
def test_guard_fails_on_stix_and_misp(
    case: dict[str, Any], terms: SelfTerms, ctx: GuardContext
) -> None:
    gctx = _ctx_for(case, ctx)
    data = _export_with(case["text"])
    for obj in (render_stix(data), render_misp(data)):
        raw = json.dumps(obj)  # ensure_ascii: the guard must decode the \u escapes itself
        result = guard(raw, terms, fmt="json", ctx=gctx)
        assert not result.ok
        assert set(case["codes"]) <= set(result.codes), result.codes
    # also through a free-text field (malware family)
    family = _export_with("http://x.example.org/", family=case["text"][:64])
    if len(case["text"]) <= 64:
        result = guard(json.dumps(render_stix(family)), terms, fmt="json", ctx=gctx)
        assert set(case["codes"]) <= set(result.codes), result.codes


# --- (c) the guard never returns the value ------------------------------------------------


@pytest.mark.parametrize("case", ALL, ids=lambda c: c["id"])
def test_guard_result_carries_no_value(
    case: dict[str, Any], terms: SelfTerms, ctx: GuardContext
) -> None:
    result = guard(case["text"], terms, ctx=_ctx_for(case, ctx))
    assert not result.ok
    shown = (repr(result) + str(result.codes) + str(dict(result.counts))).lower()
    assert case["secret"] not in shown
    assert SELF_ADDRESS not in shown
    assert OWNER_DOMAIN not in shown
    assert all(isinstance(n, int) for n in result.counts.values())


def test_guard_utf16_bytes(terms: SelfTerms, ctx: GuardContext) -> None:
    result = guard(f"x {SELF_ADDRESS} y".encode("utf-16-le"), terms, ctx=ctx)
    assert "self_address" in result.codes


def test_guard_fails_closed_without_terms_or_self_address(ctx: GuardContext) -> None:
    assert guard("hello", None).codes == ("self_terms_unavailable",)
    empty = load_self_terms([], {})
    assert not empty.has_self_address
    assert guard("hello", empty, ctx=ctx).codes == ("no_self_address",)


NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)


def _row(
    source: str, *, confirmed: bool = False, age_h: float | None = 1, kind: str = "address"
) -> SelfTermRow:
    seen = None if age_h is None else NOW - timedelta(hours=age_h)
    return SelfTermRow(
        kind=kind,
        value="203.0.113.5",
        source=source,
        confirmed=confirmed,
        last_seen=seen,
    )


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        (_row("manual", age_h=None), True),  # manual never expires
        (_row("manual", age_h=5000), True),
        (_row("sensor", age_h=71), True),
        (_row("sensor", age_h=73), False),  # stale
        (_row("sensor", age_h=None), False),
        (_row("learned", confirmed=True, age_h=2), True),
        (_row("learned", confirmed=True, age_h=100), False),
        (_row("learned", confirmed=False, age_h=1), False),
    ],
)
def test_has_self_address_rules(row: SelfTermRow, expected: bool) -> None:
    assert load_self_terms([row], {}, now=NOW).has_self_address is expected


def test_unconfirmed_learned_terms_do_not_act() -> None:
    rows = [
        SelfTermRow(kind="address", value="203.0.113.5", source="learned", last_seen=NOW),
        SelfTermRow(kind="name", value="victim.example.org", source="learned", last_seen=NOW),
        SelfTermRow(kind="text", value="villa example", source="learned", last_seen=NOW),
    ]
    terms = load_self_terms(rows, {}, now=NOW)
    assert not terms.addresses and not [n for n in terms.names if n.value == "victim.example.org"]
    assert not terms.texts
    # a stale trusted row still blocks (deny set), it just does not satisfy the precondition
    stale = load_self_terms([_row("sensor", age_h=500)], {}, now=NOW)
    assert "203.0.113.5" in stale.addresses and not stale.has_self_address


def test_artefact_vocabulary_never_enters_the_deny_set() -> None:
    rows = [
        SelfTermRow(kind="name", value=v, source="manual")
        for v in ("evidence.csv", "report.txt", "x-arf.org", "www.x-arf.org", "mitre.org", "csv")
    ] + [SelfTermRow(kind="text", value="report", source="manual")]
    terms = load_self_terms(rows, {"API_ALLOWED_HOSTS": "xarf.org,attack.mitre.org"})
    assert not [
        n.value
        for n in terms.names
        if "x-arf" in n.value or "csv" in n.value or "mitre" in n.value or "xarf" in n.value
    ]
    assert not terms.texts
    # a real X-ARF report and CSV stay clean even when the owner typed those words
    from tests.conftest import make_evidence

    msg = render_xarf(make_evidence(), SETTINGS)
    assert guard_message(msg, terms, ctx=GuardContext(allow_documentation=True)).codes == (
        "no_self_address",
    )


LEGACY_SAMPLES = [
    "Hello,\n\nThe addresses below, announced by your network, attacked a monitored system.",
    "Please investigate and stop this activity.",
    "Abuse report: SSH brute force from 198.51.100.23 (AS64500)",
    "All times are UTC. The destination address is withheld; source ports are given so you can match your flow records.",
    "User-Agent: xarf-report/0.2",
    'Content-Type: multipart/mixed; boundary="=_0a513bf681842abfee69bbe8"',
    "Observed by a monitored system.",
]


@pytest.mark.parametrize("sample", LEGACY_SAMPLES)
@pytest.mark.parametrize("fmt", ["text", "xarf", "csv", "eml", "json"])
def test_default_wording_fails_every_format(
    sample: str, fmt: str, terms: SelfTerms, ctx: GuardContext
) -> None:
    artefact = json.dumps({"k": sample}) if fmt == "json" else sample
    result = guard(artefact, terms, fmt=fmt, ctx=ctx)  # type: ignore[arg-type]
    assert "default_wording" in result.codes


def test_owner_wording_passes(terms: SelfTerms, ctx: GuardContext) -> None:
    msg = render_text(make_evidence(), SETTINGS)
    assert guard_message(msg, terms, ctx=ctx).ok


def test_neutral_defaults_do_not_trip_the_legacy_guard(terms: SelfTerms, ctx: GuardContext) -> None:
    from suckerpot_reporting import ReportSettings
    from tests.conftest import make_evidence as _ev

    bare = ReportSettings(reply_contact="reports@example.org")
    for evidence in (_ev(), _ev(demo=True)):
        msg = render_xarf(evidence, bare)
        assert msg.subject.endswith("Abuse report for 198.51.100.23")
        assert not legacy_hit(msg.subject) and not legacy_hit(msg.body)
        assert "default_wording" not in guard_message(msg, terms, ctx=ctx).codes
        eml = render_eml(msg)
        assert "default_wording" not in guard(eml, terms, fmt="eml", ctx=ctx).codes
    # an owner-written text equal to the old shipped wording is still refused
    old = bare.model_copy(update={"subject_template": "Abuse report: {value}"})
    assert "default_wording" in guard_message(render_text(_ev(), old), terms, ctx=ctx).codes


def test_the_overflow_line_of_a_long_report_is_not_default_wording(
    terms: SelfTerms, ctx: GuardContext
) -> None:
    # More activities than the body lists: the renderer adds a line that points to evidence.csv.
    evidence = make_evidence()
    subject = evidence.subjects[0]
    many = tuple(make_activity(ts=t(14, i)) for i in range(15))
    long_one = evidence.model_copy(
        update={"subjects": (subject.model_copy(update={"activities": many}),)}
    )
    msg = render_text(long_one, SETTINGS)
    assert "5 more in evidence.csv" in msg.body
    assert not legacy_hit(msg.body)
    assert "default_wording" not in guard_message(msg, terms, ctx=ctx).codes


def test_guard_mime_decoding(terms: SelfTerms, ctx: GuardContext) -> None:
    import quopri

    leak = quopri.encodestring(f"visit {SELF_ADDRESS}".encode())
    qp = (
        b"To: abuse@example.net\r\nSubject: x\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=us-ascii\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
        + leak.replace(b"203", b"=32=30=33")
        + b"\r\n"
    )
    assert "self_address" in guard(qp, terms, fmt="eml", ctx=ctx).codes
    b64 = base64.b64encode(f"go to {SELF_ADDRESS}".encode())
    msg = (
        b"To: abuse@example.net\r\nSubject: x\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=us-ascii\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n" + b64 + b"\r\n"
    )
    assert "self_address" in guard(msg, terms, fmt="eml", ctx=ctx).codes


def test_guard_json_unescapes_strings(terms: SelfTerms, ctx: GuardContext) -> None:
    raw = '{"a": ["\\u0032\\u0030\\u0033.0.113.77"]}'
    assert "self_address" in guard(raw, terms, fmt="json", ctx=ctx).codes


# --- clean corpus: nothing is touched, nothing is flagged ---------------------------------


@pytest.mark.parametrize("text", CLEAN)
def test_clean_text_passes_unchanged(
    text: str, rctx: RedactionContext, terms: SelfTerms, ctx: GuardContext
) -> None:
    out = redact(text, rctx)
    assert out.text == text
    assert (out.addresses_masked, out.lines_dropped) == (0, 0)
    assert guard(text, terms, ctx=ctx).ok


def test_clean_evidence_renders_pass_the_guard(terms: SelfTerms, ctx: GuardContext) -> None:
    for line in CLEAN:
        evidence = make_evidence(text=line)
        msg = render_text(evidence, SETTINGS)
        assert guard_message(msg, terms, ctx=ctx).ok, line
        assert guard(render_eml(render_xarf(evidence, SETTINGS)), terms, fmt="eml", ctx=ctx).ok


def test_documentation_addresses_need_allow_flag(terms: SelfTerms) -> None:
    msg = render_text(make_evidence(), SETTINGS)
    blocked = guard_message(msg, terms, ctx=GuardContext(allow_documentation=False))
    assert blocked.codes == ("documentation_address",)
    assert guard_message(msg, terms, ctx=GuardContext(allow_documentation=True)).ok


def test_clean_exports_pass_the_guard(terms: SelfTerms, ctx: GuardContext) -> None:
    from tests.conftest import make_export

    data = make_export()
    assert guard(json.dumps(render_stix(data)), terms, fmt="json", ctx=ctx).ok
    assert guard(json.dumps(render_misp(data)), terms, fmt="json", ctx=ctx).ok


# --- redaction details --------------------------------------------------------------------


def test_redact_counters_and_masks(rctx: RedactionContext) -> None:
    text = "ping 10.0.0.1\nhostname srv-web01\nmail root@victim.example.org\ncurl http://user:pw@intranet/x"  # gitleaks:allow
    out = redact(text, rctx)
    assert out.lines_dropped == 1
    assert "[address]" in out.text and "[email]" in out.text
    assert "http://[host]/x" in out.text and "pw" not in out.text
    assert out.addresses_masked == 4  # address, email, userinfo, single-label host


def test_redact_bounds_and_ascii(rctx: RedactionContext) -> None:
    assert redact("a" * 5000, rctx).text.endswith("...")
    assert len(redact("a" * 5000, rctx).text) == 200
    out = redact("echo caf\u00e9 \x1b[31mred\x1b[0m\x07", rctx)
    assert out.text == "echo caf\\u00e9 red"


def test_redact_single_line(rctx: RedactionContext) -> None:
    assert redact("ls\npwd\n\nid", rctx, single_line=True).text == "ls; pwd; id"


def test_redact_drops_context_not_just_the_word(rctx: RedactionContext) -> None:
    out = redact("curl http://dashboard.example.net/x -o /tmp/y", rctx)
    assert out.text == "" and out.lines_dropped == 1


def test_subject_models_reject_oversize() -> None:
    with pytest.raises(ValueError):
        Activity(
            ts=t(1, 1),
            src_ip=SUBJECT_IP,
            src_port=1,
            dst_port=22,
            protocol="tcp",
            service="ssh",
            action="command",
            text="x" * 201,
        )
    with pytest.raises(ValueError):
        Activity(
            ts=t(1, 1),
            src_ip=SUBJECT_IP,
            src_port=1,
            dst_port=22,
            protocol="tcp",
            service="ssh",
            action="failed_logins",
            usernames=tuple("abcdef"),
        )
    with pytest.raises(ValueError):
        Subject(
            type="ip",
            value="x",
            first_ts=__import__("datetime").datetime(2026, 1, 1),
            last_ts=t(1, 1),
            sessions=1,
            events=1,
        )
    assert isinstance(make_evidence(), Evidence)
