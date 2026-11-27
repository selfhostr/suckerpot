"""The shared directory of abuse forms and the copy kit (design M38, section 6)."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from suckerpot_reporting import GuardContext, RenderUnavailable, ReportSettings, SelfTerms
from suckerpot_reporting.forms import (
    SCHEMA,
    Directory,
    DirectoryError,
    build_kit,
    bundled,
    dumps,
    fill_data,
    guard_kit,
    main,
    merge_evidence,
    url_problem,
    validate,
)

from .conftest import (
    DYNAMIC_NAME,
    SELF_ADDRESS,
    SETTINGS,
    SUBJECT_IP,
    make_activity,
    make_evidence,
    t,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "forms" / "abuse-forms.yaml"
COMPILED = ROOT / "suckerpot_reporting" / "data" / "abuse-forms.json"
TODAY = date(2026, 11, 22)
REF = "0123456789ab"


def entry(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "example-hosting",
        "provider": "Example Hosting",
        "match": {"mailbox_domains": ["example.net"], "asns": [64500]},
        "official_domains": ["example.net"],
        "form_url": "https://www.example.net/abuse/report",
        "accepts_mail": False,
        "source": "https://www.example.net/legal/abuse",
        "verified_on": "2026-11-01",
    }
    base.update(kw)
    return base


def doc(*entries: dict[str, Any]) -> dict[str, Any]:
    return {"schema": SCHEMA, "entries": list(entries)}


def problems(*entries: dict[str, Any]) -> str:
    with pytest.raises(DirectoryError) as exc:
        validate(doc(*entries), TODAY)
    return "; ".join(exc.value.problems)


# --- the shipped file ------------------------------------------------------------------------


def test_the_shipped_directory_validates_and_is_compiled() -> None:
    raw = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))
    directory = validate(raw)  # the real date: a shipped entry is checked on the day it is added
    assert COMPILED.read_text(encoding="ascii") == dumps(directory)
    assert bundled().entries == directory.entries


def test_check_command_fails_on_an_out_of_date_file(tmp_path: Path) -> None:
    out = tmp_path / "forms.json"
    assert main(["check", str(SOURCE), str(out)]) == 1
    assert main(["compile", str(SOURCE), str(out)]) == 0
    assert main(["check", str(SOURCE), str(out)]) == 0
    assert main(["nonsense"]) == 2


def test_check_command_refuses_an_invalid_file(tmp_path: Path, capsys: Any) -> None:
    src = tmp_path / "bad.yaml"
    src.write_text(yaml.safe_dump(doc(entry(form_url="http://www.example.net/x"))))
    assert main(["check", str(src), str(tmp_path / "x.json")]) == 1
    assert "not_https" in capsys.readouterr().out


def test_check_command_warns_on_old_entries(tmp_path: Path, capsys: Any) -> None:
    src = tmp_path / "old.yaml"
    src.write_text(yaml.safe_dump(doc(entry(verified_on="2020-01-01"))))
    dst = tmp_path / "old.json"
    assert main(["compile", str(src), str(dst)]) == 0
    assert "::warning" in capsys.readouterr().out


# --- the validator ---------------------------------------------------------------------------


def test_a_good_entry_validates() -> None:
    d = validate(doc(entry()), TODAY)
    e = d.entries[0]
    assert e.form_only and e.max_chars == 1000 and e.file_types == ("csv",)
    assert not e.stale(TODAY)
    assert e.stale(TODAY + timedelta(days=400))


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://www.example.net/abuse", "not_https"),
        ("https://192.0.2.10/abuse", "ip_literal"),
        ("https://[2001:db8::1]/abuse", "ip_literal"),
        ("https://www.example.org/abuse", "foreign_host"),
        ("https://example.net.evil.example/abuse", "foreign_host"),
        ("https://notexample.net/abuse", "foreign_host"),
        ("https://www.example.net/abuse?session=abc", "query_string"),
        ("https://www.example.net/abuse?lang=en&token=1", "query_string"),
        ("https://user:pw@www.example.net/abuse", "user_info"),
        ("https://user@www.example.net/abuse", "user_info"),
        ("https://www.example.net:8443/abuse", "port"),
        ("https://www.example.net/abuse#top", "fragment"),
        ("https://www.example.net/abuse;jsessionid=1", "bad_path"),
        ("https://www.example.net/a b", "bad_characters"),
        ("https://www.example.net/" + "a" * 300, "too_long"),
        ("javascript:alert(1)", "not_https"),
        ("https://WWW.EXAMPLE.NET/abuse", "bad_host"),
    ],
)
def test_form_url_rules(url: str, reason: str) -> None:
    assert url_problem(url, ["example.net"]) == reason
    assert reason in problems(entry(form_url=url))


def test_form_url_allows_lang_only() -> None:
    assert url_problem("https://www.example.net/abuse?lang=en", ["example.net"]) is None
    assert url_problem("https://www.example.net/abuse?lang=pt-BR", ["example.net"]) is None
    assert url_problem("https://abuse.example.net/", ["example.net"]) is None
    assert url_problem("https://example.net", ["example.net"]) is None


def test_source_follows_the_same_rules_without_a_query() -> None:
    assert "source: query_string" in problems(entry(source="https://www.example.net/abuse?lang=en"))
    assert "source: foreign_host" in problems(entry(source="https://www.example.org/abuse"))


@pytest.mark.parametrize(
    ("change", "needle"),
    [
        ({"id": "Bad Id"}, "not a slug"),
        ({"provider": ""}, "provider: length"),
        ({"provider": "<b>Example</b>"}, "provider: bad_characters"),
        ({"provider": "x" * 81}, "provider: length"),
        ({"official_domains": []}, "official_domains"),
        (
            {
                "official_domains": [
                    "a.example",
                    "b.example",
                    "c.example",
                    "d.example",
                    "e.example",
                    "f.example",
                ]
            },
            "official_domains",
        ),
        ({"match": {"mailbox_domains": [], "asns": []}}, "at least one"),
        ({"match": {"asns": [0]}}, "asns"),
        ({"match": {"asns": list(range(1, 52))}}, "asns"),
        ({"match": {"mailbox_domains": ["Example.NET"]}}, "mailbox_domains"),
        ({"match": {"cidrs": ["192.0.2.0/24"]}}, "only mailbox_domains"),
        ({"accepts_mail": "maybe"}, "accepts_mail"),
        ({"accepts_mail": 0}, "accepts_mail"),
        ({"xarf": "yes"}, "xarf"),
        ({"max_chars": 50}, "max_chars"),
        ({"max_chars": True}, "max_chars"),
        ({"file_types": ["pdf"]}, "file_types"),
        ({"file_types": []}, "file_types"),
        ({"fields": [{"key": "secret", "label": "X"}]}, "fields[0].key"),
        (
            {"fields": [{"key": "name", "label": "N", "choices": {"login_attack": "x"}}]},
            "abuse_type only",
        ),
        ({"fields": [{"key": "abuse_type", "label": "T", "choices": {"spam": "Spam"}}]}, "choices"),
        ({"fields": [{"key": "name", "label": "<script>"}]}, "label: bad_characters"),
        ({"fields": [{"key": "name", "label": "A"}, {"key": "name", "label": "B"}]}, "repeated"),
        ({"fields": [{"key": "name", "label": "A", "script": "x"}]}, "fields[0]"),
        ({"fields": [{"key": "name", "label": "N", "selector": "a{b}"}]}, "selector"),
        ({"fields": [{"key": "name", "label": "N", "selector": "[name='x']"}]}, "selector"),
        ({"fields": [{"key": "name", "label": "N", "selector": ""}]}, "selector"),
        ({"fields": [{"key": "name", "label": "N", "selector": "#a" * 101}]}, "selector"),
        ({"fields": [{"key": "evidence", "label": "File", "selector": "#file"}]}, "selector"),
        ({"fields": [{"key": "form", "label": "Form", "selector": "form"}]}, "selector"),
        ({"verified_on": "yesterday"}, "verified_on"),
        ({"verified_on": "2027-01-01"}, "in the future"),
        ({"template": "{{x}}"}, "unknown keys"),
    ],
)
def test_entry_bounds(change: dict[str, Any], needle: str) -> None:
    assert needle in problems(entry(**change))


def test_missing_keys_and_bad_documents() -> None:
    bare = entry()
    del bare["source"]
    assert "missing source" in problems(bare)
    with pytest.raises(DirectoryError):
        validate({"schema": "other/1", "entries": []}, TODAY)
    with pytest.raises(DirectoryError):
        validate({"schema": SCHEMA, "entries": [], "extra": 1}, TODAY)
    with pytest.raises(DirectoryError):
        validate([], TODAY)


def test_ids_and_mailbox_domains_are_unique() -> None:
    second = entry(provider="Other", match={"asns": [64501]})
    assert "repeated id" in problems(entry(), second)
    third = entry(id="other-hosting")
    assert "also in example-hosting" in problems(entry(), third)


def test_nothing_is_accepted_in_part() -> None:
    good = entry()
    bad = entry(id="bad-one", form_url="http://x.example.net/")
    with pytest.raises(DirectoryError):
        validate(doc(good, bad), TODAY)


# --- matching --------------------------------------------------------------------------------


def test_match_by_mailbox_domain_first_then_asn_under_an_official_domain() -> None:
    a = entry()
    b = entry(
        id="other-net",
        provider="Other Net",
        match={"mailbox_domains": ["other.example"], "asns": [64500, 64511]},
        official_domains=["other.example"],
        form_url="https://other.example/report",
        source="https://other.example/abuse",
    )
    d = validate(doc(a, b), TODAY)
    assert d.match("other.example", [64500]).id == "other-net"  # type: ignore[union-attr]
    assert d.match("EXAMPLE.NET", []).id == "example-hosting"  # type: ignore[union-attr]
    # An ASN routes only when the mailbox domain is under the entry's official domains.
    assert d.match("support.other.example", [64511]).id == "other-net"  # type: ignore[union-attr]
    assert d.match("mail.example.net", [64500]).id == "example-hosting"  # type: ignore[union-attr]
    # An ASN alone never routes: a customer's own desk is not the provider's.
    assert d.match("unknown.example", [64511]) is None
    assert d.match("unknown.example", [64500]) is None
    assert d.match(None, [64500]) is None
    assert d.by_id("other-net") is b_entry(d)


def b_entry(d: Directory) -> Any:
    return d.entries[1]


# --- the kit ---------------------------------------------------------------------------------


def two_source_evidence() -> Any:
    ev = make_evidence()
    second = ev.subjects[0].model_copy(
        update={
            "value": "198.51.100.9",
            "first_ts": t(10, 0),
            "last_ts": t(11, 0),
            "activities": (
                make_activity(src_ip="198.51.100.9", action="exploit_attempt", text="GET /x"),
            ),
            "xarf_id": None,
        }
    )
    return ev.model_copy(update={"subjects": (ev.subjects[0], second)})


def test_kit_fields() -> None:
    ev = two_source_evidence()
    kit = build_kit(ev, SETTINGS, form_name="A. Volunteer", reply_token=REF, now=t(16, 0))
    assert kit.email == "reports@example.org"
    assert kit.name == "A. Volunteer"
    assert kit.addresses.splitlines() == [SUBJECT_IP, "198.51.100.9"]  # newest first
    assert kit.abuse_type in ("Login attack", "Exploit attempt")
    assert kit.first_seen.startswith("2026-10-30T10:00")
    assert kit.description.endswith(f"ref {REF}")
    assert len(kit.description) <= 1000
    assert kit.evidence.name == "evidence.csv"
    assert [s.abuse_type for s in kit.sources] == ["Login attack", "Exploit attempt"]
    assert all(s.description.endswith(f"ref {REF}") for s in kit.sources)
    assert "Login attempts: 412" in kit.log_excerpt
    assert f"{SUBJECT_IP}:41022 TCP/22 (ssh)" in kit.log_excerpt
    assert not kit.sources[0].stale
    later = build_kit(ev, SETTINGS, reply_token=REF, now=t(16, 0, day=30) + timedelta(days=8))
    assert all(s.stale for s in later.sources)


def test_kit_uses_the_directory_labels_and_limits() -> None:
    e = validate(
        doc(
            entry(
                max_chars=200,
                file_types=["txt"],
                one_ip_per_submission=True,
                fields=[
                    {
                        "key": "abuse_type",
                        "label": "Type of abuse",
                        "choices": {"login_attack": "Brute force", "exploit": "Hacking"},
                    },
                    {"key": "description", "label": "Comments"},
                ],
            )
        ),
        TODAY,
    ).entries[0]
    ev = two_source_evidence()
    kit = build_kit(ev, SETTINGS, entry=e, reply_token=REF)
    assert kit.one_ip_per_submission and kit.max_chars == 200
    assert len(kit.description) <= 200 and kit.description.endswith(f"ref {REF}")
    assert [s.abuse_type for s in kit.sources] == ["Brute force", "Hacking"]
    assert kit.labels == {"abuse_type": "Type of abuse", "description": "Comments"}
    assert kit.evidence.name == "evidence.txt" and kit.evidence.media_type == "text/plain"


def test_description_counts_what_does_not_fit() -> None:
    ev = make_evidence()
    many = tuple(
        ev.subjects[0].model_copy(update={"value": f"198.51.100.{i}", "xarf_id": None})
        for i in range(1, 40)
    )
    big = ev.model_copy(update={"subjects": many})
    kit = build_kit(big, SETTINGS, reply_token=REF)
    assert len(kit.description) <= 1000
    assert "more in evidence.csv)" in kit.description
    assert kit.description.endswith(f"ref {REF}")


def test_reference_style_off_leaves_the_token_out() -> None:
    kit = build_kit(make_evidence(), SETTINGS, reply_token=REF, reference_style="off")
    assert REF not in kit.description


def test_kit_needs_a_mail_address() -> None:
    with pytest.raises(RenderUnavailable):
        build_kit(make_evidence(), ReportSettings(reply_contact="call us"))


def test_kit_never_names_the_node(terms: SelfTerms, ctx: GuardContext) -> None:
    kit = build_kit(make_evidence(), SETTINGS, reply_token=REF)
    assert guard_kit(kit, terms, ctx=ctx, links=["https://www.example.net/abuse"]).ok
    assert SELF_ADDRESS not in "\n".join(v for _n, v in kit.texts())


def test_a_planted_self_term_blocks_the_kit(terms: SelfTerms, ctx: GuardContext) -> None:
    planted = make_evidence(text=f"wget http://{SELF_ADDRESS}/x")
    kit = build_kit(planted, SETTINGS, reply_token=REF)
    assert not guard_kit(kit, terms, ctx=ctx).ok
    named = build_kit(make_evidence(), SETTINGS, form_name=DYNAMIC_NAME)
    assert not guard_kit(named, terms, ctx=ctx).ok
    clean = build_kit(make_evidence(), SETTINGS)
    link = f"https://{DYNAMIC_NAME}/form"
    assert not guard_kit(clean, terms, ctx=ctx, links=[link]).ok


def test_guard_without_terms_fails_closed() -> None:
    kit = build_kit(make_evidence(), SETTINGS)
    assert not guard_kit(kit, None).ok


def test_directory_json_round_trip() -> None:
    d = validate(doc(entry(fields=[{"key": "name", "label": "Your name"}])), TODAY)
    again = validate(copy.deepcopy(d.to_json()), TODAY)
    assert again == d


# --- the browser fill helper's data ------------------------------------------------------------


def test_a_field_may_carry_a_css_selector() -> None:
    fields = [
        {"key": "email", "label": "Email", "selector": "form#abuse input[name=email]"},
        {"key": "name", "label": "Name"},
    ]
    d = validate(doc(entry(fields=fields)), TODAY)
    assert [f.selector for f in d.entries[0].fields] == ["form#abuse input[name=email]", None]
    out = d.to_json()["entries"][0]["fields"]
    assert out[0]["selector"] == "form#abuse input[name=email]" and "selector" not in out[1]
    assert validate(copy.deepcopy(d.to_json()), TODAY) == d


def test_the_fill_data_carries_the_kit_values_labels_and_selectors() -> None:
    e = validate(
        doc(
            entry(
                fields=[
                    {"key": "email", "label": "Your e-mail", "selector": "#reporter-mail"},
                    {"key": "abuse_type", "label": "Type of abuse"},
                    {"key": "evidence", "label": "Attachment"},
                ]
            )
        ),
        TODAY,
    ).entries[0]
    kit = build_kit(two_source_evidence(), SETTINGS, entry=e, form_name="A. V", reply_token=REF)
    data = json.loads(kit.fill)
    assert data["format"] == "formfill/1"
    assert data["type"] in ("login_attack", "exploit") and data["type"] == kit.type_key
    assert data["values"] == {
        "email": kit.email,
        "name": kit.name,
        "abuse_type": kit.abuse_type,
        "addresses": kit.addresses,
        "first_seen": kit.first_seen,
        "last_seen": kit.last_seen,
        "description": kit.description,
        "log_excerpt": kit.log_excerpt,
    }
    # Only fields the helper fills: never the evidence file input.
    assert data["labels"] == {"email": "Your e-mail", "abuse_type": "Type of abuse"}
    assert data["selectors"] == {"email": "#reporter-mail"}
    assert kit.fill.isascii() and "\n" not in kit.fill
    # One address per submission: each source has its own fill data.
    one = json.loads(kit.sources[1].fill)
    assert one["values"]["addresses"] == "198.51.100.9"
    assert one["values"]["description"] == kit.sources[1].description
    assert one["type"] == "exploit" and kit.sources[1].type_key == "exploit"


def test_the_fill_data_never_names_the_project() -> None:
    kit = build_kit(make_evidence(), SETTINGS, reply_token=REF)
    names = ("suckerpot", "selfhostr", "honeypot", "honey")
    for _name, value in kit.fills():
        assert not any(n in value.lower() for n in names)
    empty = json.loads(fill_data({"email": "", "name": ""}, type_key="malware"))
    assert empty == {"format": "formfill/1", "type": "malware", "values": {}}


def test_the_guard_covers_the_fill_data(terms: SelfTerms, ctx: GuardContext) -> None:
    kit = build_kit(make_evidence(), SETTINGS, reply_token=REF)
    assert guard_kit(kit, terms, ctx=ctx).ok
    planted = json.dumps({"values": {"description": f"see\nhttp://{DYNAMIC_NAME}/"}})
    assert not guard_kit(replace(kit, fill=planted), terms, ctx=ctx).ok
    source = replace(kit.sources[0], fill=planted)
    assert not guard_kit(replace(kit, sources=(source,)), terms, ctx=ctx).ok


# --- one kit per provider ------------------------------------------------------------------------


def test_merge_evidence_keeps_every_source_once() -> None:
    a = make_evidence()
    b = two_source_evidence()
    b = b.model_copy(update={"window_end": b.window_end + timedelta(days=2)})
    merged = merge_evidence([a, b])
    assert merged.kind == "digest"
    assert sorted(s.value for s in merged.subjects) == [SUBJECT_IP, "198.51.100.9"]
    assert all(s.kind is not None for s in merged.subjects)
    assert merged.window_end == b.window_end and merged.window_start == a.window_start
    assert merge_evidence([a]) is a
    with pytest.raises(ValueError):
        merge_evidence([])
    kit = build_kit(merged, SETTINGS, reply_token=REF)
    assert kit.addresses.splitlines() == [SUBJECT_IP, "198.51.100.9"]
    assert "198.51.100.9" in kit.evidence.content and SUBJECT_IP in kit.evidence.content
