"""The form-only desks on the ingest side (M38, section 6): weeks, mailbox domains, matching."""

from datetime import UTC, date, datetime

from suckerpot_reporting.forms import SCHEMA, Directory, validate

from ingest.abuse import forms

ENTRY = {
    "id": "example-hosting",
    "provider": "Example Hosting",
    "match": {"mailbox_domains": ["example.org"], "asns": [64496]},
    "official_domains": ["example.org"],
    "form_url": "https://www.example.org/abuse",
    "accepts_mail": False,
    "source": "https://www.example.org/legal",
    "verified_on": "2026-11-01",
}


def directory(**kw: object) -> Directory:
    return validate({"schema": SCHEMA, "entries": [{**ENTRY, **kw}]}, date(2026, 11, 22))


def test_week_is_the_monday_in_utc() -> None:
    assert forms.week_of(datetime(2026, 11, 22, 23, 59, tzinfo=UTC)) == date(2026, 11, 16)
    assert forms.week_of(datetime(2026, 11, 23, 0, 0, tzinfo=UTC)) == date(2026, 11, 23)


def test_mailbox_domain() -> None:
    assert forms.mailbox_domain("Abuse@Example.ORG") == "example.org"
    assert forms.mailbox_domain("nobody") is None
    assert forms.mailbox_domain(None) is None


def test_entry_for_matches_by_mailbox_then_asn() -> None:
    d = directory()
    assert forms.entry_for(d, "abuse@example.org", []) is d.entries[0]
    assert forms.entry_for(d, "abuse@other.example", [64496]) is d.entries[0]
    assert forms.entry_for(d, "abuse@other.example", [64497, None]) is None


def test_an_entry_that_takes_mail_routes_nothing() -> None:
    assert not directory(accepts_mail=True).entries[0].form_only
    assert directory(accepts_mail="ignored").entries[0].form_only


def test_the_bundled_directory_loads() -> None:
    forms.directory.cache_clear()
    assert isinstance(forms.directory(), Directory)
