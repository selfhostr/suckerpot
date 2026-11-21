"""The batch builder: planted self addresses never reach a batch (N3, N4, N6, N10)."""

from __future__ import annotations

import json
from datetime import date

import pytest
from suckerpot_netproto import blind

from ingest.network.builder import BatchBuilder, activities_of, mentions_self
from ingest.network.source import C2Fact, FileFact, PayloadFact, SessionFact

from .helpers import SELF_IP, SELF_NAME, FakeTerms, make_terms

DAY = date(2026, 11, 2)
GOOD_IP = "198.51.100.23"
GOOD_HOST = "dropper.example.org"
SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def session(ip: str = GOOD_IP, **kw: object) -> SessionFact:
    base = {
        "ip": ip, "sensor": "ssh", "sessions": 3, "login_attempts": 12, "login_success": False,
        "commands": 0, "downloads": 0, "http_requests": 0, "tags": ("mirai",),
    }  # fmt: skip
    return SessionFact(**{**base, **kw})  # type: ignore[arg-type]


class Source:
    def __init__(
        self,
        sessions: list[SessionFact] | None = None,
        payloads: list[PayloadFact] | None = None,
        c2: list[C2Fact] | None = None,
        files: list[FileFact] | None = None,
    ) -> None:
        self._s, self._p, self._c, self._f = sessions or [], payloads or [], c2 or [], files or []
        self.called = False

    async def sessions(self, day: date) -> list[SessionFact]:
        self.called = True
        return self._s

    async def payloads(self, day: date) -> list[PayloadFact]:
        return self._p

    async def c2(self, day: date) -> list[C2Fact]:
        return self._c

    async def files(self, day: date) -> list[FileFact]:
        return self._f


def builder(source: Source, *, terms: bool = True, docs: bool = True, **kw: object) -> BatchBuilder:
    return BatchBuilder(
        source,
        FakeTerms(make_terms() if terms else make_terms(with_address=False)),
        allow_documentation=docs,
        batch_id=lambda: "AAECAwQFBgcICQoLDA0ODw",
        **kw,  # type: ignore[arg-type]
    )


async def test_a_clean_day_builds_a_valid_batch() -> None:
    src = Source(
        sessions=[session(), session("198.51.100.99", sensor="telnet", login_attempts=0, tags=())],
        payloads=[PayloadFact(f"http://{GOOD_HOST}/x.sh", SHA, "mirai", "elf", "arm")],
        c2=[C2Fact("c2_ip", "198.51.100.50", 23, SHA, "mirai")],
        files=[FileFact(SHA, "mirai", "elf", "arm")],
    )
    res = await builder(src).build(DAY)
    assert res.status == "ok" and res.batch is not None
    b = res.batch
    assert b["day"] == "2026-11-02" and res.counts == {
        "sources": 2,
        "payloads": 1,
        "c2": 1,
        "files": 1,
    }
    first = b["sources"][0]
    assert first["services"] == ["ssh"] and first["sessions"] == 1 and first["attempts"] == 2
    assert first["tags"] == ["mirai"] and "login" in first["activity"]
    pay = b["payloads"][0]
    assert pay["url_b"] == blind.blind_url(f"http://{GOOD_HOST}/x.sh")
    assert "host_b" in pay and pay["fetched"] and pay["file_type"] == "elf-arm"
    # URLs and domains only ever leave blinded
    assert GOOD_HOST not in json.dumps(b) and "x.sh" not in json.dumps(b)


async def test_no_confirmed_self_address_sends_nothing() -> None:
    src = Source(sessions=[session()])
    res = await builder(src, terms=False).build(DAY)
    assert res.status == "waiting_self_address" and res.batch is None
    assert not src.called  # not even read


async def test_unavailable_terms_send_nothing() -> None:
    b = BatchBuilder(Source(sessions=[session()]), FakeTerms(None))
    assert (await b.build(DAY)).status == "terms_unavailable"


SELF_FORMS = [
    SELF_IP,
    "3405803853",  # 203.0.113.77 as one decimal number
    "0xcb00714d",  # hex
    "::ffff:203.0.113.77",  # IPv4-mapped
    "0313.0.0161.0115",  # octal parts
]


@pytest.mark.parametrize("form", SELF_FORMS)
def test_the_own_address_in_any_spelling_is_recognised(form: str) -> None:
    terms = make_terms()
    host = f"[{form}]" if ":" in form else form
    assert mentions_self(f"http://{host}/a.sh", terms)
    assert mentions_self(form, terms)


async def test_planted_self_addresses_never_reach_a_batch() -> None:
    planted = [
        PayloadFact(f"http://{SELF_IP}/x.sh", SHA, None, "elf", "arm"),  # host is us
        PayloadFact("http://3405803853/x.sh", None, None, None, None),  # decimal host
        PayloadFact("http://0xcb00714d/x.sh", None, None, None, None),  # hex host
        PayloadFact("http://[::ffff:203.0.113.77]/x.sh", None, None, None, None),  # mapped
        PayloadFact(f"http://{GOOD_HOST}/x.sh?ref={SELF_IP}", None, None, None, None),  # query
        PayloadFact(f"http://{GOOD_HOST}/{SELF_NAME}/x.sh", None, None, None, None),  # path name
        PayloadFact(f"http://{SELF_NAME}/x.sh", None, None, None, None),  # host name
    ]
    src = Source(
        sessions=[session(SELF_IP), session("198.51.100.5")],
        payloads=planted,
        c2=[
            C2Fact("c2_ip", SELF_IP, 23, SHA, None),
            C2Fact("c2_domain", SELF_NAME, 23, SHA, None),
        ],
    )
    res = await builder(src).build(DAY)
    assert res.status == "ok" and res.batch is not None
    wire_text = json.dumps(res.batch)
    for needle in (SELF_IP, SELF_NAME, "3405803853", "cb00714d", "ffff"):
        assert needle not in wire_text, needle
    for planted_url in planted:
        assert blind.blind_url(planted_url.url) not in wire_text
    assert [s["ip"] for s in res.batch["sources"]] == ["198.51.100.5"]
    assert res.batch["payloads"] == [] and res.batch["c2"] == []
    assert res.dropped.get("self", 0) + res.dropped.get("guard", 0) >= 9


async def test_documentation_addresses_never_leave_by_default() -> None:
    """N10: the default builder (no test overlay) drops documentation ranges."""
    src = Source(sessions=[session("198.51.100.23")])
    res = await builder(src, docs=False).build(DAY)
    assert res.status == "ok" and res.batch is not None
    assert res.batch["sources"] == [] and res.dropped["range"] == 1


async def test_private_and_never_block_addresses_are_excluded() -> None:
    private = [".".join(p) for p in (("10", "0", "0", "5"), ("192", "168", "1", "9"))]
    src = Source(sessions=[*(session(p) for p in private), session("8.8.8.8")])
    res = await builder(src, docs=False).build(DAY)
    assert res.batch is not None and res.batch["sources"] == []


async def test_tags_outside_the_allow_list_are_dropped() -> None:
    src = Source(sessions=[session(tags=("mirai", "my-private-tag", "cve-2026-1234", "x"))])
    res = await builder(src).build(DAY)
    assert res.batch is not None
    assert res.batch["sources"][0]["tags"] == ["cve-2026-1234", "mirai"]
    assert "exploit" in res.batch["sources"][0]["activity"]


async def test_the_source_cap_keeps_the_most_severe() -> None:
    sessions = [session("198.51.100.1", login_attempts=1, tags=(), sessions=1)]
    sessions.append(session("198.51.100.2", commands=4, tags=(), sessions=1))
    sessions.append(session("198.51.100.3", downloads=1, tags=(), sessions=1))
    res = await builder(Source(sessions=sessions), max_sources=2).build(DAY)
    assert res.batch is not None
    assert [s["ip"] for s in res.batch["sources"]] == ["198.51.100.3", "198.51.100.2"]
    assert res.dropped["cap"] == 1


def test_activity_mapping() -> None:
    assert activities_of(session(login_attempts=0, tags=())) == {"connect"}
    assert activities_of(session(login_attempts=0, tags=("recon",))) == {"scan"}
    got = activities_of(session(login_success=True, commands=2, downloads=1, http_requests=1))
    assert got == {"login", "login_success", "command", "download", "http"}


async def test_no_credential_or_command_field_exists_in_the_batch() -> None:
    src = Source(sessions=[session(commands=5)], files=[FileFact(SHA, "nope", "elf", "mips")])
    res = await builder(src).build(DAY)
    assert res.batch is not None
    keys = {k for s in res.batch["sources"] for k in s}
    assert keys == {"ip", "services", "activity", "tags", "sessions", "attempts"}
    assert res.batch["files"] == [
        {"sha256": SHA, "file_type": "elf-mips"}
    ]  # unknown family dropped


async def test_addresses_that_wrap_an_ipv4_address_are_dropped() -> None:
    wrapped = ["64:ff9b::c633:6417", "2002:c633:6417::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2"]
    res = await builder(Source(sessions=[session(w) for w in wrapped]), docs=False).build(DAY)
    assert res.batch is not None and res.batch["sources"] == []


async def test_sip_sessions_add_presence_only() -> None:
    """Security review H2: a spoofed SIP REGISTER flood "from" an address, next to one real TCP
    connect, must not be sent as a brute force. One source row merges every service, so SIP
    sessions give the service and the session count, never activity, tags or attempts."""
    src = Source(
        sessions=[
            session(sensor="sip", login_attempts=500, login_success=True, tags=("sip-scan",)),
            session(sensor="ssh", sessions=1, login_attempts=0, tags=()),
        ]
    )
    res = await builder(src).build(DAY)
    assert res.batch is not None
    (row,) = res.batch["sources"]
    assert row["services"] == ["sip", "ssh"]
    assert row["activity"] == ["connect"]
    assert row["attempts"] == 0 and row["tags"] == []
    sip_only = await builder(Source(sessions=[session(sensor="sip", tags=())])).build(DAY)
    assert sip_only.batch is not None
    assert sip_only.batch["sources"][0]["activity"] == ["connect"]
    assert sip_only.batch["sources"][0]["attempts"] == 0


# -- gate G (M37 P2) -------------------------------------------------------------------------------


class Gate:
    def __init__(self, tags: frozenset[str] | None) -> None:
        self.tags = tags
        self.days: list[date] = []

    async def gated_tags(self, day: date) -> frozenset[str] | None:
        self.days.append(day)
        return self.tags


def test_gate_g_holds_back_the_exploit_activity_of_a_new_pack_cve() -> None:
    fact = session(login_attempts=0, http_requests=1, tags=("cve-2026-55501", "edgegate"))
    assert "exploit" in activities_of(fact)
    assert activities_of(fact, frozenset({"cve-2026-55501"})) == {"http"}
    assert activities_of(fact, None) == {"http"}  # gate state unknown: fail closed
    # Another CVE tag or a built-in exploit tag is not held back.
    other = session(login_attempts=0, tags=("cve-2026-55501", "cve-2025-1111"))
    assert "exploit" in activities_of(other, frozenset({"cve-2026-55501"}))
    builtin = session(login_attempts=0, tags=("cve-2026-55501", "php2shell"))
    assert "exploit" in activities_of(builtin, None)


async def test_gate_g_in_the_batch_keeps_the_tag_but_not_the_activity() -> None:
    src = Source(sessions=[session(login_attempts=0, http_requests=2, tags=("cve-2026-55501",))])
    gate = Gate(frozenset({"cve-2026-55501"}))
    res = await builder(src, trap_gate=gate).build(DAY)
    assert res.status == "ok" and res.batch is not None and gate.days == [DAY]
    item = res.batch["sources"][0]
    assert item["tags"] == ["cve-2026-55501"] and item["activity"] == ["http"]
    res = await builder(src, trap_gate=Gate(None)).build(DAY)
    assert res.batch is not None and res.batch["sources"][0]["activity"] == ["http"]
    res = await builder(src, trap_gate=Gate(frozenset())).build(DAY)
    assert res.batch is not None and "exploit" in res.batch["sources"][0]["activity"]


def test_the_validator_reserves_the_same_exploit_tags() -> None:
    from suckerpot_common import traps

    from ingest.network.builder import EXPLOIT_TAGS

    assert traps.EXPLOIT_TAGS == EXPLOIT_TAGS
