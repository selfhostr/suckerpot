from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from suckerpot_netproto import ProtoError, enums, models, sign
from suckerpot_netproto.models import ObservationBatch, parse_body

PRIV10 = ".".join(("10", "0", "0", "1"))
PRIV10_B = ".".join(("10", "99", "99", "99"))
PRIV192 = ".".join(("192", "168", "1", "1"))
H = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
BATCH: dict[str, Any] = {
    "protocol": "spn/1",
    "batch_id": sign.new_nonce(),
    "day": "2026-10-30",
    "sources": [
        {
            "ip": "8.8.4.4",
            "services": ["ssh"],
            "activity": ["login", "command"],
            "tags": ["mirai", "cve-2021-44228", "not-in-list"],
            "sessions": 1,
            "attempts": 3,
        }
    ],
    "payloads": [
        {"url_b": H, "host_ip": "1.1.1.1", "sha256": H, "family": "mirai", "fetched": True}
    ],
    "c2": [{"ip": "9.9.9.9", "port": 23, "family": "mirai", "via_sha256": H}],
    "files": [{"sha256": H, "family": "mirai", "file_type": "elf-arm"}],
}


def parse(data: dict[str, Any], **kw: Any) -> ObservationBatch:
    return parse_body(
        ObservationBatch, json.dumps(data).encode(), max_bytes=models.MAX_BODY_OBSERVATIONS, **kw
    )


def bad(data: dict[str, Any], code: str = "invalid_payload", **kw: Any) -> None:
    with pytest.raises(ProtoError) as err:
        parse(data, **kw)
    assert err.value.code == code


def mutated(path: str, value: Any) -> dict[str, Any]:
    data = copy.deepcopy(BATCH)
    node: Any = data
    keys = path.split(".")
    for k in keys[:-1]:
        node = node[int(k)] if k.isdigit() else node[k]
    last = keys[-1]
    if value is ...:
        del node[int(last) if last.isdigit() else last]
    else:
        node[int(last) if last.isdigit() else last] = value
    return data


def test_valid_batch_and_tag_filter() -> None:
    batch = parse(BATCH)
    assert batch.sources[0].tags == ["mirai", "cve-2021-44228"]  # unknown tag dropped
    assert batch.sources[0].ip == "8.8.4.4"


def test_unknown_and_reserved_fields() -> None:
    bad(mutated("extra", 1) | {"extra": 1})
    bad(mutated("sources.0.port", 22) | {})
    data = copy.deepcopy(BATCH)
    data["credentials"] = [{"u": "root", "p": "x"}]
    bad(data)
    data = copy.deepcopy(BATCH)
    data["sources"][0]["credentials"] = []
    bad(data)


@pytest.mark.parametrize(
    "ip",
    [
        PRIV10,
        PRIV192,
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "224.0.0.1",
        "0.0.0.0",  # noqa: S104
        "192.0.2.5",
        "198.51.100.7",
        "203.0.113.9",
        "::1",
        "fe80::1",
        "fc00::1",
        "2001:db8::1",
        "::ffff:8.8.8.8",
        "not-an-ip",
        "8.8.8",
        "08.8.8.8",
    ],
)
def test_non_global_addresses_refused(ip: str) -> None:
    bad(mutated("sources.0.ip", ip))
    bad(mutated("payloads.0.host_ip", ip))
    bad(mutated("c2.0.ip", ip))


def test_documentation_ranges_only_with_flag() -> None:
    data = mutated("sources.0.ip", "198.51.100.23")
    bad(data)
    assert parse(data, allow_documentation=True).sources[0].ip == "198.51.100.23"
    # the flag does not open private space
    bad(mutated("sources.0.ip", PRIV10), allow_documentation=True)


def test_ipv6_is_normalised() -> None:
    batch = parse(mutated("sources.0.ip", "2606:4700:4700:0:0:0:0:1111"))
    assert batch.sources[0].ip == "2606:4700:4700::1111"


@pytest.mark.parametrize(
    "path,value",
    [
        ("sources.0.services", ["ssh", "gopher"]),
        ("sources.0.services", []),
        ("sources.0.services", ["ssh", "ssh"]),
        ("sources.0.activity", ["hack"]),
        ("sources.0.sessions", 5),
        ("sources.0.attempts", -1),
        ("sources.0.sessions", "1"),
        ("payloads.0.family", "unknown-family"),
        ("payloads.0.file_type", "exe"),
        ("payloads.0.url_b", "ABC"),
        ("payloads.0.url_b", H.upper()),
        ("payloads.0.host_b", H),  # both host_ip and host_b
        ("payloads.0.sha256", None),  # fetched without sha256
        ("c2.0.port", 0),
        ("c2.0.port", 70000),
        ("c2.0.domain_b", H),  # both ip and domain_b
        ("files.0.sha256", "zz"),
        ("day", "2026-13-01"),
        ("day", "30-10-2026"),
        ("batch_id", "short"),
        ("pad", "not spaces"),
        ("protocol", ...),
    ],
)
def test_field_rejections(path: str, value: Any) -> None:
    bad(mutated(path, value))


def test_unsupported_protocol_code() -> None:
    bad(mutated("protocol", "spn/2"), "unsupported_protocol")
    bad(mutated("protocol", 1), "invalid_payload")


def test_caps() -> None:
    src = BATCH["sources"][0]
    many = [src | {"ip": f"8.{i // 256}.{i % 256}.1"} for i in range(5001)]
    bad(BATCH | {"sources": many})
    ok = [src | {"ip": f"8.{i // 256}.{i % 256}.1"} for i in range(5000)]
    assert len(parse(BATCH | {"sources": ok}).sources) == 5000
    bad(BATCH | {"files": [{"sha256": f"{i:064x}"} for i in range(1001)]})


def test_duplicates_refused() -> None:
    bad(BATCH | {"sources": BATCH["sources"] * 2})
    bad(BATCH | {"files": BATCH["files"] * 2})
    bad(BATCH | {"c2": BATCH["c2"] * 2})
    bad(BATCH | {"payloads": BATCH["payloads"] * 2})


def test_size_json_and_depth() -> None:
    with pytest.raises(ProtoError) as err:
        parse_body(ObservationBatch, b" " * 100, max_bytes=50)
    assert err.value.code == "too_large"
    for raw in (b"", b"[]", b"{", b'"x"', b"\xff\xfe"):
        with pytest.raises(ProtoError) as err:
            parse_body(ObservationBatch, raw)
        assert err.value.code == "invalid_payload"
    deep: Any = {"protocol": "spn/1", "x": {"a": {"b": {"c": {"d": {"e": 1}}}}}}
    with pytest.raises(ProtoError) as err:
        parse_body(ObservationBatch, json.dumps(deep).encode())
    assert err.value.code == "invalid_payload"
    with pytest.raises(ProtoError):
        parse_body(ObservationBatch, b"[" * 100000)


def test_error_detail_has_no_values() -> None:
    with pytest.raises(ProtoError) as err:
        parse(mutated("sources.0.ip", PRIV10_B))
    assert PRIV10_B not in err.value.detail


def test_padding_roundtrip_is_accepted() -> None:
    raw = sign.pad_body(BATCH)
    assert len(raw) % 4096 == 0
    assert parse_body(ObservationBatch, raw, max_bytes=models.MAX_BODY_OBSERVATIONS)


def test_enrol_and_node_models() -> None:
    challenge = sign.b64u_encode(b"c" * 32)
    ok = {
        "protocol": "spn/1",
        "challenge": challenge,
        "pow_nonce": sign.b64u_encode(b"\x00" * 8),
        "pseudonym": "night-owl",
        "country": "CH",
        "show_country": True,
    }
    assert parse_body(models.EnrolRequest, json.dumps(ok).encode()).country == "CH"
    for patch in (
        {"country": "ch"},
        {"country": "CHE"},
        {"pow_nonce": sign.b64u_encode(b"x" * 17)},
        {"challenge": sign.b64u_encode(b"c" * 31)},
        {"unknown": 1},
    ):
        with pytest.raises(ProtoError):
            parse_body(models.EnrolRequest, json.dumps(ok | patch).encode())
    req = models.ChallengeRequest(protocol="spn/1", node_key=sign.node_key(b"k" * 32))
    assert req.node_key


def test_reveals_rechecks_limits() -> None:
    item = {"kind": "url", "value_b": H, "value": "http://example.org/x"}
    ok = {"protocol": "spn/1", "items": [item]}
    assert parse_body(models.RevealsRequest, json.dumps(ok).encode()).items
    with pytest.raises(ProtoError):
        parse_body(models.RevealsRequest, json.dumps({**ok, "items": [item] * 201}).encode())
    with pytest.raises(ProtoError):
        parse_body(
            models.RevealsRequest, json.dumps({**ok, "items": [item | {"kind": "ip"}]}).encode()
        )
    rc: dict[str, Any] = {
        "protocol": "spn/1",
        "day": "2026-10-30",
        "items": [{"id": "t_8c1d2e0a11bb", "state": "down"}],
    }
    assert parse_body(models.RechecksRequest, json.dumps(rc).encode()).items
    with pytest.raises(ProtoError):
        parse_body(models.RechecksRequest, json.dumps(rc | {"items": rc["items"] * 2}).encode())
    with pytest.raises(ProtoError):
        bad_rc = {"items": [{"id": "t_8c1d2e0a11bb", "state": "maybe"}]}
        parse_body(models.RechecksRequest, json.dumps(rc | bad_rc).encode())


def test_target_response_privacy_shape() -> None:
    target = {
        "id": "t_8c1d2e0a11bb",
        "kind": "ip",
        "value": "8.8.4.4",
        "value_b": None,
        "state": "confirmed",
        "nodes": 1,
        "countries": 4,
        "first_day": "2026-10-26",
        "last_day": "2026-10-30",
        "services": ["ssh"],
        "activity": ["login"],
        "tags": ["mirai"],
        "families": [],
        "reported_day": None,
        "taken_down_day": None,
    }
    resp = {"cursor": "c_1", "targets": [target], "reveal": [], "recheck": []}
    assert models.parse_response(models.TargetsResponse, json.dumps(resp).encode()).targets
    # countries below 3 and nodes outside the bucket range are not representable
    for patch in ({"countries": 2}, {"nodes": 5}, {"node_id": "x"}):
        broken = {**resp, "targets": [target | patch]}
        with pytest.raises(ProtoError):
            models.parse_response(models.TargetsResponse, json.dumps(broken).encode())


def test_vocabularies() -> None:
    assert enums.is_valid_tag("cve-2026-109618")
    assert enums.is_valid_tag("mirai")
    for tag in ("CVE-2026-1", "cve-26-1234", "selfhostr", "cve-2026-12345678", ""):
        assert not enums.is_valid_tag(tag)
    assert "credentials" in enums.RESERVED_FIELDS
    for word in ("suckerpot", "selfhostr", "honeypot"):
        for vocab in (enums.TAGS_V1, enums.FAMILIES_V1, enums.FILE_TYPES_V1):
            assert not any(word in v for v in vocab)


@pytest.mark.parametrize(
    "ip",
    ["64:ff9b::808:808", "64:ff9b:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2002:808:808::1"],
)
def test_addresses_that_embed_an_ipv4_address_are_refused(ip: str) -> None:
    bad(mutated("sources.0.ip", ip))
    bad(mutated("c2.0.ip", ip), allow_documentation=True)
    assert models.parse_global_ip("2606:4700:4700::1111") == "2606:4700:4700::1111"


def _target(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "t_0123456789ab", "kind": "ip", "value": "198.51.100.23", "value_b": None,
        "state": "confirmed", "nodes": 2, "countries": 3, "first_day": "2026-10-30",
        "last_day": "2026-11-02", "services": ["ssh"], "activity": ["login"],
        "tags": ["mirai"], "families": ["mirai"], "reported_day": None, "taken_down_day": None,
    }  # fmt: skip
    return {**base, **kw}


def test_target_fields_are_bounded() -> None:
    models.Target.model_validate(_target())
    for bad in (
        {"value": "a" * 2049},
        {"services": ["ssh"] * 40},
        {"services": ["not-a-service"]},
        {"activity": ["nope"]},
        {"families": ["not-a-family"]},
        {"families": ["mirai"] * 33},
    ):
        with pytest.raises(ValueError):
            models.Target.model_validate(_target(**bad))
    assert models.Target.model_validate(_target(value="a" * 2048)).value == "a" * 2048
    kept = models.Target.model_validate(_target(tags=["mirai", "x" * 5000, "mirai"]))
    assert kept.tags == ["mirai"]  # unknown tags are dropped, never stored


def test_network_country_needs_two_members() -> None:
    assert models.NetworkCountry.model_validate({"cc": "CH", "members": 2}).members == 2
    for members in (0, 1):
        with pytest.raises(ValueError):
            models.NetworkCountry.model_validate({"cc": "CH", "members": members})
