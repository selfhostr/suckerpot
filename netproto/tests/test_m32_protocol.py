"""M32 protocol additions: verify wire shapes, hub key set and alternate signature, defaults."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from suckerpot_netproto import ERROR_STATUS, ProtoError, defaults, enums, models, sign
from suckerpot_netproto.feeds import minisign
from suckerpot_netproto.models import (
    VerifyResultsRequest,
    VerifyRevealsResponse,
    VerifyTasksResponse,
    parse_body,
    parse_response,
)

FEED_PUBLIC = minisign.generate_keypair().public.encoded
H = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
REPO = Path(__file__).resolve().parents[2]


def _results(*items: dict[str, Any]) -> bytes:
    return json.dumps({"protocol": "spn/1", "items": list(items)}).encode()


FETCHED = {
    "id": "v_0123456789ab",
    "outcome": "fetched",
    "sha256": H,
    "size": 48213,
    "file_type": "elf-arm",
    "family": "mirai",
}


# --- verify models ---


def test_error_code_not_verifier() -> None:
    assert ERROR_STATUS["not_verifier"] == 403
    assert ProtoError("not_verifier").status == 403


def test_reveals_answer() -> None:
    ok = json.dumps({"items": [{"kind": "url", "value_b": H}]}).encode()
    assert parse_response(VerifyRevealsResponse, ok).items[0].value_b == H
    for bad in (
        {"items": [{"kind": "domain", "value_b": H}]},
        {"items": [{"kind": "url", "value_b": "zz"}]},
        {"items": [{"kind": "url", "value_b": H, "x": 1}]},
        {"items": [{"kind": "url", "value_b": H}] * 201},
        {"items": [], "extra": 1},
    ):
        with pytest.raises(ProtoError):
            parse_response(VerifyRevealsResponse, json.dumps(bad).encode())


def test_tasks_answer() -> None:
    task = {
        "id": "v_0123456789ab",
        "url": "http://198.51.100.9/x.sh",
        "lease_until": "2026-11-03T18:00:00Z",
    }
    got = parse_response(VerifyTasksResponse, json.dumps({"tasks": [task]}).encode())
    assert got.tasks[0].url == "http://198.51.100.9/x.sh"
    bad_tasks: list[Any] = [
        [{**task, "id": "v_XYZ"}],
        [{**task, "lease_until": "tomorrow"}],
        [{**task, "url": ""}],
        [{**task, "url": "http://example.org/" + "a" * 2048}],
        [task, task],  # duplicate id
        [task] * 21,
    ]
    for bad in bad_tasks:
        with pytest.raises(ProtoError):
            parse_response(VerifyTasksResponse, json.dumps({"tasks": bad}).encode())


def test_results_request_valid() -> None:
    req = parse_body(
        VerifyResultsRequest,
        _results(
            FETCHED,
            {"id": "v_aaaaaaaaaaaa", "outcome": "timeout"},
            {**FETCHED, "id": "v_bbbbbbbbbbbb", "family": None},
        ),
    )
    assert [i.outcome for i in req.items] == ["fetched", "timeout", "fetched"]
    # padded like every spn/1 request
    padded = sign.pad_body({"protocol": "spn/1", "items": [FETCHED]})
    assert parse_body(VerifyResultsRequest, padded).items[0].size == 48213


@pytest.mark.parametrize("outcome", models.VERIFY_OUTCOMES)
def test_every_outcome_is_accepted_without_fetch_fields(outcome: str) -> None:
    item: dict[str, Any] = {"id": "v_0123456789ab", "outcome": outcome}
    if outcome == "fetched":
        item = FETCHED
    assert parse_body(VerifyResultsRequest, _results(item)).items[0].outcome == outcome


def test_outcomes_match_the_literal() -> None:
    literal = models.VerifyResult.model_fields["outcome"].annotation
    assert set(literal.__args__) == set(models.VERIFY_OUTCOMES)  # type: ignore[union-attr]


def test_results_request_refuses() -> None:
    nofile = {"id": "v_0123456789ab", "outcome": "unreachable"}
    cases: list[dict[str, Any]] = [
        {k: v for k, v in FETCHED.items() if k != "sha256"},
        {k: v for k, v in FETCHED.items() if k != "size"},
        {k: v for k, v in FETCHED.items() if k != "file_type"},
        {**FETCHED, "size": 0},
        {**FETCHED, "size": 67_108_865},
        {**FETCHED, "file_type": "exe"},
        {**FETCHED, "family": "notafamily"},
        {**FETCHED, "sha256": "ABC"},
        {**FETCHED, "id": "x_0123456789ab"},
        {**FETCHED, "outcome": "ok"},
        {**nofile, "sha256": H},
        {**nofile, "family": "mirai"},
        {**nofile, "size": 5},
        {**FETCHED, "extra": 1},
    ]
    for item in cases:
        with pytest.raises(ProtoError) as err:
            parse_body(VerifyResultsRequest, _results(item))
        assert err.value.code == "invalid_payload"


def test_results_request_envelope_rules() -> None:
    with pytest.raises(ProtoError):
        parse_body(VerifyResultsRequest, _results(FETCHED, FETCHED))  # duplicate id
    many = [{"id": f"v_{i:012x}", "outcome": "skipped"} for i in range(51)]
    with pytest.raises(ProtoError):
        parse_body(VerifyResultsRequest, _results(*many))
    fifty = many[:50]
    assert len(parse_body(VerifyResultsRequest, _results(*fifty)).items) == 50
    with pytest.raises(ProtoError) as err:
        parse_body(VerifyResultsRequest, json.dumps({"protocol": "spn/2", "items": []}).encode())
    assert err.value.code == "unsupported_protocol"
    with pytest.raises(ProtoError):
        parse_body(VerifyResultsRequest, json.dumps({"items": []}).encode())
    with pytest.raises(ProtoError) as err:
        parse_body(VerifyResultsRequest, b"x" * (64 * 1024 + 1))
    assert err.value.code == "too_large"


def test_family_and_file_type_vocabularies_are_reused() -> None:
    for fam in enums.FAMILIES_V1:
        item = {**FETCHED, "family": fam}
        parse_body(VerifyResultsRequest, _results(item))


def test_existing_models_still_refuse_new_names() -> None:
    # Old shapes are untouched: unknown fields stay refused.
    with pytest.raises(ProtoError):
        parse_body(
            models.RevealsRequest, json.dumps({"protocol": "spn/1", "items": [], "x": 1}).encode()
        )


# --- key set and alternate signature ---


def _keys(n: int) -> tuple[list[bytes], list[str]]:
    privs = [sign.generate_private_key() for _ in range(n)]
    return privs, [sign.node_key(sign.public_key_of(p)) for p in privs]


def test_parse_key_set() -> None:
    _, keys = _keys(3)
    assert sign.parse_key_set(keys[0]) == (keys[0],)
    assert sign.parse_key_set(f" {keys[0]} , {keys[1]},{keys[2]}") == tuple(keys)
    for bad in (
        "",
        ",",
        f"{keys[0]},",
        f"{keys[0]},{keys[0]}",
        "<HUB_PUBLIC_KEY>",
        "short",
        ",".join([*keys, sign.node_key(sign.public_key_of(sign.generate_private_key()))]),
    ):
        with pytest.raises(ValueError):
            sign.parse_key_set(bad)


def test_answer_accepted_under_any_pinned_key_and_either_header() -> None:
    privs, keys = _keys(3)
    binding = sign.RequestBinding.unsigned("GET", "/v1/info", "n" * 22)
    body = b'{"ok":true}'
    primary = sign.sign_response(privs[0], binding, 200, body)
    alt = sign.sign_response(privs[1], binding, 200, body)
    assert sign.verify_response_any(keys[:2], [primary, alt], binding, 200, body)
    # a node that pins only the new key accepts through the alternate header
    assert sign.verify_response_any([keys[1]], [primary, alt], binding, 200, body)
    # a node that pins only the old key accepts through the primary header
    assert sign.verify_response_any([keys[0]], [primary, alt], binding, 200, body)
    # the alternate header may be absent
    assert sign.verify_response_any([keys[0]], [primary, None], binding, 200, body)
    assert not sign.verify_response_any([keys[2]], [primary, alt], binding, 200, body)


def test_answer_checks_stay_bound_to_the_request() -> None:
    privs, keys = _keys(2)
    binding = sign.RequestBinding.unsigned("GET", "/v1/info", "n" * 22)
    other = sign.RequestBinding.unsigned("GET", "/v1/info", "m" * 22)
    body = b"{}"
    sig = sign.sign_response(privs[0], binding, 200, body)
    assert not sign.verify_response_any(keys, [sig, None], other, 200, body)
    assert not sign.verify_response_any(keys, [sig, None], binding, 201, body)
    assert not sign.verify_response_any(keys, [sig, None], binding, 200, b"{ }")
    assert not sign.verify_response_any(keys, [None, None], binding, 200, body)
    assert not sign.verify_response_any(keys, ["", "!!"], binding, 200, body)


def test_key_set_size_and_garbage_keys_fail_closed() -> None:
    privs, keys = _keys(4)
    binding = sign.RequestBinding.unsigned("GET", "/v1/info", "n" * 22)
    sig = sign.sign_response(privs[0], binding, 200, b"")
    assert not sign.verify_response_any([], [sig], binding, 200, b"")
    assert not sign.verify_response_any(keys, [sig], binding, 200, b"")  # 4 keys
    assert sign.verify_response_any(["garbage", keys[0]], [sig], binding, 200, b"")
    assert not sign.verify_response_any(["<HUB_PUBLIC_KEY>"], [sig], binding, 200, b"")
    with pytest.raises(ProtoError) as err:
        sign.require_response_any(keys[1:3], [sig], binding, 200, b"")
    assert err.value.code == "hub_signature"
    sign.require_response_any(keys[:2], [sig], binding, 200, b"")
    assert sign.key_in_set(keys[:2], keys[1]) and not sign.key_in_set(keys[:2], keys[2])


def test_single_key_verify_response_unchanged() -> None:
    privs, keys = _keys(2)
    binding = sign.RequestBinding.unsigned("GET", "/v1/info", "n" * 22)
    sig = sign.sign_response(privs[0], binding, 200, b"x")
    assert sign.verify_response(keys[0], sig, binding, 200, b"x")
    assert not sign.verify_response(keys[1], sig, binding, 200, b"x")
    assert sign.H_HUB_SIGNATURE == "X-SPN-Hub-Signature"
    assert sign.H_HUB_SIGNATURE_ALT == "X-SPN-Hub-Signature-Alt"


# --- committed defaults ---


def test_committed_defaults_load_and_are_placeholders_until_release() -> None:
    d = defaults.load()
    assert d.version == 1
    assert d.hub_url == "https://suckerpot-hub.selfhostr.io"
    assert d.feed_url == "https://suckerpot-feeds.selfhostr.io/v1"
    # Until the release fills the keys, they are placeholders and the network is not joinable.
    if d.placeholders():
        assert set(d.placeholders()) == {"NETWORK_HUB_KEY", "NETWORK_FEED_KEY"}
        assert not d.hub_configured and not d.feed_configured
        assert d.hub_keys == () and d.feed_keys == ()
    else:
        assert d.hub_configured and d.feed_configured
        assert len(d.hub_keys) == 1 and len(d.feed_keys) == 1


def test_host_mirror_is_identical_to_package_data() -> None:
    pkg = Path(defaults.__file__).parent / "data" / defaults.DEFAULTS_FILE
    mirror = REPO / "config" / "network-defaults.env"
    assert mirror.read_bytes() == pkg.read_bytes()


def test_placeholder_detection() -> None:
    for v in ("", "  ", "<HUB_PUBLIC_KEY>", "<FEED_PUBLIC_KEY>", "prefix<X>"):
        assert defaults.is_placeholder(v)
    assert not defaults.is_placeholder("https://suckerpot-hub.selfhostr.io")
    assert not defaults.is_placeholder(
        sign.node_key(sign.public_key_of(sign.generate_private_key()))
    )


def _file(**over: str) -> str:
    _, keys = _keys(2)
    values = {
        "NETWORK_DEFAULTS_VERSION": "1",
        "NETWORK_HUB_URL": "https://hub.example.org",
        "NETWORK_HUB_KEY": ",".join(keys),
        "NETWORK_FEED_URL": "https://feeds.example.org/v1",
        "NETWORK_FEED_KEY": FEED_PUBLIC,
    }
    values.update(over)
    return "# c\n" + "\n".join(f"{k}={v}" for k, v in values.items() if v != "<DROP>") + "\n"


def test_real_values_validate() -> None:
    d = defaults.from_text(_file())
    assert d.placeholders() == ()
    assert d.hub_configured and d.feed_configured
    assert len(d.hub_keys) == 2 and len(d.feed_keys) == 1


@pytest.mark.parametrize(
    "over",
    [
        {"NETWORK_DEFAULTS_VERSION": "2"},
        {"NETWORK_DEFAULTS_VERSION": "x"},
        {"NETWORK_HUB_URL": "http://hub.example.org"},
        {"NETWORK_HUB_URL": "https://hub.example.org/path"},
        {"NETWORK_HUB_URL": "https://user:pw@hub.example.org"},
        {"NETWORK_HUB_URL": "https://198.51.100.9"},
        {"NETWORK_HUB_URL": "https://hub.internal"},
        {"NETWORK_HUB_URL": "https://localhost"},
        {"NETWORK_FEED_URL": "https://feeds.example.org/v1?x=1"},
        {"NETWORK_FEED_URL": "ftp://feeds.example.org"},
        {"NETWORK_HUB_KEY": "notakey"},
        {"NETWORK_FEED_KEY": "notakey"},
        {"NETWORK_HUB_KEY": "<DROP>"},
    ],
)
def test_malformed_defaults_are_refused(over: dict[str, str]) -> None:
    with pytest.raises(defaults.DefaultsError):
        defaults.from_text(_file(**over))


def test_trap_pack_key_is_optional_and_checked() -> None:
    """M37: TRAP_PACK_KEY may be absent or empty (downloaded trap packs off); a value must be a
    minisign public key. It never makes a release a placeholder release."""
    assert defaults.from_text(_file()).trap_key == ""
    assert defaults.from_text(_file(TRAP_PACK_KEY="")).trap_key == ""
    d = defaults.from_text(_file(TRAP_PACK_KEY=FEED_PUBLIC))
    assert d.trap_key == FEED_PUBLIC and d.placeholders() == ()
    with pytest.raises(defaults.DefaultsError):
        defaults.from_text(_file(TRAP_PACK_KEY="notakey"))
    committed = defaults.load().trap_key
    assert committed == "" or minisign.parse_public_key(committed)
    assert defaults.effective({"TRAP_PACK_KEY": FEED_PUBLIC}, "TRAP_PACK_KEY") == FEED_PUBLIC


def test_parse_is_strict() -> None:
    good = _file()
    for bad in (
        good + "NETWORK_EXTRA=1\n",
        good + "NETWORK_HUB_URL=https://hub.example.org\n",
        good + "not a line\n",
        good + "network_hub_url=x\n",
    ):
        with pytest.raises(defaults.DefaultsError):
            defaults.from_text(bad)


def test_effective_prefers_explicit_environment_value() -> None:
    assert defaults.effective(
        {"NETWORK_HUB_URL": "https://hub.example.org"}, "NETWORK_HUB_URL"
    ) == ("https://hub.example.org")
    assert defaults.effective({"NETWORK_HUB_URL": "  "}, "NETWORK_HUB_URL") == (
        "https://suckerpot-hub.selfhostr.io"
    )
    # a placeholder default reads as unset
    if defaults.load().placeholders():
        assert defaults.effective({}, "NETWORK_HUB_KEY") == ""
    assert defaults.effective({}, "NETWORK_UNKNOWN") == ""


def test_defaults_file_names_no_private_values() -> None:
    text = (REPO / "config" / "network-defaults.env").read_text()
    assert not re.search(r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+", text)
    # the product name may appear only inside the two public hostnames (owner decision 2026-11-04)
    stripped = text.replace("suckerpot-hub.selfhostr.io", "").replace(
        "suckerpot-feeds.selfhostr.io", ""
    )
    assert "suckerpot" not in stripped.lower()


# --- pseudonym words ---


def test_pseudonym_words() -> None:
    adjectives, nouns = defaults.pseudonym_words()
    assert len(adjectives) >= 64 and len(nouns) >= 64
    assert len(set(adjectives)) == len(adjectives) and len(set(nouns)) == len(nouns)
    assert not set(adjectives) & set(nouns)
    reserved = {
        "admin", "administrator", "root", "hub", "official", "moderator", "staff", "support",
        "system", "network", "node", "suckerpot", "selfhostr", "honeypot",
    }  # fmt: skip
    pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{1,22}[A-Za-z0-9]$")
    for a in adjectives:
        for n in (nouns[0], nouns[-1], max(nouns, key=len)):
            name = f"{a}-{n}-99"
            assert pattern.fullmatch(name) and len(name) <= 24
    for w in (*adjectives, *nouns):
        assert w not in reserved
        assert not any(r in w for r in ("suckerpot", "selfhostr", "honeypot"))
    longest = max(map(len, adjectives)) + max(map(len, nouns)) + 4
    assert longest <= 24
