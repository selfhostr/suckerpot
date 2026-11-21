"""Signed trap pack bundles (M37 P2): sign, verify, refuse forgeries, other keys and rollback."""

from __future__ import annotations

import json

import pytest

from suckerpot_netproto.feeds import FeedError, minisign
from suckerpot_netproto.feeds import traps as tb

from .test_feeds_common import SECRET, SECRET2


def bundle(seq: int, **extra: object) -> bytes:
    doc = {"schema": tb.SCHEMA, "seq": seq, "packs": [], **extra}
    return json.dumps(doc, sort_keys=True).encode()


def test_round_trip_and_comment() -> None:
    data = bundle(7)
    sig = tb.sign_bundle(data, SECRET)
    assert "trusted comment: suckerpot-traps seq=7\n" in sig
    assert tb.verify_bundle(data, sig, SECRET.public) == 7
    assert tb.verify_bundle(data, sig, SECRET.public, last_seq=7) == 7
    assert tb.verify_bundle(data, sig, SECRET.public, last_seq=3) == 7


def test_forged_signature_is_refused() -> None:
    data = bundle(7)
    sig = tb.sign_bundle(data, SECRET)
    with pytest.raises(FeedError) as err:
        tb.verify_bundle(data.replace(b'"packs": []', b'"packs": [ ]'), sig, SECRET.public)
    assert err.value.code == "bad_signature"
    # A signature made by another key with the first key's id.
    forged_key = minisign.SecretKey(SECRET2.seed, SECRET.key_id)
    with pytest.raises(FeedError) as err:
        tb.verify_bundle(data, tb.sign_bundle(data, forged_key), SECRET.public)
    assert err.value.code == "bad_signature"


def test_wrong_key_is_refused() -> None:
    data = bundle(7)
    with pytest.raises(FeedError) as err:
        tb.verify_bundle(data, tb.sign_bundle(data, SECRET2), SECRET.public)
    assert err.value.code == "wrong_key"


def test_lower_seq_is_refused() -> None:
    data = bundle(7)
    with pytest.raises(FeedError) as err:
        tb.verify_bundle(data, tb.sign_bundle(data, SECRET), SECRET.public, last_seq=8)
    assert err.value.code == "rollback"


def test_signature_cannot_move_to_another_seq() -> None:
    """The trusted comment names the seq: a signed comment for seq 9 over a file that says 7."""
    data = bundle(7)
    sig = minisign.sign(data, SECRET, tb.trusted_comment(9))
    with pytest.raises(FeedError) as err:
        tb.verify_bundle(data, sig, SECRET.public)
    assert err.value.code == "wrong_serial"


@pytest.mark.parametrize(
    "comment",
    ["timestamp:1 file:traps.json serial:7", "suckerpot-traps seq=", "suckerpot-traps seq=07",
     "suckerpot-traps seq=7 ", "suckerpot-traps seq=-7", "suckerpot-traps seq=99999999999999999"],
)  # fmt: skip
def test_other_trusted_comments_are_refused(comment: str) -> None:
    data = bundle(7)
    with pytest.raises(FeedError) as err:
        tb.verify_bundle(data, minisign.sign(data, SECRET, comment), SECRET.public)
    assert err.value.code == "bad_format"


@pytest.mark.parametrize(
    "data",
    [
        b"not json",
        b"[]",
        json.dumps({"schema": "other/1", "seq": 1}).encode(),
        json.dumps({"schema": tb.SCHEMA, "seq": "1"}).encode(),
        json.dumps({"schema": tb.SCHEMA, "seq": True}).encode(),
        json.dumps({"schema": tb.SCHEMA, "seq": -1}).encode(),
        json.dumps(
            {"schema": tb.SCHEMA, "seq": 1, "x": [[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]}
        ).encode(),
    ],
)
def test_bad_envelopes(data: bytes) -> None:
    with pytest.raises(FeedError) as err:
        tb.bundle_seq(data)
    assert err.value.code == "bad_format"


def test_size_cap() -> None:
    data = bundle(1, pad="x" * tb.MAX_BYTES)
    with pytest.raises(FeedError) as err:
        tb.bundle_seq(data)
    assert err.value.code == "too_large"
    with pytest.raises(FeedError) as err:
        tb.verify_bundle(data, "", SECRET.public)
    assert err.value.code == "too_large"
