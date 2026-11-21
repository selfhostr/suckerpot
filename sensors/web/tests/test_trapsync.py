"""Downloaded trap packs in the web sensor (M37 P2): signature, rollback, kill list, fallback and
reload without dropping a connection."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from conftest import Harness
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from test_traps import StartWith, edgegate, req

from web_sensor import packsig
from web_sensor.trapsync import ACTIVE, SIGNATURE, SyncSettings, TrapSync

TODAY = date(2026, 11, 20)
BUNDLED_IDS = ["log4j-log4shell", "phpunit-eval-stdin", "router-boaform-gponform"]


class Signer:
    """A minisign-compatible signer for tests (pre-hashed Ed25519, as the release workflow)."""

    def __init__(self, seed: int, key_id: bytes | None = None) -> None:
        self.sk = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
        self.key_id = key_id or bytes([seed]) * 8
        raw = self.sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public = base64.b64encode(b"Ed" + self.key_id + raw).decode()

    def sign(self, data: bytes, comment: str) -> str:
        sig = self.sk.sign(hashlib.blake2b(data, digest_size=64).digest())
        glob = self.sk.sign(sig + comment.encode())
        line = base64.b64encode(b"ED" + self.key_id + sig).decode()
        return (
            f"untrusted comment: test\n{line}\ntrusted comment: {comment}\n"
            f"{base64.b64encode(glob).decode()}\n"
        )


KEY = Signer(7)
OTHER = Signer(9)


def bundle(seq: int, packs: list[dict[str, Any]] | None = None, **extra: Any) -> bytes:
    doc = {"schema": "suckerpot-traps/1", "seq": seq, "packs": packs or [], **extra}
    return json.dumps(doc, sort_keys=True, indent=1).encode()


def publish(d: Path, data: bytes, sig: str) -> None:
    """What ingest does: temporary file, then rename over the active one."""
    for name, body in ((SIGNATURE, sig.encode()), (ACTIVE, data)):
        tmp = d / f"{name}.tmp"
        tmp.write_bytes(body)
        os.replace(tmp, d / name)


def put(d: Path, seq: int, packs: list[dict[str, Any]] | None = None, *, signer: Signer = KEY,
        comment_seq: int | None = None, **extra: Any) -> bytes:  # fmt: skip
    data = bundle(seq, packs, **extra)
    publish(d, data, signer.sign(data, f"suckerpot-traps seq={comment_seq or seq}"))
    return data


def sync(d: Path, **kw: Any) -> TrapSync:
    settings = SyncSettings(key=kw.pop("key", KEY.public), directory=d, **kw)
    return TrapSync(settings, today=lambda: TODAY)


def ids(s: TrapSync) -> list[str]:
    return [p.id for p in s.current.packs]


def new_pack(pid: str = "acme-edgegate-cve-2026-55501", version: int = 1) -> dict[str, Any]:
    obj = edgegate()
    obj["id"], obj["version"] = pid, version
    return obj


# -- signature ------------------------------------------------------------------------------


def test_packsig_matches_the_reference_format() -> None:
    data = bundle(5)
    key = packsig.parse_key(KEY.public)
    assert packsig.verify(data, KEY.sign(data, "suckerpot-traps seq=5"), key) == 5
    for bad_comment in ("suckerpot-traps seq=05", "timestamp:1 file:x serial:5", "seq=5"):
        with pytest.raises(packsig.SignatureError) as err:
            packsig.verify(data, KEY.sign(data, bad_comment), key)
        assert err.value.code == "bad_format"
    with pytest.raises(packsig.SignatureError) as err:
        packsig.parse_key("not a key")
    assert err.value.code == "bad_key"


def test_valid_bundle_loads_with_the_bundled_packs(tmp_path: Path) -> None:
    s = sync(tmp_path)
    assert ids(s) == BUNDLED_IDS and s.current.seq == 0
    put(tmp_path, 12, [new_pack()])
    fresh = s.check()
    assert fresh is not None and fresh is s.current
    assert ids(s) == sorted([*BUNDLED_IDS, "acme-edgegate-cve-2026-55501"])
    assert s.current.seq == 12 and s.loaded_seq == 12
    assert s.check() is None  # unchanged files: nothing to do


def test_forged_signature_is_refused(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    s = sync(tmp_path)
    put(tmp_path, 12, [new_pack()])
    assert s.check() is not None
    before = s.current
    data = bundle(13, [new_pack(version=2)])
    sig = KEY.sign(bundle(13, [new_pack()]), "suckerpot-traps seq=13")  # signs other bytes
    publish(tmp_path, data, sig)
    assert s.check() is None and s.current is before
    assert s.last_error == "bad_signature" and s.refused == 1
    assert "trap bundle refused: bad_signature" in caplog.text
    assert "EdgeGate" not in caplog.text  # never pack content in logs
    # A key with the right id but another secret is a forgery too.
    put(tmp_path, 14, [new_pack(version=3)], signer=Signer(9, key_id=KEY.key_id))
    assert s.check() is None and s.current is before and s.last_error == "bad_signature"


def test_wrong_key_is_refused(tmp_path: Path) -> None:
    s = sync(tmp_path)
    put(tmp_path, 12, [new_pack()], signer=OTHER)
    assert s.check() is None and ids(s) == BUNDLED_IDS and s.last_error == "wrong_key"


def test_lower_seq_is_refused(tmp_path: Path) -> None:
    s = sync(tmp_path)
    put(tmp_path, 12, [new_pack(version=2)])
    assert s.check() is not None
    loaded = s.current
    put(tmp_path, 11, [new_pack(version=1)])  # an older, validly signed bundle
    assert s.check() is None and s.current is loaded and s.last_error == "rollback"
    put(tmp_path, 12, [new_pack(version=2)])  # the same seq again is fine
    assert s.check() is not None and s.current.seq == 12


def test_signature_for_another_seq_is_refused(tmp_path: Path) -> None:
    s = sync(tmp_path)
    put(tmp_path, 12, [new_pack()], comment_seq=99)
    assert s.check() is None and s.last_error == "wrong_seq"


def test_unparsable_bundle_keeps_the_current_set(tmp_path: Path) -> None:
    s = sync(tmp_path)
    data = b"{not json"
    publish(tmp_path, data, KEY.sign(data, "suckerpot-traps seq=3"))
    assert s.check() is None and s.last_error == "schema" and ids(s) == BUNDLED_IDS


def test_no_key_means_bundled_packs_only(tmp_path: Path) -> None:
    put(tmp_path, 12, [new_pack()])
    for key in ("", "<TRAP_PACK_KEY>", "garbage"):
        s = (
            sync(tmp_path, key=key)
            if key != "<TRAP_PACK_KEY>"
            else TrapSync(
                SyncSettings.from_env({"TRAP_PACK_KEY": key, "TRAP_PACKS_DIR": str(tmp_path)}),
                today=lambda: TODAY,
            )
        )
        assert s.check() is None and ids(s) == BUNDLED_IDS


# -- what loads ------------------------------------------------------------------------------


def test_bad_pack_does_not_stop_the_others(tmp_path: Path) -> None:
    bad = new_pack("bad-pack")
    bad["traps"][0]["outcome"]["flags"] = ["rce"]  # a built-in flag
    s = sync(tmp_path)
    put(tmp_path, 3, [bad, new_pack()])
    assert s.check() is not None
    assert "acme-edgegate-cve-2026-55501" in ids(s) and "bad-pack" not in ids(s)
    assert ("bad-pack", "schema") in s.current.rejected


def test_kill_list_turns_off_a_bundled_pack(tmp_path: Path) -> None:
    s = sync(tmp_path)
    put(tmp_path, 3, [], disabled=[{"id": "log4j-log4shell", "reason": "flags benign traffic"}])
    assert s.check() is not None
    assert ids(s) == ["phpunit-eval-stdin", "router-boaform-gponform"]
    flags = s.current.severe
    assert "log4shell" not in flags and "phpunit_rce" in flags


def test_local_disabled_setting(tmp_path: Path) -> None:
    settings = SyncSettings.from_env(
        {"TRAP_PACK_KEY": KEY.public, "TRAP_PACKS_DIR": str(tmp_path),
         "TRAP_PACKS_DISABLED": "phpunit-eval-stdin, acme-edgegate-cve-2026-55501"}
    )  # fmt: skip
    s = TrapSync(settings, today=lambda: TODAY)
    assert ids(s) == ["log4j-log4shell", "router-boaform-gponform"]
    put(tmp_path, 3, [new_pack()])
    assert s.check() is not None
    assert ids(s) == ["log4j-log4shell", "router-boaform-gponform"]


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"TRAP_PACKS_DISABLED": "Bad Id"}, "TRAP_PACKS_DISABLED"),
        ({"TRAP_PACKS_RELOAD_S": "1"}, "TRAP_PACKS_RELOAD_S"),
        ({"TRAP_PACKS_DIR": "relative"}, "TRAP_PACKS_DIR"),
    ],
)
def test_settings_are_checked(env: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        SyncSettings.from_env(env)


def test_files_gone_fall_back_to_bundled(tmp_path: Path) -> None:
    s = sync(tmp_path)
    put(tmp_path, 12, [new_pack()])
    assert s.check() is not None
    (tmp_path / ACTIVE).unlink()
    (tmp_path / SIGNATURE).unlink()
    assert s.check() is not None and ids(s) == BUNDLED_IDS
    # The seq stays remembered: an older bundle put back later is still refused.
    put(tmp_path, 5, [new_pack()])
    assert s.check() is None and s.last_error == "rollback"


def test_bundle_older_than_the_image_is_ignored(tmp_path: Path) -> None:
    image = tmp_path / "bundled.json"
    image.write_bytes(bundle(50))
    d = tmp_path / "traps"
    d.mkdir()
    s = TrapSync(SyncSettings(key=KEY.public, directory=d), bundled_path=image)
    put(d, 40, [new_pack()])
    assert s.check() is None and ids(s) == []
    put(d, 60, [new_pack()])
    assert s.check() is not None and ids(s) == [new_pack()["id"]]


def test_half_written_pair_is_retried(tmp_path: Path) -> None:
    """Ingest renames the signature, then the bundle: a check in between sees a mismatch and
    the next one (the stamp changed) loads the pair."""
    s = sync(tmp_path)
    data = bundle(4, [new_pack()])
    (tmp_path / SIGNATURE).write_text(KEY.sign(data, "suckerpot-traps seq=4"))
    (tmp_path / ACTIVE).write_bytes(bundle(3))
    assert s.check() is None and s.last_error == "bad_signature"
    (tmp_path / ACTIVE).write_bytes(data)
    assert s.check() is not None and s.current.seq == 4


def test_oversized_files_are_refused_unread(tmp_path: Path) -> None:
    s = sync(tmp_path)
    (tmp_path / ACTIVE).write_bytes(b" " * (1024 * 1024 + 1))
    (tmp_path / SIGNATURE).write_text("x")
    assert s.check() is None and s.last_error == "limits"


# -- in the running sensor -------------------------------------------------------------------


async def test_reload_under_load_drops_no_connection(start_with: StartWith, tmp_path: Path) -> None:
    """Requests keep flowing while the set is swapped many times; every one gets an answer and
    the events carry the seq of the set that analysed them."""
    body = b"host=192.0.2.10;wget"
    request = (
        b"POST /api/v1/diag/ping HTTP/1.1\r\nHost: 192.0.2.10\r\nContent-Length: %d\r\n"
        b"Connection: %s\r\n\r\n%s"
    )
    async with start_with(max_per_ip=100) as h:
        s = sync(tmp_path)
        put(tmp_path, 1, [new_pack(version=1)])
        first = s.check()
        assert first is not None
        h.sensor.detector.use_traps(first)
        stop = asyncio.Event()
        swaps = 0

        async def swapper() -> None:
            nonlocal swaps
            seq = 2
            while not stop.is_set():
                put(tmp_path, seq, [new_pack(version=seq)])
                fresh = s.check()
                assert fresh is not None
                h.sensor.detector.use_traps(fresh)
                swaps += 1
                seq += 1
                await asyncio.sleep(0.002)

        async def client() -> bytes:
            return await h.raw(request % (len(body), b"close", body), wait=5.0)

        async def keep_alive() -> list[bytes]:
            """One connection, several requests, set swaps in between."""
            reader, writer = await asyncio.open_connection("127.0.0.1", h.http)
            heads: list[bytes] = []
            for _ in range(8):
                writer.write(request % (len(body), b"keep-alive", body))
                await writer.drain()
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                length = int(head.lower().split(b"content-length: ")[1].split(b"\r\n")[0])
                await asyncio.wait_for(reader.readexactly(length), 5)
                heads.append(head)
                await asyncio.sleep(0.01)
            writer.close()
            return heads

        task = asyncio.create_task(swapper())
        kept = asyncio.create_task(keep_alive())
        answers = await asyncio.gather(*(client() for _ in range(60)))
        heads = await kept
        stop.set()
        await task
        assert swaps > 5
        assert all(a.startswith(b"HTTP/1.1 200 ") for a in answers), [a[:40] for a in answers]
        assert len(heads) == 8 and all(x.startswith(b"HTTP/1.1 200 ") for x in heads)
        events = await h.events("http_request")
        assert len(events) == 68
        assert all(e.data["trap_seq"] >= 1 for e in events)
        assert all("edgegate_rce" in e.data["flags"] for e in events)


async def test_events_carry_trap_seq(harness: Harness) -> None:
    await harness.raw(b"GET / HTTP/1.1\r\nHost: 192.0.2.10\r\nConnection: close\r\n\r\n")
    (event,) = await harness.events("http_request")
    assert event.data["trap_seq"] == 0


def test_detector_swap_updates_the_severe_set(tmp_path: Path) -> None:
    from web_sensor.config import Config
    from web_sensor.detect import Detector

    s = sync(tmp_path)
    d = Detector(Config(), s.current)
    assert "edgegate_rce" not in d.severe
    put(tmp_path, 2, [new_pack()])
    fresh = s.check()
    assert fresh is not None
    d.use_traps(fresh)
    out = d.analyze(req("POST", "/api/v1/diag/ping", body=b"host=x;wget"), "192.0.2.1")
    assert "edgegate_rce" in out.flags and out.severe
    assert out.cve == ["CVE-2026-55501"]


def test_key_comes_from_the_release_defaults_unless_set(tmp_path: Path) -> None:
    defaults = tmp_path / "network-defaults.env"
    defaults.write_text(f"# comment\nNETWORK_FEED_KEY=RWxyz\nTRAP_PACK_KEY={KEY.public}\n")
    assert SyncSettings.from_env({}, defaults=defaults).key == KEY.public
    assert SyncSettings.from_env({"TRAP_PACK_KEY": OTHER.public}, defaults=defaults).key == (
        OTHER.public
    )
    defaults.write_text("TRAP_PACK_KEY=\n")
    assert SyncSettings.from_env({}, defaults=defaults).key == ""
    assert SyncSettings.from_env({}, defaults=tmp_path / "missing").key == ""


def test_the_image_carries_the_release_defaults() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()
    assert "COPY config/network-defaults.env /app/network-defaults.env" in dockerfile
