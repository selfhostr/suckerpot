"""Authoring tool for trap packs: ``new``, ``check``, ``build`` (``just trap-*``), and the
distribution steps ``release``, ``sign`` and ``keygen`` (the trap-packs workflow, M37 P2).

Packs are written in YAML in ``traps/packs/<id>.yaml``. This tool validates them with the same
code the sensors use (``suckerpot_common.traps``) and compiles them to the canonical JSON bundle
that ships in the web sensor image. Sensors never read YAML.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml
from suckerpot_common import traps
from suckerpot_netproto.feeds import FeedError, minisign
from suckerpot_netproto.feeds import traps as tb

ROOT = Path(__file__).resolve().parents[2]
PACKS = ROOT / "traps" / "packs"
FIXTURES = ROOT / "traps" / "fixtures"
WEB_BUNDLE = ROOT / "sensors" / "web" / "web_sensor" / "data" / "traps-bundled.json"
DISABLED = ROOT / "traps" / "disabled.yaml"
DEFAULTS = ROOT / "config" / "network-defaults.env"

TEMPLATE = """\
# Trap pack for {cve}. Replace every TODO, then run: just trap-check
# Format: docs/trap-packs.md. Requests in fixtures use documentation addresses only
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and example.net.
schema: suckerpot-trap/1
id: {pid}
version: 1
engine: 1
sensor: web
title: "TODO: product and flaw"
cve: [{cve}]
disclosed: {today}
product: {{vendor: TODO, name: TODO}}
tag: {pid}
attack: [T1190]
traps:
  - id: probe
    level: probe
    match:
      method: [GET, HEAD]
      path: {{exact: /todo/version}}
    outcome: {{flags: [todo_probe]}}
  - id: exploit
    level: exploit
    match:
      method: [POST]
      path: {{exact: /todo/vulnerable/endpoint}}
      needles:
        - {{in: body, any: ["todo_param="]}}
    outcome: {{flags: [todo_exploit]}}
"""

EXPECT = """\
{{
 "exploit-1.http": {{"hits": ["{pid}/exploit"]}},
 "probe-1.http": {{"hits": ["{pid}/probe"]}},
 "benign-1.http": {{"hits": []}}
}}
"""


def _plain(obj: Any) -> Any:
    """YAML gives dates as objects: turn them back into the text the format expects."""
    if isinstance(obj, dt.date):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {str(k): _plain(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_plain(v) for v in obj]
    return obj


def load_sources() -> tuple[list[dict[str, Any]], list[str]]:
    """Every pack source, validated. Returns (packs as JSON objects, errors)."""
    out: list[dict[str, Any]] = []
    errors: list[str] = []
    for path in sorted(PACKS.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        name = path.relative_to(ROOT)
        if "TODO" in text:
            errors.append(f"{name}: still has TODO")
            continue
        try:
            obj = _plain(yaml.safe_load(text))
            pack = traps.validate_pack(obj)
        except yaml.YAMLError as err:
            errors.append(f"{name}: YAML: {err}")
            continue
        except traps.PackError as err:
            errors.append(f"{name}: {err}")
            continue
        if pack.id != path.stem:
            errors.append(f"{name}: the file name must be the pack id ({pack.id}.yaml)")
            continue
        if not (FIXTURES / pack.id / "expect.json").is_file():
            errors.append(f"{name}: no fixtures (traps/fixtures/{pack.id}/expect.json)")
        out.append(obj)
    return out, errors


def compile_bundle() -> tuple[bytes, list[str]]:
    objs, errors = load_sources()
    packs = [traps.validate_pack(o) for o in objs]
    errors += traps.find_conflicts(packs)
    web = [o for o in objs if o.get("sensor") == "web"]
    data = traps.build_bundle(web)
    if len(data) > traps.MAX_BUNDLE_BYTES:
        errors.append(f"bundle is {len(data)} bytes, at most {traps.MAX_BUNDLE_BYTES}")
    try:
        result = traps.load_bundle(data, today=dt.datetime.now(dt.UTC).date())
    except traps.PackError as err:
        errors.append(f"bundle: {err}")
    else:
        errors += [f"{pid}: {reason}" for pid, reason in result.rejected]
    return data, errors


def cmd_build(_: argparse.Namespace) -> int:
    data, errors = compile_bundle()
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    if errors:
        return 1
    WEB_BUNDLE.write_bytes(data)
    print(f"wrote {WEB_BUNDLE.relative_to(ROOT)} ({len(data)} bytes)")
    return 0


def cmd_check(_: argparse.Namespace) -> int:
    data, errors = compile_bundle()
    errors += load_disabled()[1]
    current = WEB_BUNDLE.read_bytes() if WEB_BUNDLE.is_file() else b""
    if current != data:
        errors.append(f"{WEB_BUNDLE.relative_to(ROOT)} is out of date: run just trap-build")
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    if not errors:
        count = len(json.loads(data)["packs"])
        print(f"{count} pack(s) valid, bundle up to date")
    return 1 if errors else 0


def cmd_new(args: argparse.Namespace) -> int:
    cve = str(args.cve).upper()
    if not traps.is_cve(cve):
        print("usage: trap-new CVE-YYYY-NNNN [pack-id]", file=sys.stderr)
        return 2
    pid = str(args.id or cve.lower())
    if not traps.is_slug(pid, 3, 48):
        print("the pack id must be 3 to 48 of a-z 0-9 -", file=sys.stderr)
        return 2
    src = PACKS / f"{pid}.yaml"
    fix = FIXTURES / pid
    if src.exists() or fix.exists():
        print(f"{pid} already exists", file=sys.stderr)
        return 1
    today = dt.datetime.now(dt.UTC).date().isoformat()
    src.write_text(TEMPLATE.format(cve=cve, pid=pid, today=today), encoding="utf-8")
    fix.mkdir(parents=True)
    (fix / "expect.json").write_text(EXPECT.format(pid=pid), encoding="utf-8")
    req = "{} {} HTTP/1.1\r\nHost: 192.0.2.10\r\nUser-Agent: TODO\r\nConnection: close\r\n\r\n"
    (fix / "probe-1.http").write_bytes(req.format("GET", "/todo/version").encode())
    (fix / "benign-1.http").write_bytes(req.format("GET", "/").encode())
    body = "todo_param=TODO"
    (fix / "exploit-1.http").write_bytes(
        (
            "POST /todo/vulnerable/endpoint HTTP/1.1\r\nHost: 192.0.2.10\r\nUser-Agent: TODO\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
        ).encode()
    )
    print(f"created {src.relative_to(ROOT)} and {fix.relative_to(ROOT)}/")
    return 0


# -- distribution (M37 P2) ----------------------------------------------------------------------


def load_disabled() -> tuple[list[dict[str, str]], list[str]]:
    """The kill list, traps/disabled.yaml: ``disabled: [{id, reason}]``."""
    if not DISABLED.is_file():
        return [], []
    raw = yaml.safe_load(DISABLED.read_text(encoding="utf-8")) or {}
    items = raw.get("disabled") if isinstance(raw, dict) else None
    if not isinstance(items, list):
        return [], ["traps/disabled.yaml: needs a list named disabled"]
    out: list[dict[str, str]] = []
    errors: list[str] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict) or set(item) != {"id", "reason"}:
            errors.append(f"traps/disabled.yaml: entry {i} needs exactly id and reason")
            continue
        out.append({"id": str(item["id"]), "reason": str(item["reason"])})
    return out, errors


def release_bundle(
    seq: int, previous: bytes | None = None, now: dt.datetime | None = None
) -> tuple[bytes, list[str]]:
    """The distributed bundle: every web pack and the kill list, with a new seq above the one
    published now. Packs never expire, so the same packs are always in it."""
    objs, errors = load_sources()
    packs = [traps.validate_pack(o) for o in objs]
    errors += traps.find_conflicts(packs)
    disabled, dis_errors = load_disabled()
    errors += dis_errors
    if previous is not None:
        try:
            old_seq = int(traps.parse_bundle(previous)["seq"])
        except traps.PackError as err:
            errors.append(f"the published bundle is unreadable: {err}")
        else:
            if seq <= old_seq:
                errors.append(f"seq {seq} is not above the published seq {old_seq}")
    if not 1 <= seq <= 2**53:
        errors.append("seq must be a positive integer")
        return b"", errors
    stamp = (now or dt.datetime.now(dt.UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        data = traps.build_bundle(
            [o for o in objs if o.get("sensor") == "web"], seq, disabled=disabled, issued_at=stamp
        )
        result = traps.load_bundle(data, today=dt.datetime.now(dt.UTC).date())
    except traps.PackError as err:
        return b"", [*errors, f"bundle: {err}"]
    errors += [f"{pid}: {reason}" for pid, reason in result.rejected]
    return data, errors


def cmd_release(args: argparse.Namespace) -> int:
    previous = args.previous.read_bytes() if args.previous and args.previous.is_file() else None
    data, errors = release_bundle(int(args.seq), previous)
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    if errors:
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "traps.json").write_bytes(data)
    print(f"wrote traps.json, seq {args.seq} ({len(data)} bytes)")
    return 0


def same_as_checkout(data: bytes) -> list[str]:
    """Rebuild the bundle from this checkout with the artifact's seq and compare everything but
    ``issued_at``. The publish job signs only a bundle it could have built itself."""
    try:
        doc = traps.parse_bundle(data)
    except traps.PackError as err:
        return [f"the bundle to sign is unreadable: {err}"]
    rebuilt, errors = release_bundle(int(doc["seq"]))
    if errors:
        return errors
    fresh = json.loads(rebuilt)
    for d in (doc, fresh):
        d.pop("issued_at", None)
    if doc != fresh:
        return ["the bundle to sign differs from the one this commit builds"]
    return []


def cmd_verify(args: argparse.Namespace) -> int:
    errors = same_as_checkout(args.bundle.read_bytes())
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    if not errors:
        print(f"{args.bundle.name} matches this commit")
    return 1 if errors else 0


def committed_public_key() -> str:
    for line in DEFAULTS.read_text(encoding="utf-8").splitlines():
        name, sep, value = line.strip().partition("=")
        if sep and name == "TRAP_PACK_KEY":
            return value.strip()
    return ""


def cmd_sign(args: argparse.Namespace) -> int:
    """Sign with the secret key from ``TRAP_PACK_SECRET_KEY`` (the minisign key file content),
    then verify with the committed public key, so a bundle signed by the wrong key is never
    published. The secret is never printed or written."""
    secret_text = os.environ.get("TRAP_PACK_SECRET_KEY", "")
    public_text = args.public or committed_public_key()
    if not secret_text.strip():
        print("error: TRAP_PACK_SECRET_KEY is empty", file=sys.stderr)
        return 1
    if not public_text:
        print("error: no TRAP_PACK_KEY in config/network-defaults.env", file=sys.stderr)
        return 1
    try:
        secret = minisign.parse_secret_key(secret_text)
        public = minisign.parse_public_key(public_text)
        data = args.bundle.read_bytes()
        sig = tb.sign_bundle(data, secret)
        seq = tb.verify_bundle(data, sig, public)
    except FeedError as err:
        print(f"error: {err.code}", file=sys.stderr)
        return 1
    args.bundle.with_name(args.bundle.name + ".minisig").write_text(sig, encoding="ascii")
    print(f"signed {args.bundle.name}, seq {seq}, key {public.key_id_hex}")
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    """A new pack key pair. The secret goes to ``--out`` (mode 0600, never overwritten); it
    belongs in the secret of the protected GitHub environment ``trap-packs`` and nowhere else.
    The public key goes into TRAP_PACK_KEY of config/network-defaults.env (a release ships it)."""
    out: Path = args.out
    if out.exists():
        print(f"error: {out} exists", file=sys.stderr)
        return 1
    secret = minisign.generate_keypair()
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(minisign.serialize_secret_key(secret))
    print(f"TRAP_PACK_KEY={secret.public.encoded}")
    print(f"secret key written to {out} (key id {secret.public.key_id_hex})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trap_packs", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build", help="compile traps/packs/*.yaml into the web sensor bundle")
    sub.add_parser("check", help="validate every pack and check that the bundle is up to date")
    new = sub.add_parser("new", help="scaffold a pack and its fixtures for a CVE")
    new.add_argument("cve")
    new.add_argument("id", nargs="?")
    rel = sub.add_parser("release", help="write the distributed bundle traps.json (M37 P2)")
    rel.add_argument("--seq", type=int, required=True, help="the new sequence number")
    rel.add_argument("--out", type=Path, required=True, help="directory for traps.json")
    rel.add_argument("--previous", type=Path, help="the bundle published now, if any")
    sign = sub.add_parser("sign", help="sign traps.json with the pack key (secret from env)")
    sign.add_argument("bundle", type=Path)
    sign.add_argument("--public", default="", help="public key to check against (RW...)")
    verify = sub.add_parser("verify", help="check that traps.json is what this commit builds")
    verify.add_argument("bundle", type=Path)
    keygen = sub.add_parser("keygen", help="create a new pack key pair (owner only)")
    keygen.add_argument("--out", type=Path, required=True, help="where to write the secret key")
    args = parser.parse_args(argv)
    handlers = {
        "build": cmd_build,
        "check": cmd_check,
        "new": cmd_new,
        "release": cmd_release,
        "sign": cmd_sign,
        "verify": cmd_verify,
        "keygen": cmd_keygen,
    }
    return handlers[str(args.cmd)](args)


if __name__ == "__main__":
    raise SystemExit(main())
