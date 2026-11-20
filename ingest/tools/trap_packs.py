"""Authoring tool for trap packs: ``new``, ``check`` and ``build`` (run through ``just trap-*``).

Packs are written in YAML in ``traps/packs/<id>.yaml``. This tool validates them with the same
code the sensors use (``suckerpot_common.traps``) and compiles them to the canonical JSON bundle
that ships in the web sensor image. Sensors never read YAML.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from suckerpot_common import traps

ROOT = Path(__file__).resolve().parents[2]
PACKS = ROOT / "traps" / "packs"
FIXTURES = ROOT / "traps" / "fixtures"
WEB_BUNDLE = ROOT / "sensors" / "web" / "web_sensor" / "data" / "traps-bundled.json"

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trap_packs", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build", help="compile traps/packs/*.yaml into the web sensor bundle")
    sub.add_parser("check", help="validate every pack and check that the bundle is up to date")
    new = sub.add_parser("new", help="scaffold a pack and its fixtures for a CVE")
    new.add_argument("cve")
    new.add_argument("id", nargs="?")
    args = parser.parse_args(argv)
    handlers = {"build": cmd_build, "check": cmd_check, "new": cmd_new}
    return handlers[str(args.cmd)](args)


if __name__ == "__main__":
    raise SystemExit(main())
