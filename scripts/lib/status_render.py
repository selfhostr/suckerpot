"""Renders `scripts/status.sh` (docs/design/m32.md section 10). Run inside the ingest container:

    docker compose exec -T ingest python -I -c "$(cat scripts/lib/status_render.py)" [--json]

Reads one JSON document on stdin, written by status.sh:

    stack, install, version        strings from .env
    ps                             [[service, state, health], ...] from `docker compose ps`
    ports                          [[router_port, host_port, protocol, sensor], ...]
    auto_enabled, auto_schedule    AUTO_UPDATE_ENABLED and `schedule_status` ("cron 04:37", "off")
    auto_state_raw                 text of .suckerpot-state/auto-update.json, or ""
    cli_raw, cli_error             output of `python -m ingest.network.cli status --json`, or ""

The network shape (written by ingest/network/cli.py) is read defensively: every key is optional.
    state, pseudonym, node, standing, counts_from, path, self_address, reveals_7d,
    hub {host, last_contact, signature_ok}, sent [{day, sources, links, files}],
    sessions_24h {sensor: n}, warnings [code], errors [code],
    network {membership {desired, last_error}}   (the only place older ingest images carry these)

Prints the text report (or JSON with --json) and exits 0 (OK), 1 (warning) or 2 (error).
Standard library only. It never prints a secret: it never receives one.
"""

import json
import sys
from datetime import UTC, datetime
from typing import Any

HUB_STALE_HOURS = 26
ERROR_CODES = {"hub_signature", "guard_failed"}
KNOWN_TEXT = {
    "consent_outdated": "the consent text is newer than your agreement: run ./scripts/participant.sh join",
    "consent_stale": "the install-time agreement is more than 7 days old and was not used: run ./scripts/participant.sh join to agree again",
    "hub_key_differs_from_release": "the hub key differs from the release's key list",
    "waiting_self_address": "the node has not learned its own address yet",
    "hub_signature": "the hub's answer failed the signature check",
    "guard_failed": "a guard stopped the network worker",
    "hub_contact_stale": f"no contact with the hub for more than {HUB_STALE_HOURS} h",
    "ingest_down": "ingest is not running or not healthy: docker compose logs ingest",
    "db_down": "the database is not running or not healthy: docker compose logs db",
    "stack_not_running": "the stack is not running: ./scripts/install.sh --repair",
    "network_status_unavailable": "ingest did not answer the network status request",
    "auto_update_failed": "the last automatic update did not complete: .suckerpot-state/auto-update.log",
}


# Why a join request is not accepted yet (membership.last_error, written by the network worker).
JOIN_PROBLEMS = {
    "egress_closed": "the path to the hub is closed",
    "egress_direct": "the direct path to the hub is not open yet",
    "stale": "the path to the hub was not checked recently",
    "hub_unreachable": "the hub cannot be reached",
    "hub_error": "the hub answered with an error",
    "waiting_enrolment": "waiting for the hub to finish enrolling this node",
    "enrolment_closed": "the hub is not accepting new nodes right now",
    "pow_timeout": "the hub's puzzle took too long, a new one will be tried",
    "pseudonym_taken": "the pseudonym is already taken",
    "pseudonym_invalid": "the pseudonym is not allowed",
    "no_settings_key": "the settings key is missing",
    "unsupported_protocol": "the hub speaks a protocol this version does not support",
}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _parse(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _ago(then: datetime, now: datetime) -> str:
    minutes = max(0, int((now - then).total_seconds() // 60))
    if minutes < 90:
        return f"{minutes} min ago"
    hours = minutes // 60
    return f"{hours} h ago" if hours < 48 else f"{hours // 24} days ago"


def _n(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def analyse(doc: dict[str, Any], now: datetime) -> dict[str, Any]:
    stack = str(doc.get("stack") or "full")
    ps = [row for row in _list(doc.get("ps")) if isinstance(row, list) and len(row) >= 2]
    warnings: list[str] = []
    errors: list[str] = []

    services = {str(r[0]): (str(r[1]), str(r[2]) if len(r) > 2 else "") for r in ps}
    if not services:
        errors.append("stack_not_running")
    for name in ("ingest", "db"):
        state, health = services.get(name, ("", ""))
        if services and (state != "running" or health not in ("healthy", "")):
            errors.append(f"{name}_down")
    sensors: dict[str, str] = {}
    for name, (state, health) in sorted(services.items()):
        if not name.startswith("sensor-"):
            continue
        ok = state == "running" and health in ("healthy", "")
        sensors[name.removeprefix("sensor-")] = "healthy" if ok else (health or state or "down")
    for name, status in sensors.items():
        if status != "healthy":
            warnings.append(f"sensor_{name}_{status}")

    cli = _parse(doc.get("cli_raw"))
    cli_error = str(doc.get("cli_error") or "")
    hub = _dict(cli.get("hub")) if cli else {}
    member = bool(cli) and cli.get("state") not in (None, "off", "left", "not_joined")
    membership = _dict(_dict(cli.get("network") if cli else None).get("membership"))
    pending = bool(cli) and cli.get("state") in ("off", "not_joined") and membership.get("desired") == "member"
    join_error = str(membership.get("last_error") or "") if pending else ""
    if cli:
        for code in _list(cli.get("errors")):
            errors.append(str(code))
        for code in _list(cli.get("warnings")):
            (errors if str(code) in ERROR_CODES else warnings).append(str(code))
        contact = _when(hub.get("last_contact"))
        if member and contact is not None and (now - contact).total_seconds() > HUB_STALE_HOURS * 3600:
            warnings.append("hub_contact_stale")
        if member and hub.get("signature_ok") is False:
            errors.append("hub_signature")
        if join_error:
            warnings.append("join_pending")
    elif services.get("ingest", ("", ""))[0] == "running":
        warnings.append("network_status_unavailable")

    auto_state = _parse(doc.get("auto_state_raw"))
    if stack == "participant":
        if not doc.get("auto_enabled"):
            warnings.append("auto_update_off")
        elif auto_state and auto_state.get("last_result") in ("failed", "refused"):
            warnings.append("auto_update_failed")
    code = 2 if errors else (1 if warnings else 0)
    return {
        "stack": stack,
        "sensors": sensors,
        "warnings": sorted(set(warnings)),
        "errors": sorted(set(errors)),
        "exit": code,
        "cli": cli,
        "cli_error": cli_error,
        "auto_state": auto_state,
        "member": member,
        "pending": pending,
        "join_error": join_error,
        "hub": hub,
    }


def _sensor_ports(doc: dict[str, Any], sensor: str) -> str:
    rows = [r for r in _list(doc.get("ports")) if isinstance(r, list) and len(r) >= 4 and r[3] == sensor]
    if not rows:
        return ""
    parts = []
    for router, host, *_ in rows:
        parts.append(f"{router}" if len(rows) > 1 and router == host else f"{router} -> {host}")
    return "router " + ", ".join(parts)


def _auto_line(doc: dict[str, Any], info: dict[str, Any]) -> str:
    schedule = str(doc.get("auto_schedule") or "off")
    if not doc.get("auto_enabled") or schedule == "off":
        return "Automatic: off (on: ./scripts/participant.sh auto-update on)"
    line = f"Automatic: on, next window {schedule.split(' ')[-1]}."
    state = info["auto_state"]
    if not state:
        return line + " No run yet."
    day = str(state.get("last_run") or "")[:10] or "unknown"
    result = str(state.get("last_result") or "")
    source, target = state.get("from"), state.get("to")
    detail = {
        "updated": f"updated {source} to {target}",
        "ok": f"already on {target or source}",
        "skipped": "skipped (nothing to do)",
        "refused": f"refused ({state.get('error_code') or 'see the log'})",
        "failed": f"failed ({state.get('error_code') or 'see the log'}), rolled back",
    }.get(result, result or "unknown")
    return f"{line} Last run {day}: {detail}"


def render_text(doc: dict[str, Any], info: dict[str, Any], now: datetime) -> str:
    out: list[str] = []
    version = doc.get("version") or "source build"
    status = {0: "OK", 1: "WARNING", 2: "ERROR"}[info["exit"]]
    head = f"SuckerPot {version}, {info['stack']} mode, {doc.get('install') or 'source'}"
    out.append(f"{head:<66}{status}")
    out.append("")

    sensors = info["sensors"]
    bad = [name for name, s in sensors.items() if s != "healthy"]
    if not sensors:
        out.append("Sensors (none running)")
    elif bad:
        out.append(f"Sensors ({len(sensors) - len(bad)} of {len(sensors)} healthy; not healthy: {', '.join(bad)})")
    else:
        out.append(f"Sensors ({len(sensors)} running, all healthy)")
    sessions = _dict(_dict(info["cli"]).get("sessions_24h"))
    for name in sensors:
        line = f"  {name:<8} {_sensor_ports(doc, name):<24}"
        if name in sessions:
            line += f" last 24 h: {_n(sessions[name]):>6,} sessions"
        out.append(line.rstrip())
    if sensors:
        out.append("  Does the internet reach them? ./scripts/participant.sh ports-check")

    out.append("Network")
    cli = info["cli"]
    hub = info["hub"]
    if not cli:
        why = info["cli_error"] or "ingest did not answer"
        out.append(f"  Status unavailable: {why}")
    elif info["pending"]:
        name = cli.get("pseudonym")
        out.append(f"  Joining{f' as {name}' if name else ''}: not accepted by the hub yet.")
        error = info["join_error"]
        if error:
            why = JOIN_PROBLEMS.get(error, "unexpected problem")
            out.append(f"  Last problem: {why} ({error}). SuckerPot keeps trying by itself.")
        else:
            out.append("  The request is in progress.")
    elif not info["member"]:
        out.append("  Not joined. Join: ./scripts/participant.sh join")
    else:
        name = cli.get("pseudonym")
        node = cli.get("node")
        who = f"{name} (Node {node})" if name and node else (name or (f"Node {node}" if node else "this node"))
        standing = f", standing: {cli['standing']}" if cli.get("standing") else ""
        out.append(f"  Member as {who}{standing}")
        if cli.get("counts_from"):
            out.append(f"  Counts toward consensus from {cli['counts_from']}")
        contact = _when(hub.get("last_contact"))
        host = hub.get("host") or "hub"
        if contact is None:
            out.append(f"  Hub contact: none yet ({host})")
        else:
            sig = "signature verified" if hub.get("signature_ok") else "signature NOT verified"
            out.append(f"  Hub contact: {'OK' if hub.get('signature_ok') else 'PROBLEM'}, {_ago(contact, now)} ({host}, {sig})")
        path = cli.get("path")
        if path == "direct":
            out.append("  Path: direct (no VPN). The hub sees this machine's address.")
        elif path == "vpn":
            out.append("  Path: through your VPN. The hub sees the VPN's address.")
        own = {"learned": "learned", "manual": "set by hand", "waiting": "waiting to be learned from traffic"}
        if cli.get("self_address"):
            out.append(f"  Own address: {own.get(str(cli['self_address']), cli['self_address'])}")
        sent = [s for s in _list(cli.get("sent")) if isinstance(s, dict)]
        for i, s in enumerate(sent[:3]):
            label = "  Sent: " if i == 0 else "        "
            out.append(
                f"{label}{s.get('day')}  {_n(s.get('sources')):,} sources, "
                f"{_n(s.get('links')):,} links (blinded), {_n(s.get('files')):,} files"
            )
        if cli.get("reveals_7d") is not None:
            out.append(f"  Links revealed for verification (7 days): {_n(cli.get('reveals_7d')):,}")
    for code in info["errors"] + info["warnings"]:
        if code in KNOWN_TEXT:
            out.append(f"  ! {KNOWN_TEXT[code]}")

    out.append("Updates")
    out.append(f"  {_auto_line(doc, info)}")
    if "auto_update_off" in info["warnings"]:
        out.append("  ! automatic updates are off: update by hand with: just update")
    out.append("")
    out.append("Exit code 0 = OK, 1 = warning, 2 = error.")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    try:
        doc = _dict(json.loads(sys.stdin.read() or "{}"))
    except ValueError:
        print("status: the input was not JSON", file=sys.stderr)
        return 2
    now = datetime.now(UTC)
    info = analyse(doc, now)
    if "--json" in argv:
        report = {
            "stack": info["stack"],
            "version": doc.get("version"),
            "install": doc.get("install"),
            "sensors": info["sensors"],
            "network": info["cli"],
            "network_error": info["cli_error"] or None,
            "updates": {
                "enabled": bool(doc.get("auto_enabled")),
                "schedule": doc.get("auto_schedule"),
                "last": info["auto_state"],
            },
            "warnings": info["warnings"],
            "errors": info["errors"],
            "exit": info["exit"],
        }
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(doc, info, now))
    return int(info["exit"])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
