"""Renders `scripts/status.sh` (docs/dev/design/m32.md section 10). Run inside the ingest container:

    docker compose exec -T ingest python -I -c "$(cat scripts/lib/status_render.py)" [--json]

Reads one JSON document on stdin, written by status.sh:

    stack, install, version        strings from .env
    ps                             [[service, state, health], ...] from `docker compose ps`
    ports                          [[router_port, host_port, protocol, sensor], ...]
    auto_enabled, auto_schedule    AUTO_UPDATE_ENABLED and `schedule_status` ("cron 04:37/6h", "off")
    auto_state_raw                 text of .suckerpot-state/auto-update.json, or ""
    firewall                       "installed", "missing" or "not_loaded" (unit stopped or tables gone)
    engine                         "docker", or "podman <version>" (absent in older status.sh)
    stack_unit                     Podman only: "active", "inactive" or "missing" (suckerpot-stack.service)
    latest, latest_age_h           newest known release of the same major version, and its age
    cli_raw, cli_error             output of `python -m ingest.network.cli status --json`, or ""

The network shape (written by ingest/network/cli.py) is read defensively: every key is optional.
    state, pseudonym, node, standing, counts_from, path, self_address, reveals_7d,
    hub {host, last_contact, signature_ok}, sent [{day, sources, links, files}],
    sessions_24h {sensor: n}, warnings [code], errors [code],
    report_effect {verdict, pairs, needed, seen_reported, seen_control, lo, hi, line} | null
    network {membership {desired, last_error, auto_retry}}   (older ingest images: no auto_retry)

Prints the text report (or JSON with --json) and exits 0 (OK), 1 (warning) or 2 (error).
Standard library only. It never prints a secret: it never receives one.
"""

import json
import sys
from datetime import UTC, datetime
from typing import Any

HUB_STALE_HOURS = 26
# Refusals that only mean "not yet": the release is younger than the minimum age. The next run
# takes it, so the status does not call the update failed.
WAITING_REFUSALS = {"too_young"}
# A newer release is only "outdated" once the automatic updater would have taken it: it waits 48 h
# and runs every 6 h, so give it three days.
OUTDATED_AFTER_H = 72
ERROR_CODES = {"hub_signature", "guard_failed"}
# Needs attention: a member with no hub contact this long after joining, or an error this old.
NO_CONTACT_AFTER_H = 2
ERROR_PERSISTS_H = 6
KNOWN_TEXT = {
    "consent_outdated": "the consent text is newer than your agreement: run ./scripts/participant.sh join",
    "consent_stale": "the install-time agreement is more than 7 days old and was not used: run ./scripts/participant.sh join to agree again",
    "hub_key_differs_from_release": "the hub key differs from the release's key list",
    "waiting_self_address": "the node has not learned its own address yet",
    "submit_paused_self_address": "batches are paused: the node does not know its own public address. Set SELF_ADDRESS=<this machine's public address> in .env, then: docker compose up -d ingest",
    "hub_signature": "the hub's answer failed the signature check",
    "guard_failed": "a guard stopped the network worker",
    "hub_contact_stale": f"no contact with the hub for more than {HUB_STALE_HOURS} h",
    "ingest_down": "ingest is not running or not healthy: docker compose logs ingest",
    "db_down": "the database is not running or not healthy: docker compose logs db",
    "stack_not_running": "the stack is not running: ./scripts/install.sh --repair",
    "network_status_unavailable": "ingest did not answer the network status request",
    "firewall_missing": "the host firewall is not installed",
    "firewall_not_loaded": "the host firewall is installed but its rules are not loaded: sudo systemctl reload-or-restart suckerpot-firewall.service",
    "firewall_required": "on Podman the host firewall is required and it is not in force: ./scripts/participant.sh firewall",
    "stack_unit_missing": "the boot unit suckerpot-stack.service is not installed: the stack does not come back after a reboot (./scripts/participant.sh firewall installs it)",
    "stack_unit_inactive": "the boot unit suckerpot-stack.service is not active: sudo systemctl start suckerpot-stack.service",
    "release_outdated": "this node runs an older release than the newest one it knows",
    "auto_update_failed": "the last automatic update did not complete: .suckerpot-state/auto-update.log",
    "join_refused": "the hub refused to enrol this node: it is not a member",
    "hub_contact_none": f"no contact with the hub {NO_CONTACT_AFTER_H} h after joining",
    "network_error_persistent": f"the same network error for more than {ERROR_PERSISTS_H} h",
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
NEW_NAME = "./scripts/participant.sh join --pseudonym NEW-NAME"
# The last network error of a member or a refused join: (plain explanation, fix or "").
# An empty fix means SuckerPot retries by itself.
ERROR_HELP = {
    "hub_unreachable": (
        "the hub could not be reached (no internet, DNS, or the hub is down)",
        "",
    ),
    "egress_closed": (
        "the path to the hub is closed (the VPN is down or not checked yet)",
        "check the VPN, or go back to the direct path: ./scripts/participant.sh vpn --remove",
    ),
    "hub_error": ("the hub answered with an error", ""),
    "rate_limited": ("the hub asked this node to slow down", ""),
    "pseudonym_taken": (
        "the hub refused the pseudonym: another node already uses it (this can be your own "
        "earlier install that never sent a batch: the hub frees its name after two silent days)",
        NEW_NAME,
    ),
    "pseudonym_invalid": ("the hub does not allow this pseudonym", NEW_NAME),
    "invalid_payload": ("the hub refused a batch as malformed", "just update"),
    "unsupported_protocol": (
        "this version speaks a protocol the hub does not support",
        "just update",
    ),
    "no_settings_key": (
        "the settings key is missing, so the node key cannot be stored",
        "./scripts/install.sh --repair",
    ),
    "self_terms_unavailable": ("the list of your own addresses could not be read", ""),
    "internal_error": ("a network step failed inside ingest", "docker compose logs ingest"),
    "guard_failed": ("a guard stopped a batch before it left", "docker compose logs ingest"),
    "hub_signature": ("the hub's answer failed the signature check", "just update"),
}
# Shown elsewhere in the report already (the own address has its own lines).
QUIET_ERRORS = {"waiting_self_address", "waiting_enrolment"}


def _fix(fix: str, stack: str) -> str:
    """participant.sh exists on participant installs only; a full install uses the dashboard."""
    if stack != "participant" and "participant.sh" in fix:
        return "the dashboard (Network page)"
    return fix


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


def _ver(tag: Any) -> tuple[int, ...] | None:
    parts = str(tag or "").removeprefix("v").split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


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
    state = cli.get("state") if cli else None
    membership = _dict(_dict(cli.get("network") if cli else None).get("membership"))
    # "error" is a join the node gave up on (desired is back to off): never a member.
    refused = state == "error"
    member = bool(cli) and state not in (None, "off", "left", "not_joined", "enrolling", "error")
    pending = (
        bool(cli)
        and state in ("off", "not_joined", "enrolling")
        and membership.get("desired") == "member"
    )
    last_error = _dict(cli.get("last_error")) if cli else {}
    error_code = str(last_error.get("code") or membership.get("last_error") or "")
    error_since = _when(last_error.get("since"))
    join_error = error_code if pending or refused else ""
    if cli:
        for code in _list(cli.get("errors")):
            errors.append(str(code))
        for code in _list(cli.get("warnings")):
            (errors if str(code) in ERROR_CODES else warnings).append(str(code))
        contact = _when(hub.get("last_contact"))
        if (
            member
            and contact is not None
            and (now - contact).total_seconds() > HUB_STALE_HOURS * 3600
        ):
            warnings.append("hub_contact_stale")
        if member and hub.get("signature_ok") is False:
            errors.append("hub_signature")
        if pending and join_error:
            warnings.append("join_pending")
        if refused:
            errors.append("join_refused")
        joined = _when(cli.get("joined_at"))
        if (
            member
            and contact is None
            and joined is not None
            and (now - joined).total_seconds() > NO_CONTACT_AFTER_H * 3600
        ):
            warnings.append("hub_contact_none")
        if (
            member
            and error_code
            and error_code not in QUIET_ERRORS
            and error_since is not None
            and (now - error_since).total_seconds() > ERROR_PERSISTS_H * 3600
        ):
            warnings.append("network_error_persistent")
    elif services.get("ingest", ("", ""))[0] == "running":
        warnings.append("network_status_unavailable")

    auto_state = _parse(doc.get("auto_state_raw"))
    if stack == "participant":
        if not doc.get("auto_enabled") or str(doc.get("auto_schedule") or "off") == "off":
            warnings.append("auto_update_off")
        elif auto_state and (
            auto_state.get("last_result") == "failed"
            or (
                auto_state.get("last_result") == "refused"
                and auto_state.get("error_code") not in WAITING_REFUSALS
            )
        ):
            warnings.append("auto_update_failed")
    podman = str(doc.get("engine") or "").startswith("podman")
    # On Podman the firewall carries the isolation of the sensors (design D5): an error.
    if podman and doc.get("firewall") in ("missing", "not_loaded"):
        errors.append("firewall_required")
    if podman and doc.get("stack_unit") == "missing":
        warnings.append("stack_unit_missing")
    if podman and doc.get("stack_unit") == "inactive":
        warnings.append("stack_unit_inactive")
    # Installed but not in force (unit stopped, tables flushed): a warning on every stack.
    if doc.get("firewall") == "not_loaded":
        warnings.append("firewall_not_loaded")
    if stack == "participant":
        if doc.get("firewall") == "missing":
            warnings.append("firewall_missing")
        running, newest = _ver(doc.get("version")), _ver(doc.get("latest"))
        if (
            running
            and newest
            and newest > running
            and _n(doc.get("latest_age_h")) >= OUTDATED_AFTER_H
        ):
            warnings.append("release_outdated")
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
        "refused": refused,
        "join_error": join_error,
        "error_code": error_code,
        "error_since": error_since,
        "hub": hub,
    }


def needs_attention(doc: dict[str, Any], info: dict[str, Any]) -> list[tuple[str, str]]:
    """(problem, the one command that fixes it) for each thing a participant should act on."""
    items: list[tuple[str, str]] = []
    code = info["error_code"]
    why, fix = ERROR_HELP.get(code, ("an unexpected problem", "docker compose logs ingest"))
    if info["refused"]:
        name = _dict(info["cli"]).get("pseudonym")
        if code == "pseudonym_taken" and name:
            why = f"the hub refused the pseudonym '{name}' (already used by another node)"
        items.append((f"Not a member: {why} ({code or 'unknown'})", fix or NEW_NAME))
    elif "hub_contact_none" in info["warnings"]:
        detail = f": last error {code}, {why}" if code else ""
        items.append(
            (
                f"No contact with the hub {NO_CONTACT_AFTER_H} h after joining{detail}",
                fix or "docker compose logs ingest",
            )
        )
    elif "network_error_persistent" in info["warnings"]:
        items.append(
            (
                f"The network keeps failing for more than {ERROR_PERSISTS_H} h: {code}, {why}",
                fix or "docker compose logs ingest   (SuckerPot keeps retrying)",
            )
        )
    if "auto_update_off" in info["warnings"]:
        if doc.get("install") not in (None, "images"):
            items.append(
                (
                    "Automatic updates are off: this install builds from source",
                    "just update   (automatic updates need the release images, see docs/updates.md)",
                )
            )
        else:
            items.append(
                ("Automatic updates are off", "./scripts/participant.sh auto-update on")
            )
    if "firewall_missing" in info["warnings"]:
        items.append(("The host firewall is not installed", "./scripts/participant.sh firewall"))
    if "firewall_not_loaded" in info["warnings"]:
        items.append(
            (
                "The host firewall is installed but its rules are not loaded",
                "sudo systemctl reload-or-restart suckerpot-firewall.service",
            )
        )
    if "firewall_required" in info["errors"]:
        items.append(
            ("On Podman the host firewall is required and it is not in force", "./scripts/participant.sh firewall")
        )
    if "stack_unit_missing" in info["warnings"]:
        items.append(("The boot unit is not installed", "./scripts/participant.sh firewall"))
    if "stack_unit_inactive" in info["warnings"]:
        items.append(("The boot unit is not active", "sudo systemctl start suckerpot-stack.service"))
    if "release_outdated" in info["warnings"]:
        items.append(
            (
                f"This node runs {doc.get('version')}, the newest release is {doc.get('latest')}",
                "just update",
            )
        )
    return items


def _sensor_ports(doc: dict[str, Any], sensor: str) -> str:
    rows = [
        r for r in _list(doc.get("ports")) if isinstance(r, list) and len(r) >= 4 and r[3] == sensor
    ]
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
    when = schedule.split(" ")[-1]
    if when.endswith("/6h"):
        line = f"Automatic: on, every 6 h from {when.removesuffix('/6h')}."
    else:
        line = f"Automatic: on, next window {when}."
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
    waiting = state.get("waiting")
    if result == "updated" and isinstance(waiting, str) and waiting and waiting != target:
        detail += f" (newest {waiting} waits for its minimum age)"
    return f"{line} Last run {day}: {detail}"


def report_effect_line(cli: Any) -> str:
    """The report effect line (M38), written by ingest with its fixed wording. Information only:
    it never changes the exit code. Empty when the node never sent an attack-source report."""
    effect = _dict(_dict(cli).get("report_effect"))
    line = effect.get("line")
    if not isinstance(line, str) or not line.startswith("Report effect: "):
        return ""
    return "".join(ch for ch in line if ch.isprintable())[:200]


def render_text(doc: dict[str, Any], info: dict[str, Any], now: datetime) -> str:
    out: list[str] = []
    version = doc.get("version") or "source build"
    status = {0: "OK", 1: "WARNING", 2: "ERROR"}[info["exit"]]
    head = f"SuckerPot {version}, {info['stack']} mode, {doc.get('install') or 'source'}"
    out.append(f"{head:<66}{status}")
    engine = str(doc.get("engine") or "")
    if engine.startswith("podman"):
        unit = {"active": "active", "inactive": "not active", "missing": "not installed"}.get(
            str(doc.get("stack_unit")), "unknown"
        )
        out.append(f"Engine: Podman {engine[7:] or '?'} (rootful, netavark), boot unit {unit}")
    out.append("")

    sensors = info["sensors"]
    bad = [name for name, s in sensors.items() if s != "healthy"]
    if not sensors:
        out.append("Sensors (none running)")
    elif bad:
        out.append(
            f"Sensors ({len(sensors) - len(bad)} of {len(sensors)} healthy; not healthy: {', '.join(bad)})"
        )
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
    elif info["refused"]:
        name = cli.get("pseudonym")
        code = info["error_code"] or "unknown"
        why = ERROR_HELP.get(code, (JOIN_PROBLEMS.get(code, "an unexpected problem"), ""))[0]
        if code == "pseudonym_taken" and name:
            why = f"the hub refused the pseudonym '{name}' (already used by another node)"
        membership = _dict(_dict(cli.get("network")).get("membership"))
        desired = membership.get("desired")
        if desired == "member":
            tail = "SuckerPot keeps trying."
        elif membership.get("auto_retry") is True:
            tail = "SuckerPot tries again by itself within 24 hours."
        else:
            tail = "SuckerPot stopped trying."
        out.append(f"  Not a member: {why} ({code}). {tail}")
        fix = ERROR_HELP.get(code, ("", ""))[1] or "./scripts/participant.sh join"
        out.append(f"  Fix: {_fix(fix, info['stack'])}")
    elif not info["member"]:
        out.append("  Not joined. Join: ./scripts/participant.sh join")
    else:
        name = cli.get("pseudonym")
        node = cli.get("node")
        who = (
            f"{name} (Node {node})"
            if name and node
            else (name or (f"Node {node}" if node else "this node"))
        )
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
            out.append(
                f"  Hub contact: {'OK' if hub.get('signature_ok') else 'PROBLEM'}, {_ago(contact, now)} ({host}, {sig})"
            )
        code = info["error_code"]
        if code and code not in QUIET_ERRORS:
            why, fix = ERROR_HELP.get(code, ("an unexpected problem", "docker compose logs ingest"))
            since = info["error_since"]
            when = f" ({_ago(since, now)})" if since is not None else ""
            line = f"  Last network error: {code}{when}. {why[0].upper()}{why[1:]}."
            fix = _fix(fix, info["stack"])
            out.append(line + (f" Fix: {fix}" if fix else " SuckerPot keeps trying by itself."))
        path = cli.get("path")
        if path == "direct":
            out.append("  Path: direct (no VPN). The hub sees this machine's address.")
        elif path == "vpn":
            out.append("  Path: through your VPN. The hub sees the VPN's address.")
        own = {
            "learned": "learned",
            "manual": "set by hand",
            "waiting": "waiting to be learned from traffic",
        }
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

    effect_line = report_effect_line(info["cli"])
    if effect_line:
        out.append("Reports")
        out.append(f"  {effect_line}")

    out.append("Updates")
    out.append(f"  {_auto_line(doc, info)}")
    attention = needs_attention(doc, info) if info["stack"] == "participant" else []
    if attention:
        out.append("")
        out.append("Needs attention")
        for problem, command in attention:
            out.append(f"  ! {problem}")
            out.append(f"    Fix: {command}")
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
            "firewall": doc.get("firewall"),
            "report_effect": _dict(info["cli"]).get("report_effect"),
            "needs_attention": [
                {"problem": p, "fix": c} for p, c in needs_attention(doc, info)
            ]
            if info["stack"] == "participant"
            else [],
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
