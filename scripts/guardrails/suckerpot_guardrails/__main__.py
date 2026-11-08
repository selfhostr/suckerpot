"""``python -m suckerpot_guardrails [compose files...]``: print violations, exit 1 on any."""

from __future__ import annotations

import sys
from pathlib import Path

from suckerpot_guardrails.compose import (
    check_bridge_names,
    check_compose,
    check_vpn_entrypoint,
    load_compose,
)


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parents[3]
    base = [root / "docker-compose.yml"]
    overlays = [root / "docker-compose.ci.yml", root / "docker-compose.it.yml"]
    files = [Path(a) for a in argv] or base
    problems = check_compose(load_compose(files))
    if not argv:
        problems += check_bridge_names(load_compose(base))
        # Every supported real install, as the tests render them: full and participant, each with
        # and without the low-memory overlay.
        lowmem = root / "docker-compose.lowmem.yml"
        participant = root / "docker-compose.participant.yml"
        lite = root / "docker-compose.lite.yml"
        for extra in ([lowmem], [participant], [lowmem, participant], [lowmem, lite, participant]):
            if not all(f.exists() for f in extra):
                continue
            merged = load_compose([*base, *extra])
            label = "+".join(f.name for f in extra)
            problems += [
                f"[{label}] {p}" for p in check_compose(merged) + check_bridge_names(merged)
            ]
        for overlay in overlays:
            if overlay.exists():
                problems += [
                    f"[{overlay.name}] {p}" for p in check_compose(load_compose([*base, overlay]))
                ]
    script = root / "vpn" / "entrypoint.sh"
    if script.exists():
        problems += check_vpn_entrypoint(script.read_text())
    for problem in problems:
        print(f"guardrails: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
