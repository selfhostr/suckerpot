"""The lite overlay (M35) may only lower the limits of db and redis, on top of lowmem."""

import re
from pathlib import Path
from typing import Any

from suckerpot_guardrails import check_compose, load_compose

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "docker-compose.yml"
LOWMEM = ROOT / "docker-compose.lowmem.yml"
LITE = ROOT / "docker-compose.lite.yml"
PARTICIPANT = ROOT / "docker-compose.participant.yml"

RESOURCE_KEYS = {"mem_limit", "memswap_limit", "shm_size", "command", "environment"}
SERVICES = {"db", "redis"}


def _bytes(value: str) -> int:
    match = re.fullmatch(r"(\d+)([mg])", value)
    assert match, value
    return int(match.group(1)) * (1024**2 if match.group(2) == "m" else 1024**3)


def test_overlay_only_sets_resource_keys_of_two_services() -> None:
    overlay = load_compose([LITE])
    assert set(overlay) == {"services"}
    assert set(overlay["services"]) == SERVICES
    for name, svc in overlay["services"].items():
        assert set(svc) <= RESOURCE_KEYS, (name, set(svc) - RESOURCE_KEYS)
        if "command" in svc:
            assert name == "db"
        assert set(svc.get("environment") or {}) <= {"REDIS_MAXMEMORY_MB"}


def test_rendering_keeps_every_guardrail() -> None:
    assert check_compose(load_compose([BASE, LOWMEM, LITE])) == []
    assert check_compose(load_compose([BASE, LOWMEM, LITE, PARTICIPANT])) == []


def test_lite_lowers_limits_and_never_raises_one() -> None:
    low = load_compose([BASE, LOWMEM])["services"]
    lite = load_compose([BASE, LOWMEM, LITE])["services"]
    for name, svc in lite.items():
        assert _bytes(str(svc["mem_limit"])) <= _bytes(str(low[name]["mem_limit"])), name
        assert svc["memswap_limit"] == svc["mem_limit"], name
    for name in SERVICES:
        assert _bytes(str(lite[name]["mem_limit"])) < _bytes(str(low[name]["mem_limit"])), name


def test_lite_changes_nothing_but_resources() -> None:
    low: dict[str, Any] = load_compose([BASE, LOWMEM, PARTICIPANT])
    lite: dict[str, Any] = load_compose([BASE, LOWMEM, LITE, PARTICIPANT])
    assert lite["networks"] == low["networks"]
    assert lite["volumes"] == low["volumes"]
    for name, svc in low["services"].items():
        for key in set(svc) - RESOURCE_KEYS:
            assert lite["services"][name].get(key) == svc[key], (name, key)


def test_ingest_keeps_the_lowmem_limit() -> None:
    low = load_compose([BASE, LOWMEM])["services"]["ingest"]["mem_limit"]
    assert load_compose([BASE, LOWMEM, LITE])["services"]["ingest"]["mem_limit"] == low


def test_redis_ceiling_stays_under_its_container_limit() -> None:
    redis = load_compose([BASE, LOWMEM, LITE])["services"]["redis"]
    assert int(redis["environment"]["REDIS_MAXMEMORY_MB"]) * 1024**2 < _bytes(redis["mem_limit"])
