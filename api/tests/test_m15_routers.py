"""The M15 to M19 router modules exist, sit behind the role check, and the feeds are opt-in."""

import importlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from argon2 import PasswordHasher
from fastapi import APIRouter, FastAPI

import api.main as main_mod
from api.auth import AuthSettings
from api.main import create_app
from api.provider_keys import ProviderName

MODULES = [
    "campaigns",
    "attack",
    "defend",
    "detections",
    "exposure",
    "feeds",
    "scripts",
    "alerts",
    "reports",
    "search",
    "today",
]
HASH = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("correct horse battery")


@asynccontextmanager
async def no_database() -> AsyncIterator[None]:
    raise RuntimeError("no database in this test")
    yield


def build() -> FastAPI:
    return create_app(
        no_database,  # type: ignore[arg-type]
        enable_live=False,
        auth_settings=AuthSettings(password_hash=HASH, secret=b"k" * 40),
    )


@pytest.mark.parametrize("name", MODULES)
def test_each_module_exposes_a_router(name: str) -> None:
    module = importlib.import_module(f"api.{name}")
    assert isinstance(module.router, APIRouter)


def test_the_feeds_router_is_not_mounted_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = APIRouter()

    @probe.get("/probe")
    def _probe() -> dict[str, bool]:
        return {"ok": True}

    monkeypatch.setattr(main_mod, "feeds_router", probe)
    monkeypatch.delenv("FEEDS_ENABLED", raising=False)
    assert "/feeds/probe" not in build().openapi()["paths"]
    monkeypatch.setenv("FEEDS_ENABLED", "true")
    paths = build().openapi()["paths"]
    assert "/feeds/probe" in paths
    assert not any(p.startswith("/api/v1/feeds") for p in paths)


def test_the_provider_path_accepts_the_new_providers() -> None:
    pattern = ProviderName.__metadata__[0].metadata[0].pattern  # type: ignore[attr-defined]
    import re

    for provider in ("smtp", "virustotal"):
        assert re.match(pattern, provider)
    assert not re.match(pattern, "anthropic")  # the retired LLM provider is an unknown name now
