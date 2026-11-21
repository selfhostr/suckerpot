"""The hub API application (uvicorn ``hub.main:app``)."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.exceptions import HTTPException
from starlette.responses import Response
from suckerpot_netproto import ProtoError

from . import logging as hub_logging
from .auth import error_reply, reply
from .config import Settings, load_signing_key
from .context import AppContext, get_ctx
from .db import make_engine, make_sessionmaker, utcnow
from .ratelimit import AddressLimiter, Counter
from .routes import delist, enrol, info, lookup, network, node, observations, targets, verify

log = logging.getLogger("hub")


def build_context(
    settings: Settings,
    engine: AsyncEngine,
    *,
    hub_private: bytes | None = None,
    hub_private_alt: bytes | None = None,
    clock: Callable[[], datetime] = utcnow,
) -> AppContext:
    if hub_private_alt is None and settings.signing_key_alt_file:
        hub_private_alt = load_signing_key(settings.signing_key_alt_file)
    return AppContext(
        settings=settings,
        sessionmaker=make_sessionmaker(engine),
        hub_private=hub_private or load_signing_key(settings.signing_key_file),
        hub_private_alt=hub_private_alt,
        clock=clock,
        address_limiter=AddressLimiter(
            per_min=settings.unsigned_per_min,
            per_day=settings.unsigned_per_day,
            failures_per_min=settings.auth_failures_per_min,
            challenges_per_prefix=settings.challenges_per_prefix,
            trust_proxy=settings.trust_proxy,
            clock=clock,
        ),
        node_limiter=Counter(3600, settings.signed_per_hour, clock),
        reveal_limiter=Counter(86400, settings.reveals_per_day, clock),
    )


def create_app(
    settings: Settings | None = None,
    *,
    engine: AsyncEngine | None = None,
    hub_private: bytes | None = None,
    hub_private_alt: bytes | None = None,
    clock: Callable[[], datetime] = utcnow,
) -> FastAPI:
    settings = settings or Settings.from_env()
    engine = engine or make_engine(settings.database_url)
    ctx = build_context(
        settings, engine, hub_private=hub_private, hub_private_alt=hub_private_alt, clock=clock
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        try:  # the last minute of served/blocked counters (hub/hub/dormant.py)
            async with ctx.sessionmaker() as session:
                await ctx.served_days.flush(session, ctx.now())
                await session.commit()
        except Exception:  # best effort: never block a shutdown
            log.warning("served-day counters not written at shutdown")
        await engine.dispose()

    app = FastAPI(
        title="hub",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.ctx = ctx
    app.state.engine = engine

    @app.exception_handler(ProtoError)
    async def _proto_error(request: Request, exc: ProtoError) -> Response:
        return error_reply(request, get_ctx(request), exc)

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException) -> Response:
        code = "invalid_payload" if exc.status_code < 500 else "server_error"
        return reply(request, get_ctx(request), exc.status_code, {"error": code})

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> Response:
        # Type name only: messages and tracebacks may hold request data.
        log.error("unhandled error: %s", type(exc).__name__)
        return error_reply(request, get_ctx(request), ProtoError("server_error"))

    @app.get("/healthz")
    async def healthz() -> Response:
        async with ctx.sessionmaker() as session:
            await session.execute(text("SELECT 1"))
        return Response(content='{"ok":true}', media_type="application/json")

    for module in (info, enrol, node, observations, targets, network, delist, lookup, verify):
        app.include_router(module.router, prefix="/v1")
    return app


def app_factory() -> FastAPI:
    hub_logging.configure()
    return create_app()
