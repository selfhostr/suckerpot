"""ASGI entry point: ``uvicorn api.main:app``."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.routing import APIRouter
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.middleware.trustedhost import TrustedHostMiddleware
from suckerpot_db import create_engine, create_session_factory

from api import authz
from api.abuse import router as abuse_router
from api.abuse_exports import router as abuse_exports_router
from api.abuse_imap import router as abuse_imap_router
from api.abuse_outcomes import router as abuse_outcomes_router
from api.abuse_replies import router as abuse_replies_router
from api.abuse_smtp import router as abuse_smtp_router
from api.alerts import router as alerts_router
from api.analytics import router as analytics_router
from api.attack import router as attack_router
from api.audit_routes import router as audit_router
from api.auth import AuthMiddleware, AuthService, AuthSettings, allowed_hosts_from_env
from api.auth import router as auth_router
from api.c2 import router as c2_router
from api.campaigns import router as campaigns_router
from api.cves import router as cves_router
from api.defend import router as defend_router
from api.detections import router as detections_router
from api.egress import router as egress_router
from api.exposure import router as exposure_router
from api.feeds import router as feeds_router
from api.indicators import router as indicators_router
from api.insights import router as insights_router
from api.live import LiveHub, LivePoller, live_router
from api.live_window import router as live_window_router
from api.malware import router as malware_router
from api.network import router as network_router
from api.provider_keys import install as install_provider_keys
from api.provider_keys import remove_retired_keys
from api.provider_keys import router as provider_keys_router
from api.reports import router as reports_router
from api.routes import health_router, router
from api.samples import router as samples_router
from api.scripts import router as scripts_router
from api.search import router as search_router
from api.settings import router as settings_router
from api.setup_status import router as setup_status_router
from api.setup_wizard import router as setup_wizard_router
from api.spa import install_security_headers, install_spa
from api.story import router as story_router
from api.takedown import router as takedown_router
from api.today import router as today_router
from api.trends import router as trends_router
from api.users import router as users_router
from api.version import router as version_router
from api.vpn_settings import router as vpn_settings_router

TRUE_VALUES = {"1", "true", "yes", "on"}
DEFAULT_WEB_DIST = "/app/web"


def create_app(
    session_factory: async_sessionmaker[AsyncSession] | None = None,
    *,
    enable_docs: bool | None = None,
    web_dist_dir: Path | None = None,
    enable_live: bool = True,
    auth_settings: AuthSettings | None = None,
) -> FastAPI:
    """Build the app. Tests pass their own session factory; production builds one from env."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = None
        factory = session_factory
        if factory is None:
            engine = create_engine()
            factory = create_session_factory(engine)
        app.state.session_factory = factory
        await remove_retired_keys(factory)
        hub: LiveHub = app.state.hub
        poller_task = None
        if enable_live:
            poller_task = asyncio.create_task(LivePoller(factory, hub).run())
        try:
            yield
        finally:
            hub.close_all()
            if poller_task is not None:
                poller_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await poller_task
            if engine is not None:
                await engine.dispose()

    if enable_docs is None:
        enable_docs = os.environ.get("API_ENABLE_DOCS", "false").strip().lower() in TRUE_VALUES
    app = FastAPI(
        title="SuckerPot API",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if enable_docs else None,
        redoc_url="/redoc" if enable_docs else None,
        openapi_url="/openapi.json" if enable_docs else None,
    )
    # Auth is added before the header middleware so that 401/403 responses carry the headers too.
    auth = AuthService(auth_settings if auth_settings is not None else AuthSettings.from_env())
    app.state.auth = auth
    app.add_middleware(AuthMiddleware, auth=auth)
    install_security_headers(app, enable_docs=enable_docs)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts_from_env())
    authz.install(app)

    def include(router_: APIRouter) -> None:
        # Default deny: every /api/v1 HTTP route goes through the role check (see api.authz).
        app.include_router(router_, prefix="/api/v1", dependencies=[Depends(authz.authorize)])

    app.include_router(health_router)
    include(auth_router)
    include(router)
    app.include_router(live_router, prefix="/api/v1")  # WebSocket: read-only, both roles
    for api_router in (
        analytics_router,
        insights_router,
        trends_router,
        cves_router,
        malware_router,
        samples_router,
        egress_router,
        c2_router,  # before indicators_router: /indicators/c2 must not match /indicators/{id}
        indicators_router,
        settings_router,
        provider_keys_router,
        vpn_settings_router,
        setup_status_router,
        setup_wizard_router,
        version_router,
        users_router,
        audit_router,
        campaigns_router,
        attack_router,
        defend_router,
        detections_router,
        exposure_router,
        scripts_router,
        alerts_router,
        reports_router,
        abuse_router,
        abuse_exports_router,
        abuse_smtp_router,
        network_router,
        abuse_imap_router,
        abuse_outcomes_router,
        abuse_replies_router,
        takedown_router,
        search_router,
        today_router,
        live_window_router,
        story_router,
    ):
        include(api_router)
    if os.environ.get("FEEDS_ENABLED", "false").strip().lower() in TRUE_VALUES:
        # Machine-readable feeds authenticate with their own bearer token, not the dashboard
        # session, so they live outside /api/v1 and outside the role check.
        app.include_router(feeds_router, prefix="/feeds")
        if not os.environ.get("AUTH_TRUSTED_PROXIES", "").strip():
            # Behind a tunnel or proxy every client then looks like the proxy: the feed's rate
            # limits and failure lockout become global instead of per client.
            logging.getLogger("api.feeds").warning(
                "FEEDS_ENABLED is on but AUTH_TRUSTED_PROXIES is empty: the feed cannot tell "
                "its clients apart behind a proxy, so one bad client can lock everyone out."
            )
    install_provider_keys(app)
    app.state.hub = LiveHub()

    dist = (
        web_dist_dir
        if web_dist_dir is not None
        else Path(os.environ.get("WEB_DIST_DIR", DEFAULT_WEB_DIST))
    )
    if (dist / "index.html").is_file():
        install_spa(app, dist)
    return app


app = create_app()
