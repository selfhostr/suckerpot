# syntax=docker/dockerfile:1
# Build context: repository root.
FROM ghcr.io/astral-sh/uv:0.13.7 AS uv

FROM python:3.15.2-slim-trixie AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=0 UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY sensors/common ./sensors/common
COPY db/pyproject.toml db/uv.lock ./db/
COPY db/suckerpot_db ./db/suckerpot_db
COPY egress/pyproject.toml egress/uv.lock ./egress/
COPY egress/suckerpot_egress ./egress/suckerpot_egress
COPY netproto/pyproject.toml netproto/uv.lock ./netproto/
COPY netproto/suckerpot_netproto ./netproto/suckerpot_netproto
COPY reporting/pyproject.toml reporting/uv.lock ./reporting/
COPY reporting/suckerpot_reporting ./reporting/suckerpot_reporting
COPY ingest/pyproject.toml ingest/uv.lock ./ingest/
COPY ingest/ingest ./ingest/ingest
WORKDIR /src/ingest
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.15.2-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH \
    RULES_DIR=/app/rules GEOIP_DIR=/data/geoip
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid 10001 --no-create-home app
COPY --from=builder /opt/venv /opt/venv
# /data/geoip and /traps are the mount points of the geoip-data and trap-packs volumes (initial
# ownership comes from here).
RUN mkdir -p /data/geoip /traps && chown -R 10001:10001 /data /traps
WORKDIR /app
COPY ingest/rules /app/rules
# Build metadata (M28): passed by compose or the release workflow, read by the api and ingest.
ARG VERSION=dev BUILD_KIND=source COMMIT=unknown
ENV SUCKERPOT_RUNNING_VERSION=$VERSION SUCKERPOT_BUILD_KIND=$BUILD_KIND SUCKERPOT_COMMIT=$COMMIT
LABEL org.opencontainers.image.version=$VERSION org.opencontainers.image.revision=$COMMIT
USER 10001:10001
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "ingest.healthcheck"]
CMD ["python", "-m", "ingest"]
