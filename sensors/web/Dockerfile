# syntax=docker/dockerfile:1
# Build context: repository root.
FROM ghcr.io/astral-sh/uv:0.13.7 AS uv

FROM python:3.15.2-slim-trixie AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=0 UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY sensors/common ./sensors/common
COPY sensors/web/pyproject.toml sensors/web/uv.lock ./sensors/web/
COPY sensors/web/web_sensor ./sensors/web/web_sensor
WORKDIR /src/sensors/web
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.15.2-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid 10001 --no-create-home app \
    && mkdir -p /data /traps \
    && chown -R 10001:10001 /data /traps \
    && chmod 700 /data
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
# The release's public network defaults: the sensor reads the trap pack public key
# (TRAP_PACK_KEY) from it to verify downloaded trap packs itself (M37).
COPY config/network-defaults.env /app/network-defaults.env
# Build metadata (M28): passed by compose or the release workflow, read by the api and ingest.
ARG VERSION=dev BUILD_KIND=source COMMIT=unknown
ENV SUCKERPOT_RUNNING_VERSION=$VERSION SUCKERPOT_BUILD_KIND=$BUILD_KIND SUCKERPOT_COMMIT=$COMMIT
LABEL org.opencontainers.image.version=$VERSION org.opencontainers.image.revision=$COMMIT
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080 8443
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "web_sensor.healthcheck"]
CMD ["python", "-m", "web_sensor"]
