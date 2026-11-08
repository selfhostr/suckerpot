# Small image so that the entrypoint and config are baked in and the container
# can run with a read-only root filesystem, as a non-root user, with no bind mounts.
FROM valkey/valkey:9.1.3-alpine3.24@sha256:bf09d58e96d6b4524a15396b65b242bbe18beebbcc15a04d8ee75ddac62fae0b

COPY redis.conf /etc/redis/redis.conf
COPY entrypoint.sh /usr/local/bin/suckerpot-redis-entrypoint
# Files are copied as root and must stay world-readable and not writable.
RUN chmod 0444 /etc/redis/redis.conf && chmod 0555 /usr/local/bin/suckerpot-redis-entrypoint

# Build metadata (M28): passed by compose or the release workflow, read by the api and ingest.
ARG VERSION=dev BUILD_KIND=source COMMIT=unknown
ENV SUCKERPOT_RUNNING_VERSION=$VERSION SUCKERPOT_BUILD_KIND=$BUILD_KIND SUCKERPOT_COMMIT=$COMMIT
LABEL org.opencontainers.image.version=$VERSION org.opencontainers.image.revision=$COMMIT
# 999 is the uid/gid of the "valkey" user of the official image; /data is already owned by it.
USER 999:999

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD ["sh", "-c", "REDISCLI_AUTH=\"$REDIS_HEALTH_PASSWORD\" valkey-cli --user health ping | grep -q PONG"]

ENTRYPOINT ["/usr/local/bin/suckerpot-redis-entrypoint"]
CMD ["valkey-server", "/etc/redis/redis.conf"]
