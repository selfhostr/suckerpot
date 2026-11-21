"""Entry point: ``python -m web_sensor``."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time
from datetime import UTC, datetime

from suckerpot_common import EventPublisher

from web_sensor.config import Config
from web_sensor.events import EventSink
from web_sensor.profile import load_or_create_profile
from web_sensor.server import WebSensor, WebServer
from web_sensor.site import Site
from web_sensor.tls import ensure_certificate, make_context
from web_sensor.trapsync import SyncSettings, TrapSync
from web_sensor.watchdog import LoopWatchdog


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        return json.dumps(payload, ensure_ascii=True)


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)


async def run() -> None:
    cfg = Config.from_env()
    watchdog = LoopWatchdog()
    watchdog.start()
    log = logging.getLogger("web_sensor")
    profile = load_or_create_profile(cfg.data_dir)
    started = datetime.fromtimestamp(
        time.time() - profile.rng("uptime").randrange(2, 40) * 86400, UTC
    )
    site = Site(cfg, profile, started.strftime("%Y-%m-%dT%H:%M:%S+0000"))
    sink = EventSink(
        EventPublisher.from_env(),
        rate=cfg.events_per_sec,
        burst=cfg.events_burst,
        queue_size=cfg.event_queue_size,
        queue_bytes=cfg.event_queue_bytes,
        global_rate=cfg.global_events_per_sec,
        global_burst=cfg.global_events_per_sec * 2,
        important_ip_rate=cfg.important_per_ip_rate,
        important_ip_burst=cfg.important_per_ip_burst,
    )
    sink.start()
    sensor_holder: list[WebSensor] = []
    cert, key = ensure_certificate(cfg.data_dir, cfg.hostname, profile)
    ctx = make_context(cert, key, lambda obj, name: sensor_holder[0].on_sni(obj, name))
    trap_sync = TrapSync(SyncSettings.from_env())
    sensor = WebSensor(cfg, sink, site, ctx, traps=trap_sync.current)
    sensor_holder.append(sensor)
    server = WebServer(cfg, sensor)
    ports = await server.start()
    log.info("listening on %s", json.dumps(ports))
    # Downloaded trap packs: checked now, then every 30 s; a new set is one reference swap.
    reloader = asyncio.create_task(trap_sync.run(sensor.detector.use_traps))

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    async def report() -> None:
        while True:
            await asyncio.sleep(60)
            log.info("stats %s", json.dumps(sensor.stats()))

    reporter = asyncio.create_task(report())
    await stop.wait()
    log.info("shutting down")
    reporter.cancel()
    reloader.cancel()
    await server.stop()
    await sink.close()
    watchdog.stop()


def main() -> None:
    setup_logging()
    asyncio.run(run())


if __name__ == "__main__":
    main()
