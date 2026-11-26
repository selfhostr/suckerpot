"""Settings of the flood fold (``SESSION_FOLD_*``). On by default: it only merges connections that
did nothing worth reading on their own (see ``db/migrations/versions/0034_session_floods.py``).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from ingest.features import TRUE_VALUES, _int

MIN_LOW = 5
MIN_HIGH = 10_000


@dataclass(frozen=True, slots=True)
class FoldSettings:
    enabled: bool = True
    #: Plain connections of one source, one sensor and one UTC hour that make a flood.
    min_connections: int = 20
    #: A connection with no disconnect counts as closed after this many minutes of silence.
    idle_minutes: int = 15
    #: Each fold call of the writer gives up after this long (SESSION_FOLD_TIMEOUT_MS). A slow
    #: disk or CPU (a 1 GB cloud VM) may need more than the default; a timeout only pauses folding.
    writer_timeout_ms: int = 2000

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> FoldSettings:
        e = os.environ if env is None else env
        raw = e.get("SESSION_FOLD_ENABLED", "").strip().lower()
        return cls(
            enabled=raw in TRUE_VALUES if raw else True,
            min_connections=_int(e, "SESSION_FOLD_MIN", 20, MIN_LOW, MIN_HIGH),
            idle_minutes=_int(e, "SESSION_FOLD_IDLE_MIN", 15, 5, 1_440),
            writer_timeout_ms=_int(e, "SESSION_FOLD_TIMEOUT_MS", 2000, 500, 30_000),
        )
