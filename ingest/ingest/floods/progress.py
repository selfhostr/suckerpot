"""How far ingest has stored each stream: the clock the fold measures idle connections against.

A connection that never sent a disconnect counts as closed once nothing arrived from it for
``SESSION_FOLD_IDLE_MIN``. "Nothing arrived" must mean nothing in the streams, not nothing in the
database: while ingest lags (a restart, a stop for maintenance, a backlog), the later events of a
connection still wait in Redis, and the wall clock would call it idle too early. It would then be
folded, and its later events would arrive for a connection that has no row any more.

The consumer reports, per stream, either that a read found everything the stream held at a given
time (caught up) or the time of the newest entry it stored when more may be waiting (behind). The
fold sweep uses the oldest of these, never later than now. A stream not heard from since the start
(still draining its pending entries, or failing) makes the answer unknown, and the sweep then folds
only connections that ended. The writer needs none of this: it measures against the newest event
of the batch it just stored.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime


class IngestProgress:
    def __init__(self, streams: Iterable[str]) -> None:
        self._at: dict[str, datetime | None] = dict.fromkeys(streams)

    def caught_up(self, stream: str, at: datetime) -> None:
        """A read at ``at`` returned everything ``stream`` held, and it is stored."""
        self._advance(stream, at)

    def stored(self, stream: str, newest: datetime) -> None:
        """Entries of ``stream`` up to ``newest`` are stored; more may be waiting."""
        self._advance(stream, newest)

    def as_of(self) -> datetime | None:
        """Everything that reached the streams before this time is stored, or None (unknown)."""
        if not self._at or any(at is None for at in self._at.values()):
            return None
        return min(at for at in self._at.values() if at is not None)

    def _advance(self, stream: str, at: datetime) -> None:
        if stream not in self._at:
            return
        at = min(at, datetime.now(UTC))  # an entry id from the future never moves the clock on
        prev = self._at[stream]
        self._at[stream] = at if prev is None else max(prev, at)
