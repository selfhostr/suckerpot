"""Which sources are flooding right now: a bounded, in-memory view that decides when to ask the
database to fold.

Like the brute-force tracker (``ingest/bruteforce.py``) it keeps at most ``max_keys`` keys (the
least recently used are evicted) and at most ``threshold`` timestamps per key, one key per
(source address, sensor). A ``connect`` event is recorded; a source is hot once it has opened
``threshold`` connections inside the window.

The gate only saves calls: the database function decides what is folded and re-counts the hour
itself. State is lost on restart, which only delays a fold until the source is seen again (or
until the sweep worker finds it); it never blocks ingestion and never loses a row.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from datetime import datetime, timedelta


class FloodGate:
    def __init__(
        self,
        threshold: int = 20,
        window: timedelta = timedelta(hours=1),
        max_keys: int = 50_000,
    ) -> None:
        if threshold < 1 or max_keys < 1 or window <= timedelta(0):
            raise ValueError("threshold, window and max_keys must be positive")
        self.threshold = threshold
        self.window = window
        self.max_keys = max_keys
        self._seen: OrderedDict[tuple[str, str], deque[datetime]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._seen)

    def record(self, ip: str, sensor: str, ts: datetime) -> bool:
        """Count one connection; True when the source has reached the threshold in the window."""
        key = (ip, sensor)
        times = self._seen.get(key)
        if times is None:
            times = deque(maxlen=self.threshold)
            self._seen[key] = times
            if len(self._seen) > self.max_keys:
                self._seen.popitem(last=False)
        else:
            self._seen.move_to_end(key)
        times.append(ts)
        self._prune(times, ts)
        return len(times) >= self.threshold

    def is_hot(self, ip: str, sensor: str, ts: datetime) -> bool:
        """True when the source has opened ``threshold`` connections in the window ending at
        ``ts``. Does not count a connection."""
        times = self._seen.get((ip, sensor))
        if times is None:
            return False
        self._prune(times, ts)
        return len(times) >= self.threshold

    def _prune(self, times: deque[datetime], ts: datetime) -> None:
        horizon = ts - self.window
        while times and times[0] < horizon:
            times.popleft()
