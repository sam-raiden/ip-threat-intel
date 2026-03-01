import time
import threading
from collections import deque


class RateLimiter:
    def __init__(
        self,
        requests_per_minute: int | None = None,
        requests_per_day: int | None = None,
    ) -> None:
        self._rpm = requests_per_minute
        self._rpd = requests_per_day
        self._minute_timestamps: deque[float] = deque()
        self._day_timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def _clean_expired(self, timestamps: deque[float], window: float) -> None:
        cutoff = time.time() - window
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

    def allow_request(self) -> None:
        with self._lock:
            now = time.time()

            if self._rpm is not None:
                self._clean_expired(self._minute_timestamps, 60.0)
                if len(self._minute_timestamps) >= self._rpm:
                    raise RuntimeError("Rate limit exceeded (per minute)")

            if self._rpd is not None:
                self._clean_expired(self._day_timestamps, 86400.0)
                if len(self._day_timestamps) >= self._rpd:
                    raise RuntimeError("Rate limit exceeded (per day)")

            if self._rpm is not None:
                self._minute_timestamps.append(now)
            if self._rpd is not None:
                self._day_timestamps.append(now)