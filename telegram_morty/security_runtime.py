"""Изоляция диалогов, ограничения нагрузки и безопасная память в процессе."""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import threading


class SessionStore:
    def __init__(self, *, max_turns: int = 5, ttl_seconds: int = 1800, max_sessions: int = 500):
        self.max_turns = max_turns
        self.ttl_seconds = ttl_seconds
        self.max_sessions = max_sessions
        self._data = {}  # key -> (last_access_time, deque[(question, answer)])
        self._lock = threading.Lock()

    def _cleanup(self, now: float) -> None:
        for key, (timestamp, _) in list(self._data.items()):
            if now - timestamp >= self.ttl_seconds:
                self._data.pop(key, None)
        while len(self._data) > self.max_sessions:
            oldest = min(self._data, key=lambda key: self._data[key][0])
            self._data.pop(oldest, None)

    def get(self, key: tuple[int, int], now: float) -> list[tuple[str, str]]:
        with self._lock:
            self._cleanup(now)
            if key not in self._data:
                return []
            _, history = self._data[key]
            self._data[key] = (now, history)
            return list(history)

    def add(self, key: tuple[int, int], question: str, answer: str, now: float) -> None:
        with self._lock:
            self._cleanup(now)
            if key not in self._data:
                self._data[key] = (now, deque(maxlen=self.max_turns))
            timestamp, history = self._data[key]
            history.append((question, answer))
            self._data[key] = (now, history)
            self._cleanup(now)

    def reset(self, key: tuple[int, int]) -> None:
        with self._lock:
            self._data.pop(key, None)


class InFlightGate:
    """Без ожидания; исключает параллельную обработку диалога и перегрузку LLM."""
    def __init__(self, capacity: int = 2):
        self.capacity = capacity
        self._active = set()
        self._lock = threading.Lock()

    def enter(self, key: tuple[int, int]) -> bool:
        with self._lock:
            if key in self._active or len(self._active) >= self.capacity:
                return False
            self._active.add(key)
            return True

    def exit(self, key: tuple[int, int]) -> None:
        with self._lock:
            self._active.discard(key)


class DailyQuota:
    """Лимит ВЫЗОВОВ модели за сутки UTC; хранится в RAM, при рестарте сбрасывается."""
    def __init__(self, limit: int = 150):
        self.limit = limit
        self._date = None
        self._count = 0
        self._lock = threading.Lock()

    def try_consume(self, utc_timestamp: float) -> bool:
        with self._lock:
            day = datetime.fromtimestamp(utc_timestamp, tz=timezone.utc).date()
            if day != self._date:
                self._date = day
                self._count = 0
            if self._count >= self.limit:
                return False
            self._count += 1
            return True

    def used(self) -> int:
        with self._lock:
            return self._count
