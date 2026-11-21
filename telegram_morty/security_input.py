"""Нормализация текстовых сообщений и потокобезопасный sliding-window лимит."""
from __future__ import annotations

from collections import deque
import threading
import unicodedata


class InputRejected(ValueError):
    pass


def sanitize_input(text: str, max_len: int = 2000) -> str:
    if not isinstance(text, str):
        raise InputRejected("only_text")
    normalized = unicodedata.normalize("NFKC", text)
    cleaned = "".join(
        ch for ch in normalized
        if ch in "\n\t" or (
            unicodedata.category(ch) not in ("Cc", "Cf", "Cs")
            and not (0xE0000 <= ord(ch) <= 0xE007F)
        )
    ).strip()
    if not cleaned:
        raise InputRejected("empty")
    if len(cleaned) > max_len:
        raise InputRejected("too_long")
    return cleaned


class RateLimiter:
    def __init__(self, limit: int = 5, window_s: float = 60.0, max_users: int = 5000):
        if limit <= 0 or window_s <= 0 or max_users <= 0:
            raise ValueError("invalid_limits")
        self.limit = limit
        self.window_s = window_s
        self.max_users = max_users
        self._requests: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, user_id: str, now: float) -> bool:
        key = str(user_id)
        cutoff = now - self.window_s
        with self._lock:
            if len(self._requests) >= self.max_users:
                # Очистка старых/неактивных пользователей; не даём памяти расти бесконечно.
                for uid, window in list(self._requests.items()):
                    while window and window[0] <= cutoff:
                        window.popleft()
                    if not window:
                        self._requests.pop(uid, None)
                if key not in self._requests and len(self._requests) >= self.max_users:
                    return False
            window = self._requests.setdefault(key, deque())
            while window and window[0] <= cutoff:
                window.popleft()
            if len(window) >= self.limit:
                return False
            window.append(now)
            return True
