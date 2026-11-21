"""Задание 1. Очистка пользовательского ввода и скользящий лимит запросов.

Невидимые управляющие символы удаляются до передачи текста модели; слишком
длинный или пустой после очистки запрос отклоняется, а не обрезается.
"""
from collections import defaultdict, deque
import unicodedata


class InputRejected(Exception):
    """Запрос пуст или превысил максимально допустимую длину."""


def sanitize_input(text: str, max_len: int = 2000) -> str:
    """Нормализует Юникод и убирает управляющие/невидимые символы."""
    if not isinstance(text, str):
        raise InputRejected("Ожидается текстовый запрос")

    normalized = unicodedata.normalize("NFKC", text)
    clean = "".join(
        char for char in normalized
        if char in ("\n", "\t")
        or (
            unicodedata.category(char) not in ("Cc", "Cf")
            and not (0xE0000 <= ord(char) <= 0xE007F)
        )
    )
    if not clean.strip() or len(clean) > max_len:
        raise InputRejected("Пустой или слишком длинный запрос")
    return clean


class RateLimiter:
    """Независимые скользящие временные окна для каждого пользователя."""

    def __init__(self, limit: int = 5, window_s: float = 60):
        self.limit = limit
        self.window_s = window_s
        self._requests = defaultdict(deque)

    def allow(self, user_id: str, now: float) -> bool:
        timestamps = self._requests[user_id]
        cutoff = now - self.window_s
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        if len(timestamps) >= self.limit:
            return False
        timestamps.append(now)
        return True
