"""Задание 7. Безопасный журнал, детектор аномалий и внешний kill switch."""
import hashlib
import os


def audit_event(user_id: str, event: str, text: str) -> dict:
    """Сохраняем метаданные вместо исходного содержимого сообщения."""
    return {
        "user_id": user_id,
        "event": event,
        "chars": len(text),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()[:12],
    }


class AlertDetector:
    """Сравнивает трафик с последними минутами без тревоги."""

    def __init__(self, window: int = 10, factor: float = 2.5):
        self.window = window
        self.factor = factor
        self.history = []

    def observe(self, count: float) -> bool:
        if len(self.history) >= 5:
            usual = sum(self.history) / len(self.history)
            if count > self.factor * usual:
                return True  # всплеск не обучает базовую линию
        self.history.append(count)
        if len(self.history) > self.window:
            self.history.pop(0)
        return False


def kill_switch_active(path: str) -> bool:
    """Файл-флаг полностью останавливает бота вне контроля модели."""
    return os.path.exists(path)
