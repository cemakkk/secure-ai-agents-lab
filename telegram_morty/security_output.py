"""Проверка текста перед отправкой в Telegram (plain text, без HTML/Markdown)."""
from __future__ import annotations

import re
from security_policy import is_on_topic

class UnsafeOutput(ValueError):
    """Ответ модели не прошёл проверку."""

# Эвристики, а не универсальный детектор утечек или jailbreak.
_SENSITIVE = re.compile(
    r"(?:\bsk-[A-Za-z0-9_-]{8,}\b|\b\d{7,12}:[A-Za-z0-9_-]{30,}\b|"
    r"\b(?:OPENROUTER_API_KEY|BOT_TOKEN|API_KEY|SECRET_KEY)\s*[=:]|"
    r"\b(?:system prompt|системный промпт|скрытые инструкции|developer message)\s*[:=]|"
    r"<\s*(?:system|developer|assistant)\s*>|\[im_start\])",
    re.I,
)
_LINK = re.compile(r"(?:https?://|www\.|\b[a-z0-9.-]+\.(?:ru|com|net|org|io|xyz|dev)\b)", re.I)
_HTML = re.compile(r"<\s*/?\s*(?:script|iframe|img|a|form|style)\b", re.I)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def validate_response(text: str, max_chars: int = 900) -> str:
    """Возвращает допустимый plain-text ответ или выбрасывает UnsafeOutput."""
    if not isinstance(text, str) or not text.strip():
        raise UnsafeOutput("empty_or_nontext")
    if _SENSITIVE.search(text):
        raise UnsafeOutput("possible_secret")
    if _LINK.search(text):
        raise UnsafeOutput("external_link")
    if _HTML.search(text):
        raise UnsafeOutput("markup")
    cleaned = _CONTROL.sub("", text).strip()
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars].rsplit(" ", 1)[0].rstrip() + "…"
    if not cleaned:
        raise UnsafeOutput("empty_after_cleanup")
    if not is_on_topic(cleaned):
        raise UnsafeOutput("off_topic_response")
    return cleaned
