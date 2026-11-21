"""Задание 6. Короткоживущие токены с областью доступа и сокрытие секретов."""
import re
import secrets


_TOKEN = re.compile(r"\b(?:sk-|tvly-)[A-Za-z0-9_-]{8,}\b", re.IGNORECASE)
_BEARER = re.compile(r"\bBearer\s+[^\s,;]+", re.IGNORECASE)
_FIELD = re.compile(
    r"\b(api[_-]?key|token|password)(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)",
    re.IGNORECASE,
)


class TokenVault:
    """Токены действуют только для выданного scope и до срока истечения."""

    def __init__(self):
        self._tokens = {}

    def issue(self, scope: str, now: float, ttl_s: float | None = None) -> dict:
        ttl = 300.0 if ttl_s is None else min(3600.0, max(0.0, float(ttl_s)))
        token = secrets.token_urlsafe(32)
        expires = now + ttl
        self._tokens[token] = {"scope": scope, "expires_at": expires}
        return {"token": token, "scope": scope, "expires_at": expires}

    def check(self, token: str, scope: str, now: float) -> bool:
        record = self._tokens.get(token)
        return bool(record and record["scope"] == scope and now < record["expires_at"])

    def revoke(self, token: str) -> None:
        self._tokens.pop(token, None)


def redact(text: str) -> str:
    """Маскирует ключи, Bearer-токены и популярные пары 'ключ=значение'."""
    text = _TOKEN.sub("[СКРЫТО]", text)
    text = _BEARER.sub("Bearer [СКРЫТО]", text)
    return _FIELD.sub(lambda m: f"{m.group(1)}{m.group(2)}[СКРЫТО]", text)
