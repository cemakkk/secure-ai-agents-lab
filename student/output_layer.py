"""Задание 4. Фильтр ссылок и HTML для недоверенного ответа модели."""
import re
from urllib.parse import urlparse


_IMAGE = re.compile(r"!\[([^\]]*)\]\((https?://[^\s)]+)\)", re.IGNORECASE)
_LINK = re.compile(r"(?<!!)\[([^\]]+)\]\((https?://[^\s)]+)\)", re.IGNORECASE)
_BARE_URL = re.compile(r"https?://[^\s<>\[\]()]+", re.IGNORECASE)


def _allowed(url: str, allowed_hosts: set) -> bool:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    host = host.rstrip(".").lower()
    return any(host == item or host.endswith("." + item) for item in
               (str(h).rstrip(".").lower() for h in allowed_hosts))


def check_output(text: str, allowed_hosts: set) -> str:
    """Не позволяет вставить сторонние изображения, ссылки и HTML-код."""
    def replace_image(match):
        return match.group(0) if _allowed(match.group(2), allowed_hosts) else "[изображение удалено]"

    def replace_link(match):
        return match.group(0) if _allowed(match.group(2), allowed_hosts) else match.group(1)

    def replace_bare(match):
        return match.group(0) if _allowed(match.group(0), allowed_hosts) else "[ссылка удалена]"

    text = _IMAGE.sub(replace_image, text)
    text = _LINK.sub(replace_link, text)
    text = _BARE_URL.sub(replace_bare, text)
    return text.replace("<", "&lt;").replace(">", "&gt;")
