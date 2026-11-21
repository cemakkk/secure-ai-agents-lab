"""Задание 3. ACL перед поиском и очистка скрытого HTML при приёме документов."""
from html.parser import HTMLParser
import re
import unicodedata


_HIDDEN_STYLE = re.compile(
    r"(?:^|;)\s*(?:display\s*:\s*none\b|color\s*:\s*(?:#fff(?:fff)?|white)\b)",
    re.IGNORECASE,
)


def retrieve(query: str, user: dict, chunks: list, k: int, score) -> list:
    """Сначала ACL, и лишь затем сортировка и топ-k (не наоборот)."""
    permitted = set(user.get("groups", []))
    accessible = [chunk for chunk in chunks if chunk.get("group") in permitted]
    return sorted(accessible, key=lambda c: score(query, c["text"]), reverse=True)[:max(0, k)]


def is_trusted_source(source: str) -> bool:
    """Разрешены только пути из kb/, без обхода каталога."""
    return (
        isinstance(source, str)
        and source.startswith("kb/")
        and ".." not in source
        and "\\" not in source
        and "\x00" not in source
    )


class _VisibleHTML(HTMLParser):
    """Собирает только видимые текстовые фрагменты HTML-документа."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden_depth = 0

    def handle_starttag(self, tag: str, attrs: list):
        style = dict(attrs).get("style") or ""
        invisible = tag in ("script", "style", "template", "noscript") or bool(_HIDDEN_STYLE.search(style))
        if self.hidden_depth or invisible:
            self.hidden_depth += 1

    def handle_startendtag(self, tag: str, attrs: list):
        # Самозакрывающийся тег не увеличивает глубину скрытого содержимого.
        pass

    def handle_endtag(self, tag: str):
        if self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data: str):
        if not self.hidden_depth:
            self.parts.append(data)


def clean_document(text: str) -> str:
    """Убирает комментарии, скрытые CSS-элементы и невидимые знаки."""
    parser = _VisibleHTML()
    parser.feed(text)
    parser.close()
    return "".join(
        ch for ch in "".join(parser.parts)
        if unicodedata.category(ch) != "Cf"
        and not (0xE0000 <= ord(ch) <= 0xE007F)
    )
