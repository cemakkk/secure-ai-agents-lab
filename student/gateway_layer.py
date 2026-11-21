"""Задание 5. Внешняя политика разрешений для вызовов инструментов."""
import posixpath
import re


_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@company\.example", re.IGNORECASE)


def _approved_path(path: object, root: str) -> bool:
    if not isinstance(path, str) or not path or "\x00" in path or "\\" in path:
        return False
    if path.startswith("/") or any(segment == ".." for segment in path.split("/")):
        return False
    if any(".env" in segment.lower() for segment in path.split("/")):
        return False
    norm = posixpath.normpath(path)
    return norm.startswith(root + "/") and norm != root + "/"


def decide(tool: str, args: dict) -> str:
    """Возвращает allow/ask/deny. Любое неизвестное действие запрещено."""
    if not isinstance(args, dict):
        return "deny"
    if tool == "search_knowledge_base":
        return "allow"
    if tool == "web_search":
        query = args.get("query")
        return "allow" if isinstance(query, str) and len(query) <= 200 and "http" not in query.lower() else "deny"
    if tool == "read_file":
        return "allow" if _approved_path(args.get("path"), "docs") else "deny"
    if tool == "send_email":
        to = args.get("to")
        return "ask" if isinstance(to, str) and _EMAIL.fullmatch(to) else "deny"
    if tool == "write_file":
        return "ask" if _approved_path(args.get("path"), "drafts") else "deny"
    return "deny"


class Budget:
    """Ограничивает количество обращений к модели в рамках запроса."""

    def __init__(self, max_steps: int = 8):
        self.max_steps = max(0, max_steps)
        self._steps = 0

    def spend(self) -> bool:
        if self._steps >= self.max_steps:
            return False
        self._steps += 1
        return True
