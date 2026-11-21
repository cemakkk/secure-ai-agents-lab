"""Чтение только доверенных фрагментов knowledge_base.txt.

Если ChromaDB / embeddings недоступны, используется простой локальный поиск
по тому же файлу. Поиск ничего не пишет в существующую базу данных.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import os
import re
import threading

from security_prompt import clean_rag_text

ROOT = Path(__file__).resolve().parent
KB_FILE = ROOT / "knowledge_base.txt"
DB_DIR = ROOT / "chroma_db"
_DB_LOCK = threading.Lock()
_DB = None
_DB_FAILED = False


def _get_chroma():
    global _DB, _DB_FAILED
    with _DB_LOCK:
        if _DB_FAILED or not DB_DIR.exists() or os.getenv("RAG_BACKEND", "chroma") != "chroma":
            return None
        if _DB is not None:
            return _DB
        if not os.getenv("OPENROUTER_API_KEY"):
            _DB_FAILED = True
            return None
        try:
            from langchain_openai import OpenAIEmbeddings
            from langchain_chroma import Chroma
            emb = OpenAIEmbeddings(
                openai_api_key=os.getenv("OPENROUTER_API_KEY"),
                openai_api_base="https://openrouter.ai/api/v1",
                model="text-embedding-3-small",
                max_retries=0,
                request_timeout=15,
            )
            _DB = Chroma(persist_directory=str(DB_DIR), embedding_function=emb)
            return _DB
        except Exception:
            _DB_FAILED = True
            return None


def _safe_doc_content(doc):
    metadata = getattr(doc, "metadata", {}) or {}
    source = metadata.get("source", "")
    # Закрываем возможность подмешать стороннюю коллекцию/файл.
    if not isinstance(source, str) or Path(source.replace("\\", "/")).name != KB_FILE.name:
        return ""
    return clean_rag_text(getattr(doc, "page_content", ""))


@lru_cache(maxsize=1)
def _local_chunks() -> tuple[str, ...]:
    try:
        text = KB_FILE.read_text(encoding="utf-8")
    except OSError:
        return ()
    paragraphs = re.split(r"\n\s*\n", text)
    chunks, current = [], ""
    for paragraph in paragraphs:
        if len(current) + len(paragraph) > 700 and current:
            chunks.append(current)
            current = ""
        current += paragraph[:700] + "\n"
    if current:
        chunks.append(current)
    return tuple(chunks)


def _local_search(query: str, k: int) -> list[str]:
    words = {w for w in re.findall(r"[a-zа-яё]{4,}", query.lower()) if len(w) >= 4}
    if not words:
        return []
    # Очень простой fallback, не заменяет полноценный семантический поиск.
    scores = []
    for chunk in _local_chunks():
        lower = chunk.lower()
        score = sum(1 for word in words if word in lower)
        if score:
            scores.append((score, chunk))
    scores.sort(key=lambda item: item[0], reverse=True)
    return [clean_rag_text(chunk) for _, chunk in scores[:k]]


def retrieve_context(query: str, *, k: int = 3, backend: str | None = None) -> str:
    k = max(1, min(k, 3))
    snippets = []
    # В локальной версии исключаем сетевые вызовы для эмбеддингов.
    mode = backend or os.getenv("RAG_BACKEND", "chroma")
    db = _get_chroma() if mode == "chroma" else None
    if db is not None:
        try:
            # Внешнее обращение только к указанной векторной БД.
            for doc in db.similarity_search(query, k=k):
                text = _safe_doc_content(doc)
                if text:
                    snippets.append(text)
        except Exception:
            pass
    if not snippets:
        snippets = _local_search(query, k)
    return "\n\n".join(f"Фрагмент {index}: {part}" for index, part in enumerate(snippets[:k], 1))[:2400]
