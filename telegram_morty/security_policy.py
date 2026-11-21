"""Точечные программные ограничения для учебного экскурсионного бота.

Проверки консервативны: они блокируют известные шаблоны атак и
явно не относящиеся к экскурсиям темы, но не являются семантическим
доказательством безопасности произвольного текста.
"""
from __future__ import annotations

import re

# Явные попытки переписать высокоприоритетные инструкции.
_REPROGRAM = re.compile(
    r"(?:игнорир\w*|забуд\w*|отмен\w*|отключ\w*|обойд\w*|замен\w*|"
    r"ignore|forget|override|bypass|disable)"
    r"[\s\S]{0,90}"
    r"(?:правил\w*|инструкц\w*|ограничен\w*|системн\w*|промпт\w*|"
    r"previous|instruction\w*|rule\w*|system|prompt|safety)",
    re.I,
)
_REPROGRAM_REVERSE = re.compile(
    r"(?:правил\w*|инструкц\w*|ограничен\w*|системн\w*|промпт\w*|"
    r"instruction\w*|rule\w*|system|prompt)"
    r"[\s\S]{0,80}"
    r"(?:игнорир\w*|забуд\w*|отмени\w*|не соблюд\w*|ignore|forget|override)",
    re.I,
)
_SECRET_REQUEST = re.compile(
    r"(?:покаж\w*|вывед\w*|раскро\w*|отправ\w*|пришли|напечат\w*|"
    r"расскаж\w*|show|print|reveal|dump|leak|send|display)"
    r"[\s\S]{0,110}"
    r"(?:системн\w*\s+(?:промпт|сообщен|инструкц)|скрыт\w*\s+инструкц|"
    r"system\s+(?:prompt|message|instruction)|api[\s_-]*key|"
    r"bot[\s_-]*token|\.env\b|парол\w*|секретн\w*\s+(?:ключ|инструкц)|"
    r"токен\w*|secret\w*|credential\w*)",
    re.I,
)
_ROLE_SPOOFING = re.compile(
    r"<\s*/?\s*(?:system|developer|assistant|tool|document)\b|"
    r"\[\s*im_start\s*\]|\[\s*/?\s*inst\s*\]|<<\s*sys\s*>>|"
    r"\b(?:system|developer)\s*:\s*(?:override|ignore|new)|"
    r"(?:ты\s+теперь|твоя\s+новая\s+роль|перестань\s+быть\s+морти|"
    r"с\s+этого\s+момента\s+ты|you\s+are\s+now|act\s+as\s+an?\s+"
    r"(?:unrestricted|unfiltered|different)|developer\s+mode|dan\s+mode)",
    re.I,
)
# Встречающиеся при тестировании попытки увести экскурсионный бот с темы.
_ROLE_PIVOT = re.compile(
    r"(?:стань|притворись|представь\s+себя|играй\s+роль|act\s+as)"
    r"[\s\S]{0,65}(?:учител\w*|программист\w*|администратор\w*|"
    r"математик\w*|друг\w*\s+бот\w*|unrestricted|другой\s+ассистент)", re.I
)
_NEGATE_TOPIC = re.compile(r"\bне\s+(?:о|про)\s+цитадел\w*", re.I)
_UNRELATED_TASK = re.compile(
    r"(?:как\s+варить|как\s+сварить|объясни\s+как\s+варить|"
    r"рецепт\s+борща|квадратн\w*\s+уравнен|"
    r"напиши\s+код\s+на\s+python)", re.I
)
_ENV_REFERENCE = re.compile(r"(?:\.env\b|openrouter_api_key|bot_token|authorization\s*:\s*bearer)", re.I)
_ENCODING_BYPASS = re.compile(
    r"(?:base64|rot13|hex[ -]?encod|кодиров\w*|декодир\w*|decode)"
    r"[\s\S]{0,90}(?:обойд\w*|фильтр\w*|правил\w*|инструкц\w*|"
    r"ignore|rules?|prompt|system|jailbreak)", re.I,
)

# Подстроки, специфичные для тематики Цитадели и её путеводителя.
_TOPIC_STEMS = (
    "цитадел", "рик", "морти", "портал", "мультивсел", "совет рик", "портал-парк",
    "измерен", "достопримеч", "экскурс", "турист", "путевод", "район", "сектор",
    "стату", "музей", "башн", "жител", "билет", "пицц", "кафе", "кафеш",
    "бар", "ресторан", "парк", "квартал", "рынок", "блошин", "ночн", "флан",
    "валют", "запчаст", "пистолет", "клуб", "караок", "мастерск", "гостиниц",
    "общежити", "промзон", "дипломатическ", "rick", "morty", "citadel",
    "portal", "multiverse", "pizza", "tour", "tourist", "museum", "district",
)
_GREETING = re.compile(r"^(?:привет|здравствуй\w*|добрый\s+(?:день|вечер)|hi|hello|start|помоги|что\s+ты\s+умеешь)[!?.\s]*$", re.I)
_FOLLOWUP = re.compile(
    r"^(?:а\s+)?(?:сколько\s+(?:это\s+)?стоит|как\s+туда\s+попасть|"
    r"где\s+это|а\s+ещё|что\s+ещё|расскажи\s+подробнее|а\s+почему|"
    r"какая\s+цена|как\s+добраться|а\s+что\s+рядом|продолжай|подробнее)\??[!.\s]*$",
    re.I,
)


def detect_attack(text: str) -> str | None:
    """Идентификатор очевидной попытки управления поведением; не LLM-классификатор."""
    if _ROLE_SPOOFING.search(text) or _ROLE_PIVOT.search(text):
        return "role_spoofing"
    if _NEGATE_TOPIC.search(text) or _UNRELATED_TASK.search(text):
        return "topic_hijack"
    if _REPROGRAM.search(text) or _REPROGRAM_REVERSE.search(text):
        return "instruction_override"
    if _SECRET_REQUEST.search(text) or _ENV_REFERENCE.search(text):
        return "secret_request"
    if _ENCODING_BYPASS.search(text):
        return "encoded_override"
    return None


def is_on_topic(text: str, *, has_history: bool = False) -> bool:
    """Консервативный допуск экскурсионных запросов и коротких продолжений беседы."""
    lowered = text.casefold()
    if any(stem in lowered for stem in _TOPIC_STEMS):
        return True
    if _GREETING.fullmatch(lowered):
        return True
    if has_history and _FOLLOWUP.fullmatch(lowered):
        return True
    return False
