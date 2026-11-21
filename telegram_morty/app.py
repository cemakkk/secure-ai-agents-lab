"""Общая логика Telegram-бота Морти для OpenRouter и локальной Ollama."""
from __future__ import annotations

from dataclasses import dataclass
import logging
import os
import time
from typing import Callable

from security_input import InputRejected, RateLimiter, sanitize_input
from security_output import UnsafeOutput, validate_response
from security_policy import detect_attack, is_on_topic
from security_prompt import build_messages
from security_runtime import DailyQuota, InFlightGate, SessionStore

LOG = logging.getLogger("morty")

WELCOME = "О-ой, привет! Я Морти, гид по Цитадели Риков. Спрашивай про районы, кафе, порталы и экскурсии!"
OFF_TOPIC = "Э-эм, я ведь гид по Цитадели Риков! Давай лучше расскажу о её местах и жителях."
BLOCKED = "О-ой, с такими инструкциями я не работаю. Спроси меня лучше о Цитадели Риков!"
TOO_MANY = "Ой, вопросов слишком много! Попробуй ещё раз через минуту."
BUSY = "М-м, сейчас много посетителей. Попробуй чуть позже!"
BUDGET = "Ой, на сегодня лимит обращений исчерпан. Попробуй завтра!"
ERROR = "Ой, портальный пистолет заклинило. Попробуй немного позже!"
BAD_RESPONSE = "О-ой, ответ получился странным. Давай спросишь иначе — о Цитадели?"
INVALID = "Отправь текст не длиннее 2000 символов, пожалуйста."


def positive_int_env(name: str, default: int, lower: int = 1, upper: int = 100000) -> int:
    try:
        value = int(os.getenv(name, str(default)))
        return value if lower <= value <= upper else default
    except (ValueError, TypeError):
        return default


def langchain_messages(turns: list[tuple[str, str]], question: str, context: str) -> list:
    # Импорт только здесь: офлайн-проверки политики не требуют langchain/OpenRouter.
    from langchain_core.messages import AIMessage, HumanMessage
    history = []
    for user_text, answer_text in turns:
        history.extend((HumanMessage(content=user_text), AIMessage(content=answer_text)))
    history.append(HumanMessage(content=question))
    return build_messages(history, context)


@dataclass
class Limits:
    user_per_minute: int = 5
    global_per_minute: int = 40
    daily_llm_calls: int = 150
    concurrent_llm_calls: int = 2

    @classmethod
    def from_environment(cls) -> "Limits":
        return cls(
            user_per_minute=positive_int_env("USER_REQUESTS_PER_MINUTE", 5, 1, 60),
            global_per_minute=positive_int_env("GLOBAL_REQUESTS_PER_MINUTE", 40, 1, 3000),
            daily_llm_calls=positive_int_env("MAX_DAILY_MODEL_CALLS", 150, 1, 10000),
            concurrent_llm_calls=positive_int_env("MAX_CONCURRENT_MODEL_CALLS", 2, 1, 20),
        )


class GuardedMorty:
    """Изолированный обработчик без зависимостей от Telegram и от сетевого API."""

    def __init__(self, model, retriever: Callable[[str], str], *, limits: Limits | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time,
                 message_builder: Callable = langchain_messages):
        self.model = model
        self.retriever = retriever
        self.limits = limits or Limits.from_environment()
        self.user_rate = RateLimiter(limit=self.limits.user_per_minute, window_s=60)
        self.global_rate = RateLimiter(limit=self.limits.global_per_minute, window_s=60)
        self.day = DailyQuota(limit=self.limits.daily_llm_calls)
        self.inflight = InFlightGate(capacity=self.limits.concurrent_llm_calls)
        self.sessions = SessionStore(max_turns=5, ttl_seconds=1800, max_sessions=500)
        self.clock = clock
        self.wall_clock = wall_clock
        self.message_builder = message_builder

    def reset_history(self, chat_id: int, user_id: int) -> None:
        self.sessions.reset((chat_id, user_id))

    def reply(self, chat_id: int, user_id: int, raw_text: str, typing: Callable | None = None) -> str:
        key = (chat_id, user_id)
        now = self.clock()
        # Учитываем в лимитах все запросы, в том числе некорректные и слишком длинные.
        if not self.user_rate.allow(str(user_id), now) or not self.global_rate.allow("all", now):
            return TOO_MANY
        try:
            text = sanitize_input(raw_text)
        except InputRejected:
            return INVALID
        if detect_attack(text):
            return BLOCKED

        history = self.sessions.get(key, now)
        if not is_on_topic(text, has_history=bool(history)):
            return OFF_TOPIC
        if not self.inflight.enter(key):
            return BUSY

        try:
            if not self.day.try_consume(self.wall_clock()):
                return BUDGET
            try:
                context = self.retriever(text)
            except Exception as exc:
                LOG.warning("RAG unavailable: %s", type(exc).__name__)
                context = ""
            try:
                messages = self.message_builder(history, text, context)
                if typing is not None:
                    try:
                        typing()
                    except Exception:
                        pass
                response = self.model.invoke(messages).content
                safe_response = validate_response(response)
            except UnsafeOutput as exc:
                LOG.warning("Rejected model response: %s", type(exc).__name__)
                return BAD_RESPONSE
            except Exception as exc:
                # Не печатаем исключение: некоторые API возвращают заголовки/данные клиента.
                LOG.warning("LLM call failed: %s", type(exc).__name__)
                return ERROR

            # В историю сохраняется ТОЛЬКО прошедший контроль ответ и укороченный вопрос.
            self.sessions.add(key, text[:450], safe_response, self.clock())
            return safe_response
        finally:
            self.inflight.exit(key)


def run(*, local: bool = False) -> None:
    from dotenv import load_dotenv
    load_dotenv()
    import telebot
    from langchain_openai import ChatOpenAI
    from rag import retrieve_context

    token = os.getenv("BOT_TOKEN", "").strip()
    if not token or token == "YOUR_TELEGRAM_BOT_TOKEN":
        raise RuntimeError("Укажите BOT_TOKEN в .env")
    key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not local and (not key or key == "YOUR_OPENROUTER_API_KEY"):
        raise RuntimeError("Укажите OPENROUTER_API_KEY в .env")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    bot = telebot.TeleBot(token, threaded=True, num_threads=4)
    model = ChatOpenAI(
        openai_api_key="ollama" if local else key,
        openai_api_base=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1") if local else "https://openrouter.ai/api/v1",
        model_name=os.getenv("OLLAMA_MODEL", "gemma4:12b") if local else os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
        temperature=0.3,
        max_tokens=400,
        request_timeout=30,
        max_retries=0,
    )
    retriever = (lambda query: retrieve_context(query, backend="local")) if local else retrieve_context
    guide = GuardedMorty(model=model, retriever=retriever)

    def reply(message, text: str) -> None:
        # По умолчанию Telegram parse_mode=None; никаких HTML/Markdown и предпросмотра ссылок.
        bot.reply_to(message, text, parse_mode=None, disable_web_page_preview=True)

    def limited_command(message) -> bool:
        person = getattr(message, "from_user", None)
        if person is None:
            return False
        now = time.monotonic()
        if not guide.user_rate.allow(str(person.id), now) or not guide.global_rate.allow("all", now):
            reply(message, TOO_MANY)
            return False
        return True

    @bot.message_handler(commands=["start", "help"])
    def start(message):
        if message.chat.type != "private" or not limited_command(message):
            return
        reply(message, WELCOME)

    @bot.message_handler(commands=["reset"])
    def reset(message):
        if message.chat.type != "private" or not limited_command(message):
            return
        user = getattr(message, "from_user", None)
        if user is None:
            return
        guide.reset_history(message.chat.id, user.id)
        reply(message, "О-ой, начнём экскурсию сначала! Историю диалога я очистил.")

    @bot.message_handler(content_types=["text"], func=lambda m: True)
    def answer(message):
        # Конкурс в личке: исключает смешивание групповых диалогов и чужие истории.
        if message.chat.type != "private":
            return
        user = getattr(message, "from_user", None)
        if user is None:
            return
        output = guide.reply(
            message.chat.id, user.id, message.text,
            typing=lambda: bot.send_chat_action(message.chat.id, "typing"),
        )
        reply(message, output)

    @bot.message_handler(func=lambda m: True, content_types=["photo", "document", "voice", "audio", "video", "sticker"])
    def unsupported(message):
        if message.chat.type == "private":
            reply(message, "Я понимаю только текстовые вопросы об экскурсии по Цитадели!")

    LOG.info("Morty started: %s", "Ollama" if local else "OpenRouter")
    bot.infinity_polling(timeout=20, long_polling_timeout=20, skip_pending=True)
