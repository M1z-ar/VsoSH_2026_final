import logging
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class App:
    bot_token: str
    api_id: int
    api_hash: str

    max_file_mb: int
    max_file_size: int
    workers: int

    vt_key: str
    vt_sleep: int
    vt_tries: int
    vt_bad: int
    vt_warn: int
    vt_min_gap: int

    hybrid_on: bool
    hybrid_key: str | None
    hybrid_env: int
    hybrid_wait: int
    hybrid_sleep: int
    hybrid_tries: int
    hybrid_ua: str

    urlintel_on: bool
    urlhaus_key: str | None
    sb_key: str | None


def load_app() -> App:
    file_mb = env_int("MAX_FILE_MB", 250)

    return App(
        bot_token=os.getenv("BOT_TOKEN", "").strip(),
        api_id=env_int("API_ID", 0),
        api_hash=os.getenv("API_HASH", "").strip(),

        max_file_mb=file_mb,
        max_file_size=file_mb * 1024 * 1024,
        workers=env_int("SCAN_CONCURRENCY", 3),

        vt_key=os.getenv("VT_KEY", "").strip(),
        vt_sleep=env_int("VT_POLL_DELAY_SEC", 3),
        vt_tries=env_int("VT_WAIT_CYCLES", 52),
        vt_bad=env_int("VT_MALICIOUS_THRESHOLD", 1),
        vt_warn=env_int("VT_SUSPICIOUS_THRESHOLD", 1),
        vt_min_gap=env_int("VT_MIN_GAP_SEC", 16),

        hybrid_on=env_bool("ENABLE_HYBRID", True),
        hybrid_key=os.getenv("HYBRID_KEY", "").strip() or None,
        hybrid_env=env_int("HYBRID_ENV_ID", 160),
        hybrid_wait=env_int("HYBRID_TIMEOUT_SEC", 300),
        hybrid_sleep=env_int("HYBRID_POLL_DELAY_SEC", 10),
        hybrid_tries=env_int("HYBRID_WAIT_CYCLES", 60),
        hybrid_ua=os.getenv("HYBRID_USER_AGENT", "Falcon").strip() or "Falcon",

        urlintel_on=env_bool("ENABLE_URL_INTEL", True),
        urlhaus_key=os.getenv("URLHAUS_KEY", "").strip() or None,
        sb_key=os.getenv("SAFE_BROWSING_KEY", "").strip() or None,
    )


app = load_app()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("bot")


def check_env() -> None:
    missing = []

    if not app.bot_token:
        missing.append("BOT_TOKEN")
    if not app.api_id:
        missing.append("API_ID")
    if not app.api_hash:
        missing.append("API_HASH")
    if not app.vt_key:
        missing.append("VT_KEY")

    if missing:
        raise RuntimeError("Не заданы переменные: " + ", ".join(missing))

    if app.hybrid_on and not app.hybrid_key:
        log.warning("Hybrid Analysis включен, но ключ не задан. Проверка Hybrid будет пропущена.")


TEXT_START = (
    "👋 **Привет!** Я проверяю файлы и ссылки.\n\n"
    "**Личка:** пришли файл или ссылку\n"
    "**Группа:** ответь на сообщение и отправь `/scan`\n\n"
    "Команды: /help, /addbot"
)

TEXT_HELP = (
    "ℹ️ **Помощь**\n\n"
    "• Проверка URL и файлов\n"
    f"• Максимальный размер файла: **{app.max_file_mb} МБ**\n"
    "• Ссылки: Safe Browsing + URLhaus + VirusTotal\n"
    "• Файлы до 32 МБ: VirusTotal + Hybrid Analysis\n"
    "• Файлы больше 32 МБ: только Hybrid Analysis\n\n"
    "В группе: ответ на сообщение + `/scan`"
)

TEXT_ADDBOT = (
    "➕ **Как добавить бота в группу**\n\n"
    "1. Добавь бота в группу\n"
    "2. При необходимости дай права администратора\n"
    "3. Для проверки ответь на сообщение и отправь `/scan`\n\n"
    "Команда `/mhelp` — краткая инструкция для группы"
)

TEXT_MHELP = (
    "👥 **Группа**\n\n"
    "Ответь на сообщение с файлом или ссылкой и отправь `/scan`.\n"
    f"Максимальный размер файла: {app.max_file_mb} МБ"
)

ERR_GROUP = "❌ Эта команда работает только в группах."
ERR_PRIVATE = "❌ Эта команда работает только в личных сообщениях."
ERR_REPLY = "❗ Ответьте `/scan` на сообщение с файлом или ссылкой."
ERR_EMPTY_PRIVATE = "❗ Пришлите файл или ссылку."
ERR_EMPTY_GROUP = "❗ В сообщении нет файла или ссылки для проверки."
ERR_SIZE = "❌ Файл слишком большой: {size_mb} МБ. Максимум: {max_mb} МБ."

WAIT = "⏳ Анализирую..."
WAIT_FILE = "⏳ Скачиваю файл..."
DONE = "✅ Готово."
QUEUED = "🧾 Принял. Поставил в очередь на проверку."

ERR_VT_LIMIT = "⏳ Лимит VirusTotal превышен, попробуйте позже."
ERR_FAIL = "❌ Не удалось выполнить проверку."
