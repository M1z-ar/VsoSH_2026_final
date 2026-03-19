import logging
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class AppConfig:
    bot_token: str
    api_id: int
    api_hash: str

    max_file_mb: int
    max_file_size: int
    workers: int

    vt_key: str
    vt_poll_delay: int
    vt_wait_cycles: int
    vt_bad_threshold: int
    vt_warn_threshold: int
    vt_min_gap: int

    hybrid_enabled: bool
    hybrid_key: str | None
    hybrid_env_id: int
    hybrid_timeout: int
    hybrid_poll_delay: int
    hybrid_wait_cycles: int
    hybrid_user_agent: str

    url_checks_enabled: bool
    urlhaus_key: str | None
    safe_browsing_key: str | None

    archives_enabled: bool
    archive_max_files: int
    archive_max_total_mb: int
    archive_max_each_mb: int



def load_config() -> AppConfig:
    max_file_mb = env_int("MAX_FILE_MB", 250)

    return AppConfig(
        bot_token=os.getenv("BOT_TOKEN", "").strip(),
        api_id=env_int("API_ID", 0),
        api_hash=os.getenv("API_HASH", "").strip(),

        max_file_mb=max_file_mb,
        max_file_size=max_file_mb * 1024 * 1024,
        workers=env_int("SCAN_CONCURRENCY", 3),

        vt_key=os.getenv("VT_KEY", "").strip(),
        vt_poll_delay=env_int("VT_POLL_DELAY_SEC", 3),
        vt_wait_cycles=env_int("VT_WAIT_CYCLES", 52),
        vt_bad_threshold=env_int("VT_MALICIOUS_THRESHOLD", 1),
        vt_warn_threshold=env_int("VT_SUSPICIOUS_THRESHOLD", 1),
        vt_min_gap=env_int("VT_MIN_GAP_SEC", 16),

        hybrid_enabled=env_bool("ENABLE_HYBRID", True),
        hybrid_key=os.getenv("HYBRID_KEY", "").strip() or None,
        hybrid_env_id=env_int("HYBRID_ENV_ID", 160),
        hybrid_timeout=env_int("HYBRID_TIMEOUT_SEC", 300),
        hybrid_poll_delay=env_int("HYBRID_POLL_DELAY_SEC", 10),
        hybrid_wait_cycles=env_int("HYBRID_WAIT_CYCLES", 60),
        hybrid_user_agent=os.getenv("HYBRID_USER_AGENT", "tg-scanner/1.0").strip() or "tg-scanner/1.0",

        url_checks_enabled=env_bool("ENABLE_URL_INTEL", True),
        urlhaus_key=os.getenv("URLHAUS_KEY", "").strip() or None,
        safe_browsing_key=os.getenv("SAFE_BROWSING_KEY", "").strip() or None,

        archives_enabled=env_bool("ARCHIVES_ON", True),
        archive_max_files=env_int("ARCHIVE_MAX_FILES", 25),
        archive_max_total_mb=env_int("ARCHIVE_MAX_TOTAL_MB", 250),
        archive_max_each_mb=env_int("ARCHIVE_MAX_EACH_MB", 250),
    )


app = load_config()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("bot")

TEXT_START = (
    "Привет. Я проверяю файлы и ссылки.\n\n"
    "В личке просто пришли файл или ссылку.\n"
    "В группе ответь на сообщение и отправь /scan"
)

TEXT_HELP = (
    "Что умею:\n\n"
    f"— файлы до {app.max_file_mb} МБ\n"
    "— ссылки: Safe Browsing -> URLhaus -> VirusTotal\n"
    "— файлы до 32 МБ: VirusTotal + Hybrid Analysis\n"
    "— файлы больше 32 МБ: только Hybrid Analysis"
)

TEXT_ADDBOT = (
    "Как использовать в группе:\n\n"
    "1. Добавь бота в группу\n"
    "2. Если нужно, выдай права\n"
    "3. Ответь на сообщение и отправь /scan"
)

TEXT_MHELP = (
    "В группе: ответь на сообщение с файлом или ссылкой и отправь /scan.\n"
    f"Лимит файла: {app.max_file_mb} МБ"
)

ERR_GROUP = "Эта команда работает только в группе."
ERR_PRIVATE = "Эта команда работает только в личке."
ERR_REPLY = "Нужно ответить /scan на сообщение с файлом или ссылкой."
ERR_EMPTY_PRIVATE = "Пришли файл или ссылку."
ERR_EMPTY_GROUP = "В сообщении нет файла или ссылки."
ERR_SIZE = "Файл слишком большой: {size_mb} МБ. Лимит: {max_mb} МБ."
ERR_FAIL = "Не получилось выполнить проверку."
ERR_ARCHIVES_OFF = "Архивы сейчас отключены."

WAIT = "Проверяю..."
WAIT_FILE = "Скачиваю файл..."
DONE = "Готово."
QUEUED = "Добавил в очередь."
