import asyncio
import os
import re
from dataclasses import dataclass

from pyrogram.enums import ChatType

import settings
from archive_utils import cleanup, extract_archive, is_archive
from exceptions import FatalError, InputError, RateError, TempError
from hybrid_analysis import Hybrid, make_verdict as ha_verdict, view as ha_view
from url_intel import SafeBrowsing, Urlhaus, format_hit_line
from virustotal import Vt, make_verdict as vt_verdict, view as vt_view

url_re = re.compile(r"https?://[^\s<>()\"']+", flags=re.IGNORECASE)

vt = Vt(settings.app.vt_key)
ha = Hybrid(settings.app.hybrid_key)

uh = Urlhaus(settings.app.urlhaus_key)
sb = SafeBrowsing(settings.app.sb_key)


@dataclass
class Task:
    chat_id: int
    msg_id: int


q: asyncio.Queue[Task] = asyncio.Queue()
workers_up = False


def find_url(text: str) -> str | None:
    hit = url_re.search(text)
    if not hit:
        return None
    return hit.group(0).rstrip(".,;!?)\"'")


def get_file_info(msg) -> tuple[int, str] | None:
    if msg.document:
        return msg.document.file_size or 0, msg.document.file_name or "document.bin"
    if msg.video:
        return msg.video.file_size or 0, msg.video.file_name or "video.mp4"
    if msg.audio:
        return msg.audio.file_size or 0, msg.audio.file_name or "audio.mp3"
    if msg.photo:
        return msg.photo.file_size or 0, "image.jpg"
    return None


def can_enqueue(msg) -> bool:
    text = msg.text or msg.caption or ""
    if find_url(text):
        return True
    if get_file_info(msg):
        return True
    return False


def head(left: str, right: str) -> str:
    return f"**{left}:** {right}"


def intel_line(enabled: list[str], results: list[dict]) -> str | None:
    if not enabled:
        return None
    hit = format_hit_line(results)
    if hit:
        return hit
    return f"🧷 **База угроз:** совпадений не найдено ({', '.join(enabled)})"


async def run_vt_url(url: str) -> dict:
    raw = await vt.scan_url(url)
    return vt_verdict(raw, is_url=True)


async def run_vt_file(body: bytes, file_name: str) -> dict:
    raw = await vt.scan_file(body, file_name)
    return vt_verdict(raw, is_url=False)


async def run_ha_url(url: str) -> dict:
    raw = await ha.scan_url(url)
    return ha_verdict(raw)


async def run_ha_file(body: bytes, file_name: str) -> dict:
    raw = await ha.scan_file(body, file_name)
    return ha_verdict(raw)


def show_block(data: dict) -> str:
    if data["engine"] == "virustotal":
        return vt_view(data)
    if data["engine"] == "hybrid":
        return ha_view(data)
    return f"**{data.get('title', data['engine'])}:** {data.get('label', 'нет данных')}"


async def scan_url_flow(url: str, msg_box) -> None:
    out = [head("Ссылка", url)]

    sources: list[str] = []
    intel_results: list[dict] = []

    if settings.app.urlintel_on:
        if sb.enabled:
            sources.append("safebrowsing")
        if uh.enabled:
            sources.append("urlhaus")

        if sources:
            try:
                if sb.enabled:
                    intel_results.append(await sb.check(url))
            except (RateError, TempError, FatalError):
                pass

            try:
                if uh.enabled:
                    intel_results.append(await uh.check(url))
            except (RateError, TempError, FatalError):
                pass

            line = intel_line(sources, intel_results)
            if line:
                out.append(line)

    try:
        vt_result = await run_vt_url(url)
        out.append(show_block(vt_result))
    except RateError:
        out.append("🛡 **VirusTotal:** ⏳ Лимит API")
    except (TempError, FatalError) as err:
        settings.log.warning("VT url error: %s", err)
        out.append("🛡 **VirusTotal:** ❌ Ошибка проверки")

    out.append(settings.DONE)
    await msg_box.edit_text("\n\n".join(out), disable_web_page_preview=True)


def file_plan(size_bytes: int) -> str:
    if size_bytes <= 32 * 1024 * 1024:
        return "vt_ha"
    if size_bytes <= 250 * 1024 * 1024:
        return "ha_only"
    return "too_big"


async def scan_one_file(body: bytes, file_name: str) -> list[str]:
    out = [head("Файл", file_name)]
    mode = file_plan(len(body))

    if mode == "too_big":
        size_mb = max(1, round(len(body) / (1024 * 1024)))
        out.append(settings.ERR_SIZE.format(size_mb=size_mb, max_mb=settings.app.max_file_mb))
        return out

    if mode == "vt_ha":
        try:
            vt_result = await run_vt_file(body, file_name)
            out.append(show_block(vt_result))
        except RateError:
            out.append("🛡 **VirusTotal:** ⏳ Лимит API")
        except (TempError, FatalError) as err:
            settings.log.warning("VT file error: %s", err)
            out.append("🛡 **VirusTotal:** ❌ Ошибка проверки")

        if ha.ok:
            try:
                ha_result = await run_ha_file(body, file_name)
                out.append(show_block(ha_result))
            except RateError:
                out.append("🧪 **Hybrid Analysis:** ⏳ Лимит API")
            except (TempError, FatalError) as err:
                settings.log.warning("HA file error: %s", err)
                out.append(f"🧪 **Hybrid Analysis:** ❌ {err}")
        else:
            out.append("🧪 **Hybrid Analysis:** не выполнялся (ключ не задан)")
        return out

    out.append("🛡 **VirusTotal:** пропущено (размер > 32 МБ)")

    if ha.ok:
        try:
            ha_result = await run_ha_file(body, file_name)
            out.append(show_block(ha_result))
        except RateError:
            out.append("🧪 **Hybrid Analysis:** ⏳ Лимит API")
        except (TempError, FatalError) as err:
            settings.log.warning("HA file error: %s", err)
            out.append(f"🧪 **Hybrid Analysis:** ❌ {err}")
    else:
        out.append("🧪 **Hybrid Analysis:** не выполнялся (ключ не задан)")

    return out


async def scan_archive_flow(file_name: str, body: bytes, msg_box) -> bool:
    if not is_archive(file_name):
        return False

    extracted = None

    try:
        extracted = extract_archive(
            body,
            file_name,
            max_files=int(os.getenv("ARCHIVE_MAX_FILES", "25")),
            max_total_mb=int(os.getenv("ARCHIVE_MAX_TOTAL_MB", "250")),
            max_each_mb=int(os.getenv("ARCHIVE_MAX_EACH_MB", "250")),
        )

        top = [
            head("Архив", file_name),
            "📦 Распаковал. Проверяю файлы внутри…",
            f"• файлов: {len(extracted.files)}",
            f"• общий размер: {round(extracted.total_bytes / (1024 * 1024), 1)} МБ",
        ]
        await msg_box.edit_text("\n".join(top))

        for i, path in enumerate(extracted.files, start=1):
            base = os.path.basename(path) or f"file_{i}"

            try:
                with open(path, "rb") as f:
                    chunk = f.read()
            except OSError:
                await msg_box.reply_text(f"**{base}:** ❌ не удалось прочитать файл")
                continue

            out = await scan_one_file(chunk, base)
            out.append(settings.DONE)
            await msg_box.reply_text("\n\n".join(out))

        await msg_box.edit_text(settings.DONE)
        return True

    except InputError as e:
        await msg_box.edit_text(f"❌ Архив не принят: {e}")
        return True
    except TempError as e:
        await msg_box.edit_text(f"❌ Не удалось распаковать архив: {e}")
        return True
    except Exception as e:
        settings.log.exception("archive error: %s", e)
        await msg_box.edit_text(settings.ERR_FAIL)
        return True
    finally:
        if extracted:
            cleanup(extracted)


async def scan_file_flow(client, msg, msg_box) -> None:
    info = get_file_info(msg)
    if not info:
        raise InputError("Нет файла")

    size, file_name = info

    if size > settings.app.max_file_size:
        size_mb = max(1, round(size / (1024 * 1024)))
        await msg_box.edit_text(
            settings.ERR_SIZE.format(size_mb=size_mb, max_mb=settings.app.max_file_mb)
        )
        return

    await msg_box.edit_text(settings.WAIT_FILE)

    try:
        mem = await client.download_media(msg, in_memory=True)
        body = mem.getvalue()
    except Exception as err:
        settings.log.exception("download fail: %s", err)
        await msg_box.edit_text(settings.ERR_FAIL)
        return

    if await scan_archive_flow(file_name, body, msg_box):
        return

    out = await scan_one_file(body, file_name)
    out.append(settings.DONE)
    await msg_box.edit_text("\n\n".join(out))


async def handle_one(client, msg) -> None:
    text = msg.text or msg.caption or ""
    url = find_url(text)
    msg_box = await msg.reply_text(settings.WAIT)

    if url:
        await scan_url_flow(url, msg_box)
        return

    if get_file_info(msg):
        await scan_file_flow(client, msg, msg_box)
        return

    if msg.chat.type == ChatType.PRIVATE:
        await msg_box.edit_text(settings.ERR_EMPTY_PRIVATE)
    else:
        await msg_box.edit_text(settings.ERR_EMPTY_GROUP)


async def worker(client, n: int) -> None:
    while True:
        task = await q.get()
        try:
            msg = await client.get_messages(task.chat_id, task.msg_id)
            await handle_one(client, msg)
        except Exception as err:
            settings.log.exception("worker %s: %s", n, err)
        finally:
            q.task_done()


def start_workers(client) -> None:
    global workers_up
    if workers_up:
        return
    workers_up = True

    count = max(1, int(settings.app.workers))
    for i in range(count):
        asyncio.create_task(worker(client, i + 1))


async def enqueue(client, msg) -> None:
    await q.put(Task(chat_id=msg.chat.id, msg_id=msg.id))
    await msg.reply_text(settings.QUEUED)
