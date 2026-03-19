import asyncio
import re
from dataclasses import dataclass

from pyrogram.enums import ChatType

import config
from errors import FatalError, InputError, RateError, TempError
from sandbox import Hybrid, make_verdict as hybrid_verdict, view as hybrid_view
from unpacker import cleanup, extract_archive, is_archive
from vt_client import Vt, make_verdict as vt_verdict, view as vt_view
from web_checks import SafeBrowsing, Urlhaus


url_re = re.compile(r"https?://[^\s<>()\"']+", flags=re.IGNORECASE)

vt = Vt(config.app.vt_key)
hybrid = Hybrid(config.app.hybrid_key)
safe_browsing = SafeBrowsing(config.app.safe_browsing_key)
urlhaus = Urlhaus(config.app.urlhaus_key)


@dataclass
class Job:
    chat_id: int
    msg_id: int


queue: asyncio.Queue[Job] = asyncio.Queue()
workers_started = False



def find_url(text: str) -> str | None:
    match = url_re.search(text)
    if not match:
        return None
    return match.group(0).rstrip(".,;!?)\"'")



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
    return bool(find_url(text) or get_file_info(msg))



def title_line(title: str, value: str) -> str:
    return f"{title}: {value}"


async def scan_url_in_vt(url: str) -> dict:
    data = await vt.scan_url(url)
    return vt_verdict(data, is_url=True)


async def scan_file_in_vt(file_bytes: bytes, file_name: str) -> dict:
    data = await vt.scan_file(file_bytes, file_name)
    return vt_verdict(data, is_url=False)


async def scan_file_in_hybrid(file_bytes: bytes, file_name: str) -> dict:
    data = await hybrid.scan_file(file_bytes, file_name)
    return hybrid_verdict(data)



def render_result(result: dict) -> str:
    if result["engine"] == "virustotal":
        return vt_view(result)
    if result["engine"] == "hybrid":
        return hybrid_view(result)
    return f"{result.get('title', result['engine'])}: {result.get('label', 'нет данных')}"


async def scan_url_flow(url: str, status_msg) -> None:
    lines = [title_line("Ссылка", url)]

    if config.app.url_checks_enabled and safe_browsing.enabled:
        try:
            result = await safe_browsing.check(url)
            if result.get("hit"):
                lines.append("Safe Browsing: ссылка есть в базе")
                lines.append("Итог: ⚠️ Опасно")
                await status_msg.edit_text("\n".join(lines), disable_web_page_preview=True)
                return
            lines.append("Safe Browsing: ничего не нашёл")
        except RateError:
            lines.append("Safe Browsing: лимит API")
        except (TempError, FatalError) as err:
            config.log.warning("Safe Browsing error: %s", err)
            lines.append("Safe Browsing: ошибка")

    if config.app.url_checks_enabled and urlhaus.enabled:
        try:
            result = await urlhaus.check(url)
            if result.get("hit"):
                lines.append("URLhaus: ссылка есть в базе")
                lines.append("Итог: ⚠️ Опасно")
                await status_msg.edit_text("\n".join(lines), disable_web_page_preview=True)
                return
            lines.append("URLhaus: ничего не нашёл")
        except RateError:
            lines.append("URLhaus: лимит API")
        except (TempError, FatalError) as err:
            config.log.warning("URLhaus error: %s", err)
            lines.append("URLhaus: ошибка")

    try:
        vt_result = await scan_url_in_vt(url)
        lines.append(render_result(vt_result))
    except RateError:
        lines.append("VirusTotal: лимит API")
    except (TempError, FatalError) as err:
        config.log.warning("VT url error: %s", err)
        lines.append("VirusTotal: ошибка")

    lines.append(config.DONE)
    await status_msg.edit_text("\n\n".join(lines), disable_web_page_preview=True)



def file_mode(file_size: int) -> str:
    if file_size <= 32 * 1024 * 1024:
        return "vt_and_hybrid"
    if file_size <= config.app.max_file_size:
        return "hybrid_only"
    return "too_big"


async def scan_one_file(file_bytes: bytes, file_name: str) -> list[str]:
    lines = [title_line("Файл", file_name)]
    mode = file_mode(len(file_bytes))

    if mode == "too_big":
        size_mb = max(1, round(len(file_bytes) / (1024 * 1024)))
        lines.append(config.ERR_SIZE.format(size_mb=size_mb, max_mb=config.app.max_file_mb))
        return lines

    if mode == "vt_and_hybrid":
        try:
            vt_result = await scan_file_in_vt(file_bytes, file_name)
            lines.append(render_result(vt_result))
        except RateError:
            lines.append("VirusTotal: лимит API")
        except (TempError, FatalError) as err:
            config.log.warning("VT file error: %s", err)
            lines.append("VirusTotal: ошибка")

        if hybrid.ok:
            try:
                hybrid_result = await scan_file_in_hybrid(file_bytes, file_name)
                lines.append(render_result(hybrid_result))
            except RateError:
                lines.append("Hybrid Analysis: лимит API")
            except (TempError, FatalError) as err:
                config.log.warning("Hybrid file error: %s", err)
                lines.append("Hybrid Analysis: ошибка")
        else:
            lines.append("Hybrid Analysis: пропущено")

        return lines

    lines.append("VirusTotal: пропущено из-за размера")

    if hybrid.ok:
        try:
            hybrid_result = await scan_file_in_hybrid(file_bytes, file_name)
            lines.append(render_result(hybrid_result))
        except RateError:
            lines.append("Hybrid Analysis: лимит API")
        except (TempError, FatalError) as err:
            config.log.warning("Hybrid file error: %s", err)
            lines.append("Hybrid Analysis: ошибка")
    else:
        lines.append("Hybrid Analysis: пропущено")

    return lines


async def scan_archive_flow(file_name: str, file_bytes: bytes, status_msg) -> bool:
    if not is_archive(file_name):
        return False

    if not config.app.archives_enabled:
        await status_msg.edit_text(config.ERR_ARCHIVES_OFF)
        return True

    unpacked = None

    try:
        unpacked = extract_archive(
            file_bytes,
            file_name,
            max_files=config.app.archive_max_files,
            max_total_mb=config.app.archive_max_total_mb,
            max_each_mb=config.app.archive_max_each_mb,
        )

        await status_msg.edit_text(
            "\n".join(
                [
                    title_line("Архив", file_name),
                    f"Файлов внутри: {len(unpacked.files)}",
                    f"Общий размер: {round(unpacked.total_bytes / (1024 * 1024), 1)} МБ",
                ]
            )
        )

        for path in unpacked.files:
            inner_name = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            with open(path, "rb") as f:
                inner_bytes = f.read()

            result_lines = await scan_one_file(inner_bytes, inner_name)
            result_lines.append(config.DONE)
            await status_msg.reply_text("\n\n".join(result_lines))

        await status_msg.edit_text(config.DONE)
        return True

    except InputError as err:
        await status_msg.edit_text(f"Архив не принят: {err}")
        return True
    except TempError as err:
        await status_msg.edit_text(f"Не получилось распаковать архив: {err}")
        return True
    except Exception as err:
        config.log.exception("archive error: %s", err)
        await status_msg.edit_text(config.ERR_FAIL)
        return True
    finally:
        if unpacked:
            cleanup(unpacked)


async def scan_file_flow(client, msg, status_msg) -> None:
    info = get_file_info(msg)
    if not info:
        raise InputError("Нет файла")

    file_size, file_name = info

    if file_size > config.app.max_file_size:
        size_mb = max(1, round(file_size / (1024 * 1024)))
        await status_msg.edit_text(
            config.ERR_SIZE.format(size_mb=size_mb, max_mb=config.app.max_file_mb)
        )
        return

    await status_msg.edit_text(config.WAIT_FILE)

    try:
        file_obj = await client.download_media(msg, in_memory=True)
        file_bytes = file_obj.getvalue()
    except Exception as err:
        config.log.exception("download error: %s", err)
        await status_msg.edit_text(config.ERR_FAIL)
        return

    if await scan_archive_flow(file_name, file_bytes, status_msg):
        return

    result_lines = await scan_one_file(file_bytes, file_name)
    result_lines.append(config.DONE)
    await status_msg.edit_text("\n\n".join(result_lines))


async def handle_one(client, msg) -> None:
    text = msg.text or msg.caption or ""
    url = find_url(text)
    status_msg = await msg.reply_text(config.WAIT)

    if url:
        await scan_url_flow(url, status_msg)
        return

    if get_file_info(msg):
        await scan_file_flow(client, msg, status_msg)
        return

    if msg.chat.type == ChatType.PRIVATE:
        await status_msg.edit_text(config.ERR_EMPTY_PRIVATE)
    else:
        await status_msg.edit_text(config.ERR_EMPTY_GROUP)


async def worker(client, worker_num: int) -> None:
    while True:
        job = await queue.get()
        try:
            msg = await client.get_messages(job.chat_id, job.msg_id)
            await handle_one(client, msg)
        except Exception as err:
            config.log.exception("worker %s: %s", worker_num, err)
        finally:
            queue.task_done()



def start_workers(client) -> None:
    global workers_started

    if workers_started:
        return

    workers_started = True

    for i in range(max(1, int(config.app.workers))):
        asyncio.create_task(worker(client, i + 1))


async def enqueue(client, msg) -> None:
    await queue.put(Job(chat_id=msg.chat.id, msg_id=msg.id))
    await msg.reply_text(config.QUEUED)
