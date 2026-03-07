import asyncio
import sys

from pyrogram import Client, filters, idle
from pyrogram.enums import ChatType

import settings
from services import can_enqueue, enqueue, start_workers

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

settings.check_env()

app = Client(
    "bot_session",
    api_id=settings.app.api_id,
    api_hash=settings.app.api_hash,
    bot_token=settings.app.bot_token,
)


@app.on_message(filters.command("start") & filters.private)
async def start(_, msg):
    await msg.reply_text(settings.TEXT_START)


@app.on_message(filters.command("help") & filters.private)
async def help_cmd(_, msg):
    await msg.reply_text(settings.TEXT_HELP)


@app.on_message(filters.command("addbot") & filters.private)
async def addbot(_, msg):
    await msg.reply_text(settings.TEXT_ADDBOT)


@app.on_message(filters.command("mhelp"))
async def mhelp(_, msg):
    if msg.chat.type == ChatType.PRIVATE:
        await msg.reply_text(settings.ERR_PRIVATE)
        return
    await msg.reply_text(settings.TEXT_MHELP)


@app.on_message(filters.command("scan"))
async def scan(client, msg):
    if msg.chat.type == ChatType.PRIVATE:
        await msg.reply_text(settings.ERR_GROUP)
        return

    if not msg.reply_to_message:
        await msg.reply_text(settings.ERR_REPLY)
        return

    target = msg.reply_to_message
    if can_enqueue(target):
        await enqueue(client, target)
    else:
        await msg.reply_text(settings.ERR_EMPTY_GROUP)


@app.on_message(filters.private & ~filters.command(["start", "help", "addbot"]))
async def inbox(client, msg):
    if can_enqueue(msg):
        await enqueue(client, msg)
    else:
        await msg.reply_text(settings.ERR_EMPTY_PRIVATE)


async def main() -> None:
    await app.start()
    start_workers(app)
    await idle()
    await app.stop()


if __name__ == "__main__":
    app.run(main())
