import asyncio
import sys

from pyrogram import Client, filters, idle
from pyrogram.enums import ChatType

import config
from handlers import can_enqueue, enqueue, start_workers

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


app = Client(
    "bot_session",
    api_id=config.app.api_id,
    api_hash=config.app.api_hash,
    bot_token=config.app.bot_token,
)


@app.on_message(filters.command("start") & filters.private)
async def start_cmd(_, msg):
    await msg.reply_text(config.TEXT_START, parse_mode=None)


@app.on_message(filters.command("help") & filters.private)
async def help_cmd(_, msg):
    await msg.reply_text(config.TEXT_HELP, parse_mode=None)


@app.on_message(filters.command("addbot") & filters.private)
async def addbot_cmd(_, msg):
    await msg.reply_text(config.TEXT_ADDBOT, parse_mode=None)


@app.on_message(filters.command("mhelp"))
async def mhelp_cmd(_, msg):
    if msg.chat.type == ChatType.PRIVATE:
        await msg.reply_text(config.ERR_PRIVATE, parse_mode=None)
        return
    await msg.reply_text(config.TEXT_MHELP, parse_mode=None)


@app.on_message(filters.command("scan"))
async def scan_cmd(client, msg):
    if msg.chat.type == ChatType.PRIVATE:
        await msg.reply_text(config.ERR_GROUP, parse_mode=None)
        return

    if not msg.reply_to_message:
        await msg.reply_text(config.ERR_REPLY, parse_mode=None)
        return

    target = msg.reply_to_message
    if can_enqueue(target):
        await enqueue(client, target)
    else:
        await msg.reply_text(config.ERR_EMPTY_GROUP, parse_mode=None)


@app.on_message(filters.private & ~filters.command(["start", "help", "addbot"]))
async def private_inbox(client, msg):
    if can_enqueue(msg):
        await enqueue(client, msg)
    else:
        await msg.reply_text(config.ERR_EMPTY_PRIVATE, parse_mode=None)


async def run() -> None:
    await app.start()
    start_workers(app)
    await idle()
    await app.stop()


if __name__ == "__main__":
    app.run(run())
