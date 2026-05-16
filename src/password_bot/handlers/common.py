"""Global commands: /start, /help, /stop, /lock, /cancel, /menu, /back. Plus error handler."""

from __future__ import annotations

import contextlib
import html
import logging
import traceback

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.state.fsm import FsmContext, Screen
from password_bot.telegram_utils.md import escape_md

log = logging.getLogger(__name__)

MENU_SCREEN = Screen(name="menu", data={})
UNLOCK_SCREEN = Screen(name="unlock", data={})


def _fsm(context: ContextTypes.DEFAULT_TYPE) -> FsmContext:
    return FsmContext(context.chat_data)  # type: ignore[arg-type]


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    fsm = _fsm(context)
    container: Container = context.application.bot_data["container"]
    user = await container.users.get(update.effective_chat.id)
    if user is None:
        fsm.reset_to(Screen(name="setup_passphrase", data={}))
        await update.message.reply_text(
            escape_md(MESSAGES["passphrase_setup_first"]),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return 0
    if fsm.get_session() is None:
        fsm.reset_to(UNLOCK_SCREEN)
        await update.message.reply_text(
            escape_md(MESSAGES["ask_passphrase"]),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return 0
    fsm.reset_to(MENU_SCREEN)
    await update.message.reply_text(_menu_body(), parse_mode=ParseMode.MARKDOWN_V2)
    return 0


async def cmd_stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    _fsm(context).clear_session()
    context.chat_data.clear()  # type: ignore[union-attr]
    await update.message.reply_text("👋 A presto.")
    from telegram.ext import ConversationHandler

    return ConversationHandler.END


async def cmd_lock(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    _fsm(context).clear_session()
    await update.message.reply_text(
        escape_md(MESSAGES["session_locked"]),
        parse_mode=ParseMode.MARKDOWN_V2,
    )


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    _fsm(context).clear_pending_input()
    await update.message.reply_text("Annullato.")


async def cmd_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    fsm = _fsm(context)
    fsm.reset_to(MENU_SCREEN)
    await update.effective_chat.send_message(_menu_body(), parse_mode=ParseMode.MARKDOWN_V2)


def _menu_body() -> str:
    lines = [
        MESSAGES["menu_title"],
        "",
        escape_md("Comandi disponibili:"),
        escape_md("• /add — nuovo account"),
        escape_md("• /list — elenca account"),
        escape_md("• /get NOME — cerca account"),
        escape_md("• /copy NOME — copia password"),
        escape_md("• /list_stale — password vecchie"),
        escape_md("• /list_reused — password riusate"),
        escape_md("• /categories — gestisci categorie"),
        escape_md("• /export — esporta vault"),
        escape_md("• /import — importa vault"),
        escape_md("• /settings — impostazioni"),
        escape_md("• /lock — blocca sessione"),
        escape_md("• /help — guida completa"),
    ]
    return "\n".join(lines)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("Unhandled exception in handler", exc_info=context.error)
    container: Container | None = context.application.bot_data.get("container")
    if container is None:
        return
    dev_id = container.dev_chat_id
    if dev_id is None:
        return
    tb = "".join(
        traceback.format_exception(type(context.error), context.error, context.error.__traceback__)
    )
    redacted = html.escape(tb[:3500])
    try:
        await context.bot.send_message(
            chat_id=dev_id,
            text=f"<pre>{redacted}</pre>",
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        log.exception("Failed to DM dev about prior error")
    if isinstance(update, Update) and update.effective_chat is not None:
        with contextlib.suppress(Exception):
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=escape_md(MESSAGES["error_internal"]),
                parse_mode=ParseMode.MARKDOWN_V2,
            )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "Comandi disponibili:\n"
        "/start — apre il bot\n"
        "/menu — menu principale\n"
        "/lock — blocca sessione\n"
        "/stop — esce dalla conversazione\n"
        "/cancel — annulla input corrente\n"
        "/back — torna indietro\n"
        "/add — nuovo account\n"
        "/get NAME — cerca account\n"
        "/copy NAME — copia password\n"
        "/list — elenca account\n"
        "/list_stale — password vecchie\n"
        "/list_reused — password riusate\n"
        "/categories — gestisci categorie\n"
        "/export — esporta vault\n"
        "/import — importa vault\n"
        "/settings — impostazioni"
    )
    await update.message.reply_text(text)


async def cmd_back(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    fsm = _fsm(context)
    fsm.pop()
    if fsm.depth() == 0:
        fsm.reset_to(MENU_SCREEN)
    await update.message.reply_text("🔙")
