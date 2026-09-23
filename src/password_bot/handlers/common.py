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
from password_bot.telegram_utils.keyboards import main_menu_keyboard
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
        # Re-entry after an autolock: make sure the passphrase can't land in a stale flow.
        fsm.lock()
        fsm.reset_to(UNLOCK_SCREEN)
        await update.message.reply_text(
            escape_md(MESSAGES["ask_passphrase"]),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return 0
    fsm.reset_to(MENU_SCREEN)
    await _send_menu(update.effective_chat)
    return 0


async def cmd_stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    _fsm(context).clear_session()
    context.chat_data.clear()  # type: ignore[union-attr]
    await update.message.reply_text("👋 A presto.")
    from telegram.ext import ConversationHandler

    return ConversationHandler.END


async def cmd_lock(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    _fsm(context).lock()
    await update.effective_chat.send_message(
        escape_md(MESSAGES["session_locked"]),
        parse_mode=ParseMode.MARKDOWN_V2,
    )


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    _fsm(context).clear_pending_input()
    await update.effective_chat.send_message("Annullato.")


async def cmd_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    fsm = _fsm(context)
    fsm.reset_to(MENU_SCREEN)
    await _send_menu(update.effective_chat)


async def _send_menu(chat) -> None:
    await chat.send_message(
        _menu_body(), parse_mode=ParseMode.MARKDOWN_V2, reply_markup=main_menu_keyboard()
    )


_QUICK_COMMANDS: tuple[tuple[str, str], ...] = (
    ("/add", "crea un nuovo account"),
    ("/list", "mostra tutti gli account"),
    ("/get NOME", "cerca account per nome"),
    ("/copy NOME", "copia password di un account"),
    ("/list_stale", "password non aggiornate"),
    ("/list_reused", "password riutilizzate"),
    ("/categories", "gestisci categorie"),
    ("/export", "esporta vault cifrato"),
    ("/import", "importa vault cifrato"),
    ("/settings", "impostazioni vault"),
    ("/lock", "blocca la sessione"),
    ("/help", "elenco comandi"),
)


def _menu_body() -> str:
    lines = [
        MESSAGES["menu_title"],
        escape_md("Scegli un'azione dai bottoni, oppure usa i comandi rapidi:"),
        "",
    ]
    lines.extend(f"{escape_md(cmd)} — {escape_md(desc)}" for cmd, desc in _QUICK_COMMANDS)
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
    from password_bot.telegram_utils.keyboards import back_menu_keyboard

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
    await update.effective_chat.send_message(text, reply_markup=back_menu_keyboard(show_menu=True))


async def on_menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    action = q.data.split(":", 1)[1]

    fsm = _fsm(context)
    if fsm.get_session() is None:
        await update.effective_chat.send_message(MESSAGES["session_locked"])
        return

    from password_bot.handlers import categories, export, inline_cmd
    from password_bot.handlers import settings as settings_h
    from password_bot.handlers.account_new import start_new_account
    from password_bot.state.keys import ChatDataKey

    chat_data = context.chat_data  # type: ignore[assignment]
    if action == "add":
        await start_new_account(update, context)
    elif action == "list":
        await inline_cmd.cmd_list(update, context)
    elif action == "search":
        chat_data[ChatDataKey.PENDING_INPUT.value] = {"field": "_search_query"}
        await update.effective_chat.send_message(
            "🔍 Scrivi il nome (o parte) dell'account da cercare. /cancel per annullare."
        )
    elif action == "copy":
        chat_data[ChatDataKey.PENDING_INPUT.value] = {"field": "_copy_query"}
        await update.effective_chat.send_message(
            "📋 Scrivi il nome dell'account da copiare. /cancel per annullare."
        )
    elif action == "stale":
        await inline_cmd.cmd_list_stale(update, context)
    elif action == "reused":
        await inline_cmd.cmd_list_reused(update, context)
    elif action == "categories":
        await categories.cmd_categories(update, context)
    elif action == "settings":
        await settings_h.cmd_settings(update, context)
    elif action == "export":
        await export.cmd_export(update, context)
    elif action == "import":
        await export.cmd_import(update, context)
    elif action == "lock":
        await cmd_lock(update, context)
    elif action == "help":
        await cmd_help(update, context)


async def cmd_back(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    fsm = _fsm(context)
    fsm.pop()
    if fsm.depth() == 0:
        fsm.reset_to(MENU_SCREEN)
    await _send_menu(update.effective_chat)
