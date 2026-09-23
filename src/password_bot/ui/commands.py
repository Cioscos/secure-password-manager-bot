"""PTB handler functions. Every entry point delegates to the Navigator."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from telegram import Update
from telegram.ext import ContextTypes, ConversationHandler

from password_bot.ui.navigator import HOME, Navigator
from password_bot.ui.screen import back

ROOT_STATE = 0

Handler = Callable[[Update, ContextTypes.DEFAULT_TYPE], Awaitable[Any]]


def _nav(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Navigator:
    return Navigator.from_update(update, context)


def open_command(screen: str, **args: Any) -> Handler:
    """Handler for a slash command that opens `screen` in a new live message."""

    async def handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await _nav(update, context).command(screen, args or None)

    handler.__name__ = f"cmd_{screen}"
    return handler


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await _nav(update, context).command(HOME)
    return ROOT_STATE


async def cmd_get(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    nav = _nav(update, context)
    query = " ".join(context.args or []).strip()
    if not query:
        await nav.command("search")
        return
    results = await nav.container.accounts.search(nav.chat_id, query)
    if len(results) == 1:
        await nav.command("account_detail", {"id": results[0][0].id})
    else:
        await nav.command("search", {"q": query})


async def cmd_back(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _nav(update, context).apply(back())


async def cmd_lock(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _nav(update, context).lock()


async def cmd_stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await _nav(update, context).stop()
    await update.effective_chat.send_message("👋 A presto. /start per ricominciare.")
    return ConversationHandler.END


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _nav(update, context).on_callback(update)


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _nav(update, context).on_text(update)


async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _nav(update, context).on_document(update)
