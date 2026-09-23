"""Global error handler."""

from __future__ import annotations

import contextlib
import html
import logging
import traceback

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.ui.navigator import Navigator

log = logging.getLogger(__name__)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("Unhandled exception in handler", exc_info=context.error)
    container = context.application.bot_data.get("container")
    dev_id = getattr(container, "dev_chat_id", None)
    if dev_id is not None:
        tb = "".join(
            traceback.format_exception(
                type(context.error), context.error, context.error.__traceback__
            )
        )
        try:
            await context.bot.send_message(
                chat_id=dev_id,
                text=f"<pre>{html.escape(tb[:3500])}</pre>",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            log.exception("Failed to DM dev about prior error")
    if (
        isinstance(update, Update)
        and update.effective_chat is not None
        and context.chat_data is not None
        and "screens" in context.application.bot_data
    ):
        with contextlib.suppress(Exception):
            await Navigator.from_context(context, update.effective_chat.id).show_error()
