"""Nav callback handler for `nav:back` and `nav:menu`."""

from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from password_bot.handlers.common import MENU_SCREEN
from password_bot.i18n.it import MESSAGES
from password_bot.state.fsm import FsmContext


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    parts = q.data.split(":", 1)
    action = parts[1] if len(parts) > 1 else ""
    fsm = FsmContext(context.chat_data)  # type: ignore[arg-type]
    if action == "back":
        fsm.pop()
        if fsm.depth() == 0:
            fsm.reset_to(MENU_SCREEN)
        await q.edit_message_text("🔙")
    elif action == "menu":
        fsm.reset_to(MENU_SCREEN)
        await q.edit_message_text(MESSAGES["menu_title"])
