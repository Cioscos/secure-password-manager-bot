"""Nav callback handler for `nav:back` and `nav:menu`."""

from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.handlers.common import MENU_SCREEN, _menu_body
from password_bot.state.fsm import FsmContext
from password_bot.telegram_utils.keyboards import main_menu_keyboard


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
        await update.effective_chat.send_message(
            _menu_body(), parse_mode=ParseMode.MARKDOWN_V2, reply_markup=main_menu_keyboard()
        )
    elif action == "menu":
        fsm.reset_to(MENU_SCREEN)
        await update.effective_chat.send_message(
            _menu_body(), parse_mode=ParseMode.MARKDOWN_V2, reply_markup=main_menu_keyboard()
        )
