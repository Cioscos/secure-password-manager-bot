"""/settings handler for autolock minutes and alert threshold."""

from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.state.fsm import FsmContext


def _settings_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("⏰ Autolock", callback_data="set:autolock")],
            [InlineKeyboardButton("⚠️ Soglia password vecchie", callback_data="set:alert")],
            [InlineKeyboardButton("🔙", callback_data="nav:back")],
        ]
    )


async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if FsmContext(context.chat_data).get_session() is None:  # type: ignore[arg-type]
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    await update.message.reply_text("⚙️ Impostazioni", reply_markup=_settings_keyboard())


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    container: Container = context.application.bot_data["container"]
    q = update.callback_query
    await q.answer()
    parts = q.data.split(":")
    if parts[1] == "autolock":
        rows = [
            [InlineKeyboardButton(f"{m} min", callback_data=f"set:autolock:{m}")]
            for m in (0, 5, 15, 30, 60)
        ]
        await q.edit_message_text("Durata autolock?", reply_markup=InlineKeyboardMarkup(rows))
    elif parts[1] == "autolock" and len(parts) == 3:
        minutes = int(parts[2])
        await container.users.update_autolock(
            update.effective_chat.id, minutes=minutes, reset_on_activity=True
        )
        await q.edit_message_text(f"Autolock impostato a {minutes} min.")
    elif parts[1] == "alert":
        rows = [
            [InlineKeyboardButton(f"{d} giorni", callback_data=f"set:alert:{d}")]
            for d in (90, 180, 365, 0)
        ]
        await q.edit_message_text(
            "Soglia per password vecchie?", reply_markup=InlineKeyboardMarkup(rows)
        )
    elif parts[1] == "alert" and len(parts) == 3:
        days = int(parts[2])
        await container.users.update_alert_days(update.effective_chat.id, days)
        await q.edit_message_text(f"Soglia impostata a {days} giorni.")
