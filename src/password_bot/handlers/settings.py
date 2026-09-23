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
            [InlineKeyboardButton("🎲 Generatore password", callback_data="set:pwgen")],
            [InlineKeyboardButton("🏠 Menu", callback_data="nav:menu")],
        ]
    )


async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if FsmContext(context.chat_data).get_session() is None:  # type: ignore[arg-type]
        await update.effective_chat.send_message(MESSAGES["session_locked"])
        return
    await update.effective_chat.send_message("⚙️ Impostazioni", reply_markup=_settings_keyboard())


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    container: Container = context.application.bot_data["container"]
    q = update.callback_query
    await q.answer()
    parts = q.data.split(":")
    section = parts[1]
    has_value = len(parts) == 3

    if section == "autolock" and has_value:
        minutes = int(parts[2])
        await container.users.update_autolock(
            update.effective_chat.id, minutes=minutes, reset_on_activity=True
        )
        await q.edit_message_text(
            f"✅ Autolock impostato a {minutes} min.\n\n⚙️ Impostazioni",
            reply_markup=_settings_keyboard(),
        )
    elif section == "autolock":
        rows = [
            [InlineKeyboardButton(f"{m} min", callback_data=f"set:autolock:{m}")]
            for m in (0, 5, 15, 30, 60)
        ]
        rows.append([InlineKeyboardButton("🔙 Indietro", callback_data="set:open")])
        await q.edit_message_text("Durata autolock?", reply_markup=InlineKeyboardMarkup(rows))
    elif section == "alert" and has_value:
        days = int(parts[2])
        await container.users.update_alert_days(update.effective_chat.id, days)
        await q.edit_message_text(
            f"✅ Soglia impostata a {days} giorni.\n\n⚙️ Impostazioni",
            reply_markup=_settings_keyboard(),
        )
    elif section == "alert":
        rows = [
            [InlineKeyboardButton(f"{d} giorni", callback_data=f"set:alert:{d}")]
            for d in (90, 180, 365, 0)
        ]
        rows.append([InlineKeyboardButton("🔙 Indietro", callback_data="set:open")])
        await q.edit_message_text(
            "Soglia per password vecchie?", reply_markup=InlineKeyboardMarkup(rows)
        )
    elif section == "pwgen":
        from password_bot.handlers import password_gen

        await password_gen.show_options_from_callback(update, context, return_to="settings")
    elif section == "open":
        await q.edit_message_text("⚙️ Impostazioni", reply_markup=_settings_keyboard())
