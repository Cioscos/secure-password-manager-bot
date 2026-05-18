"""Receive plain-text input for a pending field edit."""

from __future__ import annotations

import contextlib

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.services.vault_service import UpdatedFields
from password_bot.state.fsm import FsmContext
from password_bot.telegram_utils.md import escape_md


async def handle_pending(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Returns True if the message was consumed by an edit pending."""
    fsm = FsmContext(context.chat_data)  # type: ignore[arg-type]
    pending = fsm.get_pending_input()
    if pending is None:
        return False
    text = (update.message.text or "").strip()
    if pending["field"] == "_delete_confirm":
        if text == MESSAGES["delete_confirm_word"]:
            container: Container = context.application.bot_data["container"]
            await container.vault.delete(pending["id"])
            await update.message.reply_text(MESSAGES["account_deleted"])
        else:
            await update.message.reply_text("Eliminazione annullata.")
        fsm.clear_pending_input()
        return True

    container = context.application.bot_data["container"]
    session = fsm.get_session()
    if session is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return True
    field = pending["field"]
    account_id = pending["id"]
    if field == "password":
        await container.vault.update_password(
            account_id, text, aes_key=session.aes_key, hmac_key=session.hmac_key
        )
    elif field in ("username", "url", "note"):
        await container.vault.update_fields(
            account_id, UpdatedFields(**{field: text}), aes_key=session.aes_key
        )
    elif field == "name":
        await container.vault.update_fields(
            account_id, UpdatedFields(name=text), aes_key=session.aes_key
        )
    fsm.clear_pending_input()
    with contextlib.suppress(Exception):
        await update.message.delete()
    await update.effective_chat.send_message(
        escape_md(MESSAGES["field_updated"]),
        parse_mode=ParseMode.MARKDOWN_V2,
    )
    return True
