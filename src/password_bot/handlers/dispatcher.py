"""Text-message dispatcher. Routes to the right sub-handler based on FSM state."""

from __future__ import annotations

import contextlib
import logging

from telegram import Update
from telegram.ext import ContextTypes

from password_bot.handlers import (
    account_edit,
    account_new,
    auth,
    categories,
    export,
    inline_cmd,
    password_gen,
)
from password_bot.state.fsm import FsmContext
from password_bot.state.keys import ChatDataKey

log = logging.getLogger(__name__)


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    fsm = FsmContext(context.chat_data)  # type: ignore[arg-type]
    pending = fsm.get_pending_input()
    log.info(
        "dispatcher.on_text chat_id=%s pending=%s session=%s",
        update.effective_chat.id if update.effective_chat else None,
        pending["field"] if pending else None,
        fsm.get_session() is not None,
    )
    if fsm.get_session() is None:
        # Locked: any text is a passphrase. Drop leftover flows so it can't be
        # captured (and left undeleted) by a search, edit or other pending input.
        fsm.lock()
        await auth.handle_passphrase_message(update, context)
        return
    if pending is not None:
        if pending["field"] == "_export_passphrase":
            text = update.message.text or ""
            with contextlib.suppress(Exception):
                await update.message.delete()
            fsm.clear_pending_input()
            await export.handle_export_passphrase(update, context, text)
            return
        if pending["field"] == "_import_passphrase":
            text = update.message.text or ""
            with contextlib.suppress(Exception):
                await update.message.delete()
            fsm.clear_pending_input()
            await export.handle_import_passphrase(update, context, text)
            return
        if pending["field"] == "_cat_new_name":
            await categories.handle_pending_name(update, context)
            return
        if pending["field"] == "_pwgen_length":
            await password_gen.handle_pending_length(update, context)
            return
        if pending["field"] == "_search_query":
            query = (update.message.text or "").strip()
            fsm.clear_pending_input()
            context.args = query.split()  # type: ignore[attr-defined]
            await inline_cmd.cmd_get(update, context)
            return
        if pending["field"] == "_copy_query":
            query = (update.message.text or "").strip()
            fsm.clear_pending_input()
            context.args = query.split()  # type: ignore[attr-defined]
            await inline_cmd.cmd_copy(update, context)
            return
        if await account_edit.handle_pending(update, context):
            return
    # Otherwise we're inside the account_new flow.
    if ChatDataKey.PENDING_NEW_ACCOUNT.value in context.chat_data:  # type: ignore[operator]
        await account_new.receive_text(update, context)
        return
    # Fallback: tell user to /menu.
    await update.message.reply_text("Non ho capito. /menu per il menu.")
