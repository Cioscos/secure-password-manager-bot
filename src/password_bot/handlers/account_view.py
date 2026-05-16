"""Account view screen with per-field action buttons."""

from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.state.fsm import FsmContext
from password_bot.telegram_utils.delete_message import schedule_delete
from password_bot.telegram_utils.md import code_inline, escape_md


def _mask(value: str | None) -> str:
    if value is None:
        return "—"
    return "•" * min(len(value), 8)


async def render(update: Update, context: ContextTypes.DEFAULT_TYPE, account_id: str) -> None:
    container: Container = context.application.bot_data["container"]
    session = FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]
    if session is None:
        await update.effective_chat.send_message(MESSAGES["session_locked"])
        return
    acc = await container.vault.get_decrypted(account_id, aes_key=session.aes_key)
    if acc is None:
        await update.effective_chat.send_message(MESSAGES["account_not_found"])
        return

    text_lines = [
        f"🔐 *{escape_md(acc.name)}*",
        f"👤 username: {escape_md(acc.username or '—')}",
        f"🔑 password: {escape_md(_mask(acc.password))}",
        f"🌐 url: {escape_md(acc.url or '—')}",
        f"📝 note: {escape_md('presenti' if acc.note else '—')}",
    ]
    import time

    age_days = (int(time.time()) - acc.password_changed_at) // 86400
    text_lines.append(f"📅 password vecchia di {age_days} giorni")
    text = "\n".join(text_lines)

    rows = [
        [
            InlineKeyboardButton("👁 password", callback_data=f"view:show:password:{acc.id}"),
            InlineKeyboardButton("✏️", callback_data=f"view:edit:password:{acc.id}"),
            InlineKeyboardButton("📋", callback_data=f"view:copy:password:{acc.id}"),
        ],
        [
            InlineKeyboardButton("✏️ username", callback_data=f"view:edit:username:{acc.id}"),
            InlineKeyboardButton("✏️ url", callback_data=f"view:edit:url:{acc.id}"),
        ],
        [
            InlineKeyboardButton("✏️ note", callback_data=f"view:edit:note:{acc.id}"),
            InlineKeyboardButton("👁 note", callback_data=f"view:show:note:{acc.id}"),
        ],
        [
            InlineKeyboardButton("🔁 Duplica", callback_data=f"view:dup:{acc.id}"),
            InlineKeyboardButton("🗑 Elimina", callback_data=f"view:del:{acc.id}"),
        ],
        [
            InlineKeyboardButton("🔙 Indietro", callback_data="nav:back"),
            InlineKeyboardButton("🏠 Menu", callback_data="nav:menu"),
        ],
    ]
    await update.effective_chat.send_message(
        text,
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=InlineKeyboardMarkup(rows),
    )


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    container: Container = context.application.bot_data["container"]
    q = update.callback_query
    await q.answer()
    parts = q.data.split(":")
    action = parts[1]
    session = FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]
    if session is None:
        await q.edit_message_text(MESSAGES["session_locked"])
        return

    if action == "show":
        field, account_id = parts[2], parts[3]
        acc = await container.vault.get_decrypted(account_id, aes_key=session.aes_key)
        if acc is None:
            return
        value = getattr(acc, field)
        msg = await update.effective_chat.send_message(
            code_inline(value or ""), parse_mode=ParseMode.MARKDOWN_V2
        )
        schedule_delete(
            context.application,
            chat_id=update.effective_chat.id,
            message_id=msg.message_id,
            delay_seconds=30,
        )

    elif action == "copy":
        field, account_id = parts[2], parts[3]
        acc = await container.vault.get_decrypted(account_id, aes_key=session.aes_key)
        if acc is None:
            return
        value = getattr(acc, field) or ""
        msg = await update.effective_chat.send_message(
            code_inline(value), parse_mode=ParseMode.MARKDOWN_V2
        )
        schedule_delete(
            context.application,
            chat_id=update.effective_chat.id,
            message_id=msg.message_id,
            delay_seconds=30,
        )

    elif action == "edit":
        field, account_id = parts[2], parts[3]
        acc = await container.vault.get_decrypted(account_id, aes_key=session.aes_key)
        FsmContext(context.chat_data).set_pending_input(
            {  # type: ignore[arg-type]
                "field": field,
                "id": account_id,
            }
        )
        old = getattr(acc, field) if acc else None
        old_view = f" (vecchio: {code_inline(old)})" if old and field != "password" else ""
        await update.effective_chat.send_message(
            f"Nuovo {field}? /cancel per annullare.{old_view}",
            parse_mode=ParseMode.MARKDOWN_V2,
        )

    elif action == "dup":
        account_id = parts[2]
        await container.vault.duplicate(
            account_id, aes_key=session.aes_key, hmac_key=session.hmac_key
        )
        await update.effective_chat.send_message("📋 Duplicato.")

    elif action == "del":
        account_id = parts[2]
        FsmContext(context.chat_data).set_pending_input(
            {  # type: ignore[arg-type]
                "field": "_delete_confirm",
                "id": account_id,
            }
        )
        await update.effective_chat.send_message(
            escape_md(MESSAGES["delete_confirm_prompt"]),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
