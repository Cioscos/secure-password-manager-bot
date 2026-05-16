"""Bypass-menu inline commands: /get, /add, /copy, /list, /list_stale, /list_reused."""

from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.handlers.account_new import start_new_account
from password_bot.handlers.account_view import render as render_account
from password_bot.i18n.it import MESSAGES
from password_bot.state.fsm import FsmContext
from password_bot.telegram_utils.delete_message import schedule_delete
from password_bot.telegram_utils.md import code_inline, escape_md


def _require_session(context: ContextTypes.DEFAULT_TYPE):
    return FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]


async def cmd_get(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    args = " ".join(context.args or []).strip()
    if not args:
        await update.message.reply_text("Uso: /get nome")
        return
    container: Container = context.application.bot_data["container"]
    results = await container.accounts.search(update.effective_chat.id, args)
    if not results:
        await update.message.reply_text("Nessun risultato.")
        return
    if len(results) == 1:
        await render_account(update, context, results[0][0].id)
        return
    lines = ["Più risultati:"]
    for row, score in results[:10]:
        lines.append(f"- {row.name} ({score}%) → /get {row.name}")
    await update.message.reply_text("\n".join(lines))


async def cmd_add(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    await start_new_account(update, context)


async def cmd_copy(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    session = _require_session(context)
    if session is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    args = " ".join(context.args or []).strip()
    if not args:
        await update.message.reply_text("Uso: /copy nome")
        return
    container: Container = context.application.bot_data["container"]
    results = await container.accounts.search(update.effective_chat.id, args)
    if not results:
        await update.message.reply_text("Nessun risultato.")
        return
    row, _ = results[0]
    acc = await container.vault.get_decrypted(row.id, aes_key=session.aes_key)
    if acc is None:
        await update.message.reply_text(MESSAGES["account_not_found"])
        return
    msg = await update.effective_chat.send_message(
        code_inline(acc.password), parse_mode=ParseMode.MARKDOWN_V2
    )
    schedule_delete(
        context.application,
        chat_id=update.effective_chat.id,
        message_id=msg.message_id,
        delay_seconds=30,
    )


async def cmd_list(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    container: Container = context.application.bot_data["container"]
    rows = await container.accounts.list_for_chat(update.effective_chat.id)
    if not rows:
        await update.message.reply_text("Vault vuoto.")
        return
    lines = ["📚 *Account*"]
    for r in rows:
        lines.append(f"- {escape_md(r.name)}")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN_V2)


async def cmd_list_stale(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    container: Container = context.application.bot_data["container"]
    stale = await container.alerts.find_stale(chat_id=update.effective_chat.id)
    if not stale:
        await update.message.reply_text("Nessuna password vecchia. 🎉")
        return
    lines = ["⚠️ *Password vecchie*"]
    for r in stale:
        lines.append(f"- {escape_md(r.name)} → /get {escape_md(r.name)}")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN_V2)


async def cmd_list_reused(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    session = _require_session(context)
    if session is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    container: Container = context.application.bot_data["container"]
    detector = container.chat_reuse_detector(context)
    clusters = detector.all_clusters(min_size=2)
    if not clusters:
        await update.message.reply_text("Nessuna password riusata. 🎉")
        return
    lines = ["⚠️ *Password riusate*"]
    for cluster in clusters:
        names = ", ".join(escape_md(name) for _, name in cluster)
        lines.append(f"- {names}")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN_V2)
