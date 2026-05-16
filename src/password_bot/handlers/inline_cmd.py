"""Bypass-menu inline commands: /get, /add, /copy, /list, /list_stale, /list_reused."""

from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.error import BadRequest
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.handlers.account_new import start_new_account
from password_bot.handlers.account_view import render as render_account
from password_bot.i18n.it import MESSAGES
from password_bot.state.fsm import FsmContext
from password_bot.telegram_utils.callback_data import ListPageData
from password_bot.telegram_utils.delete_message import schedule_delete
from password_bot.telegram_utils.keyboards import (
    ACCOUNTS_PAGE_SIZE,
    accounts_page_keyboard,
    back_menu_keyboard,
)
from password_bot.telegram_utils.md import code_inline, escape_md


def _require_session(context: ContextTypes.DEFAULT_TYPE):
    return FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]


async def on_account_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    parts = q.data.split(":")
    if parts[1] == "open":
        account_id = parts[2]
        await render_account(update, context, account_id)


async def cmd_get(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.effective_chat.send_message(MESSAGES["session_locked"])
        return
    args = " ".join(context.args or []).strip()
    if not args:
        await update.effective_chat.send_message(
            "Uso: /get nome", reply_markup=back_menu_keyboard(show_menu=True)
        )
        return
    container: Container = context.application.bot_data["container"]
    results = await container.accounts.search(update.effective_chat.id, args)
    if not results:
        await update.effective_chat.send_message(
            "Nessun risultato.", reply_markup=back_menu_keyboard(show_menu=True)
        )
        return
    if len(results) == 1:
        await render_account(update, context, results[0][0].id)
        return
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup

    rows = [
        [InlineKeyboardButton(f"{row.name} ({score}%)", callback_data=f"acc:open:{row.id}")]
        for row, score in results[:10]
    ]
    rows.append([InlineKeyboardButton("🏠 Menu", callback_data="nav:menu")])
    await update.effective_chat.send_message(
        "Più risultati:", reply_markup=InlineKeyboardMarkup(rows)
    )


async def cmd_add(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.effective_chat.send_message(MESSAGES["session_locked"])
        return
    await start_new_account(update, context)


async def cmd_copy(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    session = _require_session(context)
    if session is None:
        await update.effective_chat.send_message(MESSAGES["session_locked"])
        return
    args = " ".join(context.args or []).strip()
    if not args:
        await update.effective_chat.send_message(
            "Uso: /copy nome", reply_markup=back_menu_keyboard(show_menu=True)
        )
        return
    container: Container = context.application.bot_data["container"]
    results = await container.accounts.search(update.effective_chat.id, args)
    if not results:
        await update.effective_chat.send_message(
            "Nessun risultato.", reply_markup=back_menu_keyboard(show_menu=True)
        )
        return
    row, _ = results[0]
    acc = await container.vault.get_decrypted(row.id, aes_key=session.aes_key)
    if acc is None:
        await update.effective_chat.send_message(MESSAGES["account_not_found"])
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


def _list_page_text(total: int, page: int) -> str:
    total_pages = max(1, (total + ACCOUNTS_PAGE_SIZE - 1) // ACCOUNTS_PAGE_SIZE)
    page = max(0, min(page, total_pages - 1))
    return escape_md(MESSAGES["list_title"].format(cur=page + 1, tot=total_pages))


async def cmd_list(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.effective_chat.send_message(MESSAGES["session_locked"])
        return
    container: Container = context.application.bot_data["container"]
    rows = await container.accounts.list_for_chat(update.effective_chat.id)
    if not rows:
        await update.effective_chat.send_message(
            MESSAGES["list_empty"], reply_markup=back_menu_keyboard(show_menu=True)
        )
        return
    await update.effective_chat.send_message(
        _list_page_text(len(rows), 0),
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=accounts_page_keyboard(rows, page=0),
    )


async def on_list_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    if _require_session(context) is None:
        await update.effective_chat.send_message(MESSAGES["session_locked"])
        return
    data = q.data
    if not isinstance(data, ListPageData):
        return
    container: Container = context.application.bot_data["container"]
    rows = await container.accounts.list_for_chat(update.effective_chat.id)
    if not rows:
        await q.edit_message_text(
            MESSAGES["list_empty"], reply_markup=back_menu_keyboard(show_menu=True)
        )
        return
    try:
        await q.edit_message_text(
            _list_page_text(len(rows), data.page),
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=accounts_page_keyboard(rows, page=data.page),
        )
    except BadRequest as e:
        if "not modified" not in str(e).lower():
            raise


async def cmd_list_stale(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.effective_chat.send_message(MESSAGES["session_locked"])
        return
    container: Container = context.application.bot_data["container"]
    stale = await container.alerts.find_stale(chat_id=update.effective_chat.id)
    if not stale:
        await update.effective_chat.send_message(
            "Nessuna password vecchia. 🎉", reply_markup=back_menu_keyboard(show_menu=True)
        )
        return
    lines = ["⚠️ *Password vecchie*"]
    for r in stale:
        lines.append(f"• {escape_md(r.name)} → /get {escape_md(r.name)}")
    await update.effective_chat.send_message(
        "\n".join(lines),
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=back_menu_keyboard(show_menu=True),
    )


async def cmd_list_reused(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    session = _require_session(context)
    if session is None:
        await update.effective_chat.send_message(MESSAGES["session_locked"])
        return
    container: Container = context.application.bot_data["container"]
    detector = container.chat_reuse_detector(context)
    clusters = detector.all_clusters(min_size=2)
    if not clusters:
        await update.effective_chat.send_message(
            "Nessuna password riusata. 🎉", reply_markup=back_menu_keyboard(show_menu=True)
        )
        return
    lines = ["⚠️ *Password riusate*"]
    for cluster in clusters:
        names = ", ".join(escape_md(name) for _, name in cluster)
        lines.append(f"• {names}")
    await update.effective_chat.send_message(
        "\n".join(lines),
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=back_menu_keyboard(show_menu=True),
    )
