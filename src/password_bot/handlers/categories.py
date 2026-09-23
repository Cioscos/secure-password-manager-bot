"""Categories management with inline-button flow."""

from __future__ import annotations

import uuid

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.models.category import Category
from password_bot.state.fsm import FsmContext
from password_bot.telegram_utils.keyboards import back_menu_keyboard, confirm_cancel_keyboard
from password_bot.telegram_utils.md import escape_md


def _require_session(context: ContextTypes.DEFAULT_TYPE):
    return FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]


def _list_keyboard(cats: list[Category]) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(c.name, callback_data=f"cat:select:{c.id}")] for c in cats]
    rows.append([InlineKeyboardButton("➕ Nuova", callback_data="cat:new")])  # noqa: RUF001
    rows.append(
        [
            InlineKeyboardButton("🔙 Indietro", callback_data="nav:back"),
            InlineKeyboardButton("🏠 Menu", callback_data="nav:menu"),
        ]
    )
    return InlineKeyboardMarkup(rows)


async def cmd_categories(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.effective_chat.send_message(MESSAGES["session_locked"])
        return
    container: Container = context.application.bot_data["container"]
    cats = await container.categories.list_for_chat(update.effective_chat.id)
    if not cats:
        await update.effective_chat.send_message(
            MESSAGES["cat_empty"],
            reply_markup=InlineKeyboardMarkup(
                [
                    [InlineKeyboardButton("➕ Nuova", callback_data="cat:new")],  # noqa: RUF001
                    [InlineKeyboardButton("🏠 Menu", callback_data="nav:menu")],
                ]
            ),
        )
        return
    text = "🏷 *Categorie*\n" + "\n".join(f"• {escape_md(c.name)}" for c in cats)
    await update.effective_chat.send_message(
        text, parse_mode="MarkdownV2", reply_markup=_list_keyboard(cats)
    )


async def cmd_cat_add(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    name = " ".join(context.args or []).strip()
    if not name:
        FsmContext(context.chat_data).set_pending_input({"field": "_cat_new_name"})  # type: ignore[arg-type]
        await update.effective_chat.send_message(MESSAGES["cat_new_prompt"])
        return
    await _create_category(update, context, name)


async def cmd_cat_del(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    name = " ".join(context.args or []).strip()
    if not name:
        await update.message.reply_text("Uso: /cat_del NOME")
        return
    container: Container = context.application.bot_data["container"]
    cat = await container.categories.get_by_name(update.effective_chat.id, name)
    if cat is None:
        await update.message.reply_text("Categoria non trovata.")
        return
    await container.categories.delete(cat.id)
    await update.message.reply_text(MESSAGES["cat_deleted"])


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    parts = q.data.split(":")
    action = parts[1]
    container: Container = context.application.bot_data["container"]
    chat_id = update.effective_chat.id

    if action == "new":
        FsmContext(context.chat_data).set_pending_input({"field": "_cat_new_name"})  # type: ignore[arg-type]
        await update.effective_chat.send_message(MESSAGES["cat_new_prompt"])
        return

    if action == "select":
        cat_id = parts[2]
        cat = await container.categories.get(cat_id)
        if cat is None or cat.chat_id != chat_id:
            await update.effective_chat.send_message("Categoria non trovata.")
            return
        kb = InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("🗑 Elimina", callback_data=f"cat:delconfirm:{cat.id}")],
                [
                    InlineKeyboardButton("🔙 Indietro", callback_data="cat:list"),
                    InlineKeyboardButton("🏠 Menu", callback_data="nav:menu"),
                ],
            ]
        )
        await q.edit_message_text(
            f"🏷 *{escape_md(cat.name)}*", parse_mode="MarkdownV2", reply_markup=kb
        )
        return

    if action == "delconfirm":
        cat_id = parts[2]
        await q.edit_message_text(
            "Confermi l'eliminazione della categoria?",
            reply_markup=confirm_cancel_keyboard(
                confirm_data=f"cat:del:{cat_id}",
                cancel_data="cat:list",
            ),
        )
        return

    if action == "del":
        cat_id = parts[2]
        await container.categories.delete(cat_id)
        await q.edit_message_text(MESSAGES["cat_deleted"])
        await _show_list(update, context)
        return

    if action == "list":
        await _show_list(update, context)
        return


async def _show_list(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    container: Container = context.application.bot_data["container"]
    cats = await container.categories.list_for_chat(update.effective_chat.id)
    if not cats:
        await update.effective_chat.send_message(
            MESSAGES["cat_empty"], reply_markup=back_menu_keyboard(show_menu=True)
        )
        return
    text = "🏷 *Categorie*\n" + "\n".join(f"• {escape_md(c.name)}" for c in cats)
    await update.effective_chat.send_message(
        text, parse_mode="MarkdownV2", reply_markup=_list_keyboard(cats)
    )


async def _create_category(update: Update, context: ContextTypes.DEFAULT_TYPE, name: str) -> None:
    container: Container = context.application.bot_data["container"]
    existing = await container.categories.get_by_name(update.effective_chat.id, name)
    if existing is not None:
        await update.effective_chat.send_message(MESSAGES["cat_duplicate"])
        await _show_list(update, context)
        return
    await container.categories.create(
        Category(
            id=str(uuid.uuid4()),
            chat_id=update.effective_chat.id,
            name=name,
            icon=None,
        )
    )
    await update.effective_chat.send_message(MESSAGES["cat_created"].format(name=name))
    await _show_list(update, context)


async def handle_pending_name(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Called by dispatcher when pending input field is `_cat_new_name`."""
    text = (update.message.text or "").strip()
    FsmContext(context.chat_data).clear_pending_input()  # type: ignore[arg-type]
    if not text:
        await update.effective_chat.send_message("Annullato.")
        await _show_list(update, context)
        return
    await _create_category(update, context, text)
