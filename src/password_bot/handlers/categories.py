"""Categories management: list, add, delete. Plus per-account assignment helper."""

from __future__ import annotations

import uuid

from telegram import Update
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.models.category import Category
from password_bot.state.fsm import FsmContext
from password_bot.telegram_utils.md import escape_md


def _require_session(context: ContextTypes.DEFAULT_TYPE):
    return FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]


async def cmd_categories(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    container: Container = context.application.bot_data["container"]
    cats = await container.categories.list_for_chat(update.effective_chat.id)
    if not cats:
        await update.message.reply_text("Nessuna categoria. /cat_add NOME per crearne una.")
        return
    lines = ["🏷 *Categorie*"]
    for c in cats:
        lines.append(f"- {escape_md(c.name)}")
    await update.message.reply_text("\n".join(lines), parse_mode="MarkdownV2")


async def cmd_cat_add(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    name = " ".join(context.args or []).strip()
    if not name:
        await update.message.reply_text("Uso: /cat_add NOME")
        return
    container: Container = context.application.bot_data["container"]
    existing = await container.categories.get_by_name(update.effective_chat.id, name)
    if existing is not None:
        await update.message.reply_text("Categoria già esistente.")
        return
    await container.categories.create(
        Category(
            id=str(uuid.uuid4()),
            chat_id=update.effective_chat.id,
            name=name,
            color=None,
        )
    )
    await update.message.reply_text(f"✅ Categoria '{name}' creata.")


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
    await update.message.reply_text(f"🗑 Categoria '{name}' eliminata.")
