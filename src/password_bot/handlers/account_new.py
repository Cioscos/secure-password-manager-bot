"""Account creation flow with optional username/URL/note/category."""

from __future__ import annotations

from typing import Any

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.services.password_generator import (
    PasswordCharset,
    PasswordGenerator,
    PasswordSpec,
)
from password_bot.services.vault_service import NewAccount
from password_bot.state.fsm import FsmContext, Screen
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.keyboards import single_column
from password_bot.telegram_utils.md import escape_md


def _draft(context: ContextTypes.DEFAULT_TYPE) -> dict[str, Any]:
    return context.chat_data.setdefault(  # type: ignore[union-attr]
        ChatDataKey.PENDING_NEW_ACCOUNT.value,
        {"step": "name"},
    )


async def start_new_account(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    context.chat_data.pop(ChatDataKey.PENDING_NEW_ACCOUNT.value, None)  # type: ignore[union-attr]
    _draft(context)
    FsmContext(context.chat_data).push(Screen(name="account_new", data={}))  # type: ignore[arg-type]
    await update.effective_message.reply_text(
        escape_md("Nome dell'account? /stop per annullare."),
        parse_mode=ParseMode.MARKDOWN_V2,
    )


async def receive_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    draft = _draft(context)
    text = (update.message.text or "").strip()
    if draft["step"] == "name":
        draft["name"] = text
        draft["step"] = "username"
        await update.message.reply_text(
            escape_md("Username (oppure premi /skip per saltarlo)?"),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
    elif draft["step"] == "username":
        draft["username"] = text
        draft["step"] = "password"
        await _ask_password(update, context)
    elif draft["step"] == "password_manual":
        draft["password"] = text
        await _show_strength(update, context, text)
        draft["step"] = "url"
        await update.message.reply_text(
            escape_md("URL? Inviami il link o /skip."),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
    elif draft["step"] == "url":
        draft["url"] = text
        draft["step"] = "note"
        await update.message.reply_text(
            escape_md("Note? Inviami il testo o /skip."),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
    elif draft["step"] == "note":
        draft["note"] = text
        await _confirm_and_save(update, context)


async def cmd_skip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    draft = _draft(context)
    step = draft["step"]
    if step == "username":
        draft["username"] = None
        draft["step"] = "password"
        await _ask_password(update, context)
    elif step == "url":
        draft["url"] = None
        draft["step"] = "note"
        await update.message.reply_text(
            escape_md("Note? Inviami il testo o /skip."),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
    elif step == "note":
        draft["note"] = None
        await _confirm_and_save(update, context)


async def _ask_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    kb = single_column(
        [
            ("🎲 Genera", "newpw:generate"),
            ("⌨️ Scrivila io", "newpw:manual"),
        ]
    )
    await update.message.reply_text("Password?", reply_markup=kb)


async def callback_generate_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.callback_query.answer()
    gen = PasswordGenerator()
    pw = gen.generate(PasswordSpec(length=20, charset=PasswordCharset.ALPHANUM_SYMBOLS))
    _draft(context)["password"] = pw
    _draft(context)["step"] = "url"
    await update.callback_query.edit_message_text(f"Generata password lunga {len(pw)} caratteri.")
    await update.effective_chat.send_message(
        escape_md("URL? Inviami il link o /skip."),
        parse_mode=ParseMode.MARKDOWN_V2,
    )


async def callback_manual_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.callback_query.answer()
    _draft(context)["step"] = "password_manual"
    await update.callback_query.edit_message_text("Inviami la password (verrà eliminata subito).")


async def _show_strength(update: Update, context: ContextTypes.DEFAULT_TYPE, password: str) -> None:
    container: Container = context.application.bot_data["container"]
    r = container.strength.evaluate(password)
    msg = MESSAGES["strength_label"].format(
        score=r.score, label=["pessima", "debole", "media", "buona", "ottima"][r.score]
    )
    if r.warning:
        msg += f"\n⚠️ {r.warning}"
    await update.message.reply_text(msg)


async def _confirm_and_save(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    container: Container = context.application.bot_data["container"]
    session = FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]
    if session is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    draft = _draft(context)
    new = NewAccount(
        chat_id=update.effective_chat.id,
        name=draft["name"],
        username=draft.get("username"),
        password=draft["password"],
        url=draft.get("url"),
        note=draft.get("note"),
        category_id=None,
    )
    acc = await container.vault.add(new, aes_key=session.aes_key, hmac_key=session.hmac_key)
    container.chat_reuse_detector(context).add(acc.id, acc.name, draft["password"])
    context.chat_data.pop(ChatDataKey.PENDING_NEW_ACCOUNT.value, None)  # type: ignore[union-attr]
    await update.message.reply_text(MESSAGES["account_saved"])
