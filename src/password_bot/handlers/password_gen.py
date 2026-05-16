"""Interactive password generator with toggle menu and saved defaults."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.models.pw_prefs import PwPrefs
from password_bot.services.password_generator import (
    MAX_LENGTH,
    MIN_LENGTH,
    PasswordGenerator,
    PasswordSpec,
    entropy_bits,
)
from password_bot.state.fsm import FsmContext
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.md import code_inline, escape_md


def _draft(context: ContextTypes.DEFAULT_TYPE) -> dict[str, Any]:
    return context.chat_data.setdefault(  # type: ignore[union-attr]
        ChatDataKey.PW_GEN_DRAFT.value, {}
    )


def _draft_to_prefs(draft: dict[str, Any]) -> PwPrefs:
    defaults = PwPrefs()
    return PwPrefs(
        length=int(draft.get("length", defaults.length)),
        upper=bool(draft.get("upper", defaults.upper)),
        lower=bool(draft.get("lower", defaults.lower)),
        digits=bool(draft.get("digits", defaults.digits)),
        symbols=bool(draft.get("symbols", defaults.symbols)),
        exclude_ambiguous=bool(draft.get("exclude_ambiguous", defaults.exclude_ambiguous)),
        no_duplicates=bool(draft.get("no_duplicates", defaults.no_duplicates)),
    )


def _check(b: bool) -> str:
    return "✅" if b else "❌"


def _options_keyboard(prefs: PwPrefs) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(f"Lunghezza: {prefs.length}", callback_data="pwgen:len")],
        [
            InlineKeyboardButton(
                f"Maiuscole {_check(prefs.upper)}", callback_data="pwgen:toggle:upper"
            ),
            InlineKeyboardButton(
                f"Minuscole {_check(prefs.lower)}", callback_data="pwgen:toggle:lower"
            ),
        ],
        [
            InlineKeyboardButton(
                f"Numeri {_check(prefs.digits)}", callback_data="pwgen:toggle:digits"
            ),
            InlineKeyboardButton(
                f"Simboli {_check(prefs.symbols)}", callback_data="pwgen:toggle:symbols"
            ),
        ],
        [
            InlineKeyboardButton(
                f"No ambigui {_check(prefs.exclude_ambiguous)}",
                callback_data="pwgen:toggle:exclude_ambiguous",
            ),
            InlineKeyboardButton(
                f"No duplicati {_check(prefs.no_duplicates)}",
                callback_data="pwgen:toggle:no_duplicates",
            ),
        ],
        [InlineKeyboardButton("🎲 Genera", callback_data="pwgen:run")],
        [
            InlineKeyboardButton("💾 Salva default", callback_data="pwgen:save"),
            InlineKeyboardButton("🔄 Reset", callback_data="pwgen:reset"),
        ],
        [
            InlineKeyboardButton("🔙 Indietro", callback_data="pwgen:cancel"),
        ],
    ]
    return InlineKeyboardMarkup(rows)


async def show_options_from_callback(
    update: Update, context: ContextTypes.DEFAULT_TYPE, *, return_to: str
) -> None:
    container: Container = context.application.bot_data["container"]
    prefs = await container.users.get_pw_prefs(update.effective_chat.id)
    context.chat_data[ChatDataKey.PW_GEN_DRAFT.value] = asdict(prefs)  # type: ignore[union-attr]
    context.chat_data[ChatDataKey.PW_GEN_RETURN_TO.value] = return_to  # type: ignore[union-attr]
    text = MESSAGES["pw_gen_title"]
    q = update.callback_query
    if q is not None:
        try:
            await q.edit_message_text(
                text, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=_options_keyboard(prefs)
            )
            return
        except Exception:
            pass
    await update.effective_chat.send_message(
        text, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=_options_keyboard(prefs)
    )


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    parts = q.data.split(":")
    action = parts[1]
    draft = _draft(context)
    if not draft:
        # state lost — reload from DB
        container: Container = context.application.bot_data["container"]
        prefs = await container.users.get_pw_prefs(update.effective_chat.id)
        context.chat_data[ChatDataKey.PW_GEN_DRAFT.value] = asdict(prefs)  # type: ignore[union-attr]
        draft = _draft(context)

    if action == "toggle":
        flag = parts[2]
        if flag in draft:
            draft[flag] = not bool(draft[flag])
        prefs = _draft_to_prefs(draft)
        try:
            await q.edit_message_reply_markup(reply_markup=_options_keyboard(prefs))
        except Exception:
            await update.effective_chat.send_message(
                MESSAGES["pw_gen_title"],
                parse_mode=ParseMode.MARKDOWN_V2,
                reply_markup=_options_keyboard(prefs),
            )
        return

    if action == "len":
        FsmContext(context.chat_data).set_pending_input({"field": "_pwgen_length"})  # type: ignore[arg-type]
        await update.effective_chat.send_message(MESSAGES["pw_gen_length_prompt"])
        return

    if action == "run":
        prefs = _draft_to_prefs(draft)
        try:
            password = PasswordGenerator().generate(_to_spec(prefs))
        except ValueError as e:
            await update.effective_chat.send_message(f"⚠️ {e}")
            return
        bits = int(entropy_bits(_to_spec(prefs)))
        body = (
            escape_md(MESSAGES["pw_gen_generated"].format(length=prefs.length, entropy=bits))
            + "\n"
            + code_inline(password)
        )
        kb = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton("🔄 Rigenera", callback_data="pwgen:run"),
                    InlineKeyboardButton("✅ Usa", callback_data="pwgen:accept"),
                ],
                [
                    InlineKeyboardButton("⚙️ Opzioni", callback_data="pwgen:back"),
                    InlineKeyboardButton("❌ Annulla", callback_data="pwgen:cancel"),
                ],
            ]
        )
        # Store last password for accept
        draft["last_password"] = password
        await update.effective_chat.send_message(
            body, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=kb
        )
        return

    if action == "accept":
        password = draft.get("last_password")
        if not password:
            await update.effective_chat.send_message("⚠️ Nessuna password generata.")
            return
        return_to = context.chat_data.get(ChatDataKey.PW_GEN_RETURN_TO.value)  # type: ignore[union-attr]
        context.chat_data.pop(ChatDataKey.PW_GEN_DRAFT.value, None)  # type: ignore[union-attr]
        context.chat_data.pop(ChatDataKey.PW_GEN_RETURN_TO.value, None)  # type: ignore[union-attr]
        if return_to == "account_new":
            from password_bot.handlers.account_new import accept_generated_password

            await accept_generated_password(update, context, password)
        else:
            await update.effective_chat.send_message(MESSAGES["pw_gen_accepted"])
        return

    if action == "save":
        prefs = _draft_to_prefs(draft)
        container: Container = context.application.bot_data["container"]
        await container.users.set_pw_prefs(update.effective_chat.id, prefs)
        await update.effective_chat.send_message(MESSAGES["pw_gen_saved_defaults"])
        return

    if action == "reset":
        defaults = PwPrefs()
        context.chat_data[ChatDataKey.PW_GEN_DRAFT.value] = asdict(defaults)  # type: ignore[union-attr]
        try:
            await q.edit_message_reply_markup(reply_markup=_options_keyboard(defaults))
        except Exception:
            await update.effective_chat.send_message(
                MESSAGES["pw_gen_title"],
                parse_mode=ParseMode.MARKDOWN_V2,
                reply_markup=_options_keyboard(defaults),
            )
        return

    if action == "back":
        prefs = _draft_to_prefs(draft)
        await update.effective_chat.send_message(
            MESSAGES["pw_gen_title"],
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=_options_keyboard(prefs),
        )
        return

    if action == "cancel":
        return_to = context.chat_data.get(ChatDataKey.PW_GEN_RETURN_TO.value)  # type: ignore[union-attr]
        context.chat_data.pop(ChatDataKey.PW_GEN_DRAFT.value, None)  # type: ignore[union-attr]
        context.chat_data.pop(ChatDataKey.PW_GEN_RETURN_TO.value, None)  # type: ignore[union-attr]
        if return_to == "account_new":
            # fall back to manual password
            from password_bot.handlers.account_new import _draft as new_draft

            new_draft(context)["step"] = "password_manual"
            await update.effective_chat.send_message(
                "Inviami la password (verrà eliminata subito)."
            )
        else:
            from password_bot.handlers.common import _send_menu

            await _send_menu(update.effective_chat)
        return


def _to_spec(prefs: PwPrefs) -> PasswordSpec:
    return PasswordSpec(
        length=prefs.length,
        upper=prefs.upper,
        lower=prefs.lower,
        digits=prefs.digits,
        symbols=prefs.symbols,
        exclude_ambiguous=prefs.exclude_ambiguous,
        no_duplicates=prefs.no_duplicates,
    )


async def handle_pending_length(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.message.text or "").strip()
    FsmContext(context.chat_data).clear_pending_input()  # type: ignore[arg-type]
    try:
        n = int(text)
    except ValueError:
        await update.effective_chat.send_message(MESSAGES["pw_gen_length_invalid"])
        return
    if n < MIN_LENGTH or n > MAX_LENGTH:
        await update.effective_chat.send_message(MESSAGES["pw_gen_length_invalid"])
        return
    draft = _draft(context)
    draft["length"] = n
    prefs = _draft_to_prefs(draft)
    await update.effective_chat.send_message(
        MESSAGES["pw_gen_title"],
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=_options_keyboard(prefs),
    )


__all__ = ["handle_pending_length", "on_callback", "show_options_from_callback"]
