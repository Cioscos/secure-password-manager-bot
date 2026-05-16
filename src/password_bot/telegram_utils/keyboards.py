"""Inline keyboard builders."""

from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup


def single_column(buttons: list[tuple[str, str]]) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text=label, callback_data=data)] for label, data in buttons]
    return InlineKeyboardMarkup(rows)


def back_menu_keyboard(*, show_menu: bool) -> InlineKeyboardMarkup:
    row = [InlineKeyboardButton("🔙 Indietro", callback_data="nav:back")]
    if show_menu:
        row.append(InlineKeyboardButton("🏠 Menu", callback_data="nav:menu"))
    return InlineKeyboardMarkup([row])


def confirm_cancel_keyboard(*, confirm_data: str, cancel_data: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("✅ Conferma", callback_data=confirm_data),
                InlineKeyboardButton("❌ Annulla", callback_data=cancel_data),
            ]
        ]
    )
