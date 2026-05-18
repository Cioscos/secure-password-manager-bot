"""Inline keyboard builders."""

from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from password_bot.models.account import AccountRow
from password_bot.telegram_utils.callback_data import ListPageData

ACCOUNTS_PAGE_SIZE = 8


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


MAIN_MENU_ITEMS: list[tuple[str, str, str]] = [
    ("➕ Nuovo", "crea un nuovo account", "menu:add"),  # noqa: RUF001
    ("📚 Lista", "mostra tutti gli account", "menu:list"),
    ("🔍 Cerca", "cerca account per nome", "menu:search"),
    ("📋 Copia", "copia password di un account", "menu:copy"),
    ("⚠️ Vecchie", "password non aggiornate", "menu:stale"),
    ("♻️ Riusate", "password riutilizzate", "menu:reused"),
    ("🏷 Categorie", "gestisci categorie", "menu:categories"),
    ("⚙️ Settings", "impostazioni vault", "menu:settings"),
    ("📤 Export", "esporta vault cifrato", "menu:export"),
    ("📥 Import", "importa vault cifrato", "menu:import"),
    ("🔒 Lock", "blocca la sessione", "menu:lock"),
    ("❓ Help", "elenco comandi", "menu:help"),
]


def main_menu_keyboard() -> InlineKeyboardMarkup:
    buttons = [
        InlineKeyboardButton(label, callback_data=data) for label, _, data in MAIN_MENU_ITEMS
    ]
    rows = [buttons[i : i + 2] for i in range(0, len(buttons), 2)]
    return InlineKeyboardMarkup(rows)


def accounts_page_keyboard(
    rows: list[AccountRow], *, page: int, page_size: int = ACCOUNTS_PAGE_SIZE
) -> InlineKeyboardMarkup:
    """Build paginated account-list keyboard.

    One row per account on the current page (tapping opens the account via the
    existing `^acc:` handler), a nav row showing `◀ | N/M | ▶` (boundary arrows
    omitted), and a final `[🔙 Indietro] [🏠 Menu]` row.
    """
    total = len(rows)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = max(0, min(page, total_pages - 1))
    start = page * page_size
    end = start + page_size
    keyboard: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton(r.name, callback_data=f"acc:open:{r.id}")] for r in rows[start:end]
    ]

    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton("◀", callback_data=ListPageData(page=page - 1)))
    nav.append(
        InlineKeyboardButton(f"{page + 1}/{total_pages}", callback_data=ListPageData(page=page))
    )
    if page < total_pages - 1:
        nav.append(InlineKeyboardButton("▶", callback_data=ListPageData(page=page + 1)))
    keyboard.append(nav)

    keyboard.append(
        [
            InlineKeyboardButton("🔙 Indietro", callback_data="nav:back"),
            InlineKeyboardButton("🏠 Menu", callback_data="nav:menu"),
        ]
    )
    return InlineKeyboardMarkup(keyboard)
