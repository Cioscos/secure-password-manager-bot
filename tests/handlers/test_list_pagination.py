"""Tests for the paginated /list keyboard and on_list_callback handler."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from password_bot.handlers.inline_cmd import on_list_callback
from password_bot.models.account import AccountRow
from password_bot.services.auth_service import Session
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.callback_data import ListPageData
from password_bot.telegram_utils.keyboards import (
    ACCOUNTS_PAGE_SIZE,
    accounts_page_keyboard,
)


def _make_rows(n: int) -> list[AccountRow]:
    return [
        AccountRow(
            id=str(i),
            chat_id=1,
            name=f"acc-{i:02d}",
            username_enc=None,
            password_enc="",
            url_enc=None,
            note_enc=None,
            category_id=None,
            password_hmac="",
            crypto_version=2,
            password_changed_at=0,
            created_at=0,
            updated_at=0,
        )
        for i in range(n)
    ]


def _nav_row(markup):
    # nav row is the one before the last (back/menu) row
    return markup.inline_keyboard[-2]


def _account_rows(markup):
    return markup.inline_keyboard[:-2]


def test_keyboard_page_size_cap():
    rows = _make_rows(20)
    kb = accounts_page_keyboard(rows, page=0)
    assert len(_account_rows(kb)) == ACCOUNTS_PAGE_SIZE


def test_keyboard_last_page_partial():
    rows = _make_rows(20)
    # page index 2 → items 16..19 → 4 buttons
    kb = accounts_page_keyboard(rows, page=2)
    assert len(_account_rows(kb)) == 4


def test_first_page_omits_left_arrow():
    rows = _make_rows(20)
    kb = accounts_page_keyboard(rows, page=0)
    labels = [b.text for b in _nav_row(kb)]
    assert "◀" not in labels
    assert "▶" in labels
    assert "1/3" in labels


def test_last_page_omits_right_arrow():
    rows = _make_rows(20)
    kb = accounts_page_keyboard(rows, page=2)
    labels = [b.text for b in _nav_row(kb)]
    assert "▶" not in labels
    assert "◀" in labels
    assert "3/3" in labels


def test_middle_page_has_both_arrows():
    rows = _make_rows(20)
    kb = accounts_page_keyboard(rows, page=1)
    labels = [b.text for b in _nav_row(kb)]
    assert "◀" in labels and "▶" in labels
    assert "2/3" in labels


def test_nav_buttons_carry_ListPageData():
    rows = _make_rows(20)
    kb = accounts_page_keyboard(rows, page=1)
    for btn in _nav_row(kb):
        assert isinstance(btn.callback_data, ListPageData)


def test_account_buttons_callback_data_format():
    rows = _make_rows(3)
    kb = accounts_page_keyboard(rows, page=0)
    acc_rows = _account_rows(kb)
    assert acc_rows[0][0].callback_data == "acc:open:0"
    assert acc_rows[1][0].callback_data == "acc:open:1"


def test_page_clamps_above_max():
    rows = _make_rows(8)  # single page
    kb = accounts_page_keyboard(rows, page=42)
    labels = [b.text for b in _nav_row(kb)]
    assert "1/1" in labels


def test_back_menu_row_present():
    rows = _make_rows(3)
    kb = accounts_page_keyboard(rows, page=0)
    last_row = kb.inline_keyboard[-1]
    assert [b.text for b in last_row] == ["🔙 Indietro", "🏠 Menu"]
    assert [b.callback_data for b in last_row] == ["nav:back", "nav:menu"]


def _make_session() -> Session:
    return Session(chat_id=1, aes_key=b"\x00" * 32, hmac_key=b"\x00" * 32, expires_at=10**12)


@pytest.mark.asyncio
async def test_on_list_callback_session_locked():
    update = MagicMock()
    update.callback_query.answer = AsyncMock()
    update.callback_query.data = ListPageData(page=1)
    update.callback_query.edit_message_text = AsyncMock()
    update.effective_chat.send_message = AsyncMock()
    update.effective_chat.id = 1

    context = MagicMock()
    context.chat_data = {}
    await on_list_callback(update, context)
    update.effective_chat.send_message.assert_called_once()
    update.callback_query.edit_message_text.assert_not_called()


@pytest.mark.asyncio
async def test_on_list_callback_edits_with_new_page():
    rows = _make_rows(20)

    update = MagicMock()
    update.callback_query.answer = AsyncMock()
    update.callback_query.data = ListPageData(page=1)
    update.callback_query.edit_message_text = AsyncMock()
    update.effective_chat.id = 1

    context = MagicMock()
    context.chat_data = {ChatDataKey.SESSION.value: _make_session()}
    container = MagicMock()
    container.accounts.list_for_chat = AsyncMock(return_value=rows)
    context.application.bot_data = {"container": container}

    await on_list_callback(update, context)
    update.callback_query.edit_message_text.assert_called_once()
    kwargs = update.callback_query.edit_message_text.call_args.kwargs
    kb = kwargs["reply_markup"]
    labels = [b.text for b in kb.inline_keyboard[-2]]
    assert "2/3" in labels


@pytest.mark.asyncio
async def test_on_list_callback_empty_vault_edits_to_empty_msg():
    update = MagicMock()
    update.callback_query.answer = AsyncMock()
    update.callback_query.data = ListPageData(page=0)
    update.callback_query.edit_message_text = AsyncMock()
    update.effective_chat.id = 1

    context = MagicMock()
    context.chat_data = {ChatDataKey.SESSION.value: _make_session()}
    container = MagicMock()
    container.accounts.list_for_chat = AsyncMock(return_value=[])
    context.application.bot_data = {"container": container}

    await on_list_callback(update, context)
    update.callback_query.edit_message_text.assert_called_once()
