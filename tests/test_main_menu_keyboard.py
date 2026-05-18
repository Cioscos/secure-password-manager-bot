"""Smoke tests for main menu keyboard."""

from __future__ import annotations

from password_bot.telegram_utils.keyboards import main_menu_keyboard


def test_main_menu_rows_count():
    kb = main_menu_keyboard()
    # Two-column layout: 12 actions -> 6 rows x 2 buttons.
    assert len(kb.inline_keyboard) == 6
    assert all(len(row) == 2 for row in kb.inline_keyboard)


def test_main_menu_labels_have_no_descriptions():
    kb = main_menu_keyboard()
    for row in kb.inline_keyboard:
        for btn in row:
            assert " — " not in btn.text


def test_main_menu_callback_data():
    kb = main_menu_keyboard()
    seen = {b.callback_data for row in kb.inline_keyboard for b in row}
    expected = {
        "menu:add",
        "menu:list",
        "menu:search",
        "menu:copy",
        "menu:stale",
        "menu:reused",
        "menu:categories",
        "menu:settings",
        "menu:export",
        "menu:import",
        "menu:lock",
        "menu:help",
    }
    assert expected <= seen
