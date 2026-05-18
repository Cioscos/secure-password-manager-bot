from telegram import InlineKeyboardMarkup

from password_bot.telegram_utils.keyboards import (
    back_menu_keyboard,
    confirm_cancel_keyboard,
    single_column,
)


def test_single_column_builds_inline_keyboard():
    kb = single_column([("Yes", "yes"), ("No", "no")])
    assert isinstance(kb, InlineKeyboardMarkup)
    assert len(kb.inline_keyboard) == 2
    assert kb.inline_keyboard[0][0].callback_data == "yes"


def test_back_menu_keyboard_has_back_and_menu():
    kb = back_menu_keyboard(show_menu=True)
    callbacks = {b.callback_data for row in kb.inline_keyboard for b in row}
    assert "nav:back" in callbacks
    assert "nav:menu" in callbacks


def test_confirm_cancel_keyboard():
    kb = confirm_cancel_keyboard(confirm_data="do_it", cancel_data="cancel_it")
    callbacks = {b.callback_data for row in kb.inline_keyboard for b in row}
    assert callbacks == {"do_it", "cancel_it"}
