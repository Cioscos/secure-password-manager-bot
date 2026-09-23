"""Bot API features the UI relies on (PTB >= 22.8)."""

import telegram
from telegram import CopyTextButton, InlineKeyboardButton


def test_ptb_is_at_least_22_8():
    major, minor = (int(x) for x in telegram.__version__.split(".")[:2])
    assert (major, minor) >= (22, 8)


def test_inline_button_accepts_style():
    from telegram.constants import KeyboardButtonStyle

    button = InlineKeyboardButton("x", callback_data="y", style=KeyboardButtonStyle.DANGER)
    assert button.style == "danger"


def test_copy_text_button_available():
    button = InlineKeyboardButton("c", copy_text=CopyTextButton("secret"))
    assert button.copy_text.text == "secret"
