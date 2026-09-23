"""Keyboard and formatting helpers shared by every screen."""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse

from telegram import CopyTextButton, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import KeyboardButtonStyle

from password_bot.models.category import Category
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import NAV, Act

PRIMARY = KeyboardButtonStyle.PRIMARY
SUCCESS = KeyboardButtonStyle.SUCCESS
DANGER = KeyboardButtonStyle.DANGER

COPY_TEXT_MAX = 256  # Bot API limit for CopyTextButton.text
LABEL_MAX = 32

_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
_IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def btn(
    label: str,
    screen: str,
    action: str,
    arg: str | int | None = None,
    *,
    style: str | None = None,
) -> InlineKeyboardButton:
    return InlineKeyboardButton(label, callback_data=Act(screen, action, arg), style=style)


def nav_btn(label: str, action: str) -> InlineKeyboardButton:
    return btn(label, NAV, action)


def copy_btn(
    label: str, value: str | None, *, style: str | None = None
) -> InlineKeyboardButton | None:
    if not value or len(value) > COPY_TEXT_MAX:
        return None
    return InlineKeyboardButton(label, copy_text=CopyTextButton(value), style=style)


def url_btn(label: str, raw: str | None) -> InlineKeyboardButton | None:
    url = normalize_url(raw)
    return InlineKeyboardButton(label, url=url) if url else None


def footer(back_label: str | None) -> list[InlineKeyboardButton | None]:
    return [nav_btn(f"🔙 {back_label or 'Indietro'}", "back"), nav_btn("🏠 Menu", "home")]


def keyboard(*rows: list[InlineKeyboardButton | None]) -> InlineKeyboardMarkup:
    clean = [[b for b in row if b is not None] for row in rows]
    return InlineKeyboardMarkup([row for row in clean if row])


def normalize_url(raw: str | None) -> str | None:
    """http(s) URL Telegram will accept in a URL button, or None."""
    if not raw:
        return None
    value = raw.strip()
    if not value or any(ch.isspace() for ch in value):
        return None
    if "://" not in value:
        value = f"https://{value}"
    try:
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        _ = parsed.port  # raises ValueError on garbage like "javascript:alert(1)"
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    if not (_HOST.fullmatch(host) or _IPV4.fullmatch(host)):
        return None
    return value


def plain_date(ts: int) -> str:
    return time.strftime("%d/%m/%Y", time.localtime(ts)) if ts > 0 else "?"


def md_date(ts: int) -> str:
    """MarkdownV2 `date_time` entity; old clients show the bracketed fallback text."""
    if ts <= 0:
        return escape_md("data sconosciuta")
    return f"![{escape_md(plain_date(ts))}](tg://time?unix={ts}&format=d)"


def label(text: str, max_len: int = LABEL_MAX) -> str:
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def category_label(cat: Category) -> str:
    return f"{cat.icon} {cat.name}" if cat.icon else cat.name
