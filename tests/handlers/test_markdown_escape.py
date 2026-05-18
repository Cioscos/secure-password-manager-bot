"""Regression tests for MarkdownV2 escaping bugs."""

from __future__ import annotations

from password_bot.telegram_utils.md import code_inline, escape_md


def test_escape_hyphen():
    assert escape_md("My-Account") == "My\\-Account"


def test_escape_parens_dot_excl():
    assert escape_md("(test). Hello!") == "\\(test\\)\\. Hello\\!"


def test_bullet_dot_not_escaped_in_bullet():
    # `•` is not a MarkdownV2 reserved char and is safe at line start.
    assert escape_md("•") == "•"


def test_list_line_format_safe():
    name = "Acme-Corp"
    line = f"• {escape_md(name)}"
    assert line == "• Acme\\-Corp"
    assert "\\-" in line


def test_code_inline_handles_backticks():
    assert code_inline("foo`bar") == "`foo\\`bar`"
