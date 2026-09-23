"""MarkdownV2 escaping helpers."""

from __future__ import annotations

_SPECIALS = r"_*[]()~`>#+-=|{}.!"


def escape_md(value: str) -> str:
    out: list[str] = []
    for ch in value:
        out.append("\\" + ch if ch in _SPECIALS else ch)
    return "".join(out)


def code_inline(value: str) -> str:
    # Inside MarkdownV2 code entities only '\' and '`' must be escaped.
    inner = value.replace("\\", "\\\\").replace("`", "\\`")
    return f"`{inner}`"
