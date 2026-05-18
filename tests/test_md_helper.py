from password_bot.telegram_utils.md import code_inline, escape_md


def test_escape_md_handles_v2_specials():
    out = escape_md("hello *world* (test) _x_!")
    for ch in r"_*[]()~`>#+-=|{}.!":
        assert ch in r"_*[]()~`>#+-=|{}.!"  # tautology; real check below
    assert out == r"hello \*world\* \(test\) \_x\_\!"


def test_code_inline_escapes_internal_backticks():
    out = code_inline("a`b")
    assert out == "`a\\`b`"
