"""Pure-function tests for password_gen handler helpers."""

from __future__ import annotations

from password_bot.handlers.password_gen import (
    _check,
    _draft_to_prefs,
    _options_keyboard,
    _to_spec,
)
from password_bot.models.pw_prefs import PwPrefs
from password_bot.services.password_generator import PasswordSpec


def test_check_emoji():
    assert _check(True) == "✅"
    assert _check(False) == "❌"


def test_draft_to_prefs_full():
    draft = {
        "length": 16,
        "upper": False,
        "lower": True,
        "digits": True,
        "symbols": False,
        "exclude_ambiguous": True,
        "no_duplicates": True,
    }
    prefs = _draft_to_prefs(draft)
    assert prefs == PwPrefs(
        length=16,
        upper=False,
        lower=True,
        digits=True,
        symbols=False,
        exclude_ambiguous=True,
        no_duplicates=True,
    )


def test_draft_to_prefs_partial_uses_defaults():
    prefs = _draft_to_prefs({})
    assert prefs == PwPrefs()


def test_to_spec_maps_fields():
    p = PwPrefs(length=12, upper=False, lower=True, digits=False, symbols=True)
    spec = _to_spec(p)
    assert isinstance(spec, PasswordSpec)
    assert spec.length == 12
    assert spec.upper is False
    assert spec.symbols is True


def test_options_keyboard_has_all_rows():
    kb = _options_keyboard(PwPrefs())
    # 7 rows: length, upper/lower, digits/symbols, ambiguous/no-dup, generate, save/reset, back
    assert len(kb.inline_keyboard) == 7
