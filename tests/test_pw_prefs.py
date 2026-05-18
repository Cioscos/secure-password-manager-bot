"""PwPrefs JSON serialization tests."""

from __future__ import annotations

from password_bot.models.pw_prefs import PwPrefs


def test_defaults():
    p = PwPrefs()
    assert p.length == 20
    assert p.upper and p.lower and p.digits and p.symbols
    assert not p.exclude_ambiguous
    assert not p.no_duplicates


def test_roundtrip():
    p = PwPrefs(length=24, symbols=False, no_duplicates=True)
    raw = p.to_json()
    parsed = PwPrefs.from_json(raw)
    assert parsed == p


def test_from_json_handles_none():
    assert PwPrefs.from_json(None) == PwPrefs()


def test_from_json_handles_empty():
    assert PwPrefs.from_json("") == PwPrefs()


def test_from_json_handles_garbage():
    assert PwPrefs.from_json("not-json") == PwPrefs()


def test_from_json_partial_keys():
    p = PwPrefs.from_json('{"length": 30}')
    assert p.length == 30
    assert p.upper is True  # default
