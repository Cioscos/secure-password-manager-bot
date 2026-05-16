import pytest

from password_bot.services.strength_meter import StrengthMeter, StrengthResult


@pytest.fixture
def meter():
    return StrengthMeter()


def test_weak_password(meter: StrengthMeter):
    r: StrengthResult = meter.evaluate("password")
    assert r.score <= 1
    assert r.crack_time_display is not None


def test_strong_password(meter: StrengthMeter):
    r = meter.evaluate("c0rrect-h0rse_BATTERY-staple-9q!")
    assert r.score >= 3


def test_returns_suggestions(meter: StrengthMeter):
    r = meter.evaluate("abc")
    assert isinstance(r.suggestions, list)


def test_empty_password_returns_zero_score(meter: StrengthMeter):
    r = meter.evaluate("")
    assert r.score == 0
    assert r.crack_time_display == ""
    assert r.suggestions == []
    assert r.warning == ""


def test_none_like_empty(meter: StrengthMeter):
    # `evaluate("")` is the contract; this just exercises the guard explicitly.
    r = meter.evaluate("")
    assert isinstance(r.warning, str)
