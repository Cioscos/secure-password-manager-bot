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
