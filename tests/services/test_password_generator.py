import string

import pytest

from password_bot.services.password_generator import (
    PasswordCharset,
    PasswordGenerator,
    PasswordSpec,
)


@pytest.fixture
def gen():
    return PasswordGenerator()


def test_length_respected(gen: PasswordGenerator):
    pw = gen.generate(PasswordSpec(length=20, charset=PasswordCharset.ALPHANUM_SYMBOLS))
    assert len(pw) == 20


def test_alphanumeric_only(gen: PasswordGenerator):
    pw = gen.generate(PasswordSpec(length=32, charset=PasswordCharset.ALPHANUM))
    allowed = set(string.ascii_letters + string.digits)
    assert set(pw) <= allowed


def test_digits_only(gen: PasswordGenerator):
    pw = gen.generate(PasswordSpec(length=8, charset=PasswordCharset.DIGITS))
    assert pw.isdigit()


def test_at_least_one_of_each_class_when_symbols(gen: PasswordGenerator):
    pw = gen.generate(PasswordSpec(length=12, charset=PasswordCharset.ALPHANUM_SYMBOLS))
    assert any(c.islower() for c in pw)
    assert any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(not c.isalnum() for c in pw)


def test_length_too_short_raises(gen: PasswordGenerator):
    with pytest.raises(ValueError):
        gen.generate(PasswordSpec(length=2, charset=PasswordCharset.ALPHANUM_SYMBOLS))
