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


def test_flags_only_lower(gen: PasswordGenerator):
    pw = gen.generate(PasswordSpec(length=10, upper=False, lower=True, digits=False, symbols=False))
    assert set(pw) <= set(string.ascii_lowercase)


def test_exclude_ambiguous_removes_chars(gen: PasswordGenerator):
    pw = gen.generate(
        PasswordSpec(
            length=64,
            upper=True,
            lower=True,
            digits=True,
            symbols=True,
            exclude_ambiguous=True,
        )
    )
    forbidden = set("0O1lI|`'\".,;: ")
    assert not (set(pw) & forbidden)


def test_no_duplicates_unique_chars(gen: PasswordGenerator):
    pw = gen.generate(
        PasswordSpec(
            length=20, upper=True, lower=True, digits=True, symbols=True, no_duplicates=True
        )
    )
    assert len(set(pw)) == 20


def test_no_class_raises(gen: PasswordGenerator):
    with pytest.raises(ValueError):
        gen.generate(PasswordSpec(length=10, upper=False, lower=False, digits=False, symbols=False))


def test_entropy_bits_positive():
    from password_bot.services.password_generator import entropy_bits

    bits = entropy_bits(PasswordSpec(length=16))
    assert bits > 50
