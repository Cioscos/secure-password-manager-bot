"""Cryptographically random password generation."""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from enum import StrEnum

_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase
_DIGITS = string.digits
_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"


class PasswordCharset(StrEnum):
    DIGITS = "digits"
    ALPHANUM = "alphanum"
    ALPHANUM_SYMBOLS = "alphanum_symbols"


@dataclass(slots=True, frozen=True)
class PasswordSpec:
    length: int
    charset: PasswordCharset


_CHARSET_POOLS: dict[PasswordCharset, list[str]] = {
    PasswordCharset.DIGITS: [_DIGITS],
    PasswordCharset.ALPHANUM: [_LOWER, _UPPER, _DIGITS],
    PasswordCharset.ALPHANUM_SYMBOLS: [_LOWER, _UPPER, _DIGITS, _SYMBOLS],
}


class PasswordGenerator:
    def generate(self, spec: PasswordSpec) -> str:
        pools = _CHARSET_POOLS[spec.charset]
        if spec.length < len(pools):
            raise ValueError(f"Length {spec.length} too short for charset {spec.charset}")
        # Guarantee at least one char from each pool.
        chars = [secrets.choice(pool) for pool in pools]
        all_chars = "".join(pools)
        chars.extend(secrets.choice(all_chars) for _ in range(spec.length - len(pools)))
        # Shuffle in place using secrets.
        for i in range(len(chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            chars[i], chars[j] = chars[j], chars[i]
        return "".join(chars)
