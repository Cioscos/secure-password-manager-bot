"""Cryptographically random password generation."""

from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass
from enum import StrEnum

_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase
_DIGITS = string.digits
_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
_AMBIGUOUS = set("0O1lI|`'\".,;: ")

MIN_LENGTH = 4
MAX_LENGTH = 128


class PasswordCharset(StrEnum):
    """Legacy charset preset, kept for backward compatibility."""

    DIGITS = "digits"
    ALPHANUM = "alphanum"
    ALPHANUM_SYMBOLS = "alphanum_symbols"


@dataclass(slots=True, frozen=True)
class PasswordSpec:
    length: int
    upper: bool = True
    lower: bool = True
    digits: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = False
    no_duplicates: bool = False
    charset: PasswordCharset | None = None  # only for legacy callers

    def pools(self) -> list[str]:
        if self.charset is not None:
            return _legacy_pools(self.charset, self.exclude_ambiguous)
        pools: list[str] = []
        if self.upper:
            pools.append(_filter(_UPPER, self.exclude_ambiguous))
        if self.lower:
            pools.append(_filter(_LOWER, self.exclude_ambiguous))
        if self.digits:
            pools.append(_filter(_DIGITS, self.exclude_ambiguous))
        if self.symbols:
            pools.append(_filter(_SYMBOLS, self.exclude_ambiguous))
        return [p for p in pools if p]


def _filter(pool: str, exclude_ambiguous: bool) -> str:
    if not exclude_ambiguous:
        return pool
    return "".join(ch for ch in pool if ch not in _AMBIGUOUS)


def _legacy_pools(charset: PasswordCharset, exclude_ambiguous: bool) -> list[str]:
    mapping = {
        PasswordCharset.DIGITS: [_DIGITS],
        PasswordCharset.ALPHANUM: [_LOWER, _UPPER, _DIGITS],
        PasswordCharset.ALPHANUM_SYMBOLS: [_LOWER, _UPPER, _DIGITS, _SYMBOLS],
    }
    return [_filter(p, exclude_ambiguous) for p in mapping[charset]]


class PasswordGenerator:
    def generate(self, spec: PasswordSpec) -> str:
        pools = spec.pools()
        if not pools:
            raise ValueError("Nessuna classe di caratteri selezionata.")
        if spec.length < max(MIN_LENGTH, len(pools)):
            raise ValueError(
                f"Lunghezza {spec.length} insufficiente (minimo {max(MIN_LENGTH, len(pools))})."
            )
        if spec.length > MAX_LENGTH:
            raise ValueError(f"Lunghezza massima {MAX_LENGTH}.")
        all_chars = "".join(pools)
        if spec.no_duplicates and len(set(all_chars)) < spec.length:
            raise ValueError("Pool di caratteri troppo piccolo per generare senza duplicati.")

        chars = [secrets.choice(pool) for pool in pools]
        if spec.no_duplicates:
            unique_universe = list(set(all_chars))
            used = set(chars)
            remaining = [c for c in unique_universe if c not in used]
            secrets.SystemRandom().shuffle(remaining)
            needed = spec.length - len(chars)
            if needed > len(remaining):
                raise ValueError("Pool insufficiente per no-duplicati.")
            chars.extend(remaining[:needed])
        else:
            chars.extend(secrets.choice(all_chars) for _ in range(spec.length - len(pools)))

        for i in range(len(chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            chars[i], chars[j] = chars[j], chars[i]
        return "".join(chars)


def entropy_bits(spec: PasswordSpec) -> float:
    pools = spec.pools()
    if not pools:
        return 0.0
    pool_size = len(set("".join(pools)))
    if pool_size <= 1:
        return 0.0
    return spec.length * math.log2(pool_size)
