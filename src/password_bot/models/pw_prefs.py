"""User-saved defaults for the password generator."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass


@dataclass(slots=True)
class PwPrefs:
    length: int = 20
    upper: bool = True
    lower: bool = True
    digits: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = False
    no_duplicates: bool = False

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str | None) -> PwPrefs:
        if not raw:
            return cls()
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            return cls()
        defaults = cls()
        return cls(
            length=int(data.get("length", defaults.length)),
            upper=bool(data.get("upper", defaults.upper)),
            lower=bool(data.get("lower", defaults.lower)),
            digits=bool(data.get("digits", defaults.digits)),
            symbols=bool(data.get("symbols", defaults.symbols)),
            exclude_ambiguous=bool(data.get("exclude_ambiguous", defaults.exclude_ambiguous)),
            no_duplicates=bool(data.get("no_duplicates", defaults.no_duplicates)),
        )
