"""Result type for expected-failure flows."""

from __future__ import annotations

from dataclasses import dataclass

from password_bot.services.errors import DomainError


@dataclass(slots=True)
class Result[T]:
    value: T | None
    error: DomainError | None

    @classmethod
    def success(cls, value: T) -> Result[T]:
        return cls(value=value, error=None)

    @classmethod
    def err(cls, error: DomainError) -> Result[T]:
        return cls(value=None, error=error)

    @property
    def ok(self) -> bool:
        return self.error is None
