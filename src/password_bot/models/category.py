from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Category:
    id: str
    chat_id: int
    name: str
    color: str | None
