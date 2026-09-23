"""Typed callback payload for every UI button (sent via arbitrary_callback_data).

Payloads are pickled into DB.pkl by PTB's callback-data cache: they must only
carry screen/action names, ids, page numbers and list indices — never secrets.
"""

from __future__ import annotations

from dataclasses import dataclass

NAV = "_nav"  # pseudo-screen handled by the Navigator itself: back, home, noop


@dataclass(frozen=True, slots=True)
class Act:
    screen: str
    action: str
    arg: str | int | None = None
    token: int | None = None  # Navigator stamps the current render; no secrets
