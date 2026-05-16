"""Typed payloads for `arbitrary_callback_data=True`.

PTB wraps these instances on the wire as UUID stand-ins and restores them on
the way back, bypassing the 64-byte string limit on `callback_data`. Caching
is per-Bot with a default max of 1024 entries — see `ApplicationBuilder
.arbitrary_callback_data`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ListPageData:
    """Page-nav button payload for the paginated `/list` keyboard."""

    page: int
