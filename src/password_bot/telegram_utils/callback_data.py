"""Legacy callback payload of the old paginated /list.

No longer produced. Kept only because PTB's pickled callback-data cache in an
existing DB.pkl may still reference `ListPageData`; removing it would make
the bot crash while loading persistence.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ListPageData:
    """Page-nav button payload for the paginated `/list` keyboard."""

    page: int
