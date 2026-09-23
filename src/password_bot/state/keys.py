"""Typed keys for context.chat_data. Never use raw strings."""

from __future__ import annotations

from enum import StrEnum


class ChatDataKey(StrEnum):
    SESSION = "session"
    NAV_STACK = "nav_stack"
    LEGACY_SESSION_EXTRAS = "legacy_session_extras"
    FLOW = "flow"  # in-progress flow drafts (may hold secrets); never persisted
    LIVE_MESSAGE_ID = "live_message_id"  # the single bot message that carries buttons
    LIVE_TOKEN = "live_token"  # bumped on every render; guards auto-close jobs
    RESUME = "resume"  # Frame to reopen after unlocking
