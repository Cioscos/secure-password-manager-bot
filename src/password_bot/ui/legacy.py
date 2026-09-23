"""One-time cleanup of chat_data written by the old (pre-Navigator) UI."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from password_bot.state.keys import ChatDataKey

# Old keys (some held plaintext drafts, e.g. the new-account password).
LEGACY_KEYS = (
    "pending_input",
    "pending_new_account",
    "pending_import_file",
    "pw_gen_draft",
    "pw_gen_return_to",
    "reuse_detector",
    "autolock_job_name",
)


def clean_chat_data(data: dict[str, Any], screens: Mapping[str, Any]) -> bool:
    """Drop old-UI keys and stacks with unknown screens. Returns True if anything changed."""
    changed = False
    for key in LEGACY_KEYS:
        if key in data:
            del data[key]
            changed = True
    stack = data.get(ChatDataKey.NAV_STACK.value) or []
    if any(getattr(frame, "name", None) not in screens for frame in stack):
        data[ChatDataKey.NAV_STACK.value] = []
        changed = True
    return changed


def cleanup_legacy_chat_data(application: Any) -> None:
    screens = application.bot_data["screens"]
    changed = [
        chat_id for chat_id, data in application.chat_data.items() if clean_chat_data(data, screens)
    ]
    if changed:
        application.mark_data_for_update_persistence(chat_ids=changed)
