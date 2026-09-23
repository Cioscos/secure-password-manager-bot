"""Typed keys for context.chat_data. Never use raw strings."""

from __future__ import annotations

from enum import StrEnum


class ChatDataKey(StrEnum):
    SESSION = "session"
    NAV_STACK = "nav_stack"
    PENDING_INPUT = "pending_input"
    AUTOLOCK_JOB_NAME = "autolock_job_name"
    PENDING_NEW_ACCOUNT = "pending_new_account"
    PENDING_IMPORT_FILE = "pending_import_file"
    LEGACY_SESSION_EXTRAS = "legacy_session_extras"
    PW_GEN_DRAFT = "pw_gen_draft"
    PW_GEN_RETURN_TO = "pw_gen_return_to"
