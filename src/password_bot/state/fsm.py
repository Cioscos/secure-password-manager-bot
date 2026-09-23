"""Typed wrapper over context.chat_data."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from password_bot.state.keys import ChatDataKey


@dataclass(slots=True)
class Frame:
    """One navigation-stack entry: a screen name and its non-secret args."""

    name: str
    data: dict[str, Any] = field(default_factory=dict)


# Stack entries in existing DB.pkl files were pickled as `password_bot.state.fsm.Screen`.
# Keep that name importable or loading an old DB.pkl crashes the bot at startup.
Screen = Frame


class FsmContext:
    """Thin wrapper that lets handlers read/write chat_data with typed keys."""

    def __init__(self, chat_data: dict[str, Any]) -> None:
        self._chat_data = chat_data

    def _stack(self) -> list[Frame]:
        raw = self._chat_data.get(ChatDataKey.NAV_STACK.value)
        if raw is None:
            raw = []
            self._chat_data[ChatDataKey.NAV_STACK.value] = raw
        return raw

    def push(self, frame: Frame) -> None:
        self._stack().append(frame)

    def pop(self) -> Frame | None:
        st = self._stack()
        return st.pop() if st else None

    def top(self) -> Frame:
        st = self._stack()
        if not st:
            raise IndexError("Empty nav stack")
        return st[-1]

    def depth(self) -> int:
        return len(self._stack())

    def frames(self) -> list[Frame]:
        return list(self._stack())

    def pop_to(self, screen_name: str) -> None:
        st = self._stack()
        while st and st[-1].name != screen_name:
            st.pop()

    def reset_to(self, frame: Frame) -> None:
        self._chat_data[ChatDataKey.NAV_STACK.value] = [frame]

    def set_resume(self, frame: Frame) -> None:
        self._chat_data[ChatDataKey.RESUME.value] = frame

    def pop_resume(self) -> Frame | None:
        return self._chat_data.pop(ChatDataKey.RESUME.value, None)

    def get_pending_input(self) -> dict[str, Any] | None:
        return self._chat_data.get(ChatDataKey.PENDING_INPUT.value)

    def set_pending_input(self, payload: dict[str, Any]) -> None:
        self._chat_data[ChatDataKey.PENDING_INPUT.value] = payload

    def clear_pending_input(self) -> None:
        self._chat_data.pop(ChatDataKey.PENDING_INPUT.value, None)

    def get_session(self) -> Any | None:
        return self._chat_data.get(ChatDataKey.SESSION.value)

    def set_session(self, session: Any) -> None:
        self._chat_data[ChatDataKey.SESSION.value] = session

    def clear_session(self) -> None:
        self._chat_data.pop(ChatDataKey.SESSION.value, None)
        self._chat_data.pop(ChatDataKey.LEGACY_SESSION_EXTRAS.value, None)

    def lock(self) -> None:
        """Drop the session and every in-progress flow, so the next text is a passphrase."""
        self.clear_session()
        for key in (
            ChatDataKey.PENDING_INPUT,
            ChatDataKey.PENDING_NEW_ACCOUNT,
            ChatDataKey.PENDING_IMPORT_FILE,
            ChatDataKey.PW_GEN_DRAFT,
            ChatDataKey.PW_GEN_RETURN_TO,
            ChatDataKey.FLOW,
            ChatDataKey.RESUME,
        ):
            self._chat_data.pop(key.value, None)
        self._chat_data[ChatDataKey.NAV_STACK.value] = []
