"""Fakes for Telegram objects and helpers to inspect rendered views."""

from __future__ import annotations

from dataclasses import replace as dc_replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

from telegram import InlineKeyboardButton

from password_bot.ui.callbacks import Act
from password_bot.ui.screen import View


class FakeBot:
    def __init__(self) -> None:
        self.sent: list[SimpleNamespace] = []
        self.edits: list[SimpleNamespace] = []
        self.deleted: list[int] = []
        self.next_id = 100
        self.edit_error: Exception | None = None
        self.send_error: Exception | None = None
        self.documents: list[SimpleNamespace] = []

    async def send_message(self, *, chat_id, text, **kw):
        if self.send_error is not None:
            raise self.send_error
        self.next_id += 1
        self.sent.append(SimpleNamespace(chat_id=chat_id, text=text, message_id=self.next_id, **kw))
        return SimpleNamespace(message_id=self.next_id)

    async def edit_message_text(self, *, text, chat_id, message_id, **kw):
        if self.edit_error is not None:
            raise self.edit_error
        self.edits.append(SimpleNamespace(text=text, message_id=message_id, **kw))

    async def delete_message(self, *, chat_id, message_id):
        self.deleted.append(message_id)

    async def send_document(self, *, chat_id, document, filename, caption=None, **kw):
        self.documents.append(
            SimpleNamespace(
                chat_id=chat_id, data=document.read(), filename=filename, caption=caption
            )
        )
        return SimpleNamespace(message_id=0)


class FakeJob:
    def __init__(self, callback, when, chat_id, data, name):
        self.callback, self.when, self.chat_id, self.data, self.name = (
            callback,
            when,
            chat_id,
            data,
            name,
        )
        self.removed = False

    def schedule_removal(self):
        self.removed = True


class FakeJobQueue:
    def __init__(self):
        self.jobs: list[FakeJob] = []

    def run_once(self, callback, when, chat_id=None, data=None, name=None):
        job = FakeJob(callback, when, chat_id, data, name)
        self.jobs.append(job)
        return job

    def get_jobs_by_name(self, name):
        return [j for j in self.jobs if j.name == name and not j.removed]


def buttons(view: View) -> list[InlineKeyboardButton]:
    if view.keyboard is None:
        return []
    return [b for row in view.keyboard.inline_keyboard for b in row]


def labels(view: View) -> list[str]:
    return [b.text for b in buttons(view)]


def button(view: View, text: str) -> InlineKeyboardButton:
    """Button whose label equals `text`, else the first one starting with it."""
    for b in buttons(view):
        if b.text == text:
            return b
    for b in buttons(view):
        if b.text.startswith(text):
            return b
    raise AssertionError(f"No button {text!r} in {labels(view)}")


def act(view: View, text: str) -> Act:
    data = button(view, text).callback_data
    assert isinstance(data, Act), data
    return data


def callback(data, message_id, *, token=None):
    if isinstance(data, Act) and data.token is None:
        data = dc_replace(data, token=token)
    query = SimpleNamespace(
        data=data,
        message=SimpleNamespace(message_id=message_id),
        answer=AsyncMock(),
        edit_message_reply_markup=AsyncMock(),
    )
    return SimpleNamespace(
        callback_query=query,
        effective_user=SimpleNamespace(full_name="Me"),
        effective_chat=SimpleNamespace(id=1),
    )


def text_message(text):
    message = SimpleNamespace(text=text, delete=AsyncMock(), document=None)
    return SimpleNamespace(
        message=message,
        effective_user=SimpleNamespace(full_name="Me"),
        effective_chat=SimpleNamespace(id=1),
    )


def stack(nav):
    return [f.name for f in nav.fsm.frames()]
