"""Handler tree, registry completeness, slash commands, legacy cleanup, error handler."""

from __future__ import annotations

import pickle
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from telegram import Chat, Document, Message, Update
from telegram.ext import CallbackQueryHandler, MessageHandler

from password_bot.bot import _SessionStrippingPersistence, build_application
from password_bot.config import AppConfig
from password_bot.handlers import common
from password_bot.state.fsm import Frame
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.callback_data import ListPageData
from password_bot.ui import commands
from password_bot.ui.legacy import clean_chat_data, cleanup_legacy_chat_data
from password_bot.ui.navigator import Navigator
from password_bot.ui.registry import build_screens
from tests.ui._helpers import FakeBot

NAV_STACK = ChatDataKey.NAV_STACK.value
LIVE = ChatDataKey.LIVE_MESSAGE_ID.value

ALL_SCREENS = {
    "home",
    "unlock",
    "help",
    "account_list",
    "search",
    "account_detail",
    "history",
    "account_delete",
    "account_edit",
    "field_edit",
    "generator",
    "password_change",
    "account_new",
    "categories",
    "category_pick",
    "category_form",
    "category_icon",
    "category_delete",
    "health",
    "settings",
    "transfer",
}


def test_registry_is_complete():
    screens = build_screens()
    assert set(screens) == ALL_SCREENS
    assert all(screen.title for screen in screens.values())


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYRING", str(tmp_path))
    config = AppConfig.load(base_dir=tmp_path)
    return build_application(config, token="0:dummy", dev_chat_id=0)


def test_every_callback_goes_through_the_navigator(app):
    root = next(h for h in app.handlers[0] if getattr(h, "name", None) == "root")
    callback_handlers = [h for h in root.states[0] if isinstance(h, CallbackQueryHandler)]
    assert [h.callback for h in callback_handlers] == [commands.on_callback]
    assert root.allow_reentry is True


def test_clean_chat_data_drops_old_ui_state():
    screens = build_screens()
    data = {
        "pending_input": {"field": "_search_query"},
        "pending_new_account": {"password": "plaintext!"},
        "pw_gen_draft": {},
        "pw_gen_return_to": "account_new",
        "pending_import_file": b"x",
        NAV_STACK: [Frame("menu", {})],
        LIVE: 3,
    }
    assert clean_chat_data(data, screens) is True
    assert data == {NAV_STACK: [], LIVE: 3}
    assert clean_chat_data(data, screens) is False


def test_cleanup_marks_changed_chats_for_persistence():
    app = SimpleNamespace(
        bot_data={"screens": build_screens()},
        chat_data={1: {"pending_input": {}}, 2: {}},
        mark_data_for_update_persistence=MagicMock(),
    )
    cleanup_legacy_chat_data(app)
    app.mark_data_for_update_persistence.assert_called_once_with(chat_ids=[1])


def test_legacy_list_page_payload_still_unpickles():
    assert pickle.loads(pickle.dumps(ListPageData(page=2))) == ListPageData(page=2)


def test_text_and_document_handlers_ignore_edited_messages(app):
    root = next(h for h in app.handlers[0] if getattr(h, "name", None) == "root")
    message_handlers = [h for h in root.states[0] if isinstance(h, MessageHandler)]
    assert message_handlers, "expected the text/document MessageHandlers to be registered"

    chat = Chat(id=1, type=Chat.PRIVATE)
    text_message = Message(
        message_id=1,
        date=None,
        chat=chat,
        text="hello",
        from_user=None,  # type: ignore[arg-type]
    )
    edited_text_message = Message(
        message_id=1,
        date=None,
        chat=chat,
        text="hello edited",
        from_user=None,  # type: ignore[arg-type]
    )
    document_message = Message(
        message_id=2,
        date=None,  # type: ignore[arg-type]
        chat=chat,
        document=Document(file_id="f", file_unique_id="u"),
    )
    edited_document_message = Message(
        message_id=2,
        date=None,  # type: ignore[arg-type]
        chat=chat,
        document=Document(file_id="f", file_unique_id="u"),
    )

    new_text_update = Update(update_id=1, message=text_message)
    edited_text_update = Update(update_id=2, edited_message=edited_text_message)
    new_document_update = Update(update_id=3, message=document_message)
    edited_document_update = Update(update_id=4, edited_message=edited_document_message)

    # At least one handler must accept an ordinary new text/document message...
    assert any(h.check_update(new_text_update) for h in message_handlers)
    assert any(h.check_update(new_document_update) for h in message_handlers)
    # ...but none may accept the edited counterpart (update.message would be None).
    for handler in message_handlers:
        assert not handler.check_update(edited_text_update)
        assert not handler.check_update(edited_document_update)


def _context(env, args):
    return SimpleNamespace(
        args=args,
        application=SimpleNamespace(
            bot_data={"container": env.container, "screens": build_screens()}, job_queue=None
        ),
        bot=FakeBot(),
        chat_data=env.chat_data,
    )


def _update():
    return SimpleNamespace(
        effective_chat=SimpleNamespace(id=1), effective_user=SimpleNamespace(full_name="Me")
    )


async def test_get_command_opens_detail_or_search(env, monkeypatch):
    acc = await env.add("Netflix")
    await env.add("GitHub")
    await env.add("GitLab")
    calls = []

    async def fake_command(self, name, args=None):
        calls.append((name, args))

    monkeypatch.setattr(Navigator, "command", fake_command)
    await commands.cmd_get(_update(), _context(env, ["netflix"]))
    await commands.cmd_get(_update(), _context(env, ["git"]))
    await commands.cmd_get(_update(), _context(env, []))
    assert calls == [
        ("account_detail", {"id": acc.id}),
        ("search", {"q": "git"}),
        ("search", None),
    ]


async def test_open_command_sends_screen_in_new_message(env):
    context = _context(env, [])
    await commands.open_command("settings")(_update(), context)
    assert "Impostazioni" in context.bot.sent[-1].text


async def test_start_returns_the_conversation_state(env):
    context = _context(env, [])
    assert await commands.cmd_start(_update(), context) == commands.ROOT_STATE
    assert "Menu principale" in context.bot.sent[-1].text


async def test_error_handler_edits_the_live_message():
    bot = FakeBot()
    app = SimpleNamespace(
        bot_data={"container": SimpleNamespace(dev_chat_id=None), "screens": build_screens()},
        job_queue=None,
    )
    context = SimpleNamespace(
        error=RuntimeError("boom"), application=app, bot=bot, chat_data={LIVE: 5}
    )
    update = MagicMock(spec=Update)
    update.effective_chat = SimpleNamespace(id=1)
    await common.error_handler(update, context)
    assert bot.edits[-1].message_id == 5
    assert "Errore interno" in bot.edits[-1].text


async def test_sensitive_flow_is_absent_after_disk_reload(tmp_path):
    path = tmp_path / "state.pkl"
    persistence = _SessionStrippingPersistence(filepath=path)
    await persistence.update_chat_data(
        1,
        {
            ChatDataKey.SESSION.value: {"key": "KEY_SENTINEL"},
            ChatDataKey.FLOW.value: {"account_new": {"password": "SECRET_SENTINEL"}},
            ChatDataKey.NAV_STACK.value: [Frame("account_list", {})],
        },
    )
    await persistence.flush()
    assert b"SECRET_SENTINEL" not in path.read_bytes()
    assert b"KEY_SENTINEL" not in path.read_bytes()
    reloaded = await _SessionStrippingPersistence(filepath=path).get_chat_data()
    assert reloaded[1] == {ChatDataKey.NAV_STACK.value: [Frame("account_list", {})]}
