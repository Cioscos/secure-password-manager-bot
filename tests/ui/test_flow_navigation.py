"""Regression: creation-flow interactions across the Navigator (lock/resume, generator hand-off)."""

from __future__ import annotations

from types import SimpleNamespace

from password_bot.state.keys import ChatDataKey
from password_bot.ui.navigator import Navigator
from password_bot.ui.registry import build_screens
from password_bot.ui.screen import open_screen
from tests.ui._helpers import FakeBot, FakeJobQueue, text_message
from tests.ui.conftest import PASSPHRASE


async def test_generator_lock_resumes_creation_root_through_navigator(env):
    bot = FakeBot()
    app = SimpleNamespace(
        bot_data={"container": env.container, "screens": build_screens()}, job_queue=FakeJobQueue()
    )
    nav = Navigator(application=app, bot=bot, chat_id=1, chat_data=env.chat_data)
    await nav.command("account_new")
    await nav.on_text(text_message("Example"))
    await nav.apply(open_screen("generator", flow="account_new", next_step="summary"))
    await nav.lock()
    assert env.chat_data[ChatDataKey.RESUME.value].name == "account_new"
    await nav.on_text(text_message(PASSPHRASE))
    assert [f.name for f in nav.fsm.frames()] == ["home", "account_new"]
    assert env.chat_data[ChatDataKey.FLOW.value]["account_new"]["step"] == "name"
