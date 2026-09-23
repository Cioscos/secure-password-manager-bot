"""Unlock / setup, home, help, autolock job, registry."""

from __future__ import annotations

from types import SimpleNamespace

from telegram.error import Forbidden

from password_bot.state.fsm import Frame
from password_bot.state.keys import ChatDataKey
from password_bot.ui.callbacks import Act
from password_bot.ui.jobs import autolock_job, schedule_autolock
from password_bot.ui.registry import build_screens
from password_bot.ui.screen import Go, Lock, open_screen, refresh
from password_bot.ui.screens.help import HelpScreen
from password_bot.ui.screens.home import HomeScreen
from password_bot.ui.screens.unlock import UnlockScreen
from tests.ui._helpers import FakeBot, FakeJobQueue, act, labels
from tests.ui.conftest import PASSPHRASE

SESSION = ChatDataKey.SESSION.value
RESUME = ChatDataKey.RESUME.value


async def test_home_has_eight_buttons_and_routes(env):
    screen = HomeScreen()
    view = await screen.render(env.ctx())
    assert labels(view) == [
        "➕ Nuovo",  # noqa: RUF001
        "🔍 Cerca",
        "📚 Lista",
        "🏷 Categorie",
        "🩺 Salute",
        "⚙️ Impostazioni",
        "🔒 Blocca",
        "❓ Help",
    ]
    assert await screen.on_action(env.ctx(), act(view, "🔍 Cerca")) == open_screen("search")
    assert await screen.on_action(env.ctx(), act(view, "🔒 Blocca")) == Lock()
    assert await screen.on_action(env.ctx(), Act("home", "go", "nope")) == refresh()


async def test_unlock_wrong_then_right_passphrase_resumes(env):
    env.chat_data.pop(SESSION)
    screen = UnlockScreen()
    assert "Vault bloccato" in (await screen.render(env.ctx())).text
    result = await screen.on_text(env.ctx(), "nope")
    assert result == refresh(notice="⚠️ Passphrase non corretta.")
    env.chat_data[RESUME] = Frame("account_list", {})
    result = await screen.on_text(env.ctx(), PASSPHRASE)
    assert isinstance(result, Go)
    assert result.home and result.push == Frame("account_list", {})
    assert env.chat_data[SESSION] is not None
    env.application.job_queue.run_once.assert_called_once()


async def test_setup_asks_passphrase_twice(env):
    screen = UnlockScreen()

    def ctx2():
        return env.ctx(chat_id=2)

    assert "Non hai ancora un vault" in (await screen.render(ctx2())).text
    await screen.on_text(ctx2(), "first secret")
    view = await screen.render(ctx2())
    assert "di nuovo" in view.text
    assert "↩️ Ricomincia" in labels(view)
    mismatch = await screen.on_text(ctx2(), "other")
    assert mismatch.notice == "⚠️ Le passphrase non coincidono. Ricominciamo."
    assert await env.container.users.get(2) is None
    await screen.on_text(ctx2(), "first secret")
    created = await screen.on_text(ctx2(), "first secret")
    assert created.home and created.notice == "✅ Vault creato."
    assert await env.container.users.get(2) is not None


async def test_help_lists_commands_with_footer(env):
    view = await HelpScreen().render(env.ctx(back_label="Sblocco"))
    assert "/add" in view.text and "/get NOME" in view.text
    assert labels(view) == ["🔙 Sblocco", "🏠 Menu"]


def test_schedule_autolock_replaces_previous_job():
    jq = FakeJobQueue()
    app = SimpleNamespace(job_queue=jq)
    schedule_autolock(app, 1, expires_at=0)
    schedule_autolock(app, 1, expires_at=0)
    live = jq.get_jobs_by_name("autolock:1")
    assert len(live) == 1 and live[0].when == 1 and live[0].chat_id == 1


async def test_autolock_job_locks_and_shows_unlock(env):
    bot = FakeBot()
    app = SimpleNamespace(
        bot_data={"container": env.container, "screens": build_screens()}, job_queue=FakeJobQueue()
    )
    env.session.expires_at = 0
    context = SimpleNamespace(
        application=app, bot=bot, chat_data=env.chat_data, job=SimpleNamespace(chat_id=1, data=0)
    )
    await autolock_job(context)
    assert SESSION not in env.chat_data
    assert "Vault bloccato" in bot.sent[-1].text


async def test_autolock_job_tolerates_blocked_user(env):
    bot = FakeBot()
    bot.send_error = Forbidden("Forbidden: bot was blocked by the user")
    app = SimpleNamespace(
        bot_data={"container": env.container, "screens": build_screens()}, job_queue=FakeJobQueue()
    )
    env.session.expires_at = 0
    context = SimpleNamespace(
        application=app, bot=bot, chat_data=env.chat_data, job=SimpleNamespace(chat_id=1, data=0)
    )
    await autolock_job(context)  # must not raise
    assert SESSION not in env.chat_data


def test_registry_contains_session_screens():
    assert {"home", "unlock", "help"} <= set(build_screens())
