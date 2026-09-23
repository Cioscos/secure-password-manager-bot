"""Navigator: single live message, stack semantics, routing, locking, auto-close."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from telegram.error import BadRequest

from password_bot.state.fsm import Frame
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import NAV, Act
from password_bot.ui.navigator import (
    LOCKED_TOAST,
    STALE_BUTTON,
    Navigator,
    autolock_job_name,
    expire_job_name,
)
from password_bot.ui.screen import (
    TEXT_NOT_ACCEPTED,
    Go,
    Lock,
    Reveal,
    Screen,
    View,
    open_screen,
    refresh,
)
from password_bot.ui.views import btn, footer, keyboard
from tests.ui._helpers import FakeBot, FakeJobQueue, callback, stack, text_message

LIVE = ChatDataKey.LIVE_MESSAGE_ID.value
SESSION = ChatDataKey.SESSION.value
RESUME = ChatDataKey.RESUME.value


class Home(Screen):
    name = "home"
    title = "Home"

    async def render(self, ctx):
        return View("home", keyboard([btn("open", self.name, "open")]))

    async def on_action(self, ctx, act):
        if act.action == "open":
            return open_screen("items", page=1)
        if act.action == "lock":
            return Lock()
        return refresh()


class Items(Screen):
    name = "items"
    title = "Lista"
    accepts_text = True

    async def render(self, ctx):
        return View(
            f"items {ctx.args.get('page')} back={ctx.back_label}",
            keyboard([btn("detail", self.name, "detail")], footer(ctx.back_label)),
        )

    async def on_action(self, ctx, act):
        if act.action == "detail":
            return open_screen("detail", id="a1")
        return refresh(toast="ok")

    async def on_text(self, ctx, text):
        return refresh(notice=f"got {text}")


class Detail(Screen):
    name = "detail"
    title = "Dettaglio"

    async def render(self, ctx):
        return View("detail", keyboard(footer(ctx.back_label)), expire_after=60)

    async def render_expired(self, ctx):
        return View("closed")

    async def on_action(self, ctx, act):
        if act.action == "reveal":
            return Reveal("s3cr`t")
        if act.action == "delete":
            return Go(pop_to="detail", pop_to_inclusive=True, toast="deleted")
        return refresh()


class Unlock(Screen):
    name = "unlock"
    title = "Sblocco"
    requires_session = False
    accepts_text = True

    async def render(self, ctx):
        return View("unlock")

    async def on_text(self, ctx, text):
        if text != "pw":
            return refresh(notice="wrong")
        ctx.fsm.set_session(SimpleNamespace(expires_at=float("inf")))
        return Go(home=True, push=ctx.fsm.pop_resume())


# --- Stub screens used only to exercise Navigator._resume_target's mapping ---


class AccountDetail(Screen):
    name = "account_detail"
    title = "Account"

    async def render(self, ctx):
        return View("account_detail")


class FieldEdit(Screen):
    name = "field_edit"
    title = "Modifica campo"

    async def render(self, ctx):
        return View("field_edit")


class PasswordChange(Screen):
    name = "password_change"
    title = "Cambia password"

    async def render(self, ctx):
        return View("password_change")


class HistoryScreen(Screen):
    name = "history"
    title = "Storico"

    async def render(self, ctx):
        return View("history")


class AccountDelete(Screen):
    name = "account_delete"
    title = "Elimina account"

    async def render(self, ctx):
        return View("account_delete")


class AccountNew(Screen):
    name = "account_new"
    title = "Nuovo account"

    async def render(self, ctx):
        return View("account_new")


class Generator(Screen):
    name = "generator"
    title = "Generatore"

    async def render(self, ctx):
        return View("generator")


class CategoryPick(Screen):
    name = "category_pick"
    title = "Categoria"

    async def render(self, ctx):
        return View("category_pick")


def make_nav(*, locked: bool = False, chat_data: dict | None = None, extra_screens=()):
    screens = {s.name: s for s in (Home(), Items(), Detail(), Unlock(), *extra_screens)}
    bot = FakeBot()
    jq = FakeJobQueue()
    app = SimpleNamespace(
        bot_data={"container": SimpleNamespace(), "screens": screens}, job_queue=jq
    )
    data = {} if chat_data is None else chat_data
    if not locked:
        data[SESSION] = SimpleNamespace(expires_at=float("inf"))
    return Navigator(application=app, bot=bot, chat_id=1, chat_data=data), bot, jq


async def test_command_sends_new_live_message_and_deletes_previous():
    nav, bot, _ = make_nav(chat_data={LIVE: 7})
    await nav.command("items", {"page": 2})
    assert bot.deleted == [7]
    assert bot.sent[-1].text == "items 2 back=Home"
    assert nav.chat_data[LIVE] == bot.sent[-1].message_id
    assert stack(nav) == ["home", "items"]


async def test_callback_edits_live_message_in_place():
    nav, bot, _ = make_nav()
    await nav.command("home")
    live = nav.chat_data[LIVE]
    update = callback(
        Act("home", "open"), live, token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value)
    )
    await nav.on_callback(update)
    assert bot.edits[-1].message_id == live
    assert bot.edits[-1].text == "items 1 back=Home"
    update.callback_query.answer.assert_awaited_once_with(None)


async def test_toast_is_the_callback_answer():
    nav, _, _ = make_nav()
    await nav.command("items")
    update = callback(
        Act("items", "other"),
        nav.chat_data[LIVE],
        token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value),
    )
    await nav.on_callback(update)
    update.callback_query.answer.assert_awaited_once_with("ok")


async def test_edit_failure_falls_back_to_new_message():
    nav, bot, _ = make_nav()
    await nav.command("home")
    old = nav.chat_data[LIVE]
    bot.edit_error = BadRequest("Message to edit not found")
    await nav.on_callback(
        callback(Act("home", "open"), old, token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value))
    )
    assert old in bot.deleted
    assert nav.chat_data[LIVE] != old
    assert bot.sent[-1].text.startswith("items")


async def test_not_modified_is_ignored():
    nav, bot, _ = make_nav()
    await nav.command("home")
    bot.edit_error = BadRequest("Message is not modified: specified new message content")
    sent = len(bot.sent)
    await nav.show()
    assert len(bot.sent) == sent


async def test_back_and_home_navigation():
    nav, bot, _ = make_nav()
    await nav.command("items")
    live = nav.chat_data[LIVE]
    await nav.on_callback(
        callback(
            Act("items", "detail"), live, token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value)
        )
    )
    assert stack(nav) == ["home", "items", "detail"]
    assert bot.edits[-1].reply_markup.inline_keyboard[0][0].text == "🔙 Lista"
    await nav.on_callback(
        callback(Act(NAV, "back"), live, token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value))
    )
    assert stack(nav) == ["home", "items"]
    await nav.on_callback(
        callback(Act(NAV, "home"), live, token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value))
    )
    assert stack(nav) == ["home"]


async def test_pop_to_inclusive_returns_below_the_frame():
    nav, _, _ = make_nav()
    await nav.command("items")
    live = nav.chat_data[LIVE]
    await nav.on_callback(
        callback(
            Act("items", "detail"), live, token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value)
        )
    )
    update = callback(
        Act("detail", "delete"), live, token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value)
    )
    await nav.on_callback(update)
    assert stack(nav) == ["home", "items"]
    update.callback_query.answer.assert_awaited_once_with("deleted")


async def test_text_is_deleted_and_routed_to_top_screen():
    nav, bot, _ = make_nav()
    await nav.command("items")
    update = text_message("hello")
    await nav.on_text(update)
    update.message.delete.assert_awaited_once()
    assert bot.edits[-1].text.startswith("got hello")


async def test_text_on_screen_without_input_shows_notice():
    nav, bot, _ = make_nav()
    await nav.command("home")
    await nav.on_text(text_message("hello"))
    assert bot.edits[-1].text.startswith(escape_md(TEXT_NOT_ACCEPTED))


async def test_button_for_another_screen_rerenders_without_acting():
    nav, _, _ = make_nav()
    await nav.command("items")
    update = callback(
        Act("home", "open"),
        nav.chat_data[LIVE],
        token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value),
    )
    await nav.on_callback(update)
    update.callback_query.answer.assert_awaited_once_with(STALE_BUTTON)
    assert stack(nav) == ["home", "items"]


async def test_button_on_old_message_opens_home_in_new_message():
    nav, bot, _ = make_nav()
    await nav.command("items")
    live = nav.chat_data[LIVE]
    update = callback(
        Act("items", "detail"), live - 50, token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value)
    )
    await nav.on_callback(update)
    update.callback_query.answer.assert_awaited_once_with(STALE_BUTTON)
    update.callback_query.edit_message_reply_markup.assert_awaited_once_with(reply_markup=None)
    assert stack(nav) == ["home"]
    assert nav.chat_data[LIVE] == bot.sent[-1].message_id != live


async def test_legacy_string_callback_is_stale():
    nav, _, _ = make_nav()
    await nav.command("items")
    update = callback(
        "view:show:password:x",
        nav.chat_data[LIVE],
        token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value),
    )
    await nav.on_callback(update)
    update.callback_query.answer.assert_awaited_once_with(STALE_BUTTON)
    assert stack(nav) == ["home"]


async def test_missing_live_id_adopts_the_pressed_message():
    nav, bot, _ = make_nav()
    nav.chat_data[ChatDataKey.LIVE_TOKEN.value] = 1
    nav.fsm.reset_to(Frame("home"))
    nav.fsm.push(Frame("items", {"page": 1}))
    await nav.on_callback(
        callback(Act("items", "detail"), 55, token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value))
    )
    assert bot.edits[-1].message_id == 55
    assert nav.chat_data[LIVE] == 55


async def test_locked_button_parks_target_then_resumes_after_unlock():
    nav, _, _ = make_nav()
    await nav.command("items")
    del nav.chat_data[SESSION]
    update = callback(
        Act("items", "detail"),
        nav.chat_data[LIVE],
        token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value),
    )
    await nav.on_callback(update)
    update.callback_query.answer.assert_awaited_once_with(LOCKED_TOAST)
    assert stack(nav) == ["unlock"]
    assert nav.chat_data[RESUME].name == "items"
    await nav.on_text(text_message("pw"))
    assert stack(nav) == ["home", "items"]


async def test_locked_text_goes_to_unlock():
    nav, bot, _ = make_nav()
    await nav.command("items")
    del nav.chat_data[SESSION]
    await nav.on_text(text_message("nope"))
    assert stack(nav) == ["unlock"]
    assert bot.edits[-1].text.startswith("wrong")


async def test_command_while_locked_parks_and_shows_unlock():
    nav, bot, _ = make_nav(locked=True)
    await nav.command("items", {"page": 3})
    assert stack(nav) == ["unlock"]
    assert nav.chat_data[RESUME] == Frame("items", {"page": 3})
    assert bot.sent[-1].text == "unlock"


async def test_lock_resets_to_unlock_and_cancels_jobs():
    nav, bot, jq = make_nav()
    await nav.command("items")
    autolock = jq.run_once(None, 60, chat_id=1, name=autolock_job_name(1))
    await nav.apply(Lock())
    assert stack(nav) == ["unlock"]
    assert SESSION not in nav.chat_data
    assert autolock.removed
    assert bot.edits[-1].text == escape_md("🔒 Sessione bloccata.") + "\n\nunlock"


async def test_detail_expires_into_closed_view():
    nav, bot, jq = make_nav()
    await nav.command("items")
    await nav.on_callback(
        callback(
            Act("items", "detail"),
            nav.chat_data[LIVE],
            token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value),
        )
    )
    job = jq.get_jobs_by_name(expire_job_name(1))[0]
    assert job.when == 60
    await nav.on_expired(job.data)
    assert bot.edits[-1].text == "closed"


async def test_expiry_is_ignored_after_navigating_away():
    nav, bot, jq = make_nav()
    await nav.command("items")
    live = nav.chat_data[LIVE]
    await nav.on_callback(
        callback(
            Act("items", "detail"), live, token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value)
        )
    )
    token = jq.get_jobs_by_name(expire_job_name(1))[0].data
    await nav.on_callback(
        callback(Act(NAV, "back"), live, token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value))
    )
    assert jq.get_jobs_by_name(expire_job_name(1)) == []
    await nav.on_expired(token)
    assert bot.edits[-1].text != "closed"


async def test_reveal_sends_code_message_scheduled_for_deletion():
    nav, bot, jq = make_nav()
    await nav.command("items")
    live = nav.chat_data[LIVE]
    await nav.on_callback(
        callback(
            Act("items", "detail"), live, token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value)
        )
    )
    await nav.on_callback(
        callback(
            Act("detail", "reveal"), live, token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value)
        )
    )
    assert bot.sent[-1].text == "`s3cr\\`t`"
    assert any(j.name.startswith("delete:") and j.when == 30 for j in jq.jobs)


# --- Regression block (Task 16 'Review regressions', included in Task 5) ---


async def test_expired_session_is_rejected_without_waiting_for_job():
    nav, _, _ = make_nav()
    await nav.command("items")
    nav.fsm.get_session().expires_at = 0
    update = callback(
        Act("items", "detail"),
        nav.chat_data[LIVE],
        token=nav.chat_data[ChatDataKey.LIVE_TOKEN.value],
    )
    await nav.on_callback(update)
    assert stack(nav) == ["unlock"]
    assert nav.fsm.get_session() is None
    update.callback_query.answer.assert_awaited_once_with(LOCKED_TOAST)


async def test_explicit_lock_resumes_target_and_discards_draft():
    nav, _, _ = make_nav()
    await nav.command("items", {"page": 3})
    nav.chat_data[ChatDataKey.FLOW.value] = {"items": {"password": "secret"}}
    await nav.lock()
    assert ChatDataKey.FLOW.value not in nav.chat_data
    assert nav.chat_data[RESUME] == Frame("items", {"page": 3})
    await nav.on_text(text_message("pw"))
    assert stack(nav) == ["home", "items"]


async def test_later_home_command_replaces_pending_resume():
    nav, _, _ = make_nav(locked=True)
    await nav.command("items")
    await nav.command("home")
    await nav.on_text(text_message("pw"))
    assert stack(nav) == ["home"]


async def test_old_render_callback_cannot_act_on_same_screen():
    nav, _, _ = make_nav()
    await nav.command("items", {"page": 1})
    old = callback(
        Act("items", "detail"),
        nav.chat_data[LIVE],
        token=nav.chat_data[ChatDataKey.LIVE_TOKEN.value],
    )
    await nav.show()
    await nav.on_callback(old)
    assert stack(nav) == ["home", "items"]
    old.callback_query.answer.assert_awaited_once_with(STALE_BUTTON)


async def test_home_and_back_discard_abandoned_flow():
    nav, _, _ = make_nav()
    await nav.command("items")
    nav.chat_data[ChatDataKey.FLOW.value] = {"items": {"password": "secret"}}
    await nav.apply(Go(pop=1))
    assert not nav.chat_data.get(ChatDataKey.FLOW.value)
    await nav.command("items")
    nav.chat_data[ChatDataKey.FLOW.value] = {"items": {"password": "secret"}}
    await nav.apply(Go(home=True))
    assert not nav.chat_data.get(ChatDataKey.FLOW.value)


async def test_obsolete_autolock_does_not_lock_new_session():
    nav, _, _ = make_nav()
    await nav.command("items")
    await nav.lock(expected_deadline=0)
    assert nav.fsm.get_session() is not None
    assert stack(nav) == ["home", "items"]


async def test_document_is_deleted_when_processing_fails():
    nav, _, _ = make_nav()
    await nav.command("items")
    nav.screens["items"].accepts_document = True
    nav.screens["items"].on_document = AsyncMock(side_effect=RuntimeError("download failed"))
    update = text_message("")
    with pytest.raises(RuntimeError, match="download failed"):
        await nav.on_document(update)
    update.message.delete.assert_awaited_once()


async def test_parser_failure_does_not_delete_live_message():
    nav, bot, _ = make_nav()
    await nav.command("home")
    bot.edit_error = BadRequest("Can't parse entities")
    with pytest.raises(BadRequest):
        await nav.show()
    assert not bot.deleted


async def test_timer_waits_for_in_flight_render_then_locks():
    nav, bot, _ = make_nav()
    await nav.command("items")
    entered, release = asyncio.Event(), asyncio.Event()
    original = nav.screens["items"].render

    async def slow_render(ctx):
        entered.set()
        await release.wait()
        return await original(ctx)

    nav.screens["items"].render = slow_render
    rendering = asyncio.create_task(nav.show())
    await asyncio.wait_for(entered.wait(), timeout=1)
    locking = asyncio.create_task(nav.lock())
    await asyncio.sleep(0)
    assert not locking.done()
    release.set()
    await asyncio.wait_for(asyncio.gather(rendering, locking), timeout=1)
    assert stack(nav) == ["unlock"]
    assert bot.edits[-1].text.endswith("unlock")


# --- _resume_target mapping (fix round 1: previously untested) ---

_ACCOUNT_DETAIL_SUBSCREENS = ("field_edit", "password_change", "history", "account_delete")
_ACCOUNT_PARENT_SUBSCREENS = ("generator", "category_pick", "category_form", "category_icon")
_ALL_MAPPED_NAMES = (
    "account_edit",
    *_ACCOUNT_DETAIL_SUBSCREENS,
    *_ACCOUNT_PARENT_SUBSCREENS,
    "category_delete",
)


async def test_lock_resumes_subscreens_to_their_account_detail_parent():
    extra = [AccountDetail(), FieldEdit(), PasswordChange(), HistoryScreen(), AccountDelete()]
    for name in _ACCOUNT_DETAIL_SUBSCREENS:
        nav, _, _ = make_nav(extra_screens=extra)
        nav.fsm.reset_to(Frame("home", {}))
        nav.fsm.push(Frame("account_detail", {"id": "acc1"}))
        nav.fsm.push(Frame(name, {"id": "acc1"}))
        await nav.lock()
        assert nav.chat_data[RESUME] == Frame("account_detail", {"id": "acc1"}), name


async def test_lock_resumes_generator_and_category_pick_to_their_stack_parent():
    extra_new = [AccountNew(), Generator(), CategoryPick()]
    nav, _, _ = make_nav(extra_screens=extra_new)
    nav.fsm.reset_to(Frame("home", {}))
    nav.fsm.push(Frame("account_new", {"draft": True}))
    nav.fsm.push(Frame("generator", {}))
    await nav.lock()
    assert nav.chat_data[RESUME] == Frame("account_new", {"draft": True})

    extra_detail = [AccountDetail(), CategoryPick()]
    nav2, _, _ = make_nav(extra_screens=extra_detail)
    nav2.fsm.reset_to(Frame("home", {}))
    nav2.fsm.push(Frame("account_detail", {"id": "acc9"}))
    nav2.fsm.push(Frame("category_pick", {}))
    await nav2.lock()
    assert nav2.chat_data[RESUME] == Frame("account_detail", {"id": "acc9"})


async def test_resume_target_generator_without_parent_falls_back_to_home():
    nav, _, _ = make_nav(extra_screens=[Generator()])
    nav.fsm.reset_to(Frame("home", {}))
    nav.fsm.push(Frame("generator", {}))
    assert nav._resume_target(Frame("generator", {})) == Frame("home", {})


async def test_send_live_keeps_old_message_when_send_fails():
    nav, bot, _ = make_nav(chat_data={LIVE: 7})
    bot.send_error = RuntimeError("network down")
    with pytest.raises(RuntimeError):
        await nav.command("items", {"page": 2})
    # The old live message must survive since no replacement was ever sent.
    assert bot.deleted == []
    assert nav.chat_data[LIVE] == 7


async def test_send_live_deletes_old_message_only_after_new_one_is_sent():
    nav, bot, _ = make_nav(chat_data={LIVE: 7})
    await nav.command("items", {"page": 2})
    assert bot.deleted == [7]
    assert nav.chat_data[LIVE] == bot.sent[-1].message_id != 7


async def test_stale_answer_after_successful_action_does_not_raise():
    nav, bot, _ = make_nav()
    await nav.command("items")
    update = callback(
        Act("items", "other"),
        nav.chat_data[LIVE],
        token=nav.chat_data.get(ChatDataKey.LIVE_TOKEN.value),
    )
    update.callback_query.answer = AsyncMock(side_effect=BadRequest("Query is too old"))
    await nav.on_callback(update)  # must not raise, even though the final answer() fails
    # The action itself (a refresh) still went through.
    assert bot.edits[-1].text.startswith("items")


async def test_resume_target_is_idempotent_for_every_mapped_name():
    nav, _, _ = make_nav(extra_screens=[AccountDetail(), AccountNew()])
    nav.fsm.reset_to(Frame("home", {}))
    nav.fsm.push(Frame("account_detail", {"id": "x"}))
    for name in _ALL_MAPPED_NAMES:
        frame = Frame(name, {"id": "x"})
        once = nav._resume_target(frame)
        twice = nav._resume_target(once)
        assert twice == once, name
