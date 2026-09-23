"""Single-live-message navigation: screen stack, rendering, routing, locking."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import replace as dc_replace
from functools import wraps
from typing import Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, LinkPreviewOptions
from telegram.constants import ParseMode
from telegram.error import BadRequest, TelegramError

from password_bot.state.fsm import Frame, FsmContext
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.delete_message import schedule_delete
from password_bot.telegram_utils.md import code_inline, escape_md
from password_bot.ui.callbacks import NAV, Act
from password_bot.ui.screen import (
    TEXT_NOT_ACCEPTED,
    Ctx,
    Go,
    Lock,
    Result,
    Reveal,
    Screen,
    View,
)
from password_bot.ui.views import keyboard, nav_btn

log = logging.getLogger(__name__)

HOME = "home"
UNLOCK = "unlock"
STALE_BUTTON = "Bottone scaduto"
LOCKED_TOAST = "🔒 Sessione bloccata"
_NO_PREVIEW = LinkPreviewOptions(is_disabled=True)
_LIVE = ChatDataKey.LIVE_MESSAGE_ID.value
_TOKEN = ChatDataKey.LIVE_TOKEN.value


def autolock_job_name(chat_id: int) -> str:
    return f"autolock:{chat_id}"


def expire_job_name(chat_id: int) -> str:
    return f"expire:{chat_id}"


async def _expire_job(context: Any) -> None:
    job = context.job
    if job is None or job.chat_id is None:
        return
    await Navigator.from_context(context, job.chat_id).on_expired(job.data)


class _ChatGate:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.owner = None


def serialized(method):
    """Serialize updates and jobs per chat, allowing internal Navigator calls."""

    @wraps(method)
    async def wrapped(self, *args, **kwargs):
        gates = self.application.bot_data.setdefault("ui_gates", {})
        gate = gates.setdefault(self.chat_id, _ChatGate())
        task = asyncio.current_task()
        if gate.owner is task:
            return await method(self, *args, **kwargs)
        async with gate.lock:
            gate.owner = task
            try:
                return await method(self, *args, **kwargs)
            finally:
                gate.owner = None

    return wrapped


class Navigator:
    """Owns UI messages, state and per-chat serialization with timer jobs."""

    def __init__(
        self,
        *,
        application: Any,
        bot: Any,
        chat_id: int,
        chat_data: dict[str, Any],
        user_name: str = "",
    ) -> None:
        self.application = application
        self.bot = bot
        self.chat_id = chat_id
        self.chat_data = chat_data
        self.user_name = user_name
        self.screens: dict[str, Screen] = application.bot_data["screens"]
        self.fsm = FsmContext(chat_data)

    @classmethod
    def from_context(cls, context: Any, chat_id: int, *, user_name: str = "") -> Navigator:
        return cls(
            application=context.application,
            bot=context.bot,
            chat_id=chat_id,
            chat_data=context.chat_data,
            user_name=user_name,
        )

    @classmethod
    def from_update(cls, update: Any, context: Any) -> Navigator:
        user = update.effective_user
        return cls.from_context(
            context, update.effective_chat.id, user_name=user.full_name if user else ""
        )

    @property
    def container(self) -> Any:
        return self.application.bot_data["container"]

    # ------------------------------------------------------------------ stack

    def _locked(self) -> bool:
        session = self.fsm.get_session()
        if session is not None and session.expires_at <= int(time.time()):
            self.fsm.clear_session()
            self.chat_data.pop(ChatDataKey.FLOW.value, None)
            session = None
        return session is None

    def _top(self) -> Frame:
        if self.fsm.depth() == 0 or self.fsm.top().name not in self.screens:
            self.fsm.reset_to(Frame(HOME, {}))
        return self.fsm.top()

    def _ctx(self, frame: Frame) -> Ctx:
        frames = self.fsm.frames()
        below = frames[-2] if len(frames) >= 2 else None
        back_label = (
            self.screens[below.name].title
            if below is not None and below.name in self.screens
            else None
        )
        return Ctx(
            container=self.container,
            chat_id=self.chat_id,
            chat_data=self.chat_data,
            args=frame.data,
            back_label=back_label,
            bot=self.bot,
            application=self.application,
            user_name=self.user_name,
            progress=self._progress,
        )

    def _resume_target(self, frame: Frame | None) -> Frame | None:
        # Only restartable screens may survive the loss of FLOW and parent frames.
        if frame is None:
            return None
        if frame.name in {
            "account_edit",
            "field_edit",
            "password_change",
            "history",
            "account_delete",
        }:
            return Frame("account_detail", {"id": frame.data.get("id")})
        if frame.name in {
            "generator",
            "category_pick",
            "category_form",
            "category_icon",
            "category_delete",
        }:
            for parent in reversed(self.fsm.frames()):
                if parent.name in {"account_new", "account_detail"}:
                    return Frame(parent.name, dict(parent.data))
            return Frame(HOME, {})
        return Frame(frame.name, dict(frame.data))

    def _park_and_unlock(self, frame: Frame | None) -> None:
        """Remember a restartable target, never an action or a partial draft."""
        frame = self._resume_target(frame)
        self.fsm.pop_resume()  # a later /menu must override an earlier /list target
        self.chat_data.pop(ChatDataKey.FLOW.value, None)
        if (
            frame is not None
            and frame.name not in (HOME, UNLOCK)
            and frame.name in self.screens
            and self.screens[frame.name].requires_session
        ):
            self.fsm.set_resume(frame)
        self.fsm.reset_to(Frame(UNLOCK, {}))

    async def _push(self, frame: Frame) -> None:
        if self._locked() and self.screens[frame.name].requires_session:
            self._park_and_unlock(frame)
            return
        self.fsm.push(frame)
        await self.screens[frame.name].on_enter(self._ctx(frame))

    # -------------------------------------------------------------- rendering

    @serialized
    async def show(self, *, notice: str | None = None, new_message: bool = False) -> None:
        top = self._top()
        if self._locked() and self.screens[top.name].requires_session:
            self._park_and_unlock(top)
            top = self._top()
        view = await self.screens[top.name].render(self._ctx(top))
        await self.present(view, notice=notice, new_message=new_message)

    @serialized
    async def present(
        self,
        view: View,
        *,
        notice: str | None = None,
        new_message: bool = False,
        enforce_session: bool = True,
    ) -> None:
        # Rendering may have awaited I/O across the session deadline.
        if enforce_session and self.screens[self._top().name].requires_session and self._locked():
            await self.show(notice=LOCKED_TOAST, new_message=new_message)
            return
        text = f"{escape_md(notice)}\n\n{view.text}" if notice else view.text
        token = int(self.chat_data.get(_TOKEN, 0)) + 1
        self.chat_data[_TOKEN] = token
        if view.keyboard is not None:
            view = dc_replace(
                view,
                keyboard=InlineKeyboardMarkup(
                    [
                        [
                            InlineKeyboardButton(
                                b.text,
                                callback_data=dc_replace(b.callback_data, token=token),
                                style=b.style,
                            )
                            if isinstance(b.callback_data, Act)
                            else b
                            for b in row
                        ]
                        for row in view.keyboard.inline_keyboard
                    ]
                ),
            )
        live = self.chat_data.get(_LIVE)
        if live is not None and not new_message:
            try:
                await self.bot.edit_message_text(
                    text=text,
                    chat_id=self.chat_id,
                    message_id=live,
                    parse_mode=ParseMode.MARKDOWN_V2,
                    reply_markup=view.keyboard,
                    link_preview_options=_NO_PREVIEW,
                )
            except BadRequest as e:
                reason = str(e).lower()
                if "not modified" in reason:
                    pass
                elif "message to edit not found" in reason or "message can't be edited" in reason:
                    await self._send_live(text, view, replacing=live)
                else:
                    raise  # malformed Markdown/URL/oversized text is not a missing message
        else:
            await self._send_live(text, view, replacing=live)
        self._schedule_expiry(view.expire_after, token)

    async def _send_live(self, text: str, view: View, *, replacing: int | None) -> None:
        if replacing is not None:
            with contextlib.suppress(TelegramError):
                await self.bot.delete_message(chat_id=self.chat_id, message_id=replacing)
        msg = await self.bot.send_message(
            chat_id=self.chat_id,
            text=text,
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=view.keyboard,
            link_preview_options=_NO_PREVIEW,
        )
        self.chat_data[_LIVE] = msg.message_id

    def _cancel_jobs(self, *names: str) -> None:
        jq = self.application.job_queue
        if jq is None:
            return
        for name in names:
            for job in jq.get_jobs_by_name(name):
                job.schedule_removal()

    def _schedule_expiry(self, seconds: int | None, token: int) -> None:
        name = expire_job_name(self.chat_id)
        self._cancel_jobs(name)
        jq = self.application.job_queue
        if seconds and jq is not None:
            jq.run_once(_expire_job, when=seconds, chat_id=self.chat_id, data=token, name=name)

    async def _progress(self, text: str) -> None:
        with contextlib.suppress(TelegramError):
            await self.present(View(escape_md(text)))

    # ---------------------------------------------------------------- routing

    @serialized
    async def command(self, name: str, args: dict[str, Any] | None = None) -> None:
        """Open a screen from a slash command, in a new live message at the bottom."""
        frame = Frame(name, dict(args or {}))
        self.chat_data.pop(ChatDataKey.FLOW.value, None)
        if self._locked() and self.screens[name].requires_session:
            self._park_and_unlock(frame)
        else:
            self.fsm.reset_to(Frame(HOME, {}))
            if name != HOME:
                await self._push(frame)
        await self.show(new_message=True)

    @serialized
    async def on_callback(self, update: Any) -> None:
        query = update.callback_query
        act = query.data
        message_id = query.message.message_id if query.message is not None else None
        live = self.chat_data.get(_LIVE)
        if live is None and message_id is not None:
            self.chat_data[_LIVE] = live = message_id
        if not isinstance(act, Act) or message_id != live:
            await self._stale(query)
            return
        if act.token is None or act.token != self.chat_data.get(_TOKEN):
            await query.answer(STALE_BUTTON)
            await self.show()
            return
        if act.screen == NAV:
            await query.answer()
            await self.apply(self._nav_result(act))
            return
        top = self._top()
        if act.screen != top.name:
            await query.answer(STALE_BUTTON)
            await self.show()
            return
        screen = self.screens[top.name]
        if self._locked() and screen.requires_session:
            await query.answer(LOCKED_TOAST)
            await self.show()
            return
        try:
            toast = await self.apply(await screen.on_action(self._ctx(top), act))
        except Exception:
            with contextlib.suppress(TelegramError):
                await query.answer("⚠️ Operazione non riuscita")
            raise
        await query.answer(toast)

    async def _stale(self, query: Any) -> None:
        await query.answer(STALE_BUTTON)
        with contextlib.suppress(TelegramError):
            await query.edit_message_reply_markup(reply_markup=None)
        await self.command(HOME)

    @staticmethod
    def _nav_result(act: Act) -> Go:
        if act.action == "back":
            return Go(pop=1)
        if act.action == "home":
            return Go(home=True)
        return Go(render=act.action != "noop")

    @serialized
    async def on_text(self, update: Any) -> None:
        text = update.message.text or ""
        with contextlib.suppress(TelegramError):
            await update.message.delete()
        top = self._top()
        if self._locked() and top.name != UNLOCK:
            # Locked: any text is a passphrase attempt.
            self._park_and_unlock(top)
            top = self._top()
        screen = self.screens[top.name]
        if not screen.accepts_text:
            await self.show(notice=TEXT_NOT_ACCEPTED)
            return
        await self.apply(await screen.on_text(self._ctx(top), text))

    @serialized
    async def on_document(self, update: Any) -> None:
        try:
            top = self._top()
            screen = self.screens[top.name]
            if self._locked() and screen.requires_session:
                await self.show()
            elif not screen.accepts_document:
                await self.show(notice="⚠️ Non mi aspettavo un file qui.")
            else:
                await self.apply(await screen.on_document(self._ctx(top), update.message.document))
        finally:
            with contextlib.suppress(TelegramError):
                await update.message.delete()

    @serialized
    async def apply(self, result: Result) -> str | None:
        """Carry out a screen's result. Returns the toast for the callback answer."""
        if isinstance(result, Reveal):
            await self.reveal(result.text, seconds=result.seconds)
            return result.toast
        if isinstance(result, Lock):
            await self.lock()
            return None
        previous = self.fsm.frames()
        if result.home:
            self.chat_data.pop(ChatDataKey.FLOW.value, None)
            self.fsm.reset_to(Frame(HOME, {}))
        for _ in range(result.pop):
            self.fsm.pop()
        if result.pop_to is not None:
            self.fsm.pop_to(result.pop_to)
            if result.pop_to_inclusive:
                self.fsm.pop()
        if result.push is not None:
            await self._push(result.push)
        active_names = {frame.name for frame in self.fsm.frames()}
        flows = self.chat_data.get(ChatDataKey.FLOW.value, {})
        for frame in previous:
            if frame.name not in active_names:
                flows.pop(frame.name, None)
        if result.render:
            await self.show(notice=result.notice)
        return result.toast

    # ------------------------------------------------------------ side effects

    async def reveal(self, secret: str, *, seconds: int = 30) -> None:
        msg = await self.bot.send_message(
            chat_id=self.chat_id, text=code_inline(secret), parse_mode=ParseMode.MARKDOWN_V2
        )
        schedule_delete(
            self.application, chat_id=self.chat_id, message_id=msg.message_id, delay_seconds=seconds
        )

    @serialized
    async def lock(
        self, *, notice: str = "🔒 Sessione bloccata.", expected_deadline: int | None = None
    ) -> None:
        if expected_deadline is not None:
            session = self.fsm.get_session()
            if (
                session is None
                or session.expires_at != expected_deadline
                or session.expires_at > int(time.time())
            ):
                return  # obsolete/early timers must not lock a newer session
        target = (
            self.chat_data.get(ChatDataKey.RESUME.value)
            if self._top().name == UNLOCK
            else self._resume_target(self._top())
        )
        self.fsm.lock()
        self._cancel_jobs(autolock_job_name(self.chat_id), expire_job_name(self.chat_id))
        self._park_and_unlock(target)
        await self.show(notice=notice)

    @serialized
    async def on_expired(self, token: int) -> None:
        if self.chat_data.get(_TOKEN) != token or self._locked():
            return
        top = self._top()
        view = await self.screens[top.name].render_expired(self._ctx(top))
        if view is None:
            return
        top.data["_closed"] = True
        try:
            await self.present(view)
        except TelegramError as e:
            log.warning("Auto-close failed for chat_id=%s: %s", self.chat_id, e)

    @serialized
    async def stop(self) -> None:
        live = self.chat_data.get(_LIVE)
        if live is not None:
            with contextlib.suppress(TelegramError):
                await self.bot.delete_message(chat_id=self.chat_id, message_id=live)
        self._cancel_jobs(autolock_job_name(self.chat_id), expire_job_name(self.chat_id))
        self.chat_data.clear()

    @serialized
    async def show_error(self) -> None:
        await self.present(
            View(
                escape_md("⚠️ Errore interno. Lo sviluppatore è stato avvisato."),
                keyboard([nav_btn("🏠 Menu", "home")]),
            ),
            enforce_session=False,  # this error view contains no vault data
        )
