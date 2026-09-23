"""Screen contract: what a screen renders and how it asks the Navigator to move."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, ClassVar

from telegram import Document, InlineKeyboardMarkup

from password_bot.state.fsm import Frame, FsmContext
from password_bot.state.keys import ChatDataKey
from password_bot.ui.callbacks import Act

TEXT_NOT_ACCEPTED = "⚠️ Usa i bottoni qui sotto."


@dataclass(slots=True)
class View:
    """MarkdownV2 text plus its inline keyboard."""

    text: str
    keyboard: InlineKeyboardMarkup | None = None
    expire_after: int | None = None  # seconds; the Navigator then shows render_expired()


@dataclass(slots=True)
class Ctx:
    """Screen context. `args` belongs to the frame; only navigation flags may be mutated."""

    container: Any
    chat_id: int
    chat_data: dict[str, Any]
    args: dict[str, Any]
    back_label: str | None = None
    bot: Any = None
    application: Any = None
    user_name: str = ""
    progress: Callable[[str], Awaitable[None]] | None = None

    @property
    def fsm(self) -> FsmContext:
        return FsmContext(self.chat_data)

    @property
    def session(self) -> Any:
        return self.fsm.get_session()

    def flow(self, key: str) -> dict[str, Any]:
        flows = self.chat_data.setdefault(ChatDataKey.FLOW.value, {})
        return flows.setdefault(key, {})

    def drop_flow(self, key: str) -> None:
        self.chat_data.get(ChatDataKey.FLOW.value, {}).pop(key, None)


@dataclass(frozen=True, slots=True)
class Go:
    """Move on the stack, then (by default) render the new top screen.

    Applied in this order: reset to [home] → pop N → pop to `pop_to` (optionally
    inclusive) → push → render with `notice`. `toast` answers the callback query.
    """

    push: Frame | None = None
    pop: int = 0
    pop_to: str | None = None
    pop_to_inclusive: bool = False
    home: bool = False
    render: bool = True
    notice: str | None = None
    toast: str | None = None


@dataclass(frozen=True, slots=True)
class Reveal:
    """Send a secret as a separate message deleted after `seconds`. The live view is unchanged."""

    text: str
    seconds: int = 30
    toast: str | None = None


@dataclass(frozen=True, slots=True)
class Lock:
    """Lock the session now."""


Result = Go | Reveal | Lock


def open_screen(name: str, **args: Any) -> Go:
    return Go(push=Frame(name, dict(args)))


def replace(name: str, *, notice: str | None = None, toast: str | None = None, **args: Any) -> Go:
    return Go(pop=1, push=Frame(name, dict(args)), notice=notice, toast=toast)


def back(notice: str | None = None, toast: str | None = None) -> Go:
    return Go(pop=1, notice=notice, toast=toast)


def refresh(notice: str | None = None, toast: str | None = None) -> Go:
    return Go(notice=notice, toast=toast)


def home(notice: str | None = None) -> Go:
    return Go(home=True, notice=notice)


def pop_to(name: str, notice: str | None = None, toast: str | None = None) -> Go:
    return Go(pop_to=name, notice=notice, toast=toast)


def finish(
    flow_screen: str,
    *,
    then: Frame | None = None,
    notice: str | None = None,
    toast: str | None = None,
) -> Go:
    """End a multi-step flow: drop its frames and optionally open `then` in their place."""
    return Go(pop_to=flow_screen, pop_to_inclusive=True, push=then, notice=notice, toast=toast)


class Screen:
    """Base class. Subclasses set `name`/`title` and override what they need."""

    name: ClassVar[str]
    title: ClassVar[str]  # used as the "🔙 <title>" label by the screen above
    requires_session: ClassVar[bool] = True
    accepts_text: ClassVar[bool] = False
    accepts_document: ClassVar[bool] = False

    async def on_enter(self, ctx: Ctx) -> None:
        """Called once when the screen is pushed (not on re-render)."""
        return None

    async def render(self, ctx: Ctx) -> View:
        raise NotImplementedError

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        return refresh()

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        return refresh(notice=TEXT_NOT_ACCEPTED)

    async def on_document(self, ctx: Ctx, document: Document) -> Result:
        return refresh(notice=TEXT_NOT_ACCEPTED)

    async def render_expired(self, ctx: Ctx) -> View | None:
        return None
