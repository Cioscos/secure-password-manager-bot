"""UI building blocks: Act, views helpers, Ctx, FsmContext additions, MarkdownV2 code."""

from __future__ import annotations

import importlib
import pickle
import time

import pytest
from telegram.constants import KeyboardButtonStyle

from password_bot.bot import _SessionStrippingPersistence
from password_bot.models.category import Category
from password_bot.state.fsm import Frame, FsmContext
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.md import code_inline
from password_bot.ui import views
from password_bot.ui.callbacks import NAV, Act
from password_bot.ui.screen import (
    Ctx,
    Go,
    back,
    finish,
    home,
    open_screen,
    pop_to,
    refresh,
    replace,
)


def test_act_is_frozen_and_picklable():
    act = Act("account_detail", "reveal", "password")
    assert pickle.loads(pickle.dumps(act)) == act
    with pytest.raises(AttributeError):
        act.screen = "x"  # type: ignore[misc]


def test_btn_carries_act_and_style():
    b = views.btn("🗑 Elimina", "account_detail", "delete", style=views.DANGER)
    assert b.callback_data == Act("account_detail", "delete", None)
    assert b.style == KeyboardButtonStyle.DANGER


def test_nav_btn_targets_nav_pseudo_screen():
    assert views.nav_btn("🏠 Menu", "home").callback_data == Act(NAV, "home", None)


def test_copy_btn_limits():
    assert views.copy_btn("📋", "") is None
    assert views.copy_btn("📋", None) is None
    assert views.copy_btn("📋", "x" * 257) is None
    b = views.copy_btn("📋", "x" * 256, style=views.PRIMARY)
    assert b is not None
    assert b.copy_text.text == "x" * 256
    assert b.style == "primary"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("github.com", "https://github.com"),
        ("https://github.com/login", "https://github.com/login"),
        ("http://1.2.3.4:8080/x", "http://1.2.3.4:8080/x"),
        ("javascript:alert(1)", None),
        ("ftp://x.com", None),
        ("not a url", None),
        ("localhost", None),
        ("word", None),
        ("", None),
        (None, None),
    ],
)
def test_normalize_url(raw, expected):
    assert views.normalize_url(raw) == expected


def test_url_btn():
    assert views.url_btn("🌐", "javascript:alert(1)") is None
    b = views.url_btn("🌐", "github.com")
    assert b is not None and b.url == "https://github.com"


def test_keyboard_drops_none_and_empty_rows():
    kb = views.keyboard([None, views.nav_btn("a", "home")], [None], [])
    assert [[b.text for b in row] for row in kb.inline_keyboard] == [["a"]]


def test_footer_names_back_target():
    assert [b.text for b in views.footer("Lista")] == ["🔙 Lista", "🏠 Menu"]
    assert views.footer(None)[0].text == "🔙 Indietro"


def test_dates():
    ts = int(time.mktime((2026, 5, 12, 12, 0, 0, 0, 0, -1)))
    assert views.md_date(ts) == f"![12/05/2026](tg://time?unix={ts}&format=d)"
    assert views.md_date(0) == "data sconosciuta"
    assert views.plain_date(ts) == "12/05/2026"


def test_label_truncates():
    assert views.label("abc", 5) == "abc"
    assert views.label("abcdefgh", 5) == "abcd…"


def test_category_label():
    assert views.category_label(Category(id="c", chat_id=1, name="Lavoro", icon="💼")) == (
        "💼 Lavoro"
    )
    assert views.category_label(Category(id="c", chat_id=1, name="Lavoro", icon=None)) == "Lavoro"


def test_code_inline_escapes_backslash_and_backtick():
    assert code_inline("a\\b`c") == "`a\\\\b\\`c`"


def test_old_pickled_screen_name_still_resolves():
    # Protocol-4 STACK_GLOBAL pickle of the historical `password_bot.state.fsm.Screen`
    # class (produced before Frame existed), not a fresh instance of the new name.
    assert importlib.import_module("password_bot.state.fsm").Screen is Frame
    # A real instance produced by the old slotted Screen class (no production data).
    old_instance = bytes.fromhex(
        "80049547000000000000008c1670617373776f72645f626f742e73746174652e66736d948c0653637265656e9493942981944e7d94288c046e616d65948c046d656e75948c0464617461947d94758694622e"
    )
    restored = pickle.loads(old_instance)
    assert isinstance(restored, Frame)
    assert restored.name == "menu" and restored.data == {}


def test_frames_and_resume():
    fsm = FsmContext({})
    fsm.reset_to(Frame("home"))
    fsm.push(Frame("account_list", {"page": 1}))
    assert [f.name for f in fsm.frames()] == ["home", "account_list"]
    fsm.set_resume(Frame("account_detail", {"id": "a1"}))
    assert fsm.pop_resume() == Frame("account_detail", {"id": "a1"})
    assert fsm.pop_resume() is None


def test_lock_clears_flow_and_resume_but_keeps_live_message():
    data = {
        ChatDataKey.FLOW.value: {"account_new": {"password": "x"}},
        ChatDataKey.RESUME.value: Frame("home"),
        ChatDataKey.LIVE_MESSAGE_ID.value: 5,
    }
    FsmContext(data).lock()
    assert ChatDataKey.FLOW.value not in data
    assert ChatDataKey.RESUME.value not in data
    assert data[ChatDataKey.LIVE_MESSAGE_ID.value] == 5


def test_ctx_flow_helpers():
    ctx = Ctx(container=None, chat_id=1, chat_data={}, args={})
    ctx.flow("x")["a"] = 1
    assert ctx.chat_data[ChatDataKey.FLOW.value] == {"x": {"a": 1}}
    ctx.drop_flow("x")
    ctx.drop_flow("missing")
    assert ctx.chat_data[ChatDataKey.FLOW.value] == {}


def test_result_helpers():
    assert open_screen("account_detail", id="a1") == Go(push=Frame("account_detail", {"id": "a1"}))
    assert replace("search", q="git", notice="n") == Go(
        pop=1, push=Frame("search", {"q": "git"}), notice="n"
    )
    assert back(notice="ok") == Go(pop=1, notice="ok")
    assert refresh(toast="t") == Go(toast="t")
    assert home() == Go(home=True)
    assert pop_to("account_detail", notice="✅") == Go(pop_to="account_detail", notice="✅")
    assert finish("account_new", then=Frame("account_detail", {"id": "a"}), notice="n") == Go(
        pop_to="account_new",
        pop_to_inclusive=True,
        push=Frame("account_detail", {"id": "a"}),
        notice="n",
    )


async def test_persistence_strips_flow(tmp_path):
    persistence = _SessionStrippingPersistence(filepath=str(tmp_path / "p.pkl"))
    await persistence.update_chat_data(
        1, {ChatDataKey.FLOW.value: {"x": 1}, ChatDataKey.NAV_STACK.value: []}
    )
    stored = await persistence.get_chat_data()
    assert ChatDataKey.FLOW.value not in stored[1]
    assert ChatDataKey.NAV_STACK.value in stored[1]
