"""Reusable password generator."""

from __future__ import annotations

from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.md import code_inline
from password_bot.ui.screen import back
from password_bot.ui.screens.generator import GeneratorScreen
from password_bot.ui.views import PRIMARY, SUCCESS
from tests.ui._helpers import act, button, labels

FLOW = ChatDataKey.FLOW.value


async def _opened(env, args):
    screen = GeneratorScreen()
    ctx = env.ctx(args, back_label="Cambio password")
    await screen.on_enter(ctx)
    return screen, ctx


async def test_generate_and_use_hands_password_to_caller(env):
    screen, ctx = await _opened(env, {"flow": "password_change", "next_step": "confirm"})
    view = await screen.render(ctx)
    assert button(view, "🎲 Genera").style == PRIMARY
    assert "✅ Usa" not in labels(view)
    await screen.on_action(ctx, act(view, "🎲 Genera"))
    password = ctx.flow("generator")["password"]
    assert len(password) == 20
    view = await screen.render(ctx)
    assert code_inline(password) in view.text
    assert "🔄 Rigenera" in labels(view)
    assert button(view, "✅ Usa").style == SUCCESS
    assert await screen.on_action(ctx, act(view, "✅ Usa")) == back()
    assert env.chat_data[FLOW]["password_change"] == {"password": password, "step": "confirm"}
    assert "generator" not in env.chat_data[FLOW]


async def test_length_input(env):
    screen, ctx = await _opened(env, {})
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "📏 Lunghezza"))
    assert "Scrivi la lunghezza" in (await screen.render(ctx)).text
    bad = await screen.on_text(ctx, "3")
    assert bad.notice == "⚠️ Lunghezza non valida: usa un numero tra 4 e 128."
    await screen.on_text(ctx, "12")
    assert "📏 Lunghezza: 12" in labels(await screen.render(ctx))


async def test_text_without_length_request_is_rejected(env):
    screen, ctx = await _opened(env, {})
    result = await screen.on_text(ctx, "12")
    assert result.notice == "⚠️ Usa i bottoni qui sotto."


async def test_no_character_class_selected(env):
    screen, ctx = await _opened(env, {})
    view = await screen.render(ctx)
    for flag in ("Maiuscole", "Minuscole", "Numeri", "Simboli"):
        await screen.on_action(ctx, act(view, flag))
    result = await screen.on_action(ctx, act(view, "🎲 Genera"))
    assert result.notice.startswith("⚠️ Nessuna classe")


async def test_save_defaults(env):
    screen, ctx = await _opened(env, {})
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "Simboli"))
    result = await screen.on_action(ctx, act(view, "💾 Salva come predefinite"))
    assert result.toast == "💾 Preferenze salvate"
    assert (await env.container.users.get_pw_prefs(1)).symbols is False


async def test_without_caller_flow_there_is_no_use_button(env):
    screen, ctx = await _opened(env, {})
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "🎲 Genera"))
    assert "✅ Usa" not in labels(await screen.render(ctx))
