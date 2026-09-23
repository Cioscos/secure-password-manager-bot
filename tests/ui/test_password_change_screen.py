"""Change password: generate or type, then confirm."""

from __future__ import annotations

from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.screen import TEXT_NOT_ACCEPTED, back, open_screen, pop_to
from password_bot.ui.screens.password_change import PasswordChangeScreen
from password_bot.ui.views import PRIMARY, SUCCESS
from tests.ui._helpers import act, button

FLOW = ChatDataKey.FLOW.value


async def _opened(env, acc):
    screen = PasswordChangeScreen()
    ctx = env.ctx({"id": acc.id}, back_label="Modifica")
    await screen.on_enter(ctx)
    return screen, ctx


async def test_manual_change_with_reuse_warning(env):
    acc = await env.add("GitHub", password="old")
    await env.add("GitLab", password="shared-pw")
    screen, ctx = await _opened(env, acc)
    view = await screen.render(ctx)
    assert button(view, "🎲 Genera").style == PRIMARY
    await screen.on_action(ctx, act(view, "⌨️ Scrivila io"))
    assert "Inviami la nuova password" in (await screen.render(ctx)).text
    await screen.on_text(ctx, "shared-pw")
    view = await screen.render(ctx)
    assert escape_md("♻️ Già usata per: GitLab") in view.text
    assert "forza" in view.text
    assert "shared-pw" not in view.text
    assert button(view, "✅ Sostituisci").style == SUCCESS
    result = await screen.on_action(ctx, act(view, "✅ Sostituisci"))
    assert result == pop_to("account_detail", notice="✅ Password aggiornata")
    updated = await env.container.vault.get_decrypted(acc.id, aes_key=env.session.aes_key)
    assert updated.password == "shared-pw"
    assert len(await env.container.history.list_for_account(acc.id)) == 1
    assert "password_change" not in env.chat_data[FLOW]


async def test_generate_opens_generator_and_result_lands_on_confirm(env):
    acc = await env.add("GitHub")
    screen, ctx = await _opened(env, acc)
    view = await screen.render(ctx)
    assert await screen.on_action(ctx, act(view, "🎲 Genera")) == open_screen(
        "generator", flow="password_change", next_step="confirm"
    )
    ctx.flow("password_change").update(password="Gen-Pass-123", step="confirm")
    assert "✅ Sostituisci" in [
        b.text for row in (await screen.render(ctx)).keyboard.inline_keyboard for b in row
    ]


async def test_change_back_to_choice(env):
    acc = await env.add("GitHub")
    screen, ctx = await _opened(env, acc)
    ctx.flow("password_change").update(password="x", step="confirm")
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "🔄 Cambia"))
    assert ctx.flow("password_change") == {"step": "choose"}


async def test_cancel_drops_the_flow(env):
    acc = await env.add("GitHub")
    screen, ctx = await _opened(env, acc)
    view = await screen.render(ctx)
    assert await screen.on_action(ctx, act(view, "❌ Annulla")) == back()
    assert "password_change" not in env.chat_data[FLOW]


async def test_text_outside_manual_step_is_rejected(env):
    acc = await env.add("GitHub")
    screen, ctx = await _opened(env, acc)
    result = await screen.on_text(ctx, "typed too early")
    assert result.notice == TEXT_NOT_ACCEPTED
