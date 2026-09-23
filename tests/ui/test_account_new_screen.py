"""Account creation: 3 steps + summary."""

from __future__ import annotations

from password_bot.state.keys import ChatDataKey
from password_bot.ui.screen import Go, back, open_screen
from password_bot.ui.screens.account_new import AccountNewScreen
from password_bot.ui.views import PRIMARY, SUCCESS
from tests.ui._helpers import act, button, labels

FLOW = ChatDataKey.FLOW.value


async def _opened(env, args=None):
    screen = AccountNewScreen()
    ctx = env.ctx(args or {})
    await screen.on_enter(ctx)
    return screen, ctx


async def test_happy_path(env):
    await env.add("Old", username="me@x.com")
    screen, ctx = await _opened(env)
    assert "passo 1/3" in (await screen.render(ctx)).text
    await screen.on_text(ctx, "GitHub")
    view = await screen.render(ctx)
    assert "passo 2/3" in view.text
    await screen.on_action(ctx, act(view, "me@x.com"))
    view = await screen.render(ctx)
    assert "passo 3/3" in view.text
    assert button(view, "🎲 Genera").style == PRIMARY
    await screen.on_action(ctx, act(view, "⌨️ Scrivila io"))
    await screen.on_text(ctx, "Tr0ub4dor&3")
    view = await screen.render(ctx)
    assert "Riepilogo" in view.text and "forza" in view.text
    assert "Tr0ub4dor" not in view.text
    await screen.on_action(ctx, act(view, "🌐 + URL"))
    await screen.on_text(ctx, "github.com")
    view = await screen.render(ctx)
    assert "🌐 https://github.com" in labels(view)
    assert button(view, "💾 Salva").style == SUCCESS
    result = await screen.on_action(ctx, act(view, "💾 Salva"))
    assert isinstance(result, Go)
    assert result.pop_to == "account_new" and result.pop_to_inclusive
    assert result.push.name == "account_detail"
    assert result.notice == "✅ Account salvato"
    saved = await env.container.vault.get_decrypted(
        result.push.data["id"], aes_key=env.session.aes_key
    )
    assert (saved.name, saved.username, saved.password, saved.url) == (
        "GitHub",
        "me@x.com",
        "Tr0ub4dor&3",
        "https://github.com",
    )
    assert "account_new" not in env.chat_data[FLOW]


async def test_duplicate_name_warns_and_links_existing(env):
    existing = await env.add("GitHub")
    screen, ctx = await _opened(env)
    await screen.on_text(ctx, "github")
    view = await screen.render(ctx)
    assert "Hai già un account" in view.text
    assert await screen.on_action(ctx, act(view, "👁 Apri esistente")) == open_screen(
        "account_detail", id=existing.id
    )


async def test_reuse_warning_in_summary(env):
    await env.add("GitLab", password="same-pass")
    screen, ctx = await _opened(env)
    ctx.flow("account_new").update(step="summary", name="GitHub", password="same-pass")
    assert "GitLab" in (await screen.render(ctx)).text


async def test_back_steps_and_edits_from_summary(env):
    screen, ctx = await _opened(env)
    await screen.on_text(ctx, "A")
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "⏭ Nessuno"))
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "🔙 Indietro"))
    assert ctx.flow("account_new")["step"] == "username"
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "⏭ Nessuno"))
    view = await screen.render(ctx)
    assert await screen.on_action(ctx, act(view, "🎲 Genera")) == open_screen(
        "generator", flow="account_new", next_step="summary"
    )
    ctx.flow("account_new").update(password="Gen-pass-1", step="summary")  # what ✅ Usa does
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "📛 Nome"))
    await screen.on_text(ctx, "B")
    assert ctx.flow("account_new")["step"] == "summary"
    assert "B" in (await screen.render(ctx)).text


async def test_category_preset_and_picker(env):
    cat = await env.category("Lavoro", icon="💼")
    screen, ctx = await _opened(env, {"category_id": cat.id})
    ctx.flow("account_new").update(step="summary", name="Jira", password="pw-123456")
    view = await screen.render(ctx)
    assert "🏷 Categoria: 💼 Lavoro" in labels(view)
    assert await screen.on_action(ctx, act(view, "🏷 Categoria")) == open_screen(
        "category_pick", flow="account_new"
    )
    result = await screen.on_action(ctx, act(view, "💾 Salva"))
    saved = await env.container.vault.get_decrypted(
        result.push.data["id"], aes_key=env.session.aes_key
    )
    assert saved.category_id == cat.id


async def test_url_validation_and_clear(env):
    screen, ctx = await _opened(env)
    ctx.flow("account_new").update(step="url", name="A", password="p", reached_summary=True)
    bad = await screen.on_text(ctx, "nope")
    assert bad.notice == "⚠️ URL non valido. Esempio: github.com"
    await screen.on_text(ctx, "a.com")
    ctx.flow("account_new")["step"] = "url"
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "🗑 Rimuovi"))
    assert ctx.flow("account_new")["url"] is None
    assert ctx.flow("account_new")["step"] == "summary"


async def test_cancel_drops_the_flow(env):
    screen, ctx = await _opened(env)
    view = await screen.render(ctx)
    assert await screen.on_action(ctx, act(view, "❌ Annulla")) == back()
    assert "account_new" not in env.chat_data[FLOW]


async def test_lost_flow_restarts_from_name(env):
    screen = AccountNewScreen()
    ctx = env.ctx({})
    assert "passo 1/3" in (await screen.render(ctx)).text
