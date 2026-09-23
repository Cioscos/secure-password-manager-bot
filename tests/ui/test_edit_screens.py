"""'Modifica…' submenu and single-field edit."""

from __future__ import annotations

from password_bot.services.reuse_detector import compute_password_hmac
from password_bot.ui.screen import open_screen, pop_to
from password_bot.ui.screens._shared import reuse_names, reuse_names_for, username_suggestions
from password_bot.ui.screens.account_edit import AccountEditScreen, FieldEditScreen
from tests.ui._helpers import act, labels


async def _decrypted(env, account_id):
    return await env.container.vault.get_decrypted(account_id, aes_key=env.session.aes_key)


async def test_edit_menu_routes(env):
    acc = await env.add("GitHub")
    screen = AccountEditScreen()
    ctx = env.ctx({"id": acc.id}, back_label="Dettaglio")
    view = await screen.render(ctx)
    assert labels(view) == [
        "🔑 Password",
        "👤 Username",
        "📛 Nome",
        "🌐 URL",
        "📝 Note",
        "🏷 Categoria",
        "🔙 Dettaglio",
        "🏠 Menu",
    ]
    assert await screen.on_action(ctx, act(view, "🔑 Password")) == open_screen(
        "password_change", id=acc.id
    )
    assert await screen.on_action(ctx, act(view, "🏷 Categoria")) == open_screen(
        "category_pick", account_id=acc.id
    )
    assert await screen.on_action(ctx, act(view, "📛 Nome")) == open_screen(
        "field_edit", id=acc.id, field="name"
    )


async def test_edit_menu_shows_history_when_present(env):
    acc = await env.add("GitHub", password="a")
    s = env.session
    await env.container.vault.update_password(acc.id, "b", aes_key=s.aes_key, hmac_key=s.hmac_key)
    screen = AccountEditScreen()
    ctx = env.ctx({"id": acc.id})
    view = await screen.render(ctx)
    assert "🕘 Storico password (1)" in labels(view)
    assert await screen.on_action(ctx, act(view, "🕘 Storico")) == open_screen("history", id=acc.id)


async def test_username_edit_offers_suggestions(env):
    await env.add("A", username="me@x.com")
    await env.add("B", username="me@x.com")
    acc = await env.add("C", username="old")
    screen = FieldEditScreen()
    ctx = env.ctx({"id": acc.id, "field": "username"})
    await screen.on_enter(ctx)
    view = await screen.render(ctx)
    assert "me@x.com" in labels(view)
    assert "old" not in labels(view)
    assert "🗑 Svuota" in labels(view)
    result = await screen.on_action(ctx, act(view, "me@x.com"))
    assert result == pop_to("account_detail", notice="✅ Aggiornato")
    assert (await _decrypted(env, acc.id)).username == "me@x.com"


async def test_clear_optional_field(env):
    acc = await env.add("GitHub", url="https://github.com")
    screen = FieldEditScreen()
    ctx = env.ctx({"id": acc.id, "field": "url"})
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "🗑 Svuota"))
    assert (await _decrypted(env, acc.id)).url is None


async def test_name_cannot_be_empty_and_has_no_clear(env):
    acc = await env.add("GitHub")
    screen = FieldEditScreen()
    ctx = env.ctx({"id": acc.id, "field": "name"})
    assert "🗑 Svuota" not in labels(await screen.render(ctx))
    result = await screen.on_text(ctx, "   ")
    assert result.notice == "⚠️ Il nome non può essere vuoto."
    await screen.on_text(ctx, "GitHub Work")
    assert (await _decrypted(env, acc.id)).name == "GitHub Work"


async def test_url_is_validated_and_normalized(env):
    acc = await env.add("GitHub")
    screen = FieldEditScreen()
    ctx = env.ctx({"id": acc.id, "field": "url"})
    bad = await screen.on_text(ctx, "not a url")
    assert bad.notice == "⚠️ URL non valido. Esempio: github.com"
    await screen.on_text(ctx, "github.com")
    assert (await _decrypted(env, acc.id)).url == "https://github.com"


async def test_note_edit_shows_current_value(env):
    acc = await env.add("GitHub", note="vecchia")
    screen = FieldEditScreen()
    ctx = env.ctx({"id": acc.id, "field": "note"})
    view = await screen.render(ctx)
    assert "`vecchia`" in view.text
    await screen.on_text(ctx, "nuova nota")
    assert (await _decrypted(env, acc.id)).note == "nuova nota"


async def test_username_suggestions_returns_unique_usernames(env):
    await env.add("A", username="me@x.com")
    await env.add("B", username="me@x.com")
    await env.add("C", username="other@x.com")
    await env.add("D", username=None)
    ctx = env.ctx({})
    suggestions = await username_suggestions(ctx)
    assert set(suggestions) == {"me@x.com", "other@x.com"}


async def test_reuse_names_for_finds_accounts_sharing_a_password(env):
    acc = await env.add("GitHub", password="S3cret!pw")
    await env.add("GitLab", password="S3cret!pw")
    await env.add("Other", password="different")
    ctx = env.ctx({})
    names = await reuse_names_for(ctx, "S3cret!pw", exclude_id=acc.id)
    assert names == ["GitLab"]


async def test_reuse_names_for_matches_reuse_detector_hmac(env):
    await env.add("GitHub", password="S3cret!pw")
    ctx = env.ctx({})
    digest = compute_password_hmac("S3cret!pw", env.session.hmac_key)
    names = await reuse_names_for(ctx, "S3cret!pw")
    assert names == await reuse_names(ctx, digest)
