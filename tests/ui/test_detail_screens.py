"""Account detail, history, delete."""

from __future__ import annotations

from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.screen import Go, Reveal, open_screen
from password_bot.ui.screens.account_delete import AccountDeleteScreen
from password_bot.ui.screens.account_detail import AUTO_CLOSE_SECONDS, AccountDetailScreen
from password_bot.ui.screens.history import HistoryScreen
from password_bot.ui.views import DANGER, PRIMARY
from tests.ui._helpers import act, button, labels


async def test_detail_full(env):
    cat = await env.category("Lavoro", icon="💼")
    acc = await env.add(
        "GitHub",
        username="me@x.com",
        password="S3cret!pw",
        url="github.com",
        note="2FA: app",
        category_id=cat.id,
    )
    await env.add("GitLab", password="S3cret!pw")
    screen = AccountDetailScreen()
    view = await screen.render(env.ctx({"id": acc.id}, back_label="Lista"))
    assert "🔐 *GitHub*" in view.text
    assert "💼 Lavoro" in view.text
    assert escape_md("me@x.com") in view.text
    assert "||" + escape_md("2FA: app") + "||" in view.text
    assert escape_md("♻️ Stessa password di: GitLab") in view.text
    assert "tg://time?unix=" in view.text
    assert "S3cret" not in view.text
    copy_pw = button(view, "📋 Copia password")
    assert copy_pw.copy_text.text == "S3cret!pw" and copy_pw.style == PRIMARY
    assert button(view, "👤 Copia username").copy_text.text == "me@x.com"
    assert button(view, "🌐 Apri URL").url == "https://github.com"
    assert button(view, "🗑 Elimina").style == DANGER
    assert labels(view)[-2:] == ["🔙 Lista", "🏠 Menu"]
    assert view.expire_after == AUTO_CLOSE_SECONDS == 60


async def test_detail_minimal_and_hostile_values(env):
    acc = await env.add("a_b*c[d](e)!", password="x" * 300, url="javascript:alert(1)")
    view = await AccountDetailScreen().render(env.ctx({"id": acc.id}))
    assert escape_md("a_b*c[d](e)!") in view.text
    assert "a_b*c" not in view.text
    assert "📋 Copia password" not in labels(view)
    assert "👁 Mostra" in labels(view)
    assert "👤 Copia username" not in labels(view)
    assert "🌐 Apri URL" not in labels(view)


async def test_detail_actions(env):
    acc = await env.add("GitHub", username="me", password="pw1")
    screen = AccountDetailScreen()
    ctx = env.ctx({"id": acc.id})
    view = await screen.render(ctx)
    result = await screen.on_action(ctx, act(view, "👁 Mostra"))
    assert isinstance(result, Reveal) and result.text == "pw1" and result.seconds == 30
    assert await screen.on_action(ctx, act(view, "✏️ Modifica…")) == open_screen(
        "account_edit", id=acc.id
    )
    assert await screen.on_action(ctx, act(view, "🗑 Elimina")) == open_screen(
        "account_delete", id=acc.id
    )


async def test_detail_expired_view(env):
    acc = await env.add("GitHub")
    view = await AccountDetailScreen().render_expired(env.ctx({"id": acc.id}))
    assert view is not None and "chiuso" in view.text
    assert labels(view) == ["🔓 Riapri", "🏠 Menu"]


async def test_detail_of_other_chat_is_not_found(env):
    acc = await env.add("GitHub")
    view = await AccountDetailScreen().render(env.ctx({"id": acc.id}, chat_id=2))
    assert "Account non trovato" in view.text


async def test_history_reveals_old_passwords(env):
    acc = await env.add("GitHub", password="old1")
    s = env.session
    await env.container.vault.update_password(
        acc.id, "old2", aes_key=s.aes_key, hmac_key=s.hmac_key
    )
    await env.container.vault.update_password(acc.id, "new", aes_key=s.aes_key, hmac_key=s.hmac_key)
    screen = HistoryScreen()
    ctx = env.ctx({"id": acc.id}, back_label="Modifica")
    view = await screen.render(ctx)
    reveal_buttons = [label for label in labels(view) if label.startswith("👁 fino al")]
    assert len(reveal_buttons) == 2
    result = await screen.on_action(ctx, act(view, reveal_buttons[0]))
    assert isinstance(result, Reveal) and result.text == "old2"


async def test_delete_confirmation(env):
    acc = await env.add("GitHub")
    screen = AccountDeleteScreen()
    ctx = env.ctx({"id": acc.id})
    view = await screen.render(ctx)
    assert button(view, "🗑 Elimina").style == DANGER
    result = await screen.on_action(ctx, act(view, "🗑 Elimina"))
    assert result == Go(pop_to="account_detail", pop_to_inclusive=True, toast="🗑 Eliminato")
    assert await env.container.accounts.get(acc.id) is None


async def test_screens_need_the_session(env):
    acc = await env.add("GitHub")
    env.chat_data.pop(ChatDataKey.SESSION.value)
    view = await AccountDetailScreen().render(env.ctx({"id": acc.id}))
    assert "Account non trovato" in view.text
