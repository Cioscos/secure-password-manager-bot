"""Health, settings, export/import."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

from password_bot.i18n.it import MESSAGES
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.screen import back, open_screen, refresh, replace
from password_bot.ui.screens.health import HealthScreen
from password_bot.ui.screens.settings import SettingsScreen
from password_bot.ui.screens.transfer import TransferScreen
from tests.ui._helpers import FakeBot, act, labels


async def test_health_lists_stale_and_reused(env):
    old = await env.add("Old")
    row = await env.container.accounts.get(old.id)
    await env.container.accounts.update_password(
        old.id,
        password_enc=row.password_enc,
        password_hmac=row.password_hmac,
        crypto_version=2,
        password_changed_at=1,
    )
    await env.add("A", password="same-pw")
    await env.add("B", password="same-pw")
    screen = HealthScreen()
    ctx = env.ctx()
    view = await screen.render(ctx)
    assert "⏳ Old" in labels(view)
    assert "♻️ A" in labels(view) and "♻️ B" in labels(view)
    assert escape_md("• A, B") in view.text
    assert await screen.on_action(ctx, act(view, "⏳ Old")) == open_screen(
        "account_detail", id=old.id
    )


async def test_health_all_good(env):
    await env.add("Fresh")
    assert "Tutto in ordine" in (await HealthScreen().render(env.ctx())).text


async def test_settings_autolock(env):
    screen = SettingsScreen()
    view = await screen.render(env.ctx())
    assert escape_md("⏰ Autolock: 15 min") in view.text
    assert await screen.on_action(env.ctx(), act(view, "⏰ Autolock")) == replace(
        "settings", sub="autolock"
    )
    sub = env.ctx({"sub": "autolock"})
    view = await screen.render(sub)
    assert "15 min ✓" in labels(view)
    assert await screen.on_action(sub, act(view, "30 min")) == replace(
        "settings", sub=None, notice="✅ Autolock: 30 min"
    )
    assert (await env.container.users.get(1)).autolock_minutes == 30


async def test_settings_alert_threshold(env):
    screen = SettingsScreen()
    sub = env.ctx({"sub": "alert"})
    view = await screen.render(sub)
    assert "180 giorni ✓" in labels(view)
    await screen.on_action(sub, act(view, "365 giorni"))
    assert (await env.container.users.get(1)).alert_days == 365


async def test_settings_links(env):
    screen = SettingsScreen()
    ctx = env.ctx()
    view = await screen.render(ctx)
    assert await screen.on_action(ctx, act(view, "🎲 Generatore password")) == open_screen(
        "generator"
    )
    assert await screen.on_action(ctx, act(view, "📤 Export")) == open_screen(
        "transfer", mode="export"
    )
    assert await screen.on_action(ctx, act(view, "📥 Import")) == open_screen(
        "transfer", mode="import"
    )


async def test_export_sends_encrypted_document(env):
    await env.add("GitHub")
    screen = TransferScreen()
    ctx = env.ctx({"mode": "export"}, back_label="Impostazioni")
    ctx.bot = FakeBot()
    await screen.on_enter(ctx)
    assert "Export" in (await screen.render(ctx)).text
    assert await screen.on_text(ctx, "exp-pass") == back(notice="📤 Export inviato qui sotto.")
    document = ctx.bot.documents[-1]
    assert document.filename.endswith(".json")
    assert b"password-bot-vault" in document.data


async def test_import_roundtrip(env):
    acc = await env.add("GitHub")
    payload = await env.container.export.export(
        chat_id=1, vault_key=env.session.aes_key, export_passphrase="exp"
    )
    await env.container.vault.delete(acc.id)
    screen = TransferScreen()
    ctx = env.ctx({"mode": "import"})
    tg_file = SimpleNamespace(
        download_as_bytearray=AsyncMock(return_value=bytearray(payload.encode()))
    )
    ctx.bot.get_file = AsyncMock(return_value=tg_file)
    await screen.on_enter(ctx)
    assert "Inviami il file" in (await screen.render(ctx)).text
    document = SimpleNamespace(file_name="vault.json", file_id="f1")
    assert await screen.on_document(ctx, document) == refresh()
    assert "passphrase del file" in (await screen.render(ctx)).text
    wrong = await screen.on_text(ctx, "nope")
    assert wrong.notice == MESSAGES["import_wrong_passphrase"]
    done = await screen.on_text(ctx, "exp")
    assert done == back(notice=MESSAGES["import_done"].format(added=1, overwritten=0, skipped=0))


async def test_import_rejects_non_json(env):
    screen = TransferScreen()
    ctx = env.ctx({"mode": "import"})
    await screen.on_enter(ctx)
    result = await screen.on_document(ctx, SimpleNamespace(file_name="x.txt", file_id="f"))
    assert result.notice == "⚠️ Serve il file .json esportato dal bot."
