"""Unlock an existing vault, create a new one (passphrase twice), or migrate a legacy one."""

from __future__ import annotations

from typing import Any

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.jobs import schedule_autolock
from password_bot.ui.screen import Ctx, Go, Result, Screen, View, open_screen, refresh
from password_bot.ui.views import btn, keyboard

WRONG = "⚠️ Passphrase non corretta."


class UnlockScreen(Screen):
    name = "unlock"
    title = "Sblocco"
    requires_session = False
    accepts_text = True

    async def render(self, ctx: Ctx) -> View:
        user = await ctx.container.users.get(ctx.chat_id)
        rows = []
        if user is None:
            if ctx.flow(self.name).get("first") is None:
                text = escape_md(
                    "🔐 Non hai ancora un vault.\n"
                    "Inviami una passphrase per crearlo: è l'unica chiave per i tuoi dati, "
                    "scegline una robusta. Cancellerò subito il messaggio."
                )
            else:
                text = escape_md("🔐 Inviami di nuovo la stessa passphrase per conferma.")
                rows.append([btn("↩️ Ricomincia", self.name, "restart")])
        else:
            text = escape_md(
                "🔒 Vault bloccato.\n"
                "Inserisci la passphrase per sbloccare il vault. Cancellerò subito il messaggio."
            )
        rows.append([btn("❓ Help", self.name, "help")])
        return View(text, keyboard(*rows))

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "restart":
            ctx.drop_flow(self.name)
        elif act.action == "help":
            return open_screen("help")
        return refresh()

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        user = await ctx.container.users.get(ctx.chat_id)
        if user is None:
            return await self._setup(ctx, text)
        if user.crypto_version == 1:
            return await self._unlock_legacy(ctx, text)
        r = await ctx.container.auth.unlock(chat_id=ctx.chat_id, passphrase=text)
        if not r.ok or r.value is None:
            return refresh(notice=WRONG)
        return self._unlocked(ctx, r.value, "🔓 Sbloccato.")

    async def _setup(self, ctx: Ctx, text: str) -> Result:
        if not text:
            return refresh()
        flow = ctx.flow(self.name)
        first = flow.get("first")
        if first is None:
            flow["first"] = text
            return refresh()
        ctx.drop_flow(self.name)
        if text != first:
            return refresh(notice="⚠️ Le passphrase non coincidono. Ricominciamo.")
        config = ctx.container.config
        r = await ctx.container.auth.register(
            chat_id=ctx.chat_id,
            name=ctx.user_name or str(ctx.chat_id),
            passphrase=text,
            autolock_minutes=config.autolock_minutes_default,
            alert_days=config.alert_days_default,
        )
        if not r.ok or r.value is None:
            return refresh(notice="⚠️ Non sono riuscito a creare il vault. Riprova.")
        return self._unlocked(ctx, r.value, "✅ Vault creato.")

    async def _unlock_legacy(self, ctx: Ctx, text: str) -> Result:
        migration = ctx.container.migration
        r = await migration.unlock_legacy(chat_id=ctx.chat_id, passphrase=text)
        if not r.ok or r.value is None:
            return refresh(notice=WRONG)
        if ctx.progress is not None:
            await ctx.progress("⏳ Sto migrando il vault…")
        await migration.migrate_user(chat_id=ctx.chat_id, passphrase=text, session=r.value)
        return self._unlocked(ctx, r.value, "✅ Vault migrato e sbloccato.")

    def _unlocked(self, ctx: Ctx, session: Any, notice: str) -> Result:
        ctx.fsm.set_session(session)
        schedule_autolock(ctx.application, ctx.chat_id, session.expires_at)
        return Go(home=True, push=ctx.fsm.pop_resume(), notice=notice)
