"""Delete confirmation with a red button."""

from __future__ import annotations

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import Ctx, Go, Result, Screen, View, refresh
from password_bot.ui.screens._shared import load_account
from password_bot.ui.views import DANGER, btn, footer, keyboard, nav_btn


class AccountDeleteScreen(Screen):
    name = "account_delete"
    title = "Elimina"

    async def render(self, ctx: Ctx) -> View:
        acc = await load_account(ctx, ctx.args.get("id"))
        if acc is None:
            return View(escape_md("Account non trovato."), keyboard(footer(ctx.back_label)))
        return View(
            escape_md("🗑 Eliminare ")
            + f"*{escape_md(acc.name)}*"
            + escape_md("? Non si può annullare."),
            keyboard(
                [btn("🗑 Elimina", self.name, "confirm", style=DANGER)],
                [nav_btn("❌ Annulla", "back")],
            ),
        )

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action != "confirm":
            return refresh()
        acc = await load_account(ctx, ctx.args.get("id"))
        if acc is not None:
            await ctx.container.vault.delete(acc.id)
        return Go(pop_to="account_detail", pop_to_inclusive=True, toast="🗑 Eliminato")
