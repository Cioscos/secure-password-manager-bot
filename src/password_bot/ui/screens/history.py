"""Previous passwords of an account; each can be revealed for 30 s."""

from __future__ import annotations

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import Ctx, Result, Reveal, Screen, View, refresh
from password_bot.ui.screens._shared import load_account
from password_bot.ui.views import btn, footer, keyboard, plain_date


class HistoryScreen(Screen):
    name = "history"
    title = "Storico"

    async def _load(self, ctx: Ctx):
        acc = await load_account(ctx, ctx.args.get("id"))
        if acc is None:
            return None, []
        return acc, await ctx.container.vault.list_history(acc.id, aes_key=ctx.session.aes_key)

    async def render(self, ctx: Ctx) -> View:
        acc, items = await self._load(ctx)
        if acc is None:
            return View(escape_md("Account non trovato."), keyboard(footer(ctx.back_label)))
        lines = [f"🕘 *Storico password* — {escape_md(acc.name)}"]
        if items:
            lines.append(
                escape_md(
                    f"Le ultime {len(items)} password sostituite. "
                    "Toccane una per vederla per 30 secondi."
                )
            )
        else:
            lines.append(escape_md("Nessuna password precedente."))
        rows = [
            [btn(f"👁 fino al {plain_date(item.replaced_at)}", self.name, "reveal", i)]
            for i, item in enumerate(items)
        ]
        return View("\n".join(lines), keyboard(*rows, footer(ctx.back_label)))

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "reveal":
            _, items = await self._load(ctx)
            index = int(act.arg or 0)
            if 0 <= index < len(items):
                return Reveal(items[index].password, toast="👁 Visibile per 30 secondi")
        return refresh()
