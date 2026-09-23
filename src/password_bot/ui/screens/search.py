"""Fuzzy search by account name."""

from __future__ import annotations

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import Ctx, Result, Screen, View, open_screen, refresh, replace
from password_bot.ui.views import btn, footer, keyboard, label

MAX_RESULTS = 10


class SearchScreen(Screen):
    name = "search"
    title = "Ricerca"
    accepts_text = True

    async def render(self, ctx: Ctx) -> View:
        query = ctx.args.get("q")
        if not query:
            return View(
                escape_md("🔍 Scrivi il nome (o una parte) dell'account da cercare."),
                keyboard(footer(ctx.back_label)),
            )
        results = await ctx.container.accounts.search(ctx.chat_id, query)
        if not results:
            text = escape_md(f"🔍 Nessun risultato per «{query}». Scrivi un altro nome.")
        else:
            text = escape_md(f"🔍 Risultati per «{query}»:")
        rows = [
            [btn(label(f"{row.name} ({score}%)"), self.name, "open", row.id)]
            for row, score in results[:MAX_RESULTS]
        ]
        return View(text, keyboard(*rows, footer(ctx.back_label)))

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        query = text.strip()
        if not query:
            return refresh()
        results = await ctx.container.accounts.search(ctx.chat_id, query)
        if len(results) == 1:
            return replace("account_detail", id=results[0][0].id)
        return replace(self.name, q=query)

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "open":
            return open_screen("account_detail", id=act.arg)
        return refresh()
