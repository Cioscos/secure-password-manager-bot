"""Password health: stale and reused passwords."""

from __future__ import annotations

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import Ctx, Result, Screen, View, open_screen, refresh
from password_bot.ui.views import btn, footer, keyboard, label

MAX_BUTTONS = 30


class HealthScreen(Screen):
    name = "health"
    title = "Salute"

    async def render(self, ctx: Ctx) -> View:
        user = await ctx.container.users.get(ctx.chat_id)
        days = user.alert_days if user is not None else 180
        stale = await ctx.container.alerts.find_stale(chat_id=ctx.chat_id)
        clusters = await ctx.container.accounts.list_reuse_clusters(ctx.chat_id)
        lines = [
            "🩺 *Salute password*",
            "",
            escape_md(f"⏳ Vecchie (più di {days} giorni): {len(stale)}"),
            escape_md(f"♻️ Riusate: {len(clusters)} gruppi"),
        ]
        lines += [escape_md("• " + ", ".join(r.name for r in cluster)) for cluster in clusters]
        if not stale and not clusters:
            lines += ["", escape_md("Tutto in ordine. 🎉")]
        rows = [[btn(label(f"⏳ {r.name}"), self.name, "open", r.id)] for r in stale]
        rows += [
            [btn(label(f"♻️ {r.name}"), self.name, "open", r.id)]
            for cluster in clusters
            for r in cluster
        ]
        return View("\n".join(lines), keyboard(*rows[:MAX_BUTTONS], footer(ctx.back_label)))

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "open":
            return open_screen("account_detail", id=act.arg)
        return refresh()
