"""Settings: autolock, stale threshold, generator defaults, export/import."""

from __future__ import annotations

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import Ctx, Result, Screen, View, open_screen, refresh, replace
from password_bot.ui.views import btn, footer, keyboard, nav_btn

AUTOLOCK_CHOICES = (5, 15, 30, 60)
ALERT_CHOICES = (90, 180, 365)


class SettingsScreen(Screen):
    name = "settings"
    title = "Impostazioni"

    async def render(self, ctx: Ctx) -> View:
        user = await ctx.container.users.get(ctx.chat_id)
        minutes = (user.autolock_minutes or 15) if user else 15
        days = user.alert_days if user else 180
        sub = ctx.args.get("sub")
        back_row = [btn("🔙 Impostazioni", self.name, "sub", ""), nav_btn("🏠 Menu", "home")]
        if sub == "autolock":
            choices = [
                btn(f"{m} min" + (" ✓" if m == minutes else ""), self.name, "set_autolock", m)
                for m in AUTOLOCK_CHOICES
            ]
            return View(
                escape_md("⏰ Dopo quanti minuti bloccare la sessione? Vale dal prossimo sblocco."),
                keyboard(choices, back_row),
            )
        if sub == "alert":
            choices = [
                btn(f"{d} giorni" + (" ✓" if d == days else ""), self.name, "set_alert", d)
                for d in ALERT_CHOICES
            ]
            return View(
                escape_md("⏳ Dopo quanti giorni una password è «vecchia»?"),
                keyboard(choices, back_row),
            )
        return View(
            "\n".join(
                [
                    "⚙️ *Impostazioni*",
                    escape_md(f"⏰ Autolock: {minutes} min"),
                    escape_md(f"⏳ Soglia password vecchie: {days} giorni"),
                ]
            ),
            keyboard(
                [
                    btn("⏰ Autolock", self.name, "sub", "autolock"),
                    btn("⏳ Soglia", self.name, "sub", "alert"),
                ],
                [btn("🎲 Generatore password", self.name, "gen")],
                [btn("📤 Export", self.name, "export"), btn("📥 Import", self.name, "import")],
                footer(ctx.back_label),
            ),
        )

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        match act.action:
            case "sub":
                return replace(self.name, sub=act.arg or None)
            case "set_autolock" if act.arg in AUTOLOCK_CHOICES:
                await ctx.container.users.update_autolock(
                    ctx.chat_id, minutes=int(act.arg), reset_on_activity=False
                )
                return replace(self.name, sub=None, notice=f"✅ Autolock: {act.arg} min")
            case "set_alert" if act.arg in ALERT_CHOICES:
                await ctx.container.users.update_alert_days(ctx.chat_id, int(act.arg))
                return replace(self.name, sub=None, notice=f"✅ Soglia: {act.arg} giorni")
            case "gen":
                return open_screen("generator")
            case "export" | "import":
                return open_screen("transfer", mode=act.action)
        return refresh()
