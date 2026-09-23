"""Home: the main menu."""

from __future__ import annotations

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import Ctx, Lock, Result, Screen, View, open_screen, refresh
from password_bot.ui.views import PRIMARY, btn, keyboard

_TARGETS = {"account_new", "search", "account_list", "categories", "health", "settings", "help"}


class HomeScreen(Screen):
    name = "home"
    title = "Home"

    async def render(self, ctx: Ctx) -> View:
        def go(text: str, target: str, style: str | None = None):
            return btn(text, self.name, "go", target, style=style)

        return View(
            "📋 *Menu principale*\n" + escape_md("Cosa vuoi fare?"),
            keyboard(
                [go("➕ Nuovo", "account_new", PRIMARY), go("🔍 Cerca", "search", PRIMARY)],  # noqa: RUF001
                [go("📚 Lista", "account_list"), go("🏷 Categorie", "categories")],
                [go("🩺 Salute", "health"), go("⚙️ Impostazioni", "settings")],
                [btn("🔒 Blocca", self.name, "lock"), go("❓ Help", "help")],
            ),
        )

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "lock":
            return Lock()
        if act.action == "go" and act.arg in _TARGETS:
            return open_screen(str(act.arg))
        return refresh()
