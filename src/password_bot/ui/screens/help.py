"""Help: slash-command shortcuts."""

from __future__ import annotations

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.screen import Ctx, Screen, View
from password_bot.ui.views import footer, keyboard

_COMMANDS = (
    ("/start", "apre il menu"),
    ("/add", "nuovo account"),
    ("/list", "elenco account"),
    ("/get NOME", "cerca un account"),
    ("/categories", "categorie"),
    ("/list_stale", "salute delle password"),
    ("/settings", "impostazioni"),
    ("/export", "esporta il vault"),
    ("/import", "importa un vault"),
    ("/back", "torna indietro"),
    ("/lock", "blocca la sessione"),
    ("/stop", "chiude il bot"),
)


class HelpScreen(Screen):
    name = "help"
    title = "Help"
    requires_session = False

    async def render(self, ctx: Ctx) -> View:
        lines = ["❓ *Comandi*", escape_md("Puoi usare i bottoni oppure questi comandi:"), ""]
        lines += [f"{escape_md(cmd)} — {escape_md(desc)}" for cmd, desc in _COMMANDS]
        return View("\n".join(lines), keyboard(footer(ctx.back_label)))
