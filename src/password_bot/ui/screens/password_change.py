"""Change an account's password: generate or type it, then confirm."""

from __future__ import annotations

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import (
    TEXT_NOT_ACCEPTED,
    Ctx,
    Result,
    Screen,
    View,
    back,
    open_screen,
    pop_to,
    refresh,
)
from password_bot.ui.screens._shared import load_account, reuse_names_for, strength_text
from password_bot.ui.views import PRIMARY, SUCCESS, btn, footer, keyboard


class PasswordChangeScreen(Screen):
    name = "password_change"
    title = "Cambio password"
    accepts_text = True

    async def on_enter(self, ctx: Ctx) -> None:
        ctx.drop_flow(self.name)
        ctx.flow(self.name)["step"] = "choose"

    async def render(self, ctx: Ctx) -> View:
        acc = await load_account(ctx, ctx.args.get("id"))
        if acc is None:
            return View(escape_md("Account non trovato."), keyboard(footer(ctx.back_label)))
        flow = ctx.flow(self.name)
        step = flow.get("step", "choose")
        name = f"*{escape_md(acc.name)}*"
        cancel = btn("❌ Annulla", self.name, "cancel")
        if step == "manual":
            return View(
                escape_md("⌨️ Inviami la nuova password per ")
                + name
                + escape_md(". Cancellerò subito il tuo messaggio."),
                keyboard([btn("🔙 Indietro", self.name, "choose")], [cancel]),
            )
        if step == "confirm" and flow.get("password"):
            password = flow["password"]
            lines = [
                escape_md("Sostituire la password di ") + name + escape_md("?"),
                escape_md("La vecchia finisce nello storico."),
                "",
                escape_md("🔑 Nuova password: " + strength_text(ctx, password)),
            ]
            reused = await reuse_names_for(ctx, password, exclude_id=acc.id)
            if reused:
                lines.append(escape_md("♻️ Già usata per: " + ", ".join(reused)))
            return View(
                "\n".join(lines),
                keyboard(
                    [btn("✅ Sostituisci", self.name, "confirm", style=SUCCESS)],
                    [btn("🔄 Cambia", self.name, "choose"), cancel],
                ),
            )
        return View(
            "🔑 " + escape_md("Nuova password per ") + name,
            keyboard(
                [
                    btn("🎲 Genera", self.name, "gen", style=PRIMARY),
                    btn("⌨️ Scrivila io", self.name, "manual"),
                ],
                [cancel],
            ),
        )

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        flow = ctx.flow(self.name)
        if flow.get("step") != "manual":
            return refresh(notice=TEXT_NOT_ACCEPTED)
        if not text:
            return refresh()
        flow["password"] = text  # kept verbatim: passwords may start/end with spaces
        flow["step"] = "confirm"
        return refresh()

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        flow = ctx.flow(self.name)
        match act.action:
            case "gen":
                return open_screen("generator", flow=self.name, next_step="confirm")
            case "manual":
                flow["step"] = "manual"
            case "choose":
                flow.pop("password", None)
                flow["step"] = "choose"
            case "cancel":
                ctx.drop_flow(self.name)
                return back()
            case "confirm":
                acc = await load_account(ctx, ctx.args.get("id"))
                password = flow.get("password")
                if acc is None or not password:
                    return refresh()
                session = ctx.session
                await ctx.container.vault.update_password(
                    acc.id, password, aes_key=session.aes_key, hmac_key=session.hmac_key
                )
                ctx.drop_flow(self.name)
                return pop_to("account_detail", notice="✅ Password aggiornata")
        return refresh()
