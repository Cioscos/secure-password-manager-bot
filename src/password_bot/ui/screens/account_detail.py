"""Account detail: actions up front; auto-closes after 60 s."""

from __future__ import annotations

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import Ctx, Result, Reveal, Screen, View, open_screen, refresh
from password_bot.ui.screens._shared import load_account, reuse_names
from password_bot.ui.views import (
    DANGER,
    PRIMARY,
    btn,
    category_label,
    copy_btn,
    footer,
    keyboard,
    md_date,
    nav_btn,
    url_btn,
)

AUTO_CLOSE_SECONDS = 60
MASK = "••••••••"


class AccountDetailScreen(Screen):
    name = "account_detail"
    title = "Dettaglio"

    async def render(self, ctx: Ctx) -> View:
        if ctx.args.get("_closed"):
            closed = await self.render_expired(ctx)
            if closed is not None:
                return closed
        acc = await load_account(ctx, ctx.args.get("id"))
        if acc is None:
            return View(escape_md("Account non trovato."), keyboard(footer(ctx.back_label)))
        lines = [f"🔐 *{escape_md(acc.name)}*"]
        if acc.category_id:
            cat = await ctx.container.categories.get(acc.category_id)
            if cat is not None:
                lines.append(f"🏷 {escape_md(category_label(cat))}")
        lines.append(f"👤 {escape_md(acc.username or '—')}")
        lines.append(f"🔑 {escape_md(MASK)}")
        lines.append(f"🌐 {escape_md(acc.url or '—')}")
        if acc.note:
            lines.append(f"📝 ||{escape_md(acc.note)}||")
        reused = await reuse_names(ctx, acc.password_hmac, exclude_id=acc.id)
        if reused:
            lines.append(escape_md("♻️ Stessa password di: " + ", ".join(reused)))
        lines.append(escape_md("📅 Password aggiornata il ") + md_date(acc.password_changed_at))

        copy_user = copy_btn("👤 Copia username", acc.username)
        if copy_user is None and acc.username:
            copy_user = btn("👁 Username", self.name, "reveal", "username")
        kb = keyboard(
            [
                copy_btn("📋 Copia password", acc.password, style=PRIMARY),
                btn("👁 Mostra", self.name, "reveal", "password"),
            ],
            [copy_user, url_btn("🌐 Apri URL", acc.url)],
            [
                btn("✏️ Modifica…", self.name, "edit"),
                btn("🗑 Elimina", self.name, "delete", style=DANGER),
            ],
            footer(ctx.back_label),
        )
        return View("\n".join(lines), kb, expire_after=AUTO_CLOSE_SECONDS)

    async def render_expired(self, ctx: Ctx) -> View | None:
        row = await ctx.container.accounts.get(str(ctx.args.get("id", "")))
        if row is None or row.chat_id != ctx.chat_id:
            return None
        return View(
            f"🔐 *{escape_md(row.name)}* — " + escape_md("chiuso"),
            keyboard(
                [btn("🔓 Riapri", self.name, "reopen", style=PRIMARY)],
                [nav_btn("🏠 Menu", "home")],
            ),
        )

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        match act.action:
            case "reopen":
                ctx.args.pop("_closed", None)
                return refresh()
            case "reveal":
                if ctx.args.get("_closed"):
                    return refresh(toast="🔒 Dettaglio chiuso")
                acc = await load_account(ctx, ctx.args.get("id"))
                value = None
                if acc is not None:
                    value = acc.username if act.arg == "username" else acc.password
                if not value:
                    return refresh()
                return Reveal(value, toast="👁 Visibile per 30 secondi")
            case "edit":
                return open_screen("account_edit", id=ctx.args.get("id"))
            case "delete":
                return open_screen("account_delete", id=ctx.args.get("id"))
        return refresh()
