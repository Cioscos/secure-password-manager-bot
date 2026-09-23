"""'Modifica…' submenu and single-field text edit (name, username, URL, note)."""

from __future__ import annotations

from password_bot.services.vault_service import UpdatedFields
from password_bot.telegram_utils.md import code_inline, escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import Ctx, Result, Screen, View, back, open_screen, pop_to, refresh
from password_bot.ui.screens._shared import load_account, username_suggestions
from password_bot.ui.views import btn, footer, keyboard, label, nav_btn, normalize_url

_MENU = (
    ("password", "🔑 Password"),
    ("username", "👤 Username"),
    ("name", "📛 Nome"),
    ("url", "🌐 URL"),
    ("note", "📝 Note"),
    ("category", "🏷 Categoria"),
)
FIELD_NAMES = {"name": "nome", "username": "username", "url": "URL", "note": "note"}
OPTIONAL = {"username", "url", "note"}


def _not_found(ctx: Ctx) -> View:
    return View(escape_md("Account non trovato."), keyboard(footer(ctx.back_label)))


class AccountEditScreen(Screen):
    name = "account_edit"
    title = "Modifica"

    async def render(self, ctx: Ctx) -> View:
        acc = await load_account(ctx, ctx.args.get("id"))
        if acc is None:
            return _not_found(ctx)
        history = await ctx.container.history.list_for_account(acc.id)
        buttons = [btn(text, self.name, "field", field) for field, text in _MENU]
        rows = [buttons[i : i + 2] for i in range(0, len(buttons), 2)]
        if history:
            rows.append([btn(f"🕘 Storico password ({len(history)})", self.name, "history")])
        rows.append(footer(ctx.back_label))
        return View(
            f"✏️ *Modifica {escape_md(acc.name)}*\n" + escape_md("Cosa vuoi modificare?"),
            keyboard(*rows),
        )

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        account_id = ctx.args.get("id")
        if act.action == "history":
            return open_screen("history", id=account_id)
        if act.action == "field":
            match act.arg:
                case "password":
                    return open_screen("password_change", id=account_id)
                case "category":
                    return open_screen("category_pick", account_id=account_id)
                case "name" | "username" | "url" | "note":
                    return open_screen("field_edit", id=account_id, field=act.arg)
        return refresh()


class FieldEditScreen(Screen):
    name = "field_edit"
    title = "Modifica campo"
    accepts_text = True

    async def on_enter(self, ctx: Ctx) -> None:
        ctx.drop_flow(self.name)
        if ctx.args.get("field") == "username":
            ctx.flow(self.name)["suggestions"] = await username_suggestions(ctx)

    async def render(self, ctx: Ctx) -> View:
        acc = await load_account(ctx, ctx.args.get("id"))
        field = ctx.args.get("field")
        if acc is None or field not in FIELD_NAMES:
            return _not_found(ctx)
        current = getattr(acc, field)
        lines = [
            escape_md(f"✏️ Nuovo {FIELD_NAMES[field]} per ")
            + f"*{escape_md(acc.name)}*"
            + escape_md("?")
        ]
        if current:
            lines.append(escape_md("Attuale: ") + code_inline(current))
        rows = []
        if field == "username":
            suggestions = ctx.flow(self.name).get("suggestions", [])
            rows += [
                [btn(label(s), self.name, "pick", i)]
                for i, s in enumerate(suggestions)
                if s != current
            ]
        if field in OPTIONAL and current:
            rows.append([btn("🗑 Svuota", self.name, "clear")])
        rows.append([nav_btn("❌ Annulla", "back")])
        return View("\n".join(lines), keyboard(*rows))

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        return await self._save(ctx, text.strip())

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "pick":
            suggestions = ctx.flow(self.name).get("suggestions", [])
            index = int(act.arg or 0)
            if 0 <= index < len(suggestions):
                return await self._save(ctx, suggestions[index])
        if act.action == "clear" and ctx.args.get("field") in OPTIONAL:
            return await self._save(ctx, "")
        return refresh()

    async def _save(self, ctx: Ctx, value: str) -> Result:
        acc = await load_account(ctx, ctx.args.get("id"))
        field = ctx.args.get("field")
        if acc is None or field not in FIELD_NAMES:
            return back()
        if field == "name" and not value:
            return refresh(notice="⚠️ Il nome non può essere vuoto.")
        if field == "url" and value:
            url = normalize_url(value)
            if url is None:
                return refresh(notice="⚠️ URL non valido. Esempio: github.com")
            value = url
        await ctx.container.vault.update_fields(
            acc.id, UpdatedFields(**{field: value}), aes_key=ctx.session.aes_key
        )
        ctx.drop_flow(self.name)
        return pop_to("account_detail", notice="✅ Aggiornato")
