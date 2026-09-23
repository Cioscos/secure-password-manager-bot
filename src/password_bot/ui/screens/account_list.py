"""Paginated account list. With a `category` arg it is also the category screen."""

from __future__ import annotations

from password_bot.repositories.account_repo import UNCATEGORIZED
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import Ctx, Result, Screen, View, open_screen, refresh, replace
from password_bot.ui.views import (
    DANGER,
    PRIMARY,
    btn,
    category_label,
    footer,
    keyboard,
    label,
    nav_btn,
)

PAGE_SIZE = 8


class AccountListScreen(Screen):
    name = "account_list"
    title = "Lista"

    async def render(self, ctx: Ctx) -> View:
        category = ctx.args.get("category")
        cat = None
        if category not in (None, UNCATEGORIZED):
            cat = await ctx.container.categories.get(str(category))
            if cat is None or cat.chat_id != ctx.chat_id:
                return View(escape_md("Categoria non trovata."), keyboard(footer(ctx.back_label)))
        rows = await ctx.container.accounts.list_for_chat(ctx.chat_id, category=category)
        total_pages = max(1, (len(rows) + PAGE_SIZE - 1) // PAGE_SIZE)
        page = max(0, min(int(ctx.args.get("page", 0) or 0), total_pages - 1))

        if cat is not None:
            header = f"🏷 *{escape_md(category_label(cat))}* — " + escape_md(f"{len(rows)} account")
        elif category == UNCATEGORIZED:
            header = "📂 *Senza categoria* — " + escape_md(f"{len(rows)} account")
        else:
            header = "📚 *Account* — " + escape_md(f"pagina {page + 1}/{total_pages}")
        lines = [header]
        if not rows:
            lines.append(escape_md("Nessun account qui."))

        start = page * PAGE_SIZE
        kb_rows = [
            [btn(label(r.name), self.name, "open", r.id)] for r in rows[start : start + PAGE_SIZE]
        ]
        if total_pages > 1:
            kb_rows.append(
                [
                    btn("◀", self.name, "page", page - 1) if page > 0 else None,
                    nav_btn(f"{page + 1}/{total_pages}", "noop"),
                    btn("▶", self.name, "page", page + 1) if page < total_pages - 1 else None,
                ]
            )
        if cat is not None:
            kb_rows.append([btn("➕ Nuovo account qui", self.name, "new", style=PRIMARY)])  # noqa: RUF001
            kb_rows.append(
                [
                    btn("✏️ Rinomina", self.name, "rename"),
                    btn("🎨 Icona", self.name, "icon"),
                    btn("🗑 Elimina", self.name, "delete", style=DANGER),
                ]
            )
        elif category is None:
            if not rows:
                kb_rows.append([btn("➕ Nuovo account", self.name, "new", style=PRIMARY)])  # noqa: RUF001
            kb_rows.append([btn("🏷 Per categoria", self.name, "categories")])
        kb_rows.append(footer(ctx.back_label))
        return View("\n".join(lines), keyboard(*kb_rows))

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        category = ctx.args.get("category")
        real_cat = category if category not in (None, UNCATEGORIZED) else None
        match act.action:
            case "open":
                return open_screen("account_detail", id=act.arg)
            case "page":
                return replace(self.name, category=category, page=int(act.arg or 0))
            case "categories":
                return open_screen("categories")
            case "new":
                return open_screen("account_new", category_id=real_cat)
            case "rename" if real_cat:
                return open_screen("category_form", mode="rename", cat_id=real_cat)
            case "icon" if real_cat:
                return open_screen("category_icon", cat_id=real_cat)
            case "delete" if real_cat:
                return open_screen("category_delete", cat_id=real_cat)
        return refresh()
