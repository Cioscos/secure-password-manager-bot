"""Categories: list with counts, picker, create/rename form, icon picker, delete."""

from __future__ import annotations

import uuid
from typing import Any

from password_bot.models.category import Category
from password_bot.repositories.account_repo import UNCATEGORIZED
from password_bot.services.vault_service import UpdatedFields
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import (
    Ctx,
    Go,
    Result,
    Screen,
    View,
    back,
    open_screen,
    pop_to,
    refresh,
    replace,
)
from password_bot.ui.screens._shared import load_account
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

ICONS = ("💼", "🏦", "👤", "🎮", "🛒", "📧", "🌐", "🏠", "💳", "📱", "🎓", "⭐")
NAME_MAX = 32


def _assign_args(args: dict[str, Any]) -> dict[str, Any]:
    """The 'who gets this category' args carried through picker → form → icon."""
    return {k: args[k] for k in ("account_id", "flow") if args.get(k)}


async def _own_category(ctx: Ctx, cat_id: object) -> Category | None:
    if not cat_id:
        return None
    cat = await ctx.container.categories.get(str(cat_id))
    return cat if cat is not None and cat.chat_id == ctx.chat_id else None


def _not_found(ctx: Ctx) -> View:
    return View(escape_md("Categoria non trovata."), keyboard(footer(ctx.back_label)))


async def assign_category(ctx: Ctx, args: dict[str, Any], cat_id: str | None) -> Result:
    if args.get("account_id"):
        acc = await load_account(ctx, args["account_id"])
        if acc is not None:
            await ctx.container.vault.update_fields(
                acc.id, UpdatedFields(category_id=cat_id or ""), aes_key=ctx.session.aes_key
            )
        return pop_to("account_detail", notice="✅ Categoria aggiornata")
    if args.get("flow"):
        flow_key = str(args["flow"])
        ctx.flow(flow_key)["category_id"] = cat_id
        return pop_to(flow_key)
    return back()


class CategoriesScreen(Screen):
    name = "categories"
    title = "Categorie"

    async def render(self, ctx: Ctx) -> View:
        items = await ctx.container.categories.list_with_counts(ctx.chat_id)
        uncategorized = await ctx.container.categories.count_uncategorized(ctx.chat_id)
        lines = ["🏷 *Categorie*"]
        if not items:
            lines.append(escape_md("Nessuna categoria. Creane una per raggruppare gli account."))
        buttons = [
            btn(label(f"{category_label(c)} ({n})", 28), self.name, "open", c.id) for c, n in items
        ]
        rows = [buttons[i : i + 2] for i in range(0, len(buttons), 2)]
        if uncategorized:
            rows.append(
                [btn(f"📂 Senza categoria ({uncategorized})", self.name, "open", UNCATEGORIZED)]
            )
        rows.append(
            [btn("➕ Nuova categoria", self.name, "new", style=None if items else PRIMARY)]  # noqa: RUF001
        )
        rows.append(footer(ctx.back_label))
        return View("\n".join(lines), keyboard(*rows))

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "open" and act.arg:
            return open_screen("account_list", category=act.arg)
        if act.action == "new":
            return open_screen("category_form", mode="create")
        return refresh()


class CategoryPickScreen(Screen):
    name = "category_pick"
    title = "Categoria"

    async def render(self, ctx: Ctx) -> View:
        cats = await ctx.container.categories.list_for_chat(ctx.chat_id)
        buttons = [btn(label(category_label(c)), self.name, "pick", c.id) for c in cats]
        rows = [buttons[i : i + 2] for i in range(0, len(buttons), 2)]
        rows.append([btn("— Nessuna", self.name, "pick", "")])
        rows.append([btn("➕ Nuova", self.name, "new")])  # noqa: RUF001
        rows.append([nav_btn("❌ Annulla", "back")])
        return View("🏷 *Scegli la categoria*", keyboard(*rows))

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "pick":
            cat_id = str(act.arg) if act.arg else None
            if cat_id is not None and await _own_category(ctx, cat_id) is None:
                return refresh(notice="⚠️ Categoria non trovata.")
            return await assign_category(ctx, ctx.args, cat_id)
        if act.action == "new":
            return open_screen("category_form", mode="create", **_assign_args(ctx.args))
        return refresh()


class CategoryFormScreen(Screen):
    name = "category_form"
    title = "Categoria"
    accepts_text = True

    async def render(self, ctx: Ctx) -> View:
        if ctx.args.get("mode") == "rename":
            cat = await _own_category(ctx, ctx.args.get("cat_id"))
            if cat is None:
                return _not_found(ctx)
            text = escape_md(f"✏️ Nuovo nome per «{cat.name}»? (massimo {NAME_MAX} caratteri)")
        else:
            text = escape_md(f"🏷 Nome della nuova categoria? (massimo {NAME_MAX} caratteri)")
        return View(text, keyboard([nav_btn("❌ Annulla", "back")]))

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        value = text.strip()
        if not value:
            return refresh(notice="⚠️ Il nome non può essere vuoto.")
        if len(value) > NAME_MAX:
            return refresh(notice=f"⚠️ Massimo {NAME_MAX} caratteri.")
        renaming = ctx.args.get("mode") == "rename"
        existing = await ctx.container.categories.get_by_name(ctx.chat_id, value)
        if existing is not None and (not renaming or existing.id != ctx.args.get("cat_id")):
            return refresh(notice=f"⚠️ Esiste già una categoria «{existing.name}».")
        if renaming:
            cat = await _own_category(ctx, ctx.args.get("cat_id"))
            if cat is None:
                return back()
            await ctx.container.categories.rename(cat.id, value)
            return back(notice="✅ Rinominata")
        cat = Category(id=str(uuid.uuid4()), chat_id=ctx.chat_id, name=value, icon=None)
        await ctx.container.categories.create(cat)
        return replace("category_icon", cat_id=cat.id, created=True, **_assign_args(ctx.args))


class CategoryIconScreen(Screen):
    name = "category_icon"
    title = "Icona"

    async def render(self, ctx: Ctx) -> View:
        cat = await _own_category(ctx, ctx.args.get("cat_id"))
        if cat is None:
            return _not_found(ctx)
        buttons = [btn(icon, self.name, "pick", i) for i, icon in enumerate(ICONS)]
        rows = [buttons[i : i + 4] for i in range(0, len(buttons), 4)]
        rows.append([btn("Nessuna", self.name, "pick", -1)])
        rows.append(footer(ctx.back_label))
        return View(escape_md(f"🎨 Scegli un'icona per «{cat.name}»"), keyboard(*rows))

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action != "pick":
            return refresh()
        cat = await _own_category(ctx, ctx.args.get("cat_id"))
        if cat is None:
            return back()
        index = int(act.arg if act.arg is not None else -1)
        icon = ICONS[index] if 0 <= index < len(ICONS) else None
        await ctx.container.categories.set_icon(cat.id, icon)
        if _assign_args(ctx.args):
            return await assign_category(ctx, ctx.args, cat.id)
        if ctx.args.get("created"):
            return back(notice="✅ Categoria creata")
        return back(notice="✅ Icona aggiornata")


class CategoryDeleteScreen(Screen):
    name = "category_delete"
    title = "Elimina categoria"

    async def render(self, ctx: Ctx) -> View:
        cat = await _own_category(ctx, ctx.args.get("cat_id"))
        if cat is None:
            return _not_found(ctx)
        count = len(await ctx.container.accounts.list_for_chat(ctx.chat_id, category=cat.id))
        return View(
            escape_md(
                f"🗑 Eliminare «{cat.name}»?\n"
                f"Account collegati: {count}. Non vengono eliminati: restano senza categoria."
            ),
            keyboard(
                [btn("🗑 Elimina", self.name, "confirm", style=DANGER)],
                [nav_btn("❌ Annulla", "back")],
            ),
        )

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action != "confirm":
            return refresh()
        cat = await _own_category(ctx, ctx.args.get("cat_id"))
        if cat is not None:
            await ctx.container.categories.delete(cat.id)
        return Go(pop_to="account_list", pop_to_inclusive=True, notice="🗑 Categoria eliminata")
