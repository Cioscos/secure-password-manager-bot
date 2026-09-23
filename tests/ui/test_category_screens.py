"""Categories: list, picker, create/rename, icon, delete."""

from __future__ import annotations

from password_bot.ui.screen import Go, back, open_screen, pop_to, replace
from password_bot.ui.screens.categories import (
    ICONS,
    CategoriesScreen,
    CategoryDeleteScreen,
    CategoryFormScreen,
    CategoryIconScreen,
    CategoryPickScreen,
)
from password_bot.ui.views import DANGER, PRIMARY
from tests.ui._helpers import act, button, labels


async def _category_of(env, account_id):
    acc = await env.container.vault.get_decrypted(account_id, aes_key=env.session.aes_key)
    return acc.category_id


async def test_list_with_counts_and_uncategorized(env):
    cat = await env.category("Lavoro", icon="💼")
    await env.add("Jira", category_id=cat.id)
    await env.add("Netflix")
    screen = CategoriesScreen()
    ctx = env.ctx()
    view = await screen.render(ctx)
    assert "💼 Lavoro (1)" in labels(view)
    assert "📂 Senza categoria (1)" in labels(view)
    assert await screen.on_action(ctx, act(view, "💼 Lavoro (1)")) == open_screen(
        "account_list", category=cat.id
    )
    assert await screen.on_action(ctx, act(view, "📂 Senza categoria")) == open_screen(
        "account_list", category="none"
    )
    assert await screen.on_action(ctx, act(view, "➕ Nuova categoria")) == open_screen(  # noqa: RUF001
        "category_form", mode="create"
    )


async def test_empty_list_makes_new_primary(env):
    view = await CategoriesScreen().render(env.ctx())
    assert "Nessuna categoria" in view.text
    assert button(view, "➕ Nuova categoria").style == PRIMARY  # noqa: RUF001


async def test_create_validates_then_asks_icon(env):
    form = CategoryFormScreen()
    ctx = env.ctx({"mode": "create"}, back_label="Categorie")
    assert "Nome della nuova categoria" in (await form.render(ctx)).text
    assert (await form.on_text(ctx, "  ")).notice == "⚠️ Il nome non può essere vuoto."
    assert (await form.on_text(ctx, "x" * 33)).notice == "⚠️ Massimo 32 caratteri."
    result = await form.on_text(ctx, "Lavoro")
    cat = await env.container.categories.get_by_name(1, "lavoro")
    assert cat is not None and cat.icon is None
    assert result == replace("category_icon", cat_id=cat.id, created=True)

    icon_screen = CategoryIconScreen()
    ictx = env.ctx({"cat_id": cat.id, "created": True}, back_label="Categorie")
    view = await icon_screen.render(ictx)
    assert [label for label in labels(view) if label in ICONS] == list(ICONS)
    assert await icon_screen.on_action(ictx, act(view, "💼")) == back(notice="✅ Categoria creata")
    assert (await env.container.categories.get(cat.id)).icon == "💼"


async def test_duplicate_name_is_rejected(env):
    await env.category("Lavoro")
    result = await CategoryFormScreen().on_text(env.ctx({"mode": "create"}), "lavoro")
    assert result.notice == "⚠️ Esiste già una categoria «Lavoro»."


async def test_rename_allows_case_change(env):
    cat = await env.category("Lavoro")
    form = CategoryFormScreen()
    ctx = env.ctx({"mode": "rename", "cat_id": cat.id})
    assert "Nuovo nome" in (await form.render(ctx)).text
    assert await form.on_text(ctx, "lavoro") == back(notice="✅ Rinominata")
    assert (await env.container.categories.get(cat.id)).name == "lavoro"


async def test_icon_change_and_removal(env):
    cat = await env.category("Lavoro", icon="💼")
    screen = CategoryIconScreen()
    ctx = env.ctx({"cat_id": cat.id})
    view = await screen.render(ctx)
    assert await screen.on_action(ctx, act(view, "Nessuna")) == back(notice="✅ Icona aggiornata")
    assert (await env.container.categories.get(cat.id)).icon is None


async def test_pick_assigns_and_clears_account_category(env):
    cat = await env.category("Lavoro")
    acc = await env.add("Jira")
    screen = CategoryPickScreen()
    ctx = env.ctx({"account_id": acc.id}, back_label="Modifica")
    view = await screen.render(ctx)
    assert await screen.on_action(ctx, act(view, "Lavoro")) == pop_to(
        "account_detail", notice="✅ Categoria aggiornata"
    )
    assert await _category_of(env, acc.id) == cat.id
    await screen.on_action(ctx, act(view, "— Nessuna"))
    assert await _category_of(env, acc.id) is None


async def test_pick_for_creation_flow(env):
    cat = await env.category("Lavoro")
    screen = CategoryPickScreen()
    ctx = env.ctx({"flow": "account_new"})
    view = await screen.render(ctx)
    assert await screen.on_action(ctx, act(view, "Lavoro")) == pop_to("account_new")
    assert ctx.flow("account_new")["category_id"] == cat.id


async def test_new_category_from_picker_is_assigned_after_icon(env):
    acc = await env.add("Banca X")
    pick = CategoryPickScreen()
    pctx = env.ctx({"account_id": acc.id})
    view = await pick.render(pctx)
    assert await pick.on_action(pctx, act(view, "➕ Nuova")) == open_screen(  # noqa: RUF001
        "category_form", mode="create", account_id=acc.id
    )
    form = CategoryFormScreen()
    result = await form.on_text(env.ctx({"mode": "create", "account_id": acc.id}), "Banche")
    assert result.push.name == "category_icon"
    assert result.push.data["account_id"] == acc.id
    icon_screen = CategoryIconScreen()
    ictx = env.ctx(result.push.data)
    view = await icon_screen.render(ictx)
    assert await icon_screen.on_action(ictx, act(view, "🏦")) == pop_to(
        "account_detail", notice="✅ Categoria aggiornata"
    )
    cat = await env.container.categories.get_by_name(1, "Banche")
    assert cat.icon == "🏦"
    assert await _category_of(env, acc.id) == cat.id


async def test_delete_keeps_accounts(env):
    cat = await env.category("Lavoro")
    acc = await env.add("Jira", category_id=cat.id)
    screen = CategoryDeleteScreen()
    ctx = env.ctx({"cat_id": cat.id})
    view = await screen.render(ctx)
    assert "Account collegati: 1" in view.text
    assert button(view, "🗑 Elimina").style == DANGER
    result = await screen.on_action(ctx, act(view, "🗑 Elimina"))
    assert result == Go(
        pop_to="account_list", pop_to_inclusive=True, notice="🗑 Categoria eliminata"
    )
    assert await env.container.categories.get(cat.id) is None
    assert await _category_of(env, acc.id) is None
