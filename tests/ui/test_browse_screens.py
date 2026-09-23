"""Account list (incl. category mode) and search."""

from __future__ import annotations

from password_bot.state.fsm import Frame
from password_bot.ui.screen import Go, open_screen, replace
from password_bot.ui.screens.account_list import AccountListScreen
from password_bot.ui.screens.search import SearchScreen
from password_bot.ui.views import DANGER, PRIMARY
from tests.ui._helpers import act, button, labels


async def test_empty_list_offers_new_account(env):
    view = await AccountListScreen().render(env.ctx())
    assert "Nessun account" in view.text
    assert button(view, "➕ Nuovo account").style == PRIMARY  # noqa: RUF001
    assert labels(view)[-2:] == ["🔙 Home", "🏠 Menu"]


async def test_list_paginates_by_eight(env):
    for i in range(10):
        await env.add(f"acc{i:02d}")
    screen = AccountListScreen()
    view = await screen.render(env.ctx({"page": 0}))
    assert [label for label in labels(view) if label.startswith("acc")] == [
        f"acc{i:02d}" for i in range(8)
    ]
    assert "1/2" in labels(view) and "▶" in labels(view) and "◀" not in labels(view)
    assert await screen.on_action(env.ctx({"page": 0}), act(view, "▶")) == replace(
        "account_list", category=None, page=1
    )
    view2 = await screen.render(env.ctx({"page": 1}))
    assert [label for label in labels(view2) if label.startswith("acc")] == ["acc08", "acc09"]
    assert "🏷 Per categoria" in labels(view2)


async def test_open_account_from_list(env):
    acc = await env.add("GitHub")
    screen = AccountListScreen()
    view = await screen.render(env.ctx())
    assert await screen.on_action(env.ctx(), act(view, "GitHub")) == open_screen(
        "account_detail", id=acc.id
    )


async def test_category_mode_shows_management_buttons(env):
    cat = await env.category("Lavoro", icon="💼")
    await env.add("Jira", category_id=cat.id)
    await env.add("Netflix")
    screen = AccountListScreen()
    ctx = env.ctx({"category": cat.id}, back_label="Categorie")
    view = await screen.render(ctx)
    assert "💼 Lavoro" in view.text and "1 account" in view.text
    assert "Jira" in labels(view) and "Netflix" not in labels(view)
    assert button(view, "🗑 Elimina").style == DANGER
    assert await screen.on_action(
        ctx,
        act(view, "➕ Nuovo account qui"),  # noqa: RUF001
    ) == open_screen("account_new", category_id=cat.id)
    assert await screen.on_action(ctx, act(view, "✏️ Rinomina")) == open_screen(
        "category_form", mode="rename", cat_id=cat.id
    )
    assert await screen.on_action(ctx, act(view, "🗑 Elimina")) == open_screen(
        "category_delete", cat_id=cat.id
    )


async def test_uncategorized_mode(env):
    cat = await env.category("Lavoro")
    await env.add("Jira", category_id=cat.id)
    await env.add("Netflix")
    view = await AccountListScreen().render(env.ctx({"category": "none"}))
    assert "Senza categoria" in view.text
    assert "Netflix" in labels(view) and "Jira" not in labels(view)
    assert "✏️ Rinomina" not in labels(view)


async def test_unknown_category(env):
    view = await AccountListScreen().render(env.ctx({"category": "missing"}))
    assert "Categoria non trovata" in view.text


async def test_search_prompt_then_results(env):
    a = await env.add("GitHub")
    await env.add("GitLab")
    screen = SearchScreen()
    assert "Scrivi il nome" in (await screen.render(env.ctx())).text
    assert await screen.on_text(env.ctx(), "  git ") == replace("search", q="git")
    view = await screen.render(env.ctx({"q": "git"}))
    assert any(label.startswith("GitHub") for label in labels(view))
    assert await screen.on_action(env.ctx({"q": "git"}), act(view, "GitHub")) == open_screen(
        "account_detail", id=a.id
    )


async def test_search_single_match_opens_detail(env):
    a = await env.add("Netflix")
    result = await SearchScreen().on_text(env.ctx(), "netflix")
    assert result == Go(pop=1, push=Frame("account_detail", {"id": a.id}))


async def test_search_no_results(env):
    view = await SearchScreen().render(env.ctx({"q": "zzz"}))
    assert "Nessun risultato" in view.text
