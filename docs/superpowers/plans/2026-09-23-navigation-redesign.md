# Navigation Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the bot's scattered handlers with a single-live-message screen router, then rebuild account detail, editing (password via generator), creation (username suggestions), categories (with icons), health, settings and export/import on top of it.

**Architecture:** A `Navigator` owns the navigation stack (in `chat_data`), the id of the one live bot message (edited in place), routing of typed `Act` callbacks / text / documents to the top `Screen`, locking and auto-close jobs. Each `Screen` is a small class whose `render()` returns a `View` (MarkdownV2 text + inline keyboard) and whose `on_action` / `on_text` / `on_document` return a navigation result (`Go`, `Reveal`, `Lock`). Old handlers keep running until Task 15 swaps the wiring in one step.

**Tech Stack:** Python 3.13+, python-telegram-bot 22.8 (`job-queue`, `callback-data` extras, `arbitrary_callback_data=True`, `PicklePersistence`), aiosqlite, pytest + pytest-asyncio (`asyncio_mode=auto`), ruff, uv.

**Spec:** `docs/superpowers/specs/2026-09-23-navigation-redesign-design.md`

## Global Constraints

- Dependency: `python-telegram-bot[job-queue,callback-data]>=22.8` in `pyproject.toml`; lock refreshed with `uv lock --upgrade-package python-telegram-bot`.
- All bot text is sent with `ParseMode.MARKDOWN_V2`. Every dynamic or static plain string goes through `escape_md()`; secrets shown in clear go through `code_inline()`.
- `Act` callback payloads carry only screen names, action names, ids, page numbers and list indices — **never** a username, password, URL or note (the PTB callback-data cache is pickled into `DB.pkl`).
- In-progress flow data lives only under `ChatDataKey.FLOW`, which is stripped from persistence and cleared by `FsmContext.lock()`.
- Stack frame args (`Frame.data`) hold only ids, page numbers, flags and search queries.
- Button styles: `primary` for the main action, `success` for confirmations (Salva, Usa, Sostituisci), `danger` for destructive actions (Elimina). Use `views.PRIMARY` / `SUCCESS` / `DANGER`.
- Timings: account detail auto-closes after **60 s**; revealed secrets are deleted after **30 s**. `CopyTextButton` text max **256** chars.
- Account list page size: **8**. Category names: required, **≤ 32** chars, unique per chat case-insensitively. Category icon palette, exactly: `💼 🏦 👤 🎮 🛒 📧 🌐 🏠 💳 📱 🎓 ⭐`.
- UI strings are Italian and copied verbatim from the code blocks in this plan.
- Lint/format: `uv run ruff check src tests` and `uv run ruff format src tests` (line length 100). Tests: `uv run pytest -q`.
- Every commit message ends with a blank line and `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. **Upgrading a production `DB.pkl`.** Old pickles contain `password_bot.state.fsm.Screen` stack entries and `password_bot.telegram_utils.callback_data.ListPageData` callback payloads; both names must stay importable or the bot crashes at startup (Task 4 test on the `Screen` alias; Task 15 keeps `callback_data.py` and tests it).
2. **Secrets with MarkdownV2-hostile characters.** A password containing `\` or `` ` `` shown via reveal or in the generator must not break parsing — `code_inline` escapes both (Task 4 test).
3. **URLs Telegram rejects in a URL button** (`javascript:alert(1)`, `ftp://x.com`, `not a url`, text with spaces, bare words). No URL button, no render failure (Task 4 `normalize_url` tests, Task 8 detail test).
4. **A button tapped on a message that isn't the live one**, after a restart (live id missing), with a legacy string payload, or after the session expired between render and tap. It must be adopted, treated as stale (→ Home), or sent through unlock and then resumed (Task 5 tests).
5. **Names and notes with MarkdownV2 specials** (`_*[]()~>#+-=|{}.!`). They must be escaped on every screen (Task 8 detail test; Task 16 renders every screen with such a name and asserts the raw name never appears unescaped).

## Notes on the spec

- **No `sensitive_input` flag.** The spec had screens declare sensitive text input. The Navigator deletes *every* user text message after reading it, so the flag would change nothing and is dropped.
- **Messages outside the live message, by design:** revealed secrets (self-destruct after 30 s, no buttons), the export `.json` document, the daily stale-password alert (a job message; its `/list_stale` hint opens Health) and the `/stop` goodbye (the conversation has ended). Everything else is the single live message.
- **Autolock choices** become 5/15/30/60 min (the old `0` meant "default 15" and was confusing) and **stale threshold** choices 90/180/365 days (the old `0` flagged every password).

---

## File Structure

**Create (`src/password_bot/ui/`)**

| File | Responsibility |
|---|---|
| `ui/__init__.py` | package marker |
| `ui/callbacks.py` | `Act` dataclass, `NAV` pseudo-screen name |
| `ui/screen.py` | `View`, `Ctx`, results (`Go`, `Reveal`, `Lock`), result helpers, `Screen` base, `TEXT_NOT_ACCEPTED` |
| `ui/views.py` | button/keyboard helpers, styles, `normalize_url`, `md_date`, `plain_date`, `label`, `category_label` |
| `ui/navigator.py` | `Navigator`, job-name helpers, expiry job |
| `ui/jobs.py` | `schedule_autolock`, `autolock_job` |
| `ui/registry.py` | `build_screens()` |
| `ui/commands.py` | PTB handler functions delegating to `Navigator` |
| `ui/legacy.py` | one-time cleanup of old-UI `chat_data` |
| `ui/screens/__init__.py` | package marker |
| `ui/screens/_shared.py` | `load_account`, `reuse_names`, `reuse_names_for`, `strength_text`, `username_suggestions` |
| `ui/screens/home.py`, `unlock.py`, `help.py` | session + menu screens |
| `ui/screens/account_list.py`, `search.py` | browsing (list doubles as category screen) |
| `ui/screens/account_detail.py`, `history.py`, `account_delete.py` | detail and its direct actions |
| `ui/screens/account_edit.py` | "Modifica…" submenu + single-field edit |
| `ui/screens/generator.py` | reusable password generator |
| `ui/screens/password_change.py` | change password (generate/manual → confirm) |
| `ui/screens/account_new.py` | creation wizard + summary |
| `ui/screens/categories.py` | category list, picker, form, icon, delete |
| `ui/screens/health.py`, `settings.py`, `transfer.py` | health, settings, export/import |

**Modify:** `pyproject.toml`, `uv.lock`, `state/keys.py`, `state/fsm.py`, `telegram_utils/md.py`, `models/category.py`, `repositories/account_repo.py`, `repositories/category_repo.py`, `services/vault_service.py`, `services/export_service.py`, `bot.py`, `handlers/common.py`, `handlers/categories.py` (one line, Task 2), `CLAUDE.md`.

**Delete (Task 15):** `handlers/{account_edit,account_new,account_view,auth,categories,dispatcher,export,inline_cmd,nav,password_gen,settings}.py`, `telegram_utils/keyboards.py`, and their tests. **Keep** `telegram_utils/callback_data.py` (unpickling old `DB.pkl`).

**Tests:** new `tests/ui/` package (`conftest.py`, `_helpers.py`, one test module per screen group), plus additions to existing repository/service tests.

---

### Task 1: Upgrade python-telegram-bot to 22.8

**Files:**
- Modify: `pyproject.toml` (dependency line)
- Modify: `uv.lock`
- Create: `tests/test_ptb_features.py`

**Interfaces:**
- Produces: PTB ≥ 22.8 with `InlineKeyboardButton(style=...)`, `telegram.constants.KeyboardButtonStyle`, `CopyTextButton`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ptb_features.py
"""Bot API features the UI relies on (PTB >= 22.8)."""

import telegram
from telegram import CopyTextButton, InlineKeyboardButton


def test_ptb_is_at_least_22_8():
    major, minor = (int(x) for x in telegram.__version__.split(".")[:2])
    assert (major, minor) >= (22, 8)


def test_inline_button_accepts_style():
    from telegram.constants import KeyboardButtonStyle

    button = InlineKeyboardButton("x", callback_data="y", style=KeyboardButtonStyle.DANGER)
    assert button.style == "danger"


def test_copy_text_button_available():
    button = InlineKeyboardButton("c", copy_text=CopyTextButton("secret"))
    assert button.copy_text.text == "secret"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_ptb_features.py -v`
Expected: FAIL — `test_ptb_is_at_least_22_8` (version 22.5) and `test_inline_button_accepts_style` (`ImportError` / unexpected keyword `style`).

- [ ] **Step 3: Upgrade**

In `pyproject.toml` replace the line `"python-telegram-bot[job-queue,callback-data]",` with:

```toml
    "python-telegram-bot[job-queue,callback-data]>=22.8",
```

Then run:

```bash
uv lock --upgrade-package python-telegram-bot
uv sync --dev
```

- [ ] **Step 4: Run the full suite**

Run: `uv run pytest -q`
Expected: all tests PASS (157 existing + 3 new).

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml uv.lock tests/test_ptb_features.py
git commit -m "Upgrade python-telegram-bot to 22.8 for button styles

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Repository and service additions

**Files:**
- Modify: `src/password_bot/models/category.py`
- Modify: `src/password_bot/repositories/category_repo.py`
- Modify: `src/password_bot/repositories/account_repo.py`
- Modify: `src/password_bot/services/vault_service.py`
- Modify: `src/password_bot/handlers/categories.py:168` (`color=None` → `icon=None`)
- Test: `tests/repositories/test_account_repo.py`, `tests/repositories/test_category_repo.py`, `tests/services/test_vault_service.py`, `tests/test_models.py`

**Interfaces:**
- Produces:
  - `Category(id: str, chat_id: int, name: str, icon: str | None)` (field renamed from `color`; DB column stays `color`).
  - `CategoryRepo.set_icon(cat_id: str, icon: str | None) -> None`
  - `CategoryRepo.list_with_counts(chat_id: int) -> list[tuple[Category, int]]` (ordered by name, case-insensitive)
  - `CategoryRepo.count_uncategorized(chat_id: int) -> int`
  - `account_repo.UNCATEGORIZED = "none"`
  - `AccountRepo.list_for_chat(chat_id: int, *, category: str | None = None) -> list[AccountRow]` — `None` = all, `UNCATEGORIZED` = no category, otherwise a category id.
  - `AccountRepo.find_by_hmac(chat_id: int, password_hmac: str) -> list[AccountRow]` (ordered by name; `''` never matches)
  - `VaultService.username_suggestions(chat_id: int, *, aes_key: bytes, limit: int = 5) -> list[str]`

- [ ] **Step 1: Write the failing tests**

In `tests/test_models.py` change `Category(id="cat1", chat_id=1, name="Work", color=None)` to `Category(id="cat1", chat_id=1, name="Work", icon=None)`.

In `tests/repositories/test_category_repo.py` replace every `color=None` with `icon=None` and `color="🟢"` with `icon="🟢"`, then add to the import block at the top of the file:

```python
from pathlib import Path

from password_bot.models.account import AccountRow
from password_bot.repositories.account_repo import AccountRepo
```

and append:

```python
def _row(account_id: str, category_id: str | None) -> AccountRow:
    return AccountRow(
        id=account_id,
        chat_id=1,
        name=account_id,
        username_enc=None,
        password_enc="p",
        url_enc=None,
        note_enc=None,
        category_id=category_id,
        password_hmac="h",
        crypto_version=2,
        password_changed_at=1,
        created_at=1,
        updated_at=1,
    )


@pytest.mark.asyncio
async def test_icon_roundtrip_and_set_icon(repo: CategoryRepo):
    await repo.create(Category(id="c1", chat_id=1, name="Work", icon="💼"))
    got = await repo.get("c1")
    assert got is not None and got.icon == "💼"
    await repo.set_icon("c1", None)
    got = await repo.get("c1")
    assert got is not None and got.icon is None


@pytest.mark.asyncio
async def test_list_with_counts_and_uncategorized(repo: CategoryRepo, tmp_db_path: Path):
    await repo.create(Category(id="c1", chat_id=1, name="Work", icon=None))
    await repo.create(Category(id="c2", chat_id=1, name="Home", icon=None))
    accounts = AccountRepo(tmp_db_path)
    await accounts.insert(_row("a1", "c1"))
    await accounts.insert(_row("a2", "c1"))
    await accounts.insert(_row("a3", None))
    counts = await repo.list_with_counts(1)
    assert [(c.name, n) for c, n in counts] == [("Home", 0), ("Work", 2)]
    assert await repo.count_uncategorized(1) == 1
```

Add to the import block at the top of `tests/repositories/test_account_repo.py`:

```python
from password_bot.models.category import Category
from password_bot.repositories.account_repo import UNCATEGORIZED
from password_bot.repositories.category_repo import CategoryRepo
```

and append:

```python
@pytest.mark.asyncio
async def test_find_by_hmac(repos: AccountRepo):
    for account_id, name, hmac in [("a1", "GitHub", "h1"), ("a2", "GitLab", "h1"), ("a3", "X", "h2")]:
        row = _make_row(account_id, name=name)
        row.password_hmac = hmac
        await repos.insert(row)
    assert [r.id for r in await repos.find_by_hmac(1, "h1")] == ["a1", "a2"]
    assert await repos.find_by_hmac(1, "") == []


@pytest.mark.asyncio
async def test_list_for_chat_category_filter(repos: AccountRepo, tmp_db_path: Path):
    await CategoryRepo(tmp_db_path).create(Category(id="c1", chat_id=1, name="Work", icon=None))
    in_cat = _make_row("a1", name="A")
    in_cat.category_id = "c1"
    await repos.insert(in_cat)
    await repos.insert(_make_row("a2", name="B"))
    assert [r.id for r in await repos.list_for_chat(1, category="c1")] == ["a1"]
    assert [r.id for r in await repos.list_for_chat(1, category=UNCATEGORIZED)] == ["a2"]
    assert len(await repos.list_for_chat(1)) == 2
```

Append to `tests/services/test_vault_service.py`:

```python
@pytest.mark.asyncio
async def test_username_suggestions_ranked_by_frequency(vault: VaultService, aes_key):
    for name, user in [
        ("a", "bob"),
        ("b", "me@x.com"),
        ("c", "ME@x.com"),
        ("d", "me@x.com"),
        ("e", "bob"),
        ("f", None),
        ("g", "solo"),
    ]:
        await vault.add(
            NewAccount(
                chat_id=1, name=name, username=user, password="p", url=None, note=None,
                category_id=None,
            ),
            aes_key=aes_key,
            hmac_key=b"\x10" * 32,
        )
    suggestions = await vault.username_suggestions(1, aes_key=aes_key)
    assert [s.lower() for s in suggestions] == ["me@x.com", "bob", "solo"]
    assert await vault.username_suggestions(1, aes_key=aes_key, limit=1) == [suggestions[0]]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_models.py tests/repositories tests/services/test_vault_service.py -q`
Expected: FAIL — `TypeError: ... unexpected keyword argument 'icon'`, `AttributeError: ... 'find_by_hmac'`, `ImportError: cannot import name 'UNCATEGORIZED'`, `AttributeError: ... 'username_suggestions'`.

- [ ] **Step 3: Implement**

`src/password_bot/models/category.py`:

```python
from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Category:
    id: str
    chat_id: int
    name: str
    icon: str | None  # stored in the legacy `categories.color` column
```

`src/password_bot/repositories/category_repo.py` — replace `_row_to_category`, `create`, and add the new methods (keep `get`, `get_by_name`, `list_for_chat`, `rename`, `delete` unchanged):

```python
def _row_to_category(row: aiosqlite.Row) -> Category:
    return Category(id=row["id"], chat_id=row["chat_id"], name=row["name"], icon=row["color"])
```

```python
    async def create(self, cat: Category) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                "INSERT INTO categories (id, chat_id, name, color) VALUES (?, ?, ?, ?)",
                (cat.id, cat.chat_id, cat.name, cat.icon),
            )

    async def set_icon(self, cat_id: str, icon: str | None) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute("UPDATE categories SET color=? WHERE id=?", (icon, cat_id))

    async def list_with_counts(self, chat_id: int) -> list[tuple[Category, int]]:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                """
                SELECT c.*, COUNT(a.id) AS n
                  FROM categories c
                  LEFT JOIN accounts a ON a.category_id = c.id
                 WHERE c.chat_id=?
                 GROUP BY c.id
                 ORDER BY c.name COLLATE NOCASE
                """,
                (chat_id,),
            )
            return [(_row_to_category(r), r["n"]) for r in await cur.fetchall()]

    async def count_uncategorized(self, chat_id: int) -> int:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT COUNT(*) FROM accounts WHERE chat_id=? AND category_id IS NULL",
                (chat_id,),
            )
            row = await cur.fetchone()
            return int(row[0]) if row else 0
```

`src/password_bot/repositories/account_repo.py` — add the constant under `_ALLOWED_UPDATE_FIELDS`, replace `list_for_chat`, add `find_by_hmac`:

```python
UNCATEGORIZED = "none"  # list_for_chat(category=UNCATEGORIZED) → accounts without category
```

```python
    async def list_for_chat(
        self, chat_id: int, *, category: str | None = None
    ) -> list[AccountRow]:
        where = "chat_id=?"
        params: list[Any] = [chat_id]
        if category == UNCATEGORIZED:
            where += " AND category_id IS NULL"
        elif category is not None:
            where += " AND category_id=?"
            params.append(category)
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                f"SELECT * FROM accounts WHERE {where} ORDER BY name COLLATE NOCASE", params
            )
            return [_row_to_account_row(r) for r in await cur.fetchall()]

    async def find_by_hmac(self, chat_id: int, password_hmac: str) -> list[AccountRow]:
        if not password_hmac:
            return []
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                """
                SELECT * FROM accounts WHERE chat_id=? AND password_hmac=?
                 ORDER BY name COLLATE NOCASE
                """,
                (chat_id, password_hmac),
            )
            return [_row_to_account_row(r) for r in await cur.fetchall()]
```

`src/password_bot/services/vault_service.py` — add after `list_decrypted`:

```python
    async def username_suggestions(
        self, chat_id: int, *, aes_key: bytes, limit: int = 5
    ) -> list[str]:
        """Most used usernames/emails, most frequent first, ties broken by most recent use.

        Emails (values containing '@') are grouped case-insensitively; the most
        recently used spelling is returned. Only `username_enc` is decrypted.
        """
        stats: dict[str, tuple[str, int, int]] = {}  # key -> (display, count, last_used)
        for row in await self._accounts.list_for_chat(chat_id):
            value = self._dec(row.username_enc, aes_key)
            if not value:
                continue
            key = value.lower() if "@" in value else value
            display, count, last = stats.get(key, (value, 0, 0))
            if row.updated_at >= last:
                display = value
            stats[key] = (display, count + 1, max(last, row.updated_at))
        ranked = sorted(stats.values(), key=lambda s: (-s[1], -s[2]))
        return [display for display, _, _ in ranked[:limit]]
```

`src/password_bot/handlers/categories.py` line 168: change `color=None,` to `icon=None,`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
uv run ruff format src tests && uv run ruff check src tests
git add src tests
git commit -m "Add category icons/counts, account filters, HMAC lookup, username suggestions

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Import restores categories

**Files:**
- Modify: `src/password_bot/services/export_service.py` (`import_payload`)
- Test: `tests/services/test_export_service.py`

**Interfaces:**
- Consumes: `Category(..., icon=...)`, `CategoryRepo.get_by_name/create` (Task 2).
- Produces: `ExportService.import_payload` creates missing categories (all names in the file's `categories` list and every item's `category`), matching existing ones case-insensitively, and assigns `category_id`.

- [ ] **Step 1: Write the failing tests**

Add to the import block at the top of `tests/services/test_export_service.py`:

```python
from password_bot.models.category import Category
from password_bot.services.vault_service import UpdatedFields
```

and append:

```python
@pytest.mark.asyncio
async def test_import_restores_categories(setup, tmp_db_path: Path):
    export, vault_key, vault = setup
    cats = CategoryRepo(tmp_db_path)
    await cats.create(Category(id="c1", chat_id=1, name="Lavoro", icon="💼"))
    await cats.create(Category(id="c2", chat_id=1, name="Vuota", icon=None))
    accs = await vault.list_decrypted(1, aes_key=vault_key)
    await vault.update_fields(accs[0].id, UpdatedFields(category_id="c1"), aes_key=vault_key)
    payload = await export.export(chat_id=1, vault_key=vault_key, export_passphrase="exp")

    for a in accs:
        await vault.delete(a.id)
    await cats.delete("c1")
    await cats.delete("c2")

    await export.import_payload(
        payload,
        chat_id=1,
        vault_key=vault_key,
        hmac_key=b"\x10" * 32,
        export_passphrase="exp",
        strategy=MergeStrategy.SKIP,
    )
    lavoro = await cats.get_by_name(1, "Lavoro")
    assert lavoro is not None
    restored = await vault.list_decrypted(1, aes_key=vault_key)
    assert restored[0].category_id == lavoro.id
    assert await cats.get_by_name(1, "Vuota") is not None


@pytest.mark.asyncio
async def test_import_reuses_existing_category(setup, tmp_db_path: Path):
    export, vault_key, vault = setup
    cats = CategoryRepo(tmp_db_path)
    await cats.create(Category(id="c1", chat_id=1, name="Lavoro", icon=None))
    accs = await vault.list_decrypted(1, aes_key=vault_key)
    await vault.update_fields(accs[0].id, UpdatedFields(category_id="c1"), aes_key=vault_key)
    payload = await export.export(chat_id=1, vault_key=vault_key, export_passphrase="exp")
    for a in accs:
        await vault.delete(a.id)
    await cats.rename("c1", "lavoro")

    await export.import_payload(
        payload,
        chat_id=1,
        vault_key=vault_key,
        hmac_key=b"\x10" * 32,
        export_passphrase="exp",
        strategy=MergeStrategy.SKIP,
    )
    assert [c.id for c in await cats.list_for_chat(1)] == ["c1"]
    restored = await vault.list_decrypted(1, aes_key=vault_key)
    assert restored[0].category_id == "c1"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/services/test_export_service.py -q`
Expected: FAIL — `restored[0].category_id` is `None`; `get_by_name(1, "Vuota")` is `None`.

- [ ] **Step 3: Implement**

In `src/password_bot/services/export_service.py` add imports:

```python
import uuid

from password_bot.models.category import Category
```

In `import_payload`, after the `existing = {...}` block and before `added = skipped = overwritten = 0`, insert:

```python
        category_ids = {c.name.lower(): c.id for c in await self._categories.list_for_chat(chat_id)}

        async def category_id_for(name: str | None) -> str | None:
            clean = (name or "").strip()[:32]
            if not clean:
                return None
            key = clean.lower()
            if key not in category_ids:
                cat = Category(id=str(uuid.uuid4()), chat_id=chat_id, name=clean, icon=None)
                await self._categories.create(cat)
                category_ids[key] = cat.id
            return category_ids[key]

        for cat_name in schema.categories:
            await category_id_for(cat_name)
```

and in the final `NewAccount(...)` replace `category_id=None,` with:

```python
                    category_id=await category_id_for(item.category),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/services/test_export_service.py -q`
Expected: PASS (all 5).

- [ ] **Step 5: Commit**

```bash
uv run ruff format src tests && uv run ruff check src tests
git add src tests
git commit -m "Restore categories when importing a vault export

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: UI foundations (Act, Screen contract, views, FSM additions)

**Files:**
- Modify: `src/password_bot/state/keys.py`
- Modify: `src/password_bot/state/fsm.py` (full replacement below)
- Modify: `src/password_bot/telegram_utils/md.py` (`code_inline`)
- Modify: `src/password_bot/bot.py` (`_SessionStrippingPersistence`)
- Create: `src/password_bot/ui/__init__.py`, `src/password_bot/ui/callbacks.py`, `src/password_bot/ui/screen.py`, `src/password_bot/ui/views.py`
- Create: `tests/ui/__init__.py` (empty), `tests/ui/test_foundations.py`

**Interfaces:**
- Consumes: `Category.icon` (Task 2).
- Produces:
  - `ChatDataKey.FLOW = "flow"`, `LIVE_MESSAGE_ID = "live_message_id"`, `LIVE_TOKEN = "live_token"`, `RESUME = "resume"`.
  - `state.fsm.Frame(name: str, data: dict = {})`, alias `Screen = Frame`; `FsmContext.frames() -> list[Frame]`, `set_resume(frame)`, `pop_resume() -> Frame | None`; `lock()` also clears `FLOW` and `RESUME`.
  - `ui.callbacks.NAV = "_nav"`, `Act(screen: str, action: str, arg: str | int | None = None)` (frozen).
  - `ui.screen`: `TEXT_NOT_ACCEPTED`, `View(text, keyboard=None, expire_after=None)`, `Ctx(container, chat_id, chat_data, args, back_label=None, bot=None, application=None, user_name="", progress=None)` with `.fsm`, `.session`, `.flow(key) -> dict`, `.drop_flow(key)`; results `Go(push, pop, pop_to, pop_to_inclusive, home, render, notice, toast)`, `Reveal(text, seconds=30, toast=None)`, `Lock()`, `Result`; helpers `open_screen(name, **args)`, `replace(name, *, notice=None, toast=None, **args)`, `back(notice=None, toast=None)`, `refresh(notice=None, toast=None)`, `home(notice=None)`, `pop_to(name, notice=None, toast=None)`, `finish(flow_screen, *, then=None, notice=None, toast=None)`; base class `Screen` (class vars `name`, `title`, `requires_session=True`, `accepts_text=False`, `accepts_document=False`; async `on_enter`, `render`, `on_action`, `on_text`, `on_document`, `render_expired`).
  - `ui.views`: `PRIMARY`, `SUCCESS`, `DANGER`, `COPY_TEXT_MAX=256`, `LABEL_MAX=32`, `btn(label, screen, action, arg=None, *, style=None)`, `nav_btn(label, action)`, `copy_btn(label, value, *, style=None) -> Button | None`, `url_btn(label, raw) -> Button | None`, `footer(back_label) -> list[Button]`, `keyboard(*rows) -> InlineKeyboardMarkup`, `normalize_url(raw) -> str | None`, `md_date(ts) -> str`, `plain_date(ts) -> str`, `label(text, max_len=LABEL_MAX) -> str`, `category_label(cat) -> str`.

- [ ] **Step 1: Write the failing tests**

Create empty `tests/ui/__init__.py`, then `tests/ui/test_foundations.py`:

```python
"""UI building blocks: Act, views helpers, Ctx, FsmContext additions, MarkdownV2 code."""

from __future__ import annotations

import importlib
import pickle
import time

import pytest
from telegram.constants import KeyboardButtonStyle

from password_bot.models.category import Category
from password_bot.state.fsm import Frame, FsmContext
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.md import code_inline
from password_bot.ui import views
from password_bot.ui.callbacks import NAV, Act
from password_bot.ui.screen import (
    Ctx,
    Go,
    back,
    finish,
    home,
    open_screen,
    pop_to,
    refresh,
    replace,
)


def test_act_is_frozen_and_picklable():
    act = Act("account_detail", "reveal", "password")
    assert pickle.loads(pickle.dumps(act)) == act
    with pytest.raises(AttributeError):
        act.screen = "x"  # type: ignore[misc]


def test_btn_carries_act_and_style():
    b = views.btn("🗑 Elimina", "account_detail", "delete", style=views.DANGER)
    assert b.callback_data == Act("account_detail", "delete", None)
    assert b.style == KeyboardButtonStyle.DANGER


def test_nav_btn_targets_nav_pseudo_screen():
    assert views.nav_btn("🏠 Menu", "home").callback_data == Act(NAV, "home", None)


def test_copy_btn_limits():
    assert views.copy_btn("📋", "") is None
    assert views.copy_btn("📋", None) is None
    assert views.copy_btn("📋", "x" * 257) is None
    b = views.copy_btn("📋", "x" * 256, style=views.PRIMARY)
    assert b is not None
    assert b.copy_text.text == "x" * 256
    assert b.style == "primary"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("github.com", "https://github.com"),
        ("https://github.com/login", "https://github.com/login"),
        ("http://1.2.3.4:8080/x", "http://1.2.3.4:8080/x"),
        ("javascript:alert(1)", None),
        ("ftp://x.com", None),
        ("not a url", None),
        ("localhost", None),
        ("word", None),
        ("", None),
        (None, None),
    ],
)
def test_normalize_url(raw, expected):
    assert views.normalize_url(raw) == expected


def test_url_btn():
    assert views.url_btn("🌐", "javascript:alert(1)") is None
    b = views.url_btn("🌐", "github.com")
    assert b is not None and b.url == "https://github.com"


def test_keyboard_drops_none_and_empty_rows():
    kb = views.keyboard([None, views.nav_btn("a", "home")], [None], [])
    assert [[b.text for b in row] for row in kb.inline_keyboard] == [["a"]]


def test_footer_names_back_target():
    assert [b.text for b in views.footer("Lista")] == ["🔙 Lista", "🏠 Menu"]
    assert views.footer(None)[0].text == "🔙 Indietro"


def test_dates():
    ts = int(time.mktime((2026, 5, 12, 12, 0, 0, 0, 0, -1)))
    assert views.md_date(ts) == f"![12/05/2026](tg://time?unix={ts}&format=d)"
    assert views.md_date(0) == "data sconosciuta"
    assert views.plain_date(ts) == "12/05/2026"


def test_label_truncates():
    assert views.label("abc", 5) == "abc"
    assert views.label("abcdefgh", 5) == "abcd…"


def test_category_label():
    assert views.category_label(Category(id="c", chat_id=1, name="Lavoro", icon="💼")) == (
        "💼 Lavoro"
    )
    assert views.category_label(Category(id="c", chat_id=1, name="Lavoro", icon=None)) == "Lavoro"


def test_code_inline_escapes_backslash_and_backtick():
    assert code_inline("a\\b`c") == "`a\\\\b\\`c`"


def test_old_pickled_screen_name_still_resolves():
    # pickle resolves classes by module attribute; old DB.pkl files reference `Screen`.
    assert importlib.import_module("password_bot.state.fsm").Screen is Frame


def test_frames_and_resume():
    fsm = FsmContext({})
    fsm.reset_to(Frame("home"))
    fsm.push(Frame("account_list", {"page": 1}))
    assert [f.name for f in fsm.frames()] == ["home", "account_list"]
    fsm.set_resume(Frame("account_detail", {"id": "a1"}))
    assert fsm.pop_resume() == Frame("account_detail", {"id": "a1"})
    assert fsm.pop_resume() is None


def test_lock_clears_flow_and_resume_but_keeps_live_message():
    data = {
        ChatDataKey.FLOW.value: {"account_new": {"password": "x"}},
        ChatDataKey.RESUME.value: Frame("home"),
        ChatDataKey.LIVE_MESSAGE_ID.value: 5,
    }
    FsmContext(data).lock()
    assert ChatDataKey.FLOW.value not in data
    assert ChatDataKey.RESUME.value not in data
    assert data[ChatDataKey.LIVE_MESSAGE_ID.value] == 5


def test_ctx_flow_helpers():
    ctx = Ctx(container=None, chat_id=1, chat_data={}, args={})
    ctx.flow("x")["a"] = 1
    assert ctx.chat_data[ChatDataKey.FLOW.value] == {"x": {"a": 1}}
    ctx.drop_flow("x")
    ctx.drop_flow("missing")
    assert ctx.chat_data[ChatDataKey.FLOW.value] == {}


def test_result_helpers():
    assert open_screen("account_detail", id="a1") == Go(push=Frame("account_detail", {"id": "a1"}))
    assert replace("search", q="git", notice="n") == Go(
        pop=1, push=Frame("search", {"q": "git"}), notice="n"
    )
    assert back(notice="ok") == Go(pop=1, notice="ok")
    assert refresh(toast="t") == Go(toast="t")
    assert home() == Go(home=True)
    assert pop_to("account_detail", notice="✅") == Go(pop_to="account_detail", notice="✅")
    assert finish("account_new", then=Frame("account_detail", {"id": "a"}), notice="n") == Go(
        pop_to="account_new",
        pop_to_inclusive=True,
        push=Frame("account_detail", {"id": "a"}),
        notice="n",
    )


async def test_persistence_strips_flow(tmp_path):
    from password_bot.bot import _SessionStrippingPersistence

    persistence = _SessionStrippingPersistence(filepath=str(tmp_path / "p.pkl"))
    await persistence.update_chat_data(
        1, {ChatDataKey.FLOW.value: {"x": 1}, ChatDataKey.NAV_STACK.value: []}
    )
    stored = await persistence.get_chat_data()
    assert ChatDataKey.FLOW.value not in stored[1]
    assert ChatDataKey.NAV_STACK.value in stored[1]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/ui/test_foundations.py -q`
Expected: FAIL at collection — `ModuleNotFoundError: No module named 'password_bot.ui'`.

- [ ] **Step 3: Implement**

`src/password_bot/state/keys.py` — add four members at the end of `ChatDataKey`:

```python
    FLOW = "flow"  # in-progress flow drafts (may hold secrets); never persisted
    LIVE_MESSAGE_ID = "live_message_id"  # the single bot message that carries buttons
    LIVE_TOKEN = "live_token"  # bumped on every render; guards auto-close jobs
    RESUME = "resume"  # Frame to reopen after unlocking
```

`src/password_bot/state/fsm.py` — full replacement:

```python
"""Typed wrapper over context.chat_data."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from password_bot.state.keys import ChatDataKey


@dataclass(slots=True)
class Frame:
    """One navigation-stack entry: a screen name and its non-secret args."""

    name: str
    data: dict[str, Any] = field(default_factory=dict)


# Stack entries in existing DB.pkl files were pickled as `password_bot.state.fsm.Screen`.
# Keep that name importable or loading an old DB.pkl crashes the bot at startup.
Screen = Frame


class FsmContext:
    """Thin wrapper that lets handlers read/write chat_data with typed keys."""

    def __init__(self, chat_data: dict[str, Any]) -> None:
        self._chat_data = chat_data

    def _stack(self) -> list[Frame]:
        raw = self._chat_data.get(ChatDataKey.NAV_STACK.value)
        if raw is None:
            raw = []
            self._chat_data[ChatDataKey.NAV_STACK.value] = raw
        return raw

    def push(self, frame: Frame) -> None:
        self._stack().append(frame)

    def pop(self) -> Frame | None:
        st = self._stack()
        return st.pop() if st else None

    def top(self) -> Frame:
        st = self._stack()
        if not st:
            raise IndexError("Empty nav stack")
        return st[-1]

    def depth(self) -> int:
        return len(self._stack())

    def frames(self) -> list[Frame]:
        return list(self._stack())

    def pop_to(self, screen_name: str) -> None:
        st = self._stack()
        while st and st[-1].name != screen_name:
            st.pop()

    def reset_to(self, frame: Frame) -> None:
        self._chat_data[ChatDataKey.NAV_STACK.value] = [frame]

    def set_resume(self, frame: Frame) -> None:
        self._chat_data[ChatDataKey.RESUME.value] = frame

    def pop_resume(self) -> Frame | None:
        return self._chat_data.pop(ChatDataKey.RESUME.value, None)

    def get_pending_input(self) -> dict[str, Any] | None:
        return self._chat_data.get(ChatDataKey.PENDING_INPUT.value)

    def set_pending_input(self, payload: dict[str, Any]) -> None:
        self._chat_data[ChatDataKey.PENDING_INPUT.value] = payload

    def clear_pending_input(self) -> None:
        self._chat_data.pop(ChatDataKey.PENDING_INPUT.value, None)

    def get_session(self) -> Any | None:
        return self._chat_data.get(ChatDataKey.SESSION.value)

    def set_session(self, session: Any) -> None:
        self._chat_data[ChatDataKey.SESSION.value] = session

    def clear_session(self) -> None:
        self._chat_data.pop(ChatDataKey.SESSION.value, None)
        self._chat_data.pop(ChatDataKey.LEGACY_SESSION_EXTRAS.value, None)

    def lock(self) -> None:
        """Drop the session and every in-progress flow, so the next text is a passphrase."""
        self.clear_session()
        for key in (
            ChatDataKey.PENDING_INPUT,
            ChatDataKey.PENDING_NEW_ACCOUNT,
            ChatDataKey.PENDING_IMPORT_FILE,
            ChatDataKey.PW_GEN_DRAFT,
            ChatDataKey.PW_GEN_RETURN_TO,
            ChatDataKey.FLOW,
            ChatDataKey.RESUME,
        ):
            self._chat_data.pop(key.value, None)
        self._chat_data[ChatDataKey.NAV_STACK.value] = []
```

`src/password_bot/telegram_utils/md.py` — replace `code_inline`:

```python
def code_inline(value: str) -> str:
    # Inside MarkdownV2 code entities only '\' and '`' must be escaped.
    inner = value.replace("\\", "\\\\").replace("`", "\\`")
    return f"`{inner}`"
```

`src/password_bot/bot.py` — in `_SessionStrippingPersistence.update_chat_data`, add `ChatDataKey.FLOW.value,` to the set of stripped keys.

`src/password_bot/ui/__init__.py`:

```python
"""Single-live-message UI: Navigator, Screen contract and screens."""
```

`src/password_bot/ui/callbacks.py`:

```python
"""Typed callback payload for every UI button (sent via arbitrary_callback_data).

Payloads are pickled into DB.pkl by PTB's callback-data cache: they must only
carry screen/action names, ids, page numbers and list indices — never secrets.
"""

from __future__ import annotations

from dataclasses import dataclass

NAV = "_nav"  # pseudo-screen handled by the Navigator itself: back, home, noop


@dataclass(frozen=True, slots=True)
class Act:
    screen: str
    action: str
    arg: str | int | None = None
```

`src/password_bot/ui/screen.py`:

```python
"""Screen contract: what a screen renders and how it asks the Navigator to move."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, ClassVar

from telegram import Document, InlineKeyboardMarkup

from password_bot.state.fsm import Frame, FsmContext
from password_bot.state.keys import ChatDataKey
from password_bot.ui.callbacks import Act

TEXT_NOT_ACCEPTED = "⚠️ Usa i bottoni qui sotto."


@dataclass(slots=True)
class View:
    """MarkdownV2 text plus its inline keyboard."""

    text: str
    keyboard: InlineKeyboardMarkup | None = None
    expire_after: int | None = None  # seconds; the Navigator then shows render_expired()


@dataclass(slots=True)
class Ctx:
    """Everything a screen may use. `args` is the top frame's data (read-only by convention)."""

    container: Any
    chat_id: int
    chat_data: dict[str, Any]
    args: dict[str, Any]
    back_label: str | None = None
    bot: Any = None
    application: Any = None
    user_name: str = ""
    progress: Callable[[str], Awaitable[None]] | None = None

    @property
    def fsm(self) -> FsmContext:
        return FsmContext(self.chat_data)

    @property
    def session(self) -> Any:
        return self.fsm.get_session()

    def flow(self, key: str) -> dict[str, Any]:
        flows = self.chat_data.setdefault(ChatDataKey.FLOW.value, {})
        return flows.setdefault(key, {})

    def drop_flow(self, key: str) -> None:
        self.chat_data.get(ChatDataKey.FLOW.value, {}).pop(key, None)


@dataclass(frozen=True, slots=True)
class Go:
    """Move on the stack, then (by default) render the new top screen.

    Applied in this order: reset to [home] → pop N → pop to `pop_to` (optionally
    inclusive) → push → render with `notice`. `toast` answers the callback query.
    """

    push: Frame | None = None
    pop: int = 0
    pop_to: str | None = None
    pop_to_inclusive: bool = False
    home: bool = False
    render: bool = True
    notice: str | None = None
    toast: str | None = None


@dataclass(frozen=True, slots=True)
class Reveal:
    """Send a secret as a separate message deleted after `seconds`. The live view is unchanged."""

    text: str
    seconds: int = 30
    toast: str | None = None


@dataclass(frozen=True, slots=True)
class Lock:
    """Lock the session now."""


Result = Go | Reveal | Lock


def open_screen(name: str, **args: Any) -> Go:
    return Go(push=Frame(name, dict(args)))


def replace(name: str, *, notice: str | None = None, toast: str | None = None, **args: Any) -> Go:
    return Go(pop=1, push=Frame(name, dict(args)), notice=notice, toast=toast)


def back(notice: str | None = None, toast: str | None = None) -> Go:
    return Go(pop=1, notice=notice, toast=toast)


def refresh(notice: str | None = None, toast: str | None = None) -> Go:
    return Go(notice=notice, toast=toast)


def home(notice: str | None = None) -> Go:
    return Go(home=True, notice=notice)


def pop_to(name: str, notice: str | None = None, toast: str | None = None) -> Go:
    return Go(pop_to=name, notice=notice, toast=toast)


def finish(
    flow_screen: str,
    *,
    then: Frame | None = None,
    notice: str | None = None,
    toast: str | None = None,
) -> Go:
    """End a multi-step flow: drop its frames and optionally open `then` in their place."""
    return Go(pop_to=flow_screen, pop_to_inclusive=True, push=then, notice=notice, toast=toast)


class Screen:
    """Base class. Subclasses set `name`/`title` and override what they need."""

    name: ClassVar[str]
    title: ClassVar[str]  # used as the "🔙 <title>" label by the screen above
    requires_session: ClassVar[bool] = True
    accepts_text: ClassVar[bool] = False
    accepts_document: ClassVar[bool] = False

    async def on_enter(self, ctx: Ctx) -> None:
        """Called once when the screen is pushed (not on re-render)."""
        return None

    async def render(self, ctx: Ctx) -> View:
        raise NotImplementedError

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        return refresh()

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        return refresh(notice=TEXT_NOT_ACCEPTED)

    async def on_document(self, ctx: Ctx, document: Document) -> Result:
        return refresh(notice=TEXT_NOT_ACCEPTED)

    async def render_expired(self, ctx: Ctx) -> View | None:
        return None
```

`src/password_bot/ui/views.py`:

```python
"""Keyboard and formatting helpers shared by every screen."""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse

from telegram import CopyTextButton, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import KeyboardButtonStyle

from password_bot.models.category import Category
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import NAV, Act

PRIMARY = KeyboardButtonStyle.PRIMARY
SUCCESS = KeyboardButtonStyle.SUCCESS
DANGER = KeyboardButtonStyle.DANGER

COPY_TEXT_MAX = 256  # Bot API limit for CopyTextButton.text
LABEL_MAX = 32

_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
_IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def btn(
    label: str,
    screen: str,
    action: str,
    arg: str | int | None = None,
    *,
    style: str | None = None,
) -> InlineKeyboardButton:
    return InlineKeyboardButton(label, callback_data=Act(screen, action, arg), style=style)


def nav_btn(label: str, action: str) -> InlineKeyboardButton:
    return btn(label, NAV, action)


def copy_btn(label: str, value: str | None, *, style: str | None = None) -> InlineKeyboardButton | None:
    if not value or len(value) > COPY_TEXT_MAX:
        return None
    return InlineKeyboardButton(label, copy_text=CopyTextButton(value), style=style)


def url_btn(label: str, raw: str | None) -> InlineKeyboardButton | None:
    url = normalize_url(raw)
    return InlineKeyboardButton(label, url=url) if url else None


def footer(back_label: str | None) -> list[InlineKeyboardButton | None]:
    return [nav_btn(f"🔙 {back_label or 'Indietro'}", "back"), nav_btn("🏠 Menu", "home")]


def keyboard(*rows: list[InlineKeyboardButton | None]) -> InlineKeyboardMarkup:
    clean = [[b for b in row if b is not None] for row in rows]
    return InlineKeyboardMarkup([row for row in clean if row])


def normalize_url(raw: str | None) -> str | None:
    """http(s) URL Telegram will accept in a URL button, or None."""
    if not raw:
        return None
    value = raw.strip()
    if not value or any(ch.isspace() for ch in value):
        return None
    if "://" not in value:
        value = f"https://{value}"
    try:
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        _ = parsed.port  # raises ValueError on garbage like "javascript:alert(1)"
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    if not (_HOST.fullmatch(host) or _IPV4.fullmatch(host)):
        return None
    return value


def plain_date(ts: int) -> str:
    return time.strftime("%d/%m/%Y", time.localtime(ts)) if ts > 0 else "?"


def md_date(ts: int) -> str:
    """MarkdownV2 `date_time` entity; old clients show the bracketed fallback text."""
    if ts <= 0:
        return escape_md("data sconosciuta")
    return f"![{escape_md(plain_date(ts))}](tg://time?unix={ts}&format=d)"


def label(text: str, max_len: int = LABEL_MAX) -> str:
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def category_label(cat: Category) -> str:
    return f"{cat.icon} {cat.name}" if cat.icon else cat.name
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: all PASS (existing `test_fsm_context.py` still imports `Screen` — the alias keeps it working).

- [ ] **Step 5: Commit**

```bash
uv run ruff format src tests && uv run ruff check src tests
git add src tests
git commit -m "Add UI foundations: Act payload, Screen contract, view helpers

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Navigator

**Files:**
- Create: `src/password_bot/ui/navigator.py`
- Create: `tests/ui/_helpers.py`
- Test: `tests/ui/test_navigator.py`

**Interfaces:**
- Produces for tests: `tests.ui._helpers` — `FakeBot` (`sent`, `edits`, `deleted`, `documents`, `edit_error`, `send_error`), `FakeJob`, `FakeJobQueue` (`jobs`, `run_once`, `get_jobs_by_name`), `buttons(view)`, `labels(view)`, `button(view, text)`, `act(view, text)`.
- Consumes: everything produced by Task 4; `telegram_utils.delete_message.schedule_delete(application, *, chat_id, message_id, delay_seconds)`.
- Produces (`password_bot.ui.navigator`):
  - constants `HOME = "home"`, `UNLOCK = "unlock"`, `STALE_BUTTON = "Bottone scaduto"`, `LOCKED_TOAST = "🔒 Sessione bloccata"`
  - `autolock_job_name(chat_id) -> str` (`"autolock:<id>"`), `expire_job_name(chat_id) -> str` (`"expire:<id>"`)
  - `class Navigator(*, application, bot, chat_id, chat_data, user_name="")` — `application.bot_data` must contain `"container"` and `"screens"` (`dict[str, Screen]`).
    - `Navigator.from_context(context, chat_id, *, user_name="")`, `Navigator.from_update(update, context)`
    - `.container`, `.fsm`, `.chat_data`, `.chat_id`
    - `async command(name, args=None)` — open a screen from a slash command in a **new** live message.
    - `async on_callback(update)`, `async on_text(update)`, `async on_document(update)`
    - `async apply(result) -> str | None` (returns toast), `async show(*, notice=None, new_message=False)`, `async present(view, *, notice=None, new_message=False)`
    - `async lock(*, notice="🔒 Sessione bloccata.")`, `async reveal(secret, *, seconds=30)`, `async on_expired(token)`, `async stop()`, `async show_error()`

- [ ] **Step 1: Write the failing tests**

`tests/ui/_helpers.py` (shared by every UI test module):

```python
"""Fakes for Telegram objects and helpers to inspect rendered views."""

from __future__ import annotations

from types import SimpleNamespace

from telegram import InlineKeyboardButton

from password_bot.ui.callbacks import Act
from password_bot.ui.screen import View


class FakeBot:
    def __init__(self) -> None:
        self.sent: list[SimpleNamespace] = []
        self.edits: list[SimpleNamespace] = []
        self.deleted: list[int] = []
        self.next_id = 100
        self.edit_error: Exception | None = None
        self.send_error: Exception | None = None
        self.documents: list[SimpleNamespace] = []

    async def send_message(self, *, chat_id, text, **kw):
        if self.send_error is not None:
            raise self.send_error
        self.next_id += 1
        self.sent.append(SimpleNamespace(chat_id=chat_id, text=text, message_id=self.next_id, **kw))
        return SimpleNamespace(message_id=self.next_id)

    async def edit_message_text(self, *, text, chat_id, message_id, **kw):
        if self.edit_error is not None:
            raise self.edit_error
        self.edits.append(SimpleNamespace(text=text, message_id=message_id, **kw))

    async def delete_message(self, *, chat_id, message_id):
        self.deleted.append(message_id)

    async def send_document(self, *, chat_id, document, filename, caption=None, **kw):
        self.documents.append(
            SimpleNamespace(chat_id=chat_id, data=document.read(), filename=filename, caption=caption)
        )
        return SimpleNamespace(message_id=0)


class FakeJob:
    def __init__(self, callback, when, chat_id, data, name):
        self.callback, self.when, self.chat_id, self.data, self.name = (
            callback, when, chat_id, data, name,
        )
        self.removed = False

    def schedule_removal(self):
        self.removed = True


class FakeJobQueue:
    def __init__(self):
        self.jobs: list[FakeJob] = []

    def run_once(self, callback, when, chat_id=None, data=None, name=None):
        job = FakeJob(callback, when, chat_id, data, name)
        self.jobs.append(job)
        return job

    def get_jobs_by_name(self, name):
        return [j for j in self.jobs if j.name == name and not j.removed]


def buttons(view: View) -> list[InlineKeyboardButton]:
    if view.keyboard is None:
        return []
    return [b for row in view.keyboard.inline_keyboard for b in row]


def labels(view: View) -> list[str]:
    return [b.text for b in buttons(view)]


def button(view: View, text: str) -> InlineKeyboardButton:
    """Button whose label equals `text`, else the first one starting with it."""
    for b in buttons(view):
        if b.text == text:
            return b
    for b in buttons(view):
        if b.text.startswith(text):
            return b
    raise AssertionError(f"No button {text!r} in {labels(view)}")


def act(view: View, text: str) -> Act:
    data = button(view, text).callback_data
    assert isinstance(data, Act), data
    return data
```

`tests/ui/test_navigator.py`:

```python
"""Navigator: single live message, stack semantics, routing, locking, auto-close."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

from telegram.error import BadRequest

from password_bot.state.fsm import Frame
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import NAV, Act
from password_bot.ui.navigator import (
    LOCKED_TOAST,
    STALE_BUTTON,
    Navigator,
    autolock_job_name,
    expire_job_name,
)
from password_bot.ui.screen import (
    TEXT_NOT_ACCEPTED,
    Go,
    Lock,
    Reveal,
    Screen,
    View,
    open_screen,
    refresh,
)
from password_bot.ui.views import btn, footer, keyboard
from tests.ui._helpers import FakeBot, FakeJobQueue

LIVE = ChatDataKey.LIVE_MESSAGE_ID.value
SESSION = ChatDataKey.SESSION.value
RESUME = ChatDataKey.RESUME.value


class Home(Screen):
    name = "home"
    title = "Home"

    async def render(self, ctx):
        return View("home", keyboard([btn("open", self.name, "open")]))

    async def on_action(self, ctx, act):
        if act.action == "open":
            return open_screen("items", page=1)
        if act.action == "lock":
            return Lock()
        return refresh()


class Items(Screen):
    name = "items"
    title = "Lista"
    accepts_text = True

    async def render(self, ctx):
        return View(
            f"items {ctx.args.get('page')} back={ctx.back_label}",
            keyboard([btn("detail", self.name, "detail")], footer(ctx.back_label)),
        )

    async def on_action(self, ctx, act):
        if act.action == "detail":
            return open_screen("detail", id="a1")
        return refresh(toast="ok")

    async def on_text(self, ctx, text):
        return refresh(notice=f"got {text}")


class Detail(Screen):
    name = "detail"
    title = "Dettaglio"

    async def render(self, ctx):
        return View("detail", keyboard(footer(ctx.back_label)), expire_after=60)

    async def render_expired(self, ctx):
        return View("closed")

    async def on_action(self, ctx, act):
        if act.action == "reveal":
            return Reveal("s3cr`t")
        if act.action == "delete":
            return Go(pop_to="detail", pop_to_inclusive=True, toast="deleted")
        return refresh()


class Unlock(Screen):
    name = "unlock"
    title = "Sblocco"
    requires_session = False
    accepts_text = True

    async def render(self, ctx):
        return View("unlock")

    async def on_text(self, ctx, text):
        if text != "pw":
            return refresh(notice="wrong")
        ctx.fsm.set_session(object())
        return Go(home=True, push=ctx.fsm.pop_resume())


def make_nav(*, locked: bool = False, chat_data: dict | None = None):
    screens = {s.name: s for s in (Home(), Items(), Detail(), Unlock())}
    bot = FakeBot()
    jq = FakeJobQueue()
    app = SimpleNamespace(bot_data={"container": SimpleNamespace(), "screens": screens}, job_queue=jq)
    data = {} if chat_data is None else chat_data
    if not locked:
        data[SESSION] = object()
    return Navigator(application=app, bot=bot, chat_id=1, chat_data=data), bot, jq


def callback(data, message_id):
    query = SimpleNamespace(
        data=data,
        message=SimpleNamespace(message_id=message_id),
        answer=AsyncMock(),
        edit_message_reply_markup=AsyncMock(),
    )
    return SimpleNamespace(
        callback_query=query,
        effective_user=SimpleNamespace(full_name="Me"),
        effective_chat=SimpleNamespace(id=1),
    )


def text_message(text):
    message = SimpleNamespace(text=text, delete=AsyncMock(), document=None)
    return SimpleNamespace(
        message=message,
        effective_user=SimpleNamespace(full_name="Me"),
        effective_chat=SimpleNamespace(id=1),
    )


def stack(nav):
    return [f.name for f in nav.fsm.frames()]


async def test_command_sends_new_live_message_and_deletes_previous():
    nav, bot, _ = make_nav(chat_data={LIVE: 7})
    await nav.command("items", {"page": 2})
    assert bot.deleted == [7]
    assert bot.sent[-1].text == "items 2 back=Home"
    assert nav.chat_data[LIVE] == bot.sent[-1].message_id
    assert stack(nav) == ["home", "items"]


async def test_callback_edits_live_message_in_place():
    nav, bot, _ = make_nav()
    await nav.command("home")
    live = nav.chat_data[LIVE]
    update = callback(Act("home", "open"), live)
    await nav.on_callback(update)
    assert bot.edits[-1].message_id == live
    assert bot.edits[-1].text == "items 1 back=Home"
    update.callback_query.answer.assert_awaited_once_with(None)


async def test_toast_is_the_callback_answer():
    nav, _, _ = make_nav()
    await nav.command("items")
    update = callback(Act("items", "other"), nav.chat_data[LIVE])
    await nav.on_callback(update)
    update.callback_query.answer.assert_awaited_once_with("ok")


async def test_edit_failure_falls_back_to_new_message():
    nav, bot, _ = make_nav()
    await nav.command("home")
    old = nav.chat_data[LIVE]
    bot.edit_error = BadRequest("Message to edit not found")
    await nav.on_callback(callback(Act("home", "open"), old))
    assert old in bot.deleted
    assert nav.chat_data[LIVE] != old
    assert bot.sent[-1].text.startswith("items")


async def test_not_modified_is_ignored():
    nav, bot, _ = make_nav()
    await nav.command("home")
    bot.edit_error = BadRequest("Message is not modified: specified new message content")
    sent = len(bot.sent)
    await nav.show()
    assert len(bot.sent) == sent


async def test_back_and_home_navigation():
    nav, bot, _ = make_nav()
    await nav.command("items")
    live = nav.chat_data[LIVE]
    await nav.on_callback(callback(Act("items", "detail"), live))
    assert stack(nav) == ["home", "items", "detail"]
    assert bot.edits[-1].reply_markup.inline_keyboard[0][0].text == "🔙 Lista"
    await nav.on_callback(callback(Act(NAV, "back"), live))
    assert stack(nav) == ["home", "items"]
    await nav.on_callback(callback(Act(NAV, "home"), live))
    assert stack(nav) == ["home"]


async def test_pop_to_inclusive_returns_below_the_frame():
    nav, _, _ = make_nav()
    await nav.command("items")
    live = nav.chat_data[LIVE]
    await nav.on_callback(callback(Act("items", "detail"), live))
    update = callback(Act("detail", "delete"), live)
    await nav.on_callback(update)
    assert stack(nav) == ["home", "items"]
    update.callback_query.answer.assert_awaited_once_with("deleted")


async def test_text_is_deleted_and_routed_to_top_screen():
    nav, bot, _ = make_nav()
    await nav.command("items")
    update = text_message("hello")
    await nav.on_text(update)
    update.message.delete.assert_awaited_once()
    assert bot.edits[-1].text.startswith("got hello")


async def test_text_on_screen_without_input_shows_notice():
    nav, bot, _ = make_nav()
    await nav.command("home")
    await nav.on_text(text_message("hello"))
    assert bot.edits[-1].text.startswith(escape_md(TEXT_NOT_ACCEPTED))


async def test_button_for_another_screen_rerenders_without_acting():
    nav, _, _ = make_nav()
    await nav.command("items")
    update = callback(Act("home", "open"), nav.chat_data[LIVE])
    await nav.on_callback(update)
    update.callback_query.answer.assert_awaited_once_with(STALE_BUTTON)
    assert stack(nav) == ["home", "items"]


async def test_button_on_old_message_opens_home_in_new_message():
    nav, bot, _ = make_nav()
    await nav.command("items")
    live = nav.chat_data[LIVE]
    update = callback(Act("items", "detail"), live - 50)
    await nav.on_callback(update)
    update.callback_query.answer.assert_awaited_once_with(STALE_BUTTON)
    update.callback_query.edit_message_reply_markup.assert_awaited_once_with(reply_markup=None)
    assert stack(nav) == ["home"]
    assert nav.chat_data[LIVE] == bot.sent[-1].message_id != live


async def test_legacy_string_callback_is_stale():
    nav, _, _ = make_nav()
    await nav.command("items")
    update = callback("view:show:password:x", nav.chat_data[LIVE])
    await nav.on_callback(update)
    update.callback_query.answer.assert_awaited_once_with(STALE_BUTTON)
    assert stack(nav) == ["home"]


async def test_missing_live_id_adopts_the_pressed_message():
    nav, bot, _ = make_nav()
    nav.fsm.reset_to(Frame("home"))
    nav.fsm.push(Frame("items", {"page": 1}))
    await nav.on_callback(callback(Act("items", "detail"), 55))
    assert bot.edits[-1].message_id == 55
    assert nav.chat_data[LIVE] == 55


async def test_locked_button_parks_target_then_resumes_after_unlock():
    nav, _, _ = make_nav()
    await nav.command("items")
    del nav.chat_data[SESSION]
    update = callback(Act("items", "detail"), nav.chat_data[LIVE])
    await nav.on_callback(update)
    update.callback_query.answer.assert_awaited_once_with(LOCKED_TOAST)
    assert stack(nav) == ["unlock"]
    assert nav.chat_data[RESUME].name == "items"
    await nav.on_text(text_message("pw"))
    assert stack(nav) == ["home", "items"]


async def test_locked_text_goes_to_unlock():
    nav, bot, _ = make_nav()
    await nav.command("items")
    del nav.chat_data[SESSION]
    await nav.on_text(text_message("nope"))
    assert stack(nav) == ["unlock"]
    assert bot.edits[-1].text.startswith("wrong")


async def test_command_while_locked_parks_and_shows_unlock():
    nav, bot, _ = make_nav(locked=True)
    await nav.command("items", {"page": 3})
    assert stack(nav) == ["unlock"]
    assert nav.chat_data[RESUME] == Frame("items", {"page": 3})
    assert bot.sent[-1].text == "unlock"


async def test_lock_resets_to_unlock_and_cancels_jobs():
    nav, bot, jq = make_nav()
    await nav.command("items")
    autolock = jq.run_once(None, 60, chat_id=1, name=autolock_job_name(1))
    await nav.apply(Lock())
    assert stack(nav) == ["unlock"]
    assert SESSION not in nav.chat_data
    assert autolock.removed
    assert bot.edits[-1].text == escape_md("🔒 Sessione bloccata.") + "\n\nunlock"


async def test_detail_expires_into_closed_view():
    nav, bot, jq = make_nav()
    await nav.command("items")
    await nav.on_callback(callback(Act("items", "detail"), nav.chat_data[LIVE]))
    job = jq.get_jobs_by_name(expire_job_name(1))[0]
    assert job.when == 60
    await nav.on_expired(job.data)
    assert bot.edits[-1].text == "closed"


async def test_expiry_is_ignored_after_navigating_away():
    nav, bot, jq = make_nav()
    await nav.command("items")
    live = nav.chat_data[LIVE]
    await nav.on_callback(callback(Act("items", "detail"), live))
    token = jq.get_jobs_by_name(expire_job_name(1))[0].data
    await nav.on_callback(callback(Act(NAV, "back"), live))
    assert jq.get_jobs_by_name(expire_job_name(1)) == []
    await nav.on_expired(token)
    assert bot.edits[-1].text != "closed"


async def test_reveal_sends_code_message_scheduled_for_deletion():
    nav, bot, jq = make_nav()
    await nav.command("items")
    live = nav.chat_data[LIVE]
    await nav.on_callback(callback(Act("items", "detail"), live))
    await nav.on_callback(callback(Act("detail", "reveal"), live))
    assert bot.sent[-1].text == "`s3cr\\`t`"
    assert any(j.name.startswith("delete:") and j.when == 30 for j in jq.jobs)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/ui/test_navigator.py -q`
Expected: FAIL at collection — `ModuleNotFoundError: No module named 'password_bot.ui.navigator'`.

- [ ] **Step 3: Implement**

`src/password_bot/ui/navigator.py`:

```python
"""Single-live-message navigation: screen stack, rendering, routing, locking."""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from telegram import LinkPreviewOptions
from telegram.constants import ParseMode
from telegram.error import BadRequest, TelegramError

from password_bot.state.fsm import Frame, FsmContext
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.delete_message import schedule_delete
from password_bot.telegram_utils.md import code_inline, escape_md
from password_bot.ui.callbacks import NAV, Act
from password_bot.ui.screen import (
    TEXT_NOT_ACCEPTED,
    Ctx,
    Go,
    Lock,
    Result,
    Reveal,
    Screen,
    View,
)
from password_bot.ui.views import keyboard, nav_btn

log = logging.getLogger(__name__)

HOME = "home"
UNLOCK = "unlock"
STALE_BUTTON = "Bottone scaduto"
LOCKED_TOAST = "🔒 Sessione bloccata"
_NO_PREVIEW = LinkPreviewOptions(is_disabled=True)
_LIVE = ChatDataKey.LIVE_MESSAGE_ID.value
_TOKEN = ChatDataKey.LIVE_TOKEN.value


def autolock_job_name(chat_id: int) -> str:
    return f"autolock:{chat_id}"


def expire_job_name(chat_id: int) -> str:
    return f"expire:{chat_id}"


async def _expire_job(context: Any) -> None:
    job = context.job
    if job is None or job.chat_id is None:
        return
    await Navigator.from_context(context, job.chat_id).on_expired(job.data)


class Navigator:
    """The only component that talks to Telegram for UI purposes."""

    def __init__(
        self,
        *,
        application: Any,
        bot: Any,
        chat_id: int,
        chat_data: dict[str, Any],
        user_name: str = "",
    ) -> None:
        self.application = application
        self.bot = bot
        self.chat_id = chat_id
        self.chat_data = chat_data
        self.user_name = user_name
        self.screens: dict[str, Screen] = application.bot_data["screens"]
        self.fsm = FsmContext(chat_data)

    @classmethod
    def from_context(cls, context: Any, chat_id: int, *, user_name: str = "") -> Navigator:
        return cls(
            application=context.application,
            bot=context.bot,
            chat_id=chat_id,
            chat_data=context.chat_data,
            user_name=user_name,
        )

    @classmethod
    def from_update(cls, update: Any, context: Any) -> Navigator:
        user = update.effective_user
        return cls.from_context(
            context, update.effective_chat.id, user_name=user.full_name if user else ""
        )

    @property
    def container(self) -> Any:
        return self.application.bot_data["container"]

    # ------------------------------------------------------------------ stack

    def _locked(self) -> bool:
        return self.fsm.get_session() is None

    def _top(self) -> Frame:
        if self.fsm.depth() == 0 or self.fsm.top().name not in self.screens:
            self.fsm.reset_to(Frame(HOME, {}))
        return self.fsm.top()

    def _ctx(self, frame: Frame) -> Ctx:
        frames = self.fsm.frames()
        below = frames[-2] if len(frames) >= 2 else None
        back_label = (
            self.screens[below.name].title
            if below is not None and below.name in self.screens
            else None
        )
        return Ctx(
            container=self.container,
            chat_id=self.chat_id,
            chat_data=self.chat_data,
            args=frame.data,
            back_label=back_label,
            bot=self.bot,
            application=self.application,
            user_name=self.user_name,
            progress=self._progress,
        )

    def _park_and_unlock(self, frame: Frame | None) -> None:
        """Remember where the user was going, then show the unlock screen."""
        if (
            frame is not None
            and frame.name not in (HOME, UNLOCK)
            and frame.name in self.screens
            and self.screens[frame.name].requires_session
        ):
            self.fsm.set_resume(frame)
        self.fsm.reset_to(Frame(UNLOCK, {}))

    async def _push(self, frame: Frame) -> None:
        self.fsm.push(frame)
        await self.screens[frame.name].on_enter(self._ctx(frame))

    # -------------------------------------------------------------- rendering

    async def show(self, *, notice: str | None = None, new_message: bool = False) -> None:
        top = self._top()
        if self._locked() and self.screens[top.name].requires_session:
            self._park_and_unlock(top)
            top = self._top()
        view = await self.screens[top.name].render(self._ctx(top))
        await self.present(view, notice=notice, new_message=new_message)

    async def present(
        self, view: View, *, notice: str | None = None, new_message: bool = False
    ) -> None:
        text = f"{escape_md(notice)}\n\n{view.text}" if notice else view.text
        token = int(self.chat_data.get(_TOKEN, 0)) + 1
        self.chat_data[_TOKEN] = token
        live = self.chat_data.get(_LIVE)
        if live is not None and not new_message:
            try:
                await self.bot.edit_message_text(
                    text=text,
                    chat_id=self.chat_id,
                    message_id=live,
                    parse_mode=ParseMode.MARKDOWN_V2,
                    reply_markup=view.keyboard,
                    link_preview_options=_NO_PREVIEW,
                )
            except BadRequest as e:
                if "not modified" not in str(e).lower():
                    log.info("Live message %s not editable (%s); sending a new one", live, e)
                    await self._send_live(text, view, replacing=live)
        else:
            await self._send_live(text, view, replacing=live)
        self._schedule_expiry(view.expire_after, token)

    async def _send_live(self, text: str, view: View, *, replacing: int | None) -> None:
        if replacing is not None:
            with contextlib.suppress(TelegramError):
                await self.bot.delete_message(chat_id=self.chat_id, message_id=replacing)
        msg = await self.bot.send_message(
            chat_id=self.chat_id,
            text=text,
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=view.keyboard,
            link_preview_options=_NO_PREVIEW,
        )
        self.chat_data[_LIVE] = msg.message_id

    def _cancel_jobs(self, *names: str) -> None:
        jq = self.application.job_queue
        if jq is None:
            return
        for name in names:
            for job in jq.get_jobs_by_name(name):
                job.schedule_removal()

    def _schedule_expiry(self, seconds: int | None, token: int) -> None:
        name = expire_job_name(self.chat_id)
        self._cancel_jobs(name)
        jq = self.application.job_queue
        if seconds and jq is not None:
            jq.run_once(_expire_job, when=seconds, chat_id=self.chat_id, data=token, name=name)

    async def _progress(self, text: str) -> None:
        with contextlib.suppress(TelegramError):
            await self.present(View(escape_md(text)))

    # ---------------------------------------------------------------- routing

    async def command(self, name: str, args: dict[str, Any] | None = None) -> None:
        """Open a screen from a slash command, in a new live message at the bottom."""
        frame = Frame(name, dict(args or {}))
        if self._locked() and self.screens[name].requires_session:
            self._park_and_unlock(frame)
        else:
            self.fsm.reset_to(Frame(HOME, {}))
            if name != HOME:
                await self._push(frame)
        await self.show(new_message=True)

    async def on_callback(self, update: Any) -> None:
        query = update.callback_query
        act = query.data
        message_id = query.message.message_id if query.message is not None else None
        live = self.chat_data.get(_LIVE)
        if live is None and message_id is not None:
            self.chat_data[_LIVE] = live = message_id
        if not isinstance(act, Act) or message_id != live:
            await self._stale(query)
            return
        if act.screen == NAV:
            await query.answer()
            await self.apply(self._nav_result(act))
            return
        top = self._top()
        if act.screen != top.name:
            await query.answer(STALE_BUTTON)
            await self.show()
            return
        screen = self.screens[top.name]
        if self._locked() and screen.requires_session:
            await query.answer(LOCKED_TOAST)
            await self.show()
            return
        toast = await self.apply(await screen.on_action(self._ctx(top), act))
        await query.answer(toast)

    async def _stale(self, query: Any) -> None:
        await query.answer(STALE_BUTTON)
        with contextlib.suppress(TelegramError):
            await query.edit_message_reply_markup(reply_markup=None)
        await self.command(HOME)

    @staticmethod
    def _nav_result(act: Act) -> Go:
        if act.action == "back":
            return Go(pop=1)
        if act.action == "home":
            return Go(home=True)
        return Go(render=act.action != "noop")

    async def on_text(self, update: Any) -> None:
        text = update.message.text or ""
        with contextlib.suppress(TelegramError):
            await update.message.delete()
        top = self._top()
        if self._locked() and top.name != UNLOCK:
            # Locked: any text is a passphrase attempt.
            self._park_and_unlock(top)
            top = self._top()
        screen = self.screens[top.name]
        if not screen.accepts_text:
            await self.show(notice=TEXT_NOT_ACCEPTED)
            return
        await self.apply(await screen.on_text(self._ctx(top), text))

    async def on_document(self, update: Any) -> None:
        top = self._top()
        screen = self.screens[top.name]
        if self._locked() and screen.requires_session:
            await self.show()
        elif not screen.accepts_document:
            await self.show(notice="⚠️ Non mi aspettavo un file qui.")
        else:
            await self.apply(await screen.on_document(self._ctx(top), update.message.document))
        with contextlib.suppress(TelegramError):
            await update.message.delete()

    async def apply(self, result: Result) -> str | None:
        """Carry out a screen's result. Returns the toast for the callback answer."""
        if isinstance(result, Reveal):
            await self.reveal(result.text, seconds=result.seconds)
            return result.toast
        if isinstance(result, Lock):
            await self.lock()
            return None
        if result.home:
            self.fsm.reset_to(Frame(HOME, {}))
        for _ in range(result.pop):
            self.fsm.pop()
        if result.pop_to is not None:
            self.fsm.pop_to(result.pop_to)
            if result.pop_to_inclusive:
                self.fsm.pop()
        if result.push is not None:
            await self._push(result.push)
        if result.render:
            await self.show(notice=result.notice)
        return result.toast

    # ------------------------------------------------------------ side effects

    async def reveal(self, secret: str, *, seconds: int = 30) -> None:
        msg = await self.bot.send_message(
            chat_id=self.chat_id, text=code_inline(secret), parse_mode=ParseMode.MARKDOWN_V2
        )
        schedule_delete(
            self.application, chat_id=self.chat_id, message_id=msg.message_id, delay_seconds=seconds
        )

    async def lock(self, *, notice: str = "🔒 Sessione bloccata.") -> None:
        self.fsm.lock()
        self._cancel_jobs(autolock_job_name(self.chat_id), expire_job_name(self.chat_id))
        self.fsm.reset_to(Frame(UNLOCK, {}))
        await self.show(notice=notice)

    async def on_expired(self, token: int) -> None:
        if self.chat_data.get(_TOKEN) != token or self._locked():
            return
        top = self._top()
        view = await self.screens[top.name].render_expired(self._ctx(top))
        if view is None:
            return
        try:
            await self.present(view)
        except TelegramError as e:
            log.warning("Auto-close failed for chat_id=%s: %s", self.chat_id, e)

    async def stop(self) -> None:
        live = self.chat_data.get(_LIVE)
        if live is not None:
            with contextlib.suppress(TelegramError):
                await self.bot.delete_message(chat_id=self.chat_id, message_id=live)
        self._cancel_jobs(autolock_job_name(self.chat_id), expire_job_name(self.chat_id))
        self.chat_data.clear()

    async def show_error(self) -> None:
        await self.present(
            View(
                escape_md("⚠️ Errore interno. Lo sviluppatore è stato avvisato."),
                keyboard([nav_btn("🏠 Menu", "home")]),
            )
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/ui/test_navigator.py -q`
Expected: PASS (all 20).

- [ ] **Step 5: Commit**

```bash
uv run ruff format src tests && uv run ruff check src tests
git add src tests
git commit -m "Add Navigator: single live message, stack routing, lock and auto-close

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Session screens (unlock, home, help), autolock job, registry, screen-test fixtures

**Files:**
- Create: `src/password_bot/ui/jobs.py`, `src/password_bot/ui/registry.py`
- Create: `src/password_bot/ui/screens/__init__.py`, `ui/screens/home.py`, `ui/screens/unlock.py`, `ui/screens/help.py`
- Create: `tests/ui/conftest.py`, `tests/ui/test_session_screens.py`

**Interfaces:**
- Consumes: Task 4 (`Screen`, `View`, `Ctx`, results, views), Task 5 (`Navigator`, `autolock_job_name`), `tests.ui._helpers`.
- Produces:
  - `ui.jobs.schedule_autolock(application, chat_id: int, expires_at: int) -> None`, `ui.jobs.autolock_job(context) -> None`
  - `ui.registry.build_screens() -> dict[str, Screen]` — later tasks add their screens to the list inside it.
  - Screens: `HomeScreen` (`"home"`, title `"Home"`), `UnlockScreen` (`"unlock"`, `"Sblocco"`, `requires_session=False`, `accepts_text=True`), `HelpScreen` (`"help"`, `"Help"`, `requires_session=False`).
  - Home `go` action args (screen names used by later tasks): `account_new`, `search`, `account_list`, `categories`, `health`, `settings`, `help`.
  - Test fixture `env` (`tests/ui/conftest.py`): `Env.container`, `.session`, `.chat_data` (contains the session), `.bot` (AsyncMock), `.application` (MagicMock), `.ctx(args=None, *, back_label="Home", chat_id=1) -> Ctx`, `await .add(name, *, username=None, password="Pw-123456!", url=None, note=None, category_id=None) -> Account`, `await .category(name, icon=None) -> Category` (id = `"cat-" + name.lower()`); constant `PASSPHRASE`.

- [ ] **Step 1: Write the failing tests**

`tests/ui/conftest.py`:

```python
"""Real services on a temp DB, an unlocked session and a Ctx factory for screen tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from password_bot.config import AppConfig
from password_bot.container import Container
from password_bot.models.account import Account
from password_bot.models.category import Category
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.services.auth_service import Session
from password_bot.services.vault_service import NewAccount
from password_bot.state.keys import ChatDataKey
from password_bot.ui.screen import Ctx

PASSPHRASE = "correct horse battery"


@dataclass
class Env:
    container: Container
    session: Session
    chat_data: dict[str, Any] = field(default_factory=dict)
    bot: Any = field(default_factory=AsyncMock)
    application: Any = field(default_factory=MagicMock)

    def ctx(self, args: dict | None = None, *, back_label: str | None = "Home", chat_id: int = 1) -> Ctx:
        return Ctx(
            container=self.container,
            chat_id=chat_id,
            chat_data=self.chat_data,
            args=dict(args or {}),
            back_label=back_label,
            bot=self.bot,
            application=self.application,
            user_name="Me",
        )

    async def add(
        self,
        name: str,
        *,
        username: str | None = None,
        password: str = "Pw-123456!",
        url: str | None = None,
        note: str | None = None,
        category_id: str | None = None,
    ) -> Account:
        return await self.container.vault.add(
            NewAccount(
                chat_id=1,
                name=name,
                username=username,
                password=password,
                url=url,
                note=note,
                category_id=category_id,
            ),
            aes_key=self.session.aes_key,
            hmac_key=self.session.hmac_key,
        )

    async def category(self, name: str, icon: str | None = None) -> Category:
        cat = Category(id=f"cat-{name.lower()}", chat_id=1, name=name, icon=icon)
        await self.container.categories.create(cat)
        return cat


@pytest.fixture
async def env(tmp_path, monkeypatch) -> Env:
    monkeypatch.setenv("KEYRING", str(tmp_path))
    config = AppConfig.load(base_dir=tmp_path)
    await migrate_to_latest(config.db_path)
    container = Container.build(config, dev_chat_id=None)
    result = await container.auth.register(
        chat_id=1, name="me", passphrase=PASSPHRASE, autolock_minutes=15, alert_days=180
    )
    assert result.value is not None
    env = Env(container=container, session=result.value)
    env.chat_data[ChatDataKey.SESSION.value] = result.value
    return env
```

`tests/ui/test_session_screens.py`:

```python
"""Unlock / setup, home, help, autolock job, registry."""

from __future__ import annotations

from types import SimpleNamespace

from telegram.error import Forbidden

from password_bot.state.fsm import Frame
from password_bot.state.keys import ChatDataKey
from password_bot.ui.callbacks import Act
from password_bot.ui.jobs import autolock_job, schedule_autolock
from password_bot.ui.registry import build_screens
from password_bot.ui.screen import Go, Lock, open_screen, refresh
from password_bot.ui.screens.help import HelpScreen
from password_bot.ui.screens.home import HomeScreen
from password_bot.ui.screens.unlock import UnlockScreen
from tests.ui._helpers import FakeBot, FakeJobQueue, act, labels
from tests.ui.conftest import PASSPHRASE

SESSION = ChatDataKey.SESSION.value
RESUME = ChatDataKey.RESUME.value


async def test_home_has_eight_buttons_and_routes(env):
    screen = HomeScreen()
    view = await screen.render(env.ctx())
    assert labels(view) == [
        "➕ Nuovo", "🔍 Cerca", "📚 Lista", "🏷 Categorie",
        "🩺 Salute", "⚙️ Impostazioni", "🔒 Blocca", "❓ Help",
    ]
    assert await screen.on_action(env.ctx(), act(view, "🔍 Cerca")) == open_screen("search")
    assert await screen.on_action(env.ctx(), act(view, "🔒 Blocca")) == Lock()
    assert await screen.on_action(env.ctx(), Act("home", "go", "nope")) == refresh()


async def test_unlock_wrong_then_right_passphrase_resumes(env):
    env.chat_data.pop(SESSION)
    screen = UnlockScreen()
    assert "Vault bloccato" in (await screen.render(env.ctx())).text
    result = await screen.on_text(env.ctx(), "nope")
    assert result == refresh(notice="⚠️ Passphrase non corretta. Riprova.")
    env.chat_data[RESUME] = Frame("account_list", {})
    result = await screen.on_text(env.ctx(), PASSPHRASE)
    assert isinstance(result, Go)
    assert result.home and result.push == Frame("account_list", {})
    assert env.chat_data[SESSION] is not None
    env.application.job_queue.run_once.assert_called_once()


async def test_setup_asks_passphrase_twice(env):
    screen = UnlockScreen()

    def ctx2():
        return env.ctx(chat_id=2)

    assert "Non hai ancora un vault" in (await screen.render(ctx2())).text
    await screen.on_text(ctx2(), "first secret")
    view = await screen.render(ctx2())
    assert "di nuovo" in view.text
    assert "↩️ Ricomincia" in labels(view)
    mismatch = await screen.on_text(ctx2(), "other")
    assert mismatch.notice == "⚠️ Le passphrase non coincidono. Ricominciamo."
    assert await env.container.users.get(2) is None
    await screen.on_text(ctx2(), "first secret")
    created = await screen.on_text(ctx2(), "first secret")
    assert created.home and created.notice == "✅ Vault creato."
    assert await env.container.users.get(2) is not None


async def test_help_lists_commands_with_footer(env):
    view = await HelpScreen().render(env.ctx(back_label="Sblocco"))
    assert "/add" in view.text and "/get NOME" in view.text
    assert labels(view) == ["🔙 Sblocco", "🏠 Menu"]


def test_schedule_autolock_replaces_previous_job():
    jq = FakeJobQueue()
    app = SimpleNamespace(job_queue=jq)
    schedule_autolock(app, 1, expires_at=0)
    schedule_autolock(app, 1, expires_at=0)
    live = jq.get_jobs_by_name("autolock:1")
    assert len(live) == 1 and live[0].when == 1 and live[0].chat_id == 1


async def test_autolock_job_locks_and_shows_unlock(env):
    bot = FakeBot()
    app = SimpleNamespace(
        bot_data={"container": env.container, "screens": build_screens()}, job_queue=FakeJobQueue()
    )
    context = SimpleNamespace(application=app, bot=bot, chat_data=env.chat_data, job=SimpleNamespace(chat_id=1))
    await autolock_job(context)
    assert SESSION not in env.chat_data
    assert "Vault bloccato" in bot.sent[-1].text


async def test_autolock_job_tolerates_blocked_user(env):
    bot = FakeBot()
    bot.send_error = Forbidden("Forbidden: bot was blocked by the user")
    app = SimpleNamespace(
        bot_data={"container": env.container, "screens": build_screens()}, job_queue=FakeJobQueue()
    )
    context = SimpleNamespace(application=app, bot=bot, chat_data=env.chat_data, job=SimpleNamespace(chat_id=1))
    await autolock_job(context)  # must not raise
    assert SESSION not in env.chat_data


def test_registry_contains_session_screens():
    assert {"home", "unlock", "help"} <= set(build_screens())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/ui/test_session_screens.py -q`
Expected: FAIL at collection — `ModuleNotFoundError: No module named 'password_bot.ui.jobs'`.

- [ ] **Step 3: Implement**

`src/password_bot/ui/jobs.py`:

```python
"""Session autolock job."""

from __future__ import annotations

import logging
import time
from typing import Any

from telegram.error import TelegramError

from password_bot.ui.navigator import Navigator, autolock_job_name

log = logging.getLogger(__name__)


def schedule_autolock(application: Any, chat_id: int, expires_at: int) -> None:
    jq = application.job_queue
    if jq is None:
        return
    name = autolock_job_name(chat_id)
    for job in jq.get_jobs_by_name(name):
        job.schedule_removal()
    jq.run_once(
        autolock_job, when=max(1, expires_at - int(time.time())), chat_id=chat_id, name=name
    )


async def autolock_job(context: Any) -> None:
    job = context.job
    if job is None or job.chat_id is None:
        return
    try:
        await Navigator.from_context(context, job.chat_id).lock()
    except TelegramError as e:
        log.warning("Autolock notice not delivered to chat_id=%s: %s", job.chat_id, e)
```

Note: `Navigator.lock()` clears the session *before* sending, so a failed send still leaves the chat locked.

`src/password_bot/ui/screens/__init__.py`:

```python
"""One module per screen group."""
```

`src/password_bot/ui/screens/home.py`:

```python
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
                [go("➕ Nuovo", "account_new", PRIMARY), go("🔍 Cerca", "search", PRIMARY)],
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
```

`src/password_bot/ui/screens/help.py`:

```python
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
```

`src/password_bot/ui/screens/unlock.py`:

```python
"""Unlock an existing vault, create a new one (passphrase twice), or migrate a legacy one."""

from __future__ import annotations

from typing import Any

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.jobs import schedule_autolock
from password_bot.ui.screen import Ctx, Go, Result, Screen, View, open_screen, refresh
from password_bot.ui.views import btn, keyboard

WRONG = "⚠️ Passphrase non corretta. Riprova."


class UnlockScreen(Screen):
    name = "unlock"
    title = "Sblocco"
    requires_session = False
    accepts_text = True

    async def render(self, ctx: Ctx) -> View:
        user = await ctx.container.users.get(ctx.chat_id)
        rows = []
        if user is None:
            if ctx.flow(self.name).get("first") is None:
                text = escape_md(
                    "🔐 Non hai ancora un vault.\n"
                    "Inviami una passphrase per crearlo: è l'unica chiave per i tuoi dati, "
                    "scegline una robusta. Cancellerò subito il messaggio."
                )
            else:
                text = escape_md("🔐 Inviami di nuovo la stessa passphrase per conferma.")
                rows.append([btn("↩️ Ricomincia", self.name, "restart")])
        else:
            text = escape_md(
                "🔒 Vault bloccato.\n"
                "Inviami la passphrase per sbloccarlo. Cancellerò subito il messaggio."
            )
        rows.append([btn("❓ Help", self.name, "help")])
        return View(text, keyboard(*rows))

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "restart":
            ctx.drop_flow(self.name)
        elif act.action == "help":
            return open_screen("help")
        return refresh()

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        user = await ctx.container.users.get(ctx.chat_id)
        if user is None:
            return await self._setup(ctx, text)
        if user.crypto_version == 1:
            return await self._unlock_legacy(ctx, text)
        r = await ctx.container.auth.unlock(chat_id=ctx.chat_id, passphrase=text)
        if not r.ok or r.value is None:
            return refresh(notice=WRONG)
        return self._unlocked(ctx, r.value, "🔓 Sbloccato.")

    async def _setup(self, ctx: Ctx, text: str) -> Result:
        if not text:
            return refresh()
        flow = ctx.flow(self.name)
        first = flow.get("first")
        if first is None:
            flow["first"] = text
            return refresh()
        ctx.drop_flow(self.name)
        if text != first:
            return refresh(notice="⚠️ Le passphrase non coincidono. Ricominciamo.")
        config = ctx.container.config
        r = await ctx.container.auth.register(
            chat_id=ctx.chat_id,
            name=ctx.user_name or str(ctx.chat_id),
            passphrase=text,
            autolock_minutes=config.autolock_minutes_default,
            alert_days=config.alert_days_default,
        )
        if not r.ok or r.value is None:
            return refresh(notice="⚠️ Non sono riuscito a creare il vault. Riprova.")
        return self._unlocked(ctx, r.value, "✅ Vault creato.")

    async def _unlock_legacy(self, ctx: Ctx, text: str) -> Result:
        migration = ctx.container.migration
        r = await migration.unlock_legacy(chat_id=ctx.chat_id, passphrase=text)
        if not r.ok or r.value is None:
            return refresh(notice=WRONG)
        if ctx.progress is not None:
            await ctx.progress("⏳ Sto migrando il vault…")
        await migration.migrate_user(chat_id=ctx.chat_id, passphrase=text, session=r.value)
        return self._unlocked(ctx, r.value, "✅ Vault migrato e sbloccato.")

    def _unlocked(self, ctx: Ctx, session: Any, notice: str) -> Result:
        ctx.fsm.set_session(session)
        schedule_autolock(ctx.application, ctx.chat_id, session.expires_at)
        return Go(home=True, push=ctx.fsm.pop_resume(), notice=notice)
```

`src/password_bot/ui/registry.py`:

```python
"""Every screen, keyed by name. New screens are added to the list below."""

from __future__ import annotations

from password_bot.ui.screen import Screen
from password_bot.ui.screens.help import HelpScreen
from password_bot.ui.screens.home import HomeScreen
from password_bot.ui.screens.unlock import UnlockScreen


def build_screens() -> dict[str, Screen]:
    screens: list[Screen] = [
        HomeScreen(),
        UnlockScreen(),
        HelpScreen(),
    ]
    return {s.name: s for s in screens}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/ui -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
uv run ruff format src tests && uv run ruff check src tests
git add src tests
git commit -m "Add unlock/setup, home and help screens with autolock job

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Browsing screens (account list / category screen, search)

**Files:**
- Create: `src/password_bot/ui/screens/account_list.py`, `src/password_bot/ui/screens/search.py`
- Modify: `src/password_bot/ui/registry.py`
- Test: `tests/ui/test_browse_screens.py`

**Interfaces:**
- Consumes: `AccountRepo.list_for_chat(chat_id, *, category)`, `UNCATEGORIZED`, `AccountRepo.search(chat_id, query)` (existing, returns `list[tuple[AccountRow, int]]`), `CategoryRepo.get`.
- Produces:
  - `AccountListScreen` (`"account_list"`, title `"Lista"`), args `category: str | None` (`None` = all, `"none"` = uncategorized, else category id), `page: int`. `PAGE_SIZE = 8`. Actions: `open` (arg account id) → `open_screen("account_detail", id=…)`; `page` (arg int); `categories` → `open_screen("categories")`; `new` → `open_screen("account_new", category_id=<real category id or None>)`; with a real category: `rename` → `open_screen("category_form", mode="rename", cat_id=…)`, `icon` → `open_screen("category_icon", cat_id=…)`, `delete` → `open_screen("category_delete", cat_id=…)`.
  - `SearchScreen` (`"search"`, title `"Ricerca"`, `accepts_text=True`), arg `q`. Single match on text input → `replace("account_detail", id=…)`; otherwise `replace("search", q=…)`. Action `open` → `open_screen("account_detail", id=…)`.

- [ ] **Step 1: Write the failing tests**

`tests/ui/test_browse_screens.py`:

```python
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
    assert button(view, "➕ Nuovo account").style == PRIMARY
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
    assert await screen.on_action(ctx, act(view, "➕ Nuovo account qui")) == open_screen(
        "account_new", category_id=cat.id
    )
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/ui/test_browse_screens.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'password_bot.ui.screens.account_list'`.

- [ ] **Step 3: Implement**

`src/password_bot/ui/screens/account_list.py`:

```python
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
            kb_rows.append([btn("➕ Nuovo account qui", self.name, "new", style=PRIMARY)])
            kb_rows.append(
                [
                    btn("✏️ Rinomina", self.name, "rename"),
                    btn("🎨 Icona", self.name, "icon"),
                    btn("🗑 Elimina", self.name, "delete", style=DANGER),
                ]
            )
        elif category is None:
            if not rows:
                kb_rows.append([btn("➕ Nuovo account", self.name, "new", style=PRIMARY)])
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
```

`src/password_bot/ui/screens/search.py`:

```python
"""Fuzzy search by account name."""

from __future__ import annotations

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import Ctx, Result, Screen, View, open_screen, refresh, replace
from password_bot.ui.views import btn, footer, keyboard, label

MAX_RESULTS = 10


class SearchScreen(Screen):
    name = "search"
    title = "Ricerca"
    accepts_text = True

    async def render(self, ctx: Ctx) -> View:
        query = ctx.args.get("q")
        if not query:
            return View(
                escape_md("🔍 Scrivi il nome (o una parte) dell'account da cercare."),
                keyboard(footer(ctx.back_label)),
            )
        results = await ctx.container.accounts.search(ctx.chat_id, query)
        if not results:
            text = escape_md(f"🔍 Nessun risultato per «{query}». Scrivi un altro nome.")
        else:
            text = escape_md(f"🔍 Risultati per «{query}»:")
        rows = [
            [btn(label(f"{row.name} ({score}%)"), self.name, "open", row.id)]
            for row, score in results[:MAX_RESULTS]
        ]
        return View(text, keyboard(*rows, footer(ctx.back_label)))

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        query = text.strip()
        if not query:
            return refresh()
        results = await ctx.container.accounts.search(ctx.chat_id, query)
        if len(results) == 1:
            return replace("account_detail", id=results[0][0].id)
        return replace(self.name, q=query)

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "open":
            return open_screen("account_detail", id=act.arg)
        return refresh()
```

`src/password_bot/ui/registry.py` — add imports and list entries:

```python
from password_bot.ui.screens.account_list import AccountListScreen
from password_bot.ui.screens.search import SearchScreen
```

```python
        AccountListScreen(),
        SearchScreen(),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/ui -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
uv run ruff format src tests && uv run ruff check src tests
git add src tests
git commit -m "Add account list (with category mode) and search screens

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Account detail, password history, delete confirmation

**Files:**
- Create: `src/password_bot/ui/screens/_shared.py`, `ui/screens/account_detail.py`, `ui/screens/history.py`, `ui/screens/account_delete.py`
- Modify: `src/password_bot/ui/registry.py`
- Test: `tests/ui/test_detail_screens.py`

**Interfaces:**
- Consumes: `AccountRepo.find_by_hmac`, `VaultService.get_decrypted/list_history/delete`, `VaultService.username_suggestions` (Task 2), views helpers.
- Produces:
  - `ui.screens._shared`: `STRENGTH_LABELS`, `async load_account(ctx, account_id) -> Account | None` (checks chat ownership), `async reuse_names(ctx, password_hmac, *, exclude_id=None) -> list[str]`, `async reuse_names_for(ctx, password, *, exclude_id=None) -> list[str]`, `strength_text(ctx, password) -> str` (plain text, e.g. `"forza 4/4 (ottima)"`), `async username_suggestions(ctx) -> list[str]`.
  - `AccountDetailScreen` (`"account_detail"`, title `"Dettaglio"`), arg `id`; `AUTO_CLOSE_SECONDS = 60`; actions `reveal` (arg `"password"`/`"username"`), `edit` → `open_screen("account_edit", id=…)`, `delete` → `open_screen("account_delete", id=…)`, `reopen` → refresh.
  - `HistoryScreen` (`"history"`, `"Storico"`), arg `id`; action `reveal` (arg index).
  - `AccountDeleteScreen` (`"account_delete"`, `"Elimina"`), arg `id`; action `confirm` → `Go(pop_to="account_detail", pop_to_inclusive=True, toast="🗑 Eliminato")`.

- [ ] **Step 1: Write the failing tests**

`tests/ui/test_detail_screens.py`:

```python
"""Account detail, history, delete."""

from __future__ import annotations

from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.screen import Go, Reveal, open_screen
from password_bot.ui.screens.account_delete import AccountDeleteScreen
from password_bot.ui.screens.account_detail import AUTO_CLOSE_SECONDS, AccountDetailScreen
from password_bot.ui.screens.history import HistoryScreen
from password_bot.ui.views import DANGER, PRIMARY
from tests.ui._helpers import act, button, labels


async def test_detail_full(env):
    cat = await env.category("Lavoro", icon="💼")
    acc = await env.add(
        "GitHub", username="me@x.com", password="S3cret!pw", url="github.com",
        note="2FA: app", category_id=cat.id,
    )
    await env.add("GitLab", password="S3cret!pw")
    screen = AccountDetailScreen()
    view = await screen.render(env.ctx({"id": acc.id}, back_label="Lista"))
    assert "🔐 *GitHub*" in view.text
    assert "💼 Lavoro" in view.text
    assert escape_md("me@x.com") in view.text
    assert "||" + escape_md("2FA: app") + "||" in view.text
    assert escape_md("♻️ Stessa password di: GitLab") in view.text
    assert "tg://time?unix=" in view.text
    assert "S3cret" not in view.text
    copy_pw = button(view, "📋 Copia password")
    assert copy_pw.copy_text.text == "S3cret!pw" and copy_pw.style == PRIMARY
    assert button(view, "👤 Copia username").copy_text.text == "me@x.com"
    assert button(view, "🌐 Apri URL").url == "https://github.com"
    assert button(view, "🗑 Elimina").style == DANGER
    assert labels(view)[-2:] == ["🔙 Lista", "🏠 Menu"]
    assert view.expire_after == AUTO_CLOSE_SECONDS == 60


async def test_detail_minimal_and_hostile_values(env):
    acc = await env.add("a_b*c[d](e)!", password="x" * 300, url="javascript:alert(1)")
    view = await AccountDetailScreen().render(env.ctx({"id": acc.id}))
    assert escape_md("a_b*c[d](e)!") in view.text
    assert "a_b*c" not in view.text
    assert "📋 Copia password" not in labels(view)
    assert "👁 Mostra" in labels(view)
    assert "👤 Copia username" not in labels(view)
    assert "🌐 Apri URL" not in labels(view)


async def test_detail_actions(env):
    acc = await env.add("GitHub", username="me", password="pw1")
    screen = AccountDetailScreen()
    ctx = env.ctx({"id": acc.id})
    view = await screen.render(ctx)
    result = await screen.on_action(ctx, act(view, "👁 Mostra"))
    assert isinstance(result, Reveal) and result.text == "pw1" and result.seconds == 30
    assert await screen.on_action(ctx, act(view, "✏️ Modifica…")) == open_screen(
        "account_edit", id=acc.id
    )
    assert await screen.on_action(ctx, act(view, "🗑 Elimina")) == open_screen(
        "account_delete", id=acc.id
    )


async def test_detail_expired_view(env):
    acc = await env.add("GitHub")
    view = await AccountDetailScreen().render_expired(env.ctx({"id": acc.id}))
    assert view is not None and "chiuso" in view.text
    assert labels(view) == ["🔓 Riapri", "🏠 Menu"]


async def test_detail_of_other_chat_is_not_found(env):
    acc = await env.add("GitHub")
    view = await AccountDetailScreen().render(env.ctx({"id": acc.id}, chat_id=2))
    assert "Account non trovato" in view.text


async def test_history_reveals_old_passwords(env):
    acc = await env.add("GitHub", password="old1")
    s = env.session
    await env.container.vault.update_password(acc.id, "old2", aes_key=s.aes_key, hmac_key=s.hmac_key)
    await env.container.vault.update_password(acc.id, "new", aes_key=s.aes_key, hmac_key=s.hmac_key)
    screen = HistoryScreen()
    ctx = env.ctx({"id": acc.id}, back_label="Modifica")
    view = await screen.render(ctx)
    reveal_buttons = [label for label in labels(view) if label.startswith("👁 fino al")]
    assert len(reveal_buttons) == 2
    result = await screen.on_action(ctx, act(view, reveal_buttons[0]))
    assert isinstance(result, Reveal) and result.text == "old2"


async def test_delete_confirmation(env):
    acc = await env.add("GitHub")
    screen = AccountDeleteScreen()
    ctx = env.ctx({"id": acc.id})
    view = await screen.render(ctx)
    assert button(view, "🗑 Elimina").style == DANGER
    result = await screen.on_action(ctx, act(view, "🗑 Elimina"))
    assert result == Go(pop_to="account_detail", pop_to_inclusive=True, toast="🗑 Eliminato")
    assert await env.container.accounts.get(acc.id) is None


async def test_screens_need_the_session(env):
    acc = await env.add("GitHub")
    env.chat_data.pop(ChatDataKey.SESSION.value)
    view = await AccountDetailScreen().render(env.ctx({"id": acc.id}))
    assert "Account non trovato" in view.text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/ui/test_detail_screens.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'password_bot.ui.screens.account_delete'`.

- [ ] **Step 3: Implement**

`src/password_bot/ui/screens/_shared.py`:

```python
"""Helpers shared by several screens."""

from __future__ import annotations

from password_bot.models.account import Account
from password_bot.services.reuse_detector import compute_password_hmac
from password_bot.ui.screen import Ctx

STRENGTH_LABELS = ("pessima", "debole", "media", "buona", "ottima")


async def load_account(ctx: Ctx, account_id: object) -> Account | None:
    """Decrypted account if it exists, belongs to this chat and the session is open."""
    session = ctx.session
    if session is None or not account_id:
        return None
    acc = await ctx.container.vault.get_decrypted(str(account_id), aes_key=session.aes_key)
    if acc is None or acc.chat_id != ctx.chat_id:
        return None
    return acc


async def reuse_names(ctx: Ctx, password_hmac: str, *, exclude_id: str | None = None) -> list[str]:
    rows = await ctx.container.accounts.find_by_hmac(ctx.chat_id, password_hmac)
    return [r.name for r in rows if r.id != exclude_id]


async def reuse_names_for(ctx: Ctx, password: str, *, exclude_id: str | None = None) -> list[str]:
    digest = compute_password_hmac(password, ctx.session.hmac_key)
    return await reuse_names(ctx, digest, exclude_id=exclude_id)


def strength_text(ctx: Ctx, password: str) -> str:
    score = ctx.container.strength.evaluate(password).score
    return f"forza {score}/4 ({STRENGTH_LABELS[score]})"


async def username_suggestions(ctx: Ctx) -> list[str]:
    return await ctx.container.vault.username_suggestions(
        ctx.chat_id, aes_key=ctx.session.aes_key
    )
```

`src/password_bot/ui/screens/account_detail.py`:

```python
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
            case "reveal":
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
```

`src/password_bot/ui/screens/history.py`:

```python
"""Previous passwords of an account; each can be revealed for 30 s."""

from __future__ import annotations

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import Ctx, Result, Reveal, Screen, View, refresh
from password_bot.ui.screens._shared import load_account
from password_bot.ui.views import btn, footer, keyboard, plain_date


class HistoryScreen(Screen):
    name = "history"
    title = "Storico"

    async def _load(self, ctx: Ctx):
        acc = await load_account(ctx, ctx.args.get("id"))
        if acc is None:
            return None, []
        return acc, await ctx.container.vault.list_history(acc.id, aes_key=ctx.session.aes_key)

    async def render(self, ctx: Ctx) -> View:
        acc, items = await self._load(ctx)
        if acc is None:
            return View(escape_md("Account non trovato."), keyboard(footer(ctx.back_label)))
        lines = [f"🕘 *Storico password* — {escape_md(acc.name)}"]
        if items:
            lines.append(
                escape_md(
                    f"Le ultime {len(items)} password sostituite. "
                    "Toccane una per vederla per 30 secondi."
                )
            )
        else:
            lines.append(escape_md("Nessuna password precedente."))
        rows = [
            [btn(f"👁 fino al {plain_date(item.replaced_at)}", self.name, "reveal", i)]
            for i, item in enumerate(items)
        ]
        return View("\n".join(lines), keyboard(*rows, footer(ctx.back_label)))

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "reveal":
            _, items = await self._load(ctx)
            index = int(act.arg or 0)
            if 0 <= index < len(items):
                return Reveal(items[index].password, toast="👁 Visibile per 30 secondi")
        return refresh()
```

`src/password_bot/ui/screens/account_delete.py`:

```python
"""Delete confirmation with a red button."""

from __future__ import annotations

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import Ctx, Go, Result, Screen, View, refresh
from password_bot.ui.screens._shared import load_account
from password_bot.ui.views import DANGER, btn, footer, keyboard, nav_btn


class AccountDeleteScreen(Screen):
    name = "account_delete"
    title = "Elimina"

    async def render(self, ctx: Ctx) -> View:
        acc = await load_account(ctx, ctx.args.get("id"))
        if acc is None:
            return View(escape_md("Account non trovato."), keyboard(footer(ctx.back_label)))
        return View(
            escape_md("🗑 Eliminare ")
            + f"*{escape_md(acc.name)}*"
            + escape_md("? Non si può annullare."),
            keyboard(
                [btn("🗑 Elimina", self.name, "confirm", style=DANGER)],
                [nav_btn("❌ Annulla", "back")],
            ),
        )

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action != "confirm":
            return refresh()
        acc = await load_account(ctx, ctx.args.get("id"))
        if acc is not None:
            await ctx.container.vault.delete(acc.id)
        return Go(pop_to="account_detail", pop_to_inclusive=True, toast="🗑 Eliminato")
```

`src/password_bot/ui/registry.py` — add imports and list entries:

```python
from password_bot.ui.screens.account_delete import AccountDeleteScreen
from password_bot.ui.screens.account_detail import AccountDetailScreen
from password_bot.ui.screens.history import HistoryScreen
```

```python
        AccountDetailScreen(),
        HistoryScreen(),
        AccountDeleteScreen(),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/ui -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
uv run ruff format src tests && uv run ruff check src tests
git add src tests
git commit -m "Add account detail with native copy buttons, history and delete screens

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: "Modifica…" submenu and single-field edit

**Files:**
- Create: `src/password_bot/ui/screens/account_edit.py`
- Modify: `src/password_bot/ui/registry.py`
- Test: `tests/ui/test_edit_screens.py`

**Interfaces:**
- Consumes: `_shared.load_account`, `_shared.username_suggestions`, `HistoryRepo.list_for_account` (via `ctx.container.history`), `VaultService.update_fields(account_id, UpdatedFields, *, aes_key)` (empty string clears optional fields), `views.normalize_url`.
- Produces:
  - `AccountEditScreen` (`"account_edit"`, title `"Modifica"`), arg `id`. Action `field` with arg `password` → `open_screen("password_change", id=…)`, `category` → `open_screen("category_pick", account_id=…)`, `name|username|url|note` → `open_screen("field_edit", id=…, field=…)`; action `history` → `open_screen("history", id=…)`.
  - `FieldEditScreen` (`"field_edit"`, title `"Modifica campo"`, `accepts_text=True`), args `id`, `field`. Flow key `"field_edit"` holds `suggestions: list[str]`. Actions `pick` (arg index), `clear`. Success → `pop_to("account_detail", notice="✅ Aggiornato")`.

- [ ] **Step 1: Write the failing tests**

`tests/ui/test_edit_screens.py`:

```python
"""'Modifica…' submenu and single-field edit."""

from __future__ import annotations

from password_bot.ui.screen import open_screen, pop_to
from password_bot.ui.screens.account_edit import AccountEditScreen, FieldEditScreen
from tests.ui._helpers import act, labels


async def _decrypted(env, account_id):
    return await env.container.vault.get_decrypted(account_id, aes_key=env.session.aes_key)


async def test_edit_menu_routes(env):
    acc = await env.add("GitHub")
    screen = AccountEditScreen()
    ctx = env.ctx({"id": acc.id}, back_label="Dettaglio")
    view = await screen.render(ctx)
    assert labels(view) == [
        "🔑 Password", "👤 Username", "📛 Nome", "🌐 URL", "📝 Note", "🏷 Categoria",
        "🔙 Dettaglio", "🏠 Menu",
    ]
    assert await screen.on_action(ctx, act(view, "🔑 Password")) == open_screen(
        "password_change", id=acc.id
    )
    assert await screen.on_action(ctx, act(view, "🏷 Categoria")) == open_screen(
        "category_pick", account_id=acc.id
    )
    assert await screen.on_action(ctx, act(view, "📛 Nome")) == open_screen(
        "field_edit", id=acc.id, field="name"
    )


async def test_edit_menu_shows_history_when_present(env):
    acc = await env.add("GitHub", password="a")
    s = env.session
    await env.container.vault.update_password(acc.id, "b", aes_key=s.aes_key, hmac_key=s.hmac_key)
    screen = AccountEditScreen()
    ctx = env.ctx({"id": acc.id})
    view = await screen.render(ctx)
    assert "🕘 Storico password (1)" in labels(view)
    assert await screen.on_action(ctx, act(view, "🕘 Storico")) == open_screen("history", id=acc.id)


async def test_username_edit_offers_suggestions(env):
    await env.add("A", username="me@x.com")
    await env.add("B", username="me@x.com")
    acc = await env.add("C", username="old")
    screen = FieldEditScreen()
    ctx = env.ctx({"id": acc.id, "field": "username"})
    await screen.on_enter(ctx)
    view = await screen.render(ctx)
    assert "me@x.com" in labels(view)
    assert "old" not in labels(view)
    assert "🗑 Svuota" in labels(view)
    result = await screen.on_action(ctx, act(view, "me@x.com"))
    assert result == pop_to("account_detail", notice="✅ Aggiornato")
    assert (await _decrypted(env, acc.id)).username == "me@x.com"


async def test_clear_optional_field(env):
    acc = await env.add("GitHub", url="https://github.com")
    screen = FieldEditScreen()
    ctx = env.ctx({"id": acc.id, "field": "url"})
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "🗑 Svuota"))
    assert (await _decrypted(env, acc.id)).url is None


async def test_name_cannot_be_empty_and_has_no_clear(env):
    acc = await env.add("GitHub")
    screen = FieldEditScreen()
    ctx = env.ctx({"id": acc.id, "field": "name"})
    assert "🗑 Svuota" not in labels(await screen.render(ctx))
    result = await screen.on_text(ctx, "   ")
    assert result.notice == "⚠️ Il nome non può essere vuoto."
    await screen.on_text(ctx, "GitHub Work")
    assert (await _decrypted(env, acc.id)).name == "GitHub Work"


async def test_url_is_validated_and_normalized(env):
    acc = await env.add("GitHub")
    screen = FieldEditScreen()
    ctx = env.ctx({"id": acc.id, "field": "url"})
    bad = await screen.on_text(ctx, "not a url")
    assert bad.notice == "⚠️ URL non valido. Esempio: github.com"
    await screen.on_text(ctx, "github.com")
    assert (await _decrypted(env, acc.id)).url == "https://github.com"


async def test_note_edit_shows_current_value(env):
    acc = await env.add("GitHub", note="vecchia")
    screen = FieldEditScreen()
    ctx = env.ctx({"id": acc.id, "field": "note"})
    view = await screen.render(ctx)
    assert "`vecchia`" in view.text
    await screen.on_text(ctx, "nuova nota")
    assert (await _decrypted(env, acc.id)).note == "nuova nota"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/ui/test_edit_screens.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'password_bot.ui.screens.account_edit'`.

- [ ] **Step 3: Implement**

`src/password_bot/ui/screens/account_edit.py`:

```python
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
```

`src/password_bot/ui/registry.py` — add:

```python
from password_bot.ui.screens.account_edit import AccountEditScreen, FieldEditScreen
```

```python
        AccountEditScreen(),
        FieldEditScreen(),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/ui -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
uv run ruff format src tests && uv run ruff check src tests
git add src tests
git commit -m "Add edit submenu and single-field edit with username suggestions

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: Password generator screen

**Files:**
- Create: `src/password_bot/ui/screens/generator.py`
- Modify: `src/password_bot/ui/registry.py`
- Test: `tests/ui/test_generator_screen.py`

**Interfaces:**
- Consumes: `UserRepo.get_pw_prefs/set_pw_prefs`, `PwPrefs`, `PasswordGenerator`, `PasswordSpec`, `entropy_bits`, `MIN_LENGTH`, `MAX_LENGTH`.
- Produces: `GeneratorScreen` (`"generator"`, title `"Generatore"`, `accepts_text=True`). Args: `flow` (caller's flow key, optional) and `next_step`. Flow key `"generator"` holds `prefs` (dict), `password`, `await_len`. Contract with callers: **`✅ Usa` writes `ctx.flow(args["flow"])["password"] = <password>` and `["step"] = args["next_step"]`, drops its own flow, returns `back()`.** Without `flow` (opened from Settings) there is no `✅ Usa` button.

- [ ] **Step 1: Write the failing tests**

`tests/ui/test_generator_screen.py`:

```python
"""Reusable password generator."""

from __future__ import annotations

from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.md import code_inline
from password_bot.ui.screen import back
from password_bot.ui.screens.generator import GeneratorScreen
from password_bot.ui.views import PRIMARY, SUCCESS
from tests.ui._helpers import act, button, labels

FLOW = ChatDataKey.FLOW.value


async def _opened(env, args):
    screen = GeneratorScreen()
    ctx = env.ctx(args, back_label="Cambio password")
    await screen.on_enter(ctx)
    return screen, ctx


async def test_generate_and_use_hands_password_to_caller(env):
    screen, ctx = await _opened(env, {"flow": "password_change", "next_step": "confirm"})
    view = await screen.render(ctx)
    assert button(view, "🎲 Genera").style == PRIMARY
    assert "✅ Usa" not in labels(view)
    await screen.on_action(ctx, act(view, "🎲 Genera"))
    password = ctx.flow("generator")["password"]
    assert len(password) == 20
    view = await screen.render(ctx)
    assert code_inline(password) in view.text
    assert "🔄 Rigenera" in labels(view)
    assert button(view, "✅ Usa").style == SUCCESS
    assert await screen.on_action(ctx, act(view, "✅ Usa")) == back()
    assert env.chat_data[FLOW]["password_change"] == {"password": password, "step": "confirm"}
    assert "generator" not in env.chat_data[FLOW]


async def test_length_input(env):
    screen, ctx = await _opened(env, {})
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "📏 Lunghezza"))
    assert "Scrivi la lunghezza" in (await screen.render(ctx)).text
    bad = await screen.on_text(ctx, "3")
    assert bad.notice == "⚠️ Lunghezza non valida: usa un numero tra 4 e 128."
    await screen.on_text(ctx, "12")
    assert "📏 Lunghezza: 12" in labels(await screen.render(ctx))


async def test_text_without_length_request_is_rejected(env):
    screen, ctx = await _opened(env, {})
    result = await screen.on_text(ctx, "12")
    assert result.notice == "⚠️ Usa i bottoni qui sotto."


async def test_no_character_class_selected(env):
    screen, ctx = await _opened(env, {})
    view = await screen.render(ctx)
    for flag in ("Maiuscole", "Minuscole", "Numeri", "Simboli"):
        await screen.on_action(ctx, act(view, flag))
    result = await screen.on_action(ctx, act(view, "🎲 Genera"))
    assert result.notice.startswith("⚠️ Nessuna classe")


async def test_save_defaults(env):
    screen, ctx = await _opened(env, {})
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "Simboli"))
    result = await screen.on_action(ctx, act(view, "💾 Salva come predefinite"))
    assert result.toast == "💾 Preferenze salvate"
    assert (await env.container.users.get_pw_prefs(1)).symbols is False


async def test_without_caller_flow_there_is_no_use_button(env):
    screen, ctx = await _opened(env, {})
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "🎲 Genera"))
    assert "✅ Usa" not in labels(await screen.render(ctx))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/ui/test_generator_screen.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'password_bot.ui.screens.generator'`.

- [ ] **Step 3: Implement**

`src/password_bot/ui/screens/generator.py`:

```python
"""Password generator screen, reusable by any flow (creation, password change, settings)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from password_bot.models.pw_prefs import PwPrefs
from password_bot.services.password_generator import (
    MAX_LENGTH,
    MIN_LENGTH,
    PasswordGenerator,
    PasswordSpec,
    entropy_bits,
)
from password_bot.telegram_utils.md import code_inline, escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import TEXT_NOT_ACCEPTED, Ctx, Result, Screen, View, back, refresh
from password_bot.ui.views import PRIMARY, SUCCESS, btn, footer, keyboard

_FLAGS = (
    ("upper", "Maiuscole"),
    ("lower", "Minuscole"),
    ("digits", "Numeri"),
    ("symbols", "Simboli"),
    ("exclude_ambiguous", "No ambigui"),
    ("no_duplicates", "No duplicati"),
)


def _spec(prefs: PwPrefs) -> PasswordSpec:
    return PasswordSpec(
        length=prefs.length,
        upper=prefs.upper,
        lower=prefs.lower,
        digits=prefs.digits,
        symbols=prefs.symbols,
        exclude_ambiguous=prefs.exclude_ambiguous,
        no_duplicates=prefs.no_duplicates,
    )


class GeneratorScreen(Screen):
    name = "generator"
    title = "Generatore"
    accepts_text = True

    async def on_enter(self, ctx: Ctx) -> None:
        prefs = await ctx.container.users.get_pw_prefs(ctx.chat_id)
        ctx.drop_flow(self.name)
        ctx.flow(self.name).update(prefs=asdict(prefs), password=None, await_len=False)

    async def _state(self, ctx: Ctx) -> dict[str, Any]:
        state = ctx.flow(self.name)
        if "prefs" not in state:  # flow lost (restart or lock): start again from saved defaults
            await self.on_enter(ctx)
            state = ctx.flow(self.name)
        return state

    async def render(self, ctx: Ctx) -> View:
        state = await self._state(ctx)
        prefs = PwPrefs(**state["prefs"])
        password = state.get("password")
        lines = ["🎲 *Generatore password*"]
        if password:
            bits = int(entropy_bits(_spec(prefs)))
            lines += [
                "",
                code_inline(password),
                escape_md(f"{len(password)} caratteri, entropia ≈ {bits} bit"),
            ]
        if state.get("await_len"):
            lines += ["", escape_md(f"Scrivi la lunghezza ({MIN_LENGTH}-{MAX_LENGTH}).")]
        toggles = [
            btn(f"{text} {'✅' if getattr(prefs, flag) else '❌'}", self.name, "toggle", flag)
            for flag, text in _FLAGS
        ]
        rows = [
            [btn(f"📏 Lunghezza: {prefs.length}", self.name, "len")],
            toggles[0:2],
            toggles[2:4],
            toggles[4:6],
            [
                btn(
                    "🔄 Rigenera" if password else "🎲 Genera",
                    self.name,
                    "run",
                    style=None if password else PRIMARY,
                )
            ],
        ]
        if password and ctx.args.get("flow"):
            rows.append([btn("✅ Usa", self.name, "use", style=SUCCESS)])
        rows.append(
            [btn("💾 Salva come predefinite", self.name, "save"), btn("🔄 Reset", self.name, "reset")]
        )
        rows.append(footer(ctx.back_label))
        return View("\n".join(lines), keyboard(*rows))

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        state = await self._state(ctx)
        if not state.get("await_len"):
            return refresh(notice=TEXT_NOT_ACCEPTED)
        try:
            length = int(text.strip())
        except ValueError:
            length = 0
        if not MIN_LENGTH <= length <= MAX_LENGTH:
            return refresh(
                notice=f"⚠️ Lunghezza non valida: usa un numero tra {MIN_LENGTH} e {MAX_LENGTH}."
            )
        state["prefs"]["length"] = length
        state["await_len"] = False
        state["password"] = None
        return refresh()

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        state = await self._state(ctx)
        prefs = state["prefs"]
        match act.action:
            case "toggle" if act.arg in prefs and act.arg != "length":
                prefs[act.arg] = not prefs[act.arg]
                state["password"] = None
            case "len":
                state["await_len"] = True
            case "run":
                try:
                    state["password"] = PasswordGenerator().generate(_spec(PwPrefs(**prefs)))
                except ValueError as e:
                    return refresh(notice=f"⚠️ {e}")
            case "use" if state.get("password") and ctx.args.get("flow"):
                target = ctx.flow(str(ctx.args["flow"]))
                target["password"] = state["password"]
                target["step"] = ctx.args.get("next_step")
                ctx.drop_flow(self.name)
                return back()
            case "save":
                await ctx.container.users.set_pw_prefs(ctx.chat_id, PwPrefs(**prefs))
                return refresh(toast="💾 Preferenze salvate")
            case "reset":
                state["prefs"] = asdict(PwPrefs())
                state["password"] = None
                return refresh(toast="🔄 Valori predefiniti")
        return refresh()
```

`src/password_bot/ui/registry.py` — add:

```python
from password_bot.ui.screens.generator import GeneratorScreen
```

```python
        GeneratorScreen(),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/ui -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
uv run ruff format src tests && uv run ruff check src tests
git add src tests
git commit -m "Add reusable password generator screen

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: Change password (generate or manual → confirm)

**Files:**
- Create: `src/password_bot/ui/screens/password_change.py`
- Modify: `src/password_bot/ui/registry.py`
- Test: `tests/ui/test_password_change_screen.py`

**Interfaces:**
- Consumes: generator contract (Task 10), `_shared.load_account/reuse_names_for/strength_text`, `VaultService.update_password(account_id, new_password, *, aes_key, hmac_key)`.
- Produces: `PasswordChangeScreen` (`"password_change"`, title `"Cambio password"`, `accepts_text=True`), arg `id`. Flow key `"password_change"`: `step` ∈ `choose | manual | confirm`, `password`. Actions: `gen` → `open_screen("generator", flow="password_change", next_step="confirm")`, `manual`, `choose`, `cancel` → drop flow + `back()`, `confirm` → update + `pop_to("account_detail", notice="✅ Password aggiornata")`.

- [ ] **Step 1: Write the failing tests**

`tests/ui/test_password_change_screen.py`:

```python
"""Change password: generate or type, then confirm."""

from __future__ import annotations

from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.screen import TEXT_NOT_ACCEPTED, back, open_screen, pop_to
from password_bot.ui.screens.password_change import PasswordChangeScreen
from password_bot.ui.views import PRIMARY, SUCCESS
from tests.ui._helpers import act, button

FLOW = ChatDataKey.FLOW.value


async def _opened(env, acc):
    screen = PasswordChangeScreen()
    ctx = env.ctx({"id": acc.id}, back_label="Modifica")
    await screen.on_enter(ctx)
    return screen, ctx


async def test_manual_change_with_reuse_warning(env):
    acc = await env.add("GitHub", password="old")
    await env.add("GitLab", password="shared-pw")
    screen, ctx = await _opened(env, acc)
    view = await screen.render(ctx)
    assert button(view, "🎲 Genera").style == PRIMARY
    await screen.on_action(ctx, act(view, "⌨️ Scrivila io"))
    assert "Inviami la nuova password" in (await screen.render(ctx)).text
    await screen.on_text(ctx, "shared-pw")
    view = await screen.render(ctx)
    assert escape_md("♻️ Già usata per: GitLab") in view.text
    assert "forza" in view.text
    assert "shared-pw" not in view.text
    assert button(view, "✅ Sostituisci").style == SUCCESS
    result = await screen.on_action(ctx, act(view, "✅ Sostituisci"))
    assert result == pop_to("account_detail", notice="✅ Password aggiornata")
    updated = await env.container.vault.get_decrypted(acc.id, aes_key=env.session.aes_key)
    assert updated.password == "shared-pw"
    assert len(await env.container.history.list_for_account(acc.id)) == 1
    assert "password_change" not in env.chat_data[FLOW]


async def test_generate_opens_generator_and_result_lands_on_confirm(env):
    acc = await env.add("GitHub")
    screen, ctx = await _opened(env, acc)
    view = await screen.render(ctx)
    assert await screen.on_action(ctx, act(view, "🎲 Genera")) == open_screen(
        "generator", flow="password_change", next_step="confirm"
    )
    ctx.flow("password_change").update(password="Gen-Pass-123", step="confirm")
    assert "✅ Sostituisci" in [b.text for row in (await screen.render(ctx)).keyboard.inline_keyboard for b in row]


async def test_change_back_to_choice(env):
    acc = await env.add("GitHub")
    screen, ctx = await _opened(env, acc)
    ctx.flow("password_change").update(password="x", step="confirm")
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "🔄 Cambia"))
    assert ctx.flow("password_change") == {"step": "choose"}


async def test_cancel_drops_the_flow(env):
    acc = await env.add("GitHub")
    screen, ctx = await _opened(env, acc)
    view = await screen.render(ctx)
    assert await screen.on_action(ctx, act(view, "❌ Annulla")) == back()
    assert "password_change" not in env.chat_data[FLOW]


async def test_text_outside_manual_step_is_rejected(env):
    acc = await env.add("GitHub")
    screen, ctx = await _opened(env, acc)
    result = await screen.on_text(ctx, "typed too early")
    assert result.notice == TEXT_NOT_ACCEPTED
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/ui/test_password_change_screen.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'password_bot.ui.screens.password_change'`.

- [ ] **Step 3: Implement**

`src/password_bot/ui/screens/password_change.py`:

```python
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
```

`src/password_bot/ui/registry.py` — add:

```python
from password_bot.ui.screens.password_change import PasswordChangeScreen
```

```python
        PasswordChangeScreen(),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/ui -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
uv run ruff format src tests && uv run ruff check src tests
git add src tests
git commit -m "Add password change screen using the generator or manual input

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: Account creation wizard with summary

**Files:**
- Create: `src/password_bot/ui/screens/account_new.py`
- Modify: `src/password_bot/ui/registry.py`
- Test: `tests/ui/test_account_new_screen.py`

**Interfaces:**
- Consumes: generator contract (Task 10), `_shared.username_suggestions/reuse_names_for/strength_text`, `VaultService.add`, `CategoryRepo.get`, `views.normalize_url`, `finish()`.
- Produces: `AccountNewScreen` (`"account_new"`, title `"Nuovo account"`, `accepts_text=True`), optional arg `category_id` (preset). Flow key `"account_new"`: `step` ∈ `name | username | password | password_manual | summary | url | note`, `name`, `username`, `password`, `url`, `note`, `category_id`, `suggestions`, `reached_summary`. Actions: `cancel`, `back_step`, `pick` (index), `no_user`, `existing` (account id) → `open_screen("account_detail", id=…)`, `gen` → `open_screen("generator", flow="account_new", next_step="summary")`, `manual`, `edit` (arg field), `clear` (arg `url`/`note`), `category` → `open_screen("category_pick", flow="account_new")`, `save` → `finish("account_new", then=Frame("account_detail", {"id": new_id}), notice="✅ Account salvato")`. The category picker (Task 13) writes `ctx.flow("account_new")["category_id"]`.

- [ ] **Step 1: Write the failing tests**

`tests/ui/test_account_new_screen.py`:

```python
"""Account creation: 3 steps + summary."""

from __future__ import annotations

from password_bot.state.keys import ChatDataKey
from password_bot.ui.screen import Go, back, open_screen
from password_bot.ui.screens.account_new import AccountNewScreen
from password_bot.ui.views import PRIMARY, SUCCESS
from tests.ui._helpers import act, button, labels

FLOW = ChatDataKey.FLOW.value


async def _opened(env, args=None):
    screen = AccountNewScreen()
    ctx = env.ctx(args or {})
    await screen.on_enter(ctx)
    return screen, ctx


async def test_happy_path(env):
    await env.add("Old", username="me@x.com")
    screen, ctx = await _opened(env)
    assert "passo 1/3" in (await screen.render(ctx)).text
    await screen.on_text(ctx, "GitHub")
    view = await screen.render(ctx)
    assert "passo 2/3" in view.text
    await screen.on_action(ctx, act(view, "me@x.com"))
    view = await screen.render(ctx)
    assert "passo 3/3" in view.text
    assert button(view, "🎲 Genera").style == PRIMARY
    await screen.on_action(ctx, act(view, "⌨️ Scrivila io"))
    await screen.on_text(ctx, "Tr0ub4dor&3")
    view = await screen.render(ctx)
    assert "Riepilogo" in view.text and "forza" in view.text
    assert "Tr0ub4dor" not in view.text
    await screen.on_action(ctx, act(view, "🌐 + URL"))
    await screen.on_text(ctx, "github.com")
    view = await screen.render(ctx)
    assert "🌐 https://github.com" in labels(view)
    assert button(view, "💾 Salva").style == SUCCESS
    result = await screen.on_action(ctx, act(view, "💾 Salva"))
    assert isinstance(result, Go)
    assert result.pop_to == "account_new" and result.pop_to_inclusive
    assert result.push.name == "account_detail"
    assert result.notice == "✅ Account salvato"
    saved = await env.container.vault.get_decrypted(
        result.push.data["id"], aes_key=env.session.aes_key
    )
    assert (saved.name, saved.username, saved.password, saved.url) == (
        "GitHub", "me@x.com", "Tr0ub4dor&3", "https://github.com",
    )
    assert "account_new" not in env.chat_data[FLOW]


async def test_duplicate_name_warns_and_links_existing(env):
    existing = await env.add("GitHub")
    screen, ctx = await _opened(env)
    await screen.on_text(ctx, "github")
    view = await screen.render(ctx)
    assert "Hai già un account" in view.text
    assert await screen.on_action(ctx, act(view, "👁 Apri esistente")) == open_screen(
        "account_detail", id=existing.id
    )


async def test_reuse_warning_in_summary(env):
    await env.add("GitLab", password="same-pass")
    screen, ctx = await _opened(env)
    ctx.flow("account_new").update(step="summary", name="GitHub", password="same-pass")
    assert "GitLab" in (await screen.render(ctx)).text


async def test_back_steps_and_edits_from_summary(env):
    screen, ctx = await _opened(env)
    await screen.on_text(ctx, "A")
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "⏭ Nessuno"))
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "🔙 Indietro"))
    assert ctx.flow("account_new")["step"] == "username"
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "⏭ Nessuno"))
    view = await screen.render(ctx)
    assert await screen.on_action(ctx, act(view, "🎲 Genera")) == open_screen(
        "generator", flow="account_new", next_step="summary"
    )
    ctx.flow("account_new").update(password="Gen-pass-1", step="summary")  # what ✅ Usa does
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "📛 Nome"))
    await screen.on_text(ctx, "B")
    assert ctx.flow("account_new")["step"] == "summary"
    assert "B" in (await screen.render(ctx)).text


async def test_category_preset_and_picker(env):
    cat = await env.category("Lavoro", icon="💼")
    screen, ctx = await _opened(env, {"category_id": cat.id})
    ctx.flow("account_new").update(step="summary", name="Jira", password="pw-123456")
    view = await screen.render(ctx)
    assert "🏷 Categoria: 💼 Lavoro" in labels(view)
    assert await screen.on_action(ctx, act(view, "🏷 Categoria")) == open_screen(
        "category_pick", flow="account_new"
    )
    result = await screen.on_action(ctx, act(view, "💾 Salva"))
    saved = await env.container.vault.get_decrypted(
        result.push.data["id"], aes_key=env.session.aes_key
    )
    assert saved.category_id == cat.id


async def test_url_validation_and_clear(env):
    screen, ctx = await _opened(env)
    ctx.flow("account_new").update(step="url", name="A", password="p", reached_summary=True)
    bad = await screen.on_text(ctx, "nope")
    assert bad.notice == "⚠️ URL non valido. Esempio: github.com"
    await screen.on_text(ctx, "a.com")
    ctx.flow("account_new")["step"] = "url"
    view = await screen.render(ctx)
    await screen.on_action(ctx, act(view, "🗑 Rimuovi"))
    assert ctx.flow("account_new")["url"] is None
    assert ctx.flow("account_new")["step"] == "summary"


async def test_cancel_drops_the_flow(env):
    screen, ctx = await _opened(env)
    view = await screen.render(ctx)
    assert await screen.on_action(ctx, act(view, "❌ Annulla")) == back()
    assert "account_new" not in env.chat_data[FLOW]


async def test_lost_flow_restarts_from_name(env):
    screen = AccountNewScreen()
    ctx = env.ctx({})
    assert "passo 1/3" in (await screen.render(ctx)).text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/ui/test_account_new_screen.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'password_bot.ui.screens.account_new'`.

- [ ] **Step 3: Implement**

`src/password_bot/ui/screens/account_new.py`:

```python
"""Account creation: name → username → password → summary (URL, note, category, save)."""

from __future__ import annotations

from typing import Any

from password_bot.models.category import Category
from password_bot.services.vault_service import NewAccount
from password_bot.state.fsm import Frame
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import (
    TEXT_NOT_ACCEPTED,
    Ctx,
    Result,
    Screen,
    View,
    back,
    finish,
    open_screen,
    refresh,
)
from password_bot.ui.screens._shared import reuse_names_for, strength_text, username_suggestions
from password_bot.ui.views import (
    PRIMARY,
    SUCCESS,
    btn,
    category_label,
    keyboard,
    label,
    normalize_url,
)

_EDITABLE = ("name", "username", "password", "url", "note")
_BEFORE_SUMMARY = {"username": "name", "password": "username", "password_manual": "password"}


class AccountNewScreen(Screen):
    name = "account_new"
    title = "Nuovo account"
    accepts_text = True

    async def on_enter(self, ctx: Ctx) -> None:
        ctx.drop_flow(self.name)
        ctx.flow(self.name).update(
            step="name",
            category_id=ctx.args.get("category_id"),
            suggestions=await username_suggestions(ctx),
            reached_summary=False,
        )

    async def _flow(self, ctx: Ctx) -> dict[str, Any]:
        flow = ctx.flow(self.name)
        if "step" not in flow:  # lost after a restart or a lock: start over
            await self.on_enter(ctx)
            flow = ctx.flow(self.name)
        return flow

    @staticmethod
    def _header(step: int) -> str:
        return "➕ *Nuovo account* — " + escape_md(f"passo {step}/3") + "\n"

    async def _category(self, ctx: Ctx, cat_id: str | None) -> Category | None:
        if not cat_id:
            return None
        cat = await ctx.container.categories.get(cat_id)
        return cat if cat is not None and cat.chat_id == ctx.chat_id else None

    async def render(self, ctx: Ctx) -> View:
        flow = await self._flow(ctx)
        step = flow["step"]
        if step == "summary":
            flow["reached_summary"] = True
            return await self._summary(ctx, flow)
        can_go_back = step != "name" or flow.get("reached_summary")
        nav_row = [
            btn("🔙 Indietro", self.name, "back_step") if can_go_back else None,
            btn("❌ Annulla", self.name, "cancel"),
        ]
        if step == "name":
            return View(self._header(1) + escape_md("Nome dell'account?"), keyboard(nav_row))
        if step == "username":
            lines = [self._header(2)]
            rows = []
            existing = await self._existing(ctx, flow.get("name", ""))
            if existing is not None:
                lines.append(escape_md(f"⚠️ Hai già un account «{existing.name}»."))
                rows.append([btn("👁 Apri esistente", self.name, "existing", existing.id)])
            lines.append(escape_md("Username o email? Scrivilo oppure scegli:"))
            rows += [
                [btn(label(s), self.name, "pick", i)]
                for i, s in enumerate(flow.get("suggestions", []))
            ]
            rows.append([btn("⏭ Nessuno", self.name, "no_user")])
            rows.append(nav_row)
            return View("\n".join(lines), keyboard(*rows))
        if step == "password":
            return View(
                self._header(3) + escape_md("Come vuoi impostare la password?"),
                keyboard(
                    [
                        btn("🎲 Genera", self.name, "gen", style=PRIMARY),
                        btn("⌨️ Scrivila io", self.name, "manual"),
                    ],
                    nav_row,
                ),
            )
        if step == "password_manual":
            return View(
                escape_md("⌨️ Inviami la password. Cancellerò subito il tuo messaggio."),
                keyboard(nav_row),
            )
        prompt = "🌐 URL dell'account?" if step == "url" else "📝 Note per l'account?"
        clear = btn("🗑 Rimuovi", self.name, "clear", step) if flow.get(step) else None
        return View(escape_md(prompt), keyboard([clear], nav_row))

    async def _existing(self, ctx: Ctx, name: str):
        wanted = name.strip().lower()
        for row in await ctx.container.accounts.list_for_chat(ctx.chat_id):
            if row.name.lower() == wanted:
                return row
        return None

    async def _summary(self, ctx: Ctx, flow: dict[str, Any]) -> View:
        password = flow.get("password") or ""
        lines = [
            "➕ *Riepilogo*",
            f"🔐 {escape_md(flow.get('name') or '—')}",
            f"👤 {escape_md(flow.get('username') or '—')}",
            escape_md(f"🔑 •••••••• — {strength_text(ctx, password)}"),
        ]
        reused = await reuse_names_for(ctx, password) if password else []
        if reused:
            lines.append(escape_md("♻️ Stessa password di: " + ", ".join(reused)))
        if flow.get("url"):
            lines.append(f"🌐 {escape_md(flow['url'])}")
        if flow.get("note"):
            lines.append(escape_md("📝 Note presenti"))
        cat = await self._category(ctx, flow.get("category_id"))
        cat_text = category_label(cat) if cat else "—"
        url_label = f"🌐 {label(flow['url'], 20)}" if flow.get("url") else "🌐 + URL"
        note_label = "📝 Note ✓" if flow.get("note") else "📝 + Note"
        return View(
            "\n".join(lines),
            keyboard(
                [
                    btn("📛 Nome", self.name, "edit", "name"),
                    btn("👤 Username", self.name, "edit", "username"),
                    btn("🔑 Password", self.name, "edit", "password"),
                ],
                [btn(url_label, self.name, "edit", "url"), btn(note_label, self.name, "edit", "note")],
                [btn(f"🏷 Categoria: {label(cat_text, 24)}", self.name, "category")],
                [btn("💾 Salva", self.name, "save", style=SUCCESS)],
                [btn("❌ Annulla", self.name, "cancel")],
            ),
        )

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        flow = await self._flow(ctx)
        step = flow["step"]
        value = text.strip()
        after = "summary" if flow.get("reached_summary") else None
        if step == "name":
            if not value:
                return refresh(notice="⚠️ Il nome non può essere vuoto.")
            flow["name"] = value
            flow["step"] = after or "username"
        elif step == "username":
            flow["username"] = value or None
            flow["step"] = after or "password"
        elif step == "password_manual":
            if not text:
                return refresh()
            flow["password"] = text  # verbatim
            flow["step"] = "summary"
        elif step == "url":
            url = normalize_url(value)
            if url is None:
                return refresh(notice="⚠️ URL non valido. Esempio: github.com")
            flow["url"] = url
            flow["step"] = "summary"
        elif step == "note":
            flow["note"] = value or None
            flow["step"] = "summary"
        else:
            return refresh(notice=TEXT_NOT_ACCEPTED)
        return refresh()

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        flow = await self._flow(ctx)
        after = "summary" if flow.get("reached_summary") else None
        match act.action:
            case "cancel":
                ctx.drop_flow(self.name)
                return back()
            case "back_step":
                step = flow["step"]
                if step == "password_manual":
                    flow["step"] = "password"
                else:
                    flow["step"] = after or _BEFORE_SUMMARY.get(step, "name")
            case "pick":
                suggestions = flow.get("suggestions", [])
                index = int(act.arg or 0)
                if 0 <= index < len(suggestions):
                    flow["username"] = suggestions[index]
                    flow["step"] = after or "password"
            case "no_user":
                flow["username"] = None
                flow["step"] = after or "password"
            case "existing":
                return open_screen("account_detail", id=act.arg)
            case "gen":
                return open_screen("generator", flow=self.name, next_step="summary")
            case "manual":
                flow["step"] = "password_manual"
            case "edit" if act.arg in _EDITABLE:
                flow["step"] = act.arg
            case "clear" if act.arg in ("url", "note"):
                flow[act.arg] = None
                flow["step"] = "summary"
            case "category":
                return open_screen("category_pick", flow=self.name)
            case "save":
                return await self._save(ctx, flow)
        return refresh()

    async def _save(self, ctx: Ctx, flow: dict[str, Any]) -> Result:
        if not flow.get("name") or not flow.get("password"):
            return refresh(notice="⚠️ Mancano nome o password.")
        cat = await self._category(ctx, flow.get("category_id"))
        session = ctx.session
        acc = await ctx.container.vault.add(
            NewAccount(
                chat_id=ctx.chat_id,
                name=flow["name"],
                username=flow.get("username"),
                password=flow["password"],
                url=flow.get("url"),
                note=flow.get("note"),
                category_id=cat.id if cat else None,
            ),
            aes_key=session.aes_key,
            hmac_key=session.hmac_key,
        )
        ctx.drop_flow(self.name)
        return finish(
            self.name, then=Frame("account_detail", {"id": acc.id}), notice="✅ Account salvato"
        )
```

`src/password_bot/ui/registry.py` — add:

```python
from password_bot.ui.screens.account_new import AccountNewScreen
```

```python
        AccountNewScreen(),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/ui -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
uv run ruff format src tests && uv run ruff check src tests
git add src tests
git commit -m "Add account creation wizard with username suggestions and summary

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: Category screens (list, picker, form, icon, delete)

**Files:**
- Create: `src/password_bot/ui/screens/categories.py`
- Modify: `src/password_bot/ui/registry.py`
- Test: `tests/ui/test_category_screens.py`

**Interfaces:**
- Consumes: `CategoryRepo.list_with_counts/count_uncategorized/get/get_by_name/create/rename/set_icon/delete/list_for_chat`, `AccountRepo.list_for_chat(category=…)`, `UNCATEGORIZED`, `VaultService.update_fields(…, UpdatedFields(category_id=cat_id or ""))`, `_shared.load_account`.
- Produces (all in `ui/screens/categories.py`):
  - `ICONS = ("💼", "🏦", "👤", "🎮", "🛒", "📧", "🌐", "🏠", "💳", "📱", "🎓", "⭐")`, `NAME_MAX = 32`
  - `async assign_category(ctx, args, cat_id) -> Result` — with `args["account_id"]`: set the account's category, `pop_to("account_detail", notice="✅ Categoria aggiornata")`; with `args["flow"]`: `ctx.flow(flow)["category_id"] = cat_id`, `pop_to(flow)`.
  - `CategoriesScreen` (`"categories"`, `"Categorie"`): actions `open` (arg category id or `"none"`) → `open_screen("account_list", category=…)`, `new` → `open_screen("category_form", mode="create")`.
  - `CategoryPickScreen` (`"category_pick"`, `"Categoria"`), args `account_id` **or** `flow`: actions `pick` (arg id, `""` = none), `new` → `open_screen("category_form", mode="create", <same account_id/flow>)`.
  - `CategoryFormScreen` (`"category_form"`, `"Categoria"`, `accepts_text=True`), args `mode` (`create`/`rename`), `cat_id` (rename), optional `account_id`/`flow`. Create → `replace("category_icon", cat_id=…, created=True, <account_id/flow>)`; rename → `back(notice="✅ Rinominata")`.
  - `CategoryIconScreen` (`"category_icon"`, `"Icona"`), args `cat_id`, optional `created`, `account_id`/`flow`: action `pick` (arg index into `ICONS`, `-1` = none).
  - `CategoryDeleteScreen` (`"category_delete"`, `"Elimina categoria"`), arg `cat_id`: `confirm` → `Go(pop_to="account_list", pop_to_inclusive=True, notice="🗑 Categoria eliminata")`.

- [ ] **Step 1: Write the failing tests**

`tests/ui/test_category_screens.py`:

```python
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
    assert await screen.on_action(ctx, act(view, "➕ Nuova categoria")) == open_screen(
        "category_form", mode="create"
    )


async def test_empty_list_makes_new_primary(env):
    view = await CategoriesScreen().render(env.ctx())
    assert "Nessuna categoria" in view.text
    assert button(view, "➕ Nuova categoria").style == PRIMARY


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
    assert await pick.on_action(pctx, act(view, "➕ Nuova")) == open_screen(
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
    assert result == Go(pop_to="account_list", pop_to_inclusive=True, notice="🗑 Categoria eliminata")
    assert await env.container.categories.get(cat.id) is None
    assert await _category_of(env, acc.id) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/ui/test_category_screens.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'password_bot.ui.screens.categories'`.

- [ ] **Step 3: Implement**

`src/password_bot/ui/screens/categories.py`:

```python
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
            [btn("➕ Nuova categoria", self.name, "new", style=None if items else PRIMARY)]
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
        rows.append([btn("➕ Nuova", self.name, "new")])
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
```

`src/password_bot/ui/registry.py` — add:

```python
from password_bot.ui.screens.categories import (
    CategoriesScreen,
    CategoryDeleteScreen,
    CategoryFormScreen,
    CategoryIconScreen,
    CategoryPickScreen,
)
```

```python
        CategoriesScreen(),
        CategoryPickScreen(),
        CategoryFormScreen(),
        CategoryIconScreen(),
        CategoryDeleteScreen(),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/ui -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
uv run ruff format src tests && uv run ruff check src tests
git add src tests
git commit -m "Add category screens: list, picker, form, icon palette, delete

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 14: Health, settings, export/import screens

**Files:**
- Create: `src/password_bot/ui/screens/health.py`, `ui/screens/settings.py`, `ui/screens/transfer.py`
- Modify: `src/password_bot/ui/registry.py`
- Test: `tests/ui/test_misc_screens.py`

**Interfaces:**
- Consumes: `AlertService.find_stale(chat_id=…)`, `AccountRepo.list_reuse_clusters(chat_id)`, `UserRepo.get/update_autolock/update_alert_days`, `ExportService.export/import_payload`, `MergeStrategy.SKIP`, `InvalidPassphraseError`, `InvalidExportFileError`, `MESSAGES`.
- Produces:
  - `HealthScreen` (`"health"`, `"Salute"`): action `open` (arg account id).
  - `SettingsScreen` (`"settings"`, `"Impostazioni"`), arg `sub` (`None`/`"autolock"`/`"alert"`): actions `sub`, `set_autolock` (arg minutes ∈ `AUTOLOCK_CHOICES = (5, 15, 30, 60)`), `set_alert` (arg days ∈ `ALERT_CHOICES = (90, 180, 365)`), `gen` → `open_screen("generator")`, `export` / `import` → `open_screen("transfer", mode=…)`.
  - `TransferScreen` (`"transfer"`, `"Export/Import"`, `accepts_text=True`, `accepts_document=True`), arg `mode` (`export`/`import`); flow key `"transfer"` (`step`, `file`); action `cancel`.

- [ ] **Step 1: Write the failing tests**

`tests/ui/test_misc_screens.py`:

```python
"""Health, settings, export/import."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

from password_bot.i18n.it import MESSAGES
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.screen import back, open_screen, refresh, replace
from password_bot.ui.screens.health import HealthScreen
from password_bot.ui.screens.settings import SettingsScreen
from password_bot.ui.screens.transfer import TransferScreen
from tests.ui._helpers import FakeBot, act, labels


async def test_health_lists_stale_and_reused(env):
    old = await env.add("Old")
    row = await env.container.accounts.get(old.id)
    await env.container.accounts.update_password(
        old.id, password_enc=row.password_enc, password_hmac=row.password_hmac,
        crypto_version=2, password_changed_at=1,
    )
    await env.add("A", password="same-pw")
    await env.add("B", password="same-pw")
    screen = HealthScreen()
    ctx = env.ctx()
    view = await screen.render(ctx)
    assert "⏳ Old" in labels(view)
    assert "♻️ A" in labels(view) and "♻️ B" in labels(view)
    assert escape_md("• A, B") in view.text
    assert await screen.on_action(ctx, act(view, "⏳ Old")) == open_screen(
        "account_detail", id=old.id
    )


async def test_health_all_good(env):
    await env.add("Fresh")
    assert "Tutto in ordine" in (await HealthScreen().render(env.ctx())).text


async def test_settings_autolock(env):
    screen = SettingsScreen()
    view = await screen.render(env.ctx())
    assert escape_md("⏰ Autolock: 15 min") in view.text
    assert await screen.on_action(env.ctx(), act(view, "⏰ Autolock")) == replace(
        "settings", sub="autolock"
    )
    sub = env.ctx({"sub": "autolock"})
    view = await screen.render(sub)
    assert "15 min ✓" in labels(view)
    assert await screen.on_action(sub, act(view, "30 min")) == replace(
        "settings", sub=None, notice="✅ Autolock: 30 min"
    )
    assert (await env.container.users.get(1)).autolock_minutes == 30


async def test_settings_alert_threshold(env):
    screen = SettingsScreen()
    sub = env.ctx({"sub": "alert"})
    view = await screen.render(sub)
    assert "180 giorni ✓" in labels(view)
    await screen.on_action(sub, act(view, "365 giorni"))
    assert (await env.container.users.get(1)).alert_days == 365


async def test_settings_links(env):
    screen = SettingsScreen()
    ctx = env.ctx()
    view = await screen.render(ctx)
    assert await screen.on_action(ctx, act(view, "🎲 Generatore password")) == open_screen("generator")
    assert await screen.on_action(ctx, act(view, "📤 Export")) == open_screen("transfer", mode="export")
    assert await screen.on_action(ctx, act(view, "📥 Import")) == open_screen("transfer", mode="import")


async def test_export_sends_encrypted_document(env):
    await env.add("GitHub")
    screen = TransferScreen()
    ctx = env.ctx({"mode": "export"}, back_label="Impostazioni")
    ctx.bot = FakeBot()
    await screen.on_enter(ctx)
    assert "Export" in (await screen.render(ctx)).text
    assert await screen.on_text(ctx, "exp-pass") == back(notice="📤 Export inviato qui sotto.")
    document = ctx.bot.documents[-1]
    assert document.filename.endswith(".json")
    assert b"password-bot-vault" in document.data


async def test_import_roundtrip(env):
    acc = await env.add("GitHub")
    payload = await env.container.export.export(
        chat_id=1, vault_key=env.session.aes_key, export_passphrase="exp"
    )
    await env.container.vault.delete(acc.id)
    screen = TransferScreen()
    ctx = env.ctx({"mode": "import"})
    tg_file = SimpleNamespace(download_as_bytearray=AsyncMock(return_value=bytearray(payload.encode())))
    ctx.bot.get_file = AsyncMock(return_value=tg_file)
    await screen.on_enter(ctx)
    assert "Inviami il file" in (await screen.render(ctx)).text
    document = SimpleNamespace(file_name="vault.json", file_id="f1")
    assert await screen.on_document(ctx, document) == refresh()
    assert "passphrase del file" in (await screen.render(ctx)).text
    wrong = await screen.on_text(ctx, "nope")
    assert wrong.notice == MESSAGES["import_wrong_passphrase"]
    done = await screen.on_text(ctx, "exp")
    assert done == back(notice=MESSAGES["import_done"].format(added=1, overwritten=0, skipped=0))


async def test_import_rejects_non_json(env):
    screen = TransferScreen()
    ctx = env.ctx({"mode": "import"})
    await screen.on_enter(ctx)
    result = await screen.on_document(ctx, SimpleNamespace(file_name="x.txt", file_id="f"))
    assert result.notice == "⚠️ Serve il file .json esportato dal bot."
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/ui/test_misc_screens.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'password_bot.ui.screens.health'`.

- [ ] **Step 3: Implement**

`src/password_bot/ui/screens/health.py`:

```python
"""Password health: stale and reused passwords."""

from __future__ import annotations

from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import Ctx, Result, Screen, View, open_screen, refresh
from password_bot.ui.views import btn, footer, keyboard, label

MAX_BUTTONS = 30


class HealthScreen(Screen):
    name = "health"
    title = "Salute"

    async def render(self, ctx: Ctx) -> View:
        user = await ctx.container.users.get(ctx.chat_id)
        days = user.alert_days if user is not None else 180
        stale = await ctx.container.alerts.find_stale(chat_id=ctx.chat_id)
        clusters = await ctx.container.accounts.list_reuse_clusters(ctx.chat_id)
        lines = [
            "🩺 *Salute password*",
            "",
            escape_md(f"⏳ Vecchie (più di {days} giorni): {len(stale)}"),
            escape_md(f"♻️ Riusate: {len(clusters)} gruppi"),
        ]
        lines += [escape_md("• " + ", ".join(r.name for r in cluster)) for cluster in clusters]
        if not stale and not clusters:
            lines += ["", escape_md("Tutto in ordine. 🎉")]
        rows = [[btn(label(f"⏳ {r.name}"), self.name, "open", r.id)] for r in stale]
        rows += [
            [btn(label(f"♻️ {r.name}"), self.name, "open", r.id)]
            for cluster in clusters
            for r in cluster
        ]
        return View("\n".join(lines), keyboard(*rows[:MAX_BUTTONS], footer(ctx.back_label)))

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "open":
            return open_screen("account_detail", id=act.arg)
        return refresh()
```

`src/password_bot/ui/screens/settings.py`:

```python
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
        minutes = user.autolock_minutes if user else 15
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
                [btn("⏰ Autolock", self.name, "sub", "autolock"), btn("⏳ Soglia", self.name, "sub", "alert")],
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
                    ctx.chat_id, minutes=int(act.arg), reset_on_activity=True
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
```

`src/password_bot/ui/screens/transfer.py`:

```python
"""Encrypted vault export and import."""

from __future__ import annotations

import io
import time

from telegram import Document

from password_bot.i18n.it import MESSAGES
from password_bot.services.errors import InvalidExportFileError, InvalidPassphraseError
from password_bot.services.export_service import MergeStrategy
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import TEXT_NOT_ACCEPTED, Ctx, Result, Screen, View, back, refresh
from password_bot.ui.views import btn, keyboard


class TransferScreen(Screen):
    name = "transfer"
    title = "Export/Import"
    accepts_text = True
    accepts_document = True

    def _exporting(self, ctx: Ctx) -> bool:
        return ctx.args.get("mode") == "export"

    async def on_enter(self, ctx: Ctx) -> None:
        ctx.drop_flow(self.name)
        ctx.flow(self.name)["step"] = "passphrase" if self._exporting(ctx) else "file"

    async def render(self, ctx: Ctx) -> View:
        cancel = keyboard([btn("❌ Annulla", self.name, "cancel")])
        if self._exporting(ctx):
            return View(
                "📤 *Export*\n"
                + escape_md(
                    "Inviami la passphrase con cui cifrare il file (può essere diversa da quella "
                    "del vault). Cancellerò subito il messaggio."
                ),
                cancel,
            )
        if ctx.flow(self.name).get("step") == "passphrase":
            return View(
                "📥 *Import*\n" + escape_md("File ricevuto. Inviami la passphrase del file."),
                cancel,
            )
        return View("📥 *Import*\n" + escape_md("Inviami il file .json esportato dal bot."), cancel)

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "cancel":
            ctx.drop_flow(self.name)
            return back()
        return refresh()

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        if not text:
            return refresh()
        session = ctx.session
        if self._exporting(ctx):
            payload = await ctx.container.export.export(
                chat_id=ctx.chat_id, vault_key=session.aes_key, export_passphrase=text
            )
            await ctx.bot.send_document(
                chat_id=ctx.chat_id,
                document=io.BytesIO(payload.encode("utf-8")),
                filename=f"vault-{time.strftime('%Y%m%d-%H%M', time.gmtime())}.json",
                caption=MESSAGES["export_done"],
            )
            ctx.drop_flow(self.name)
            return back(notice="📤 Export inviato qui sotto.")
        flow = ctx.flow(self.name)
        if flow.get("step") != "passphrase" or flow.get("file") is None:
            return refresh(notice=TEXT_NOT_ACCEPTED)
        try:
            report = await ctx.container.export.import_payload(
                flow["file"].decode("utf-8"),
                chat_id=ctx.chat_id,
                vault_key=session.aes_key,
                hmac_key=session.hmac_key,
                export_passphrase=text,
                strategy=MergeStrategy.SKIP,
            )
        except InvalidPassphraseError:
            return refresh(notice=MESSAGES["import_wrong_passphrase"])
        except (InvalidExportFileError, UnicodeDecodeError):
            flow.pop("file", None)
            flow["step"] = "file"
            return refresh(notice=MESSAGES["import_invalid_file"])
        ctx.drop_flow(self.name)
        return back(
            notice=MESSAGES["import_done"].format(
                added=report.added, overwritten=report.overwritten, skipped=report.skipped
            )
        )

    async def on_document(self, ctx: Ctx, document: Document) -> Result:
        flow = ctx.flow(self.name)
        if self._exporting(ctx) or flow.get("step") != "file":
            return refresh(notice="⚠️ Non mi aspettavo un file qui.")
        if not (document.file_name or "").lower().endswith(".json"):
            return refresh(notice="⚠️ Serve il file .json esportato dal bot.")
        tg_file = await ctx.bot.get_file(document.file_id)
        flow["file"] = bytes(await tg_file.download_as_bytearray())
        flow["step"] = "passphrase"
        return refresh()
```

`src/password_bot/ui/registry.py` — add:

```python
from password_bot.ui.screens.health import HealthScreen
from password_bot.ui.screens.settings import SettingsScreen
from password_bot.ui.screens.transfer import TransferScreen
```

```python
        HealthScreen(),
        SettingsScreen(),
        TransferScreen(),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/ui -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
uv run ruff format src tests && uv run ruff check src tests
git add src tests
git commit -m "Add health, settings and export/import screens

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 15: Switch-over — wire the Navigator, remove the old handlers

**Files:**
- Create: `src/password_bot/ui/commands.py`, `src/password_bot/ui/legacy.py`, `tests/ui/test_wiring.py`
- Modify (full replacement below): `src/password_bot/bot.py`, `src/password_bot/handlers/common.py`, `src/password_bot/state/keys.py`
- Modify: `src/password_bot/state/fsm.py`, `src/password_bot/services/vault_service.py`, `src/password_bot/telegram_utils/callback_data.py` (docstring only), `CLAUDE.md`
- Modify tests: `tests/test_fsm_context.py`, `tests/test_state_keys.py`, `tests/services/test_vault_service.py`
- Delete: `src/password_bot/handlers/{account_edit,account_new,account_view,auth,categories,dispatcher,export,inline_cmd,nav,password_gen,settings}.py`, `src/password_bot/telegram_utils/keyboards.py`, `tests/handlers/{test_categories_integration,test_list_pagination,test_password_gen_integration,test_dispatcher_locked}.py`, `tests/{test_keyboards,test_main_menu_keyboard,test_password_gen_helpers}.py`

**Interfaces:**
- Consumes: `Navigator` (Task 5), `build_screens()` with all 21 screens (Tasks 6–14).
- Produces:
  - `ui.commands`: `ROOT_STATE = 0`, `open_command(screen, **args) -> handler`, `cmd_start` (returns `ROOT_STATE`), `cmd_get`, `cmd_back`, `cmd_lock`, `cmd_stop` (returns `ConversationHandler.END`), `on_callback`, `on_text`, `on_document`.
  - `ui.legacy`: `LEGACY_KEYS`, `clean_chat_data(data, screens) -> bool`, `cleanup_legacy_chat_data(application) -> None`.
  - `ChatDataKey` reduced to `SESSION`, `NAV_STACK`, `LEGACY_SESSION_EXTRAS`, `FLOW`, `LIVE_MESSAGE_ID`, `LIVE_TOKEN`, `RESUME`.

- [ ] **Step 1: Write the failing tests**

`tests/ui/test_wiring.py`:

```python
"""Handler tree, registry completeness, slash commands, legacy cleanup, error handler."""

from __future__ import annotations

import pickle
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from telegram import Update
from telegram.ext import CallbackQueryHandler

from password_bot.bot import build_application
from password_bot.config import AppConfig
from password_bot.handlers import common
from password_bot.state.fsm import Frame
from password_bot.state.keys import ChatDataKey
from password_bot.ui import commands
from password_bot.ui.legacy import clean_chat_data, cleanup_legacy_chat_data
from password_bot.ui.navigator import Navigator
from password_bot.ui.registry import build_screens
from tests.ui._helpers import FakeBot

NAV_STACK = ChatDataKey.NAV_STACK.value
LIVE = ChatDataKey.LIVE_MESSAGE_ID.value

ALL_SCREENS = {
    "home", "unlock", "help",
    "account_list", "search",
    "account_detail", "history", "account_delete",
    "account_edit", "field_edit",
    "generator", "password_change", "account_new",
    "categories", "category_pick", "category_form", "category_icon", "category_delete",
    "health", "settings", "transfer",
}


def test_registry_is_complete():
    screens = build_screens()
    assert set(screens) == ALL_SCREENS
    assert all(screen.title for screen in screens.values())


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYRING", str(tmp_path))
    config = AppConfig.load(base_dir=tmp_path)
    return build_application(config, token="0:dummy", dev_chat_id=0)


def test_every_callback_goes_through_the_navigator(app):
    root = next(h for h in app.handlers[0] if getattr(h, "name", None) == "root")
    callback_handlers = [h for h in root.states[0] if isinstance(h, CallbackQueryHandler)]
    assert [h.callback for h in callback_handlers] == [commands.on_callback]
    assert root.allow_reentry is True


def test_clean_chat_data_drops_old_ui_state():
    screens = build_screens()
    data = {
        "pending_input": {"field": "_search_query"},
        "pending_new_account": {"password": "plaintext!"},
        "pw_gen_draft": {},
        "pw_gen_return_to": "account_new",
        "pending_import_file": b"x",
        NAV_STACK: [Frame("menu", {})],
        LIVE: 3,
    }
    assert clean_chat_data(data, screens) is True
    assert data == {NAV_STACK: [], LIVE: 3}
    assert clean_chat_data(data, screens) is False


def test_cleanup_marks_changed_chats_for_persistence():
    app = SimpleNamespace(
        bot_data={"screens": build_screens()},
        chat_data={1: {"pending_input": {}}, 2: {}},
        mark_data_for_update_persistence=MagicMock(),
    )
    cleanup_legacy_chat_data(app)
    app.mark_data_for_update_persistence.assert_called_once_with(chat_ids=[1])


def test_legacy_list_page_payload_still_unpickles():
    from password_bot.telegram_utils.callback_data import ListPageData

    assert pickle.loads(pickle.dumps(ListPageData(page=2))) == ListPageData(page=2)


def _context(env, args):
    return SimpleNamespace(
        args=args,
        application=SimpleNamespace(
            bot_data={"container": env.container, "screens": build_screens()}, job_queue=None
        ),
        bot=FakeBot(),
        chat_data=env.chat_data,
    )


def _update():
    return SimpleNamespace(
        effective_chat=SimpleNamespace(id=1), effective_user=SimpleNamespace(full_name="Me")
    )


async def test_get_command_opens_detail_or_search(env, monkeypatch):
    acc = await env.add("Netflix")
    await env.add("GitHub")
    await env.add("GitLab")
    calls = []

    async def fake_command(self, name, args=None):
        calls.append((name, args))

    monkeypatch.setattr(Navigator, "command", fake_command)
    await commands.cmd_get(_update(), _context(env, ["netflix"]))
    await commands.cmd_get(_update(), _context(env, ["git"]))
    await commands.cmd_get(_update(), _context(env, []))
    assert calls == [
        ("account_detail", {"id": acc.id}),
        ("search", {"q": "git"}),
        ("search", None),
    ]


async def test_open_command_sends_screen_in_new_message(env):
    context = _context(env, [])
    await commands.open_command("settings")(_update(), context)
    assert "Impostazioni" in context.bot.sent[-1].text


async def test_start_returns_the_conversation_state(env):
    context = _context(env, [])
    assert await commands.cmd_start(_update(), context) == commands.ROOT_STATE
    assert "Menu principale" in context.bot.sent[-1].text


async def test_error_handler_edits_the_live_message():
    bot = FakeBot()
    app = SimpleNamespace(
        bot_data={"container": SimpleNamespace(dev_chat_id=None), "screens": build_screens()},
        job_queue=None,
    )
    context = SimpleNamespace(error=RuntimeError("boom"), application=app, bot=bot, chat_data={LIVE: 5})
    update = MagicMock(spec=Update)
    update.effective_chat = SimpleNamespace(id=1)
    await common.error_handler(update, context)
    assert bot.edits[-1].message_id == 5
    assert "Errore interno" in bot.edits[-1].text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/ui/test_wiring.py -q`
Expected: FAIL at collection — `ImportError: cannot import name 'commands' from 'password_bot.ui'`.

- [ ] **Step 3: Implement the new modules**

`src/password_bot/ui/commands.py`:

```python
"""PTB handler functions. Every entry point delegates to the Navigator."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from telegram import Update
from telegram.ext import ContextTypes, ConversationHandler

from password_bot.ui.navigator import HOME, Navigator
from password_bot.ui.screen import back

ROOT_STATE = 0

Handler = Callable[[Update, ContextTypes.DEFAULT_TYPE], Awaitable[Any]]


def _nav(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Navigator:
    return Navigator.from_update(update, context)


def open_command(screen: str, **args: Any) -> Handler:
    """Handler for a slash command that opens `screen` in a new live message."""

    async def handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await _nav(update, context).command(screen, args or None)

    handler.__name__ = f"cmd_{screen}"
    return handler


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await _nav(update, context).command(HOME)
    return ROOT_STATE


async def cmd_get(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    nav = _nav(update, context)
    query = " ".join(context.args or []).strip()
    if not query:
        await nav.command("search")
        return
    results = await nav.container.accounts.search(nav.chat_id, query)
    if len(results) == 1:
        await nav.command("account_detail", {"id": results[0][0].id})
    else:
        await nav.command("search", {"q": query})


async def cmd_back(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _nav(update, context).apply(back())


async def cmd_lock(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _nav(update, context).lock()


async def cmd_stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await _nav(update, context).stop()
    await update.effective_chat.send_message("👋 A presto. /start per ricominciare.")
    return ConversationHandler.END


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _nav(update, context).on_callback(update)


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _nav(update, context).on_text(update)


async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _nav(update, context).on_document(update)
```

`src/password_bot/ui/legacy.py`:

```python
"""One-time cleanup of chat_data written by the old (pre-Navigator) UI."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from password_bot.state.keys import ChatDataKey

# Old keys (some held plaintext drafts, e.g. the new-account password).
LEGACY_KEYS = (
    "pending_input",
    "pending_new_account",
    "pending_import_file",
    "pw_gen_draft",
    "pw_gen_return_to",
    "reuse_detector",
    "autolock_job_name",
)


def clean_chat_data(data: dict[str, Any], screens: Mapping[str, Any]) -> bool:
    """Drop old-UI keys and stacks with unknown screens. Returns True if anything changed."""
    changed = False
    for key in LEGACY_KEYS:
        if key in data:
            del data[key]
            changed = True
    stack = data.get(ChatDataKey.NAV_STACK.value) or []
    if any(getattr(frame, "name", None) not in screens for frame in stack):
        data[ChatDataKey.NAV_STACK.value] = []
        changed = True
    return changed


def cleanup_legacy_chat_data(application: Any) -> None:
    screens = application.bot_data["screens"]
    changed = [
        chat_id
        for chat_id, data in application.chat_data.items()
        if clean_chat_data(data, screens)
    ]
    if changed:
        application.mark_data_for_update_persistence(chat_ids=changed)
```

`src/password_bot/bot.py` — full replacement (the daily scan and `_users_iter` are unchanged):

```python
"""Build the PTB Application and register handlers."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import time as dtime

import aiosqlite
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ConversationHandler,
    MessageHandler,
    PicklePersistence,
    filters,
)

from password_bot.config import AppConfig
from password_bot.container import Container
from password_bot.handlers import common
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.state.keys import ChatDataKey
from password_bot.ui import commands
from password_bot.ui.legacy import cleanup_legacy_chat_data
from password_bot.ui.registry import build_screens

log = logging.getLogger(__name__)

_NOT_PERSISTED = {
    ChatDataKey.SESSION.value,
    ChatDataKey.LEGACY_SESSION_EXTRAS.value,
    ChatDataKey.FLOW.value,
}


class _SessionStrippingPersistence(PicklePersistence):
    """Never write the live session or in-progress flow drafts to disk."""

    async def update_chat_data(self, chat_id: int, data: dict) -> None:  # type: ignore[override]
        clean = {k: v for k, v in data.items() if k not in _NOT_PERSISTED}
        await super().update_chat_data(chat_id, clean)


async def _daily_stale_scan(context) -> None:
    from password_bot.i18n.it import MESSAGES

    container: Container = context.application.bot_data["container"]
    async with _users_iter(container) as chat_ids:
        for chat_id in chat_ids:
            user = await container.users.get(chat_id)
            # Legacy (v1) users never unlocked since the migration: their
            # password_changed_at is 0, so every account would look stale.
            if user is None or user.crypto_version == 1:
                continue
            stale = await container.alerts.find_stale(chat_id=chat_id)
            if not stale:
                continue
            try:
                await context.bot.send_message(
                    chat_id,
                    MESSAGES["stale_alert_template"].format(count=len(stale), days=user.alert_days),
                )
            except TelegramError as e:
                # e.g. Forbidden: user blocked the bot or deactivated the account.
                log.warning("Stale alert not delivered to chat_id=%s: %s", chat_id, e)


@asynccontextmanager
async def _users_iter(container: Container):
    async with aiosqlite.connect(container.config.db_path) as conn:
        cur = await conn.execute("SELECT chat_id FROM users")
        yield [r[0] for r in await cur.fetchall()]


def build_application(config: AppConfig, *, token: str, dev_chat_id: int | None) -> Application:
    persistence = _SessionStrippingPersistence(filepath=str(config.pkl_path))

    async def _post_init(app: Application) -> None:
        await migrate_to_latest(config.db_path)
        app.bot_data["container"] = Container.build(config, dev_chat_id=dev_chat_id)
        app.bot_data["screens"] = build_screens()
        cleanup_legacy_chat_data(app)
        log.info("Migrations applied, container and screens built. DB: %s", config.db_path)

    application = (
        ApplicationBuilder()
        .token(token)
        .persistence(persistence)
        .arbitrary_callback_data(True)
        .post_init(_post_init)
        .build()
    )

    conv = ConversationHandler(
        entry_points=[CommandHandler("start", commands.cmd_start)],
        states={
            commands.ROOT_STATE: [
                CommandHandler("menu", commands.cmd_start),
                CommandHandler("help", commands.open_command("help")),
                CommandHandler("add", commands.open_command("account_new")),
                CommandHandler("list", commands.open_command("account_list")),
                CommandHandler(["get", "copy"], commands.cmd_get),
                CommandHandler("categories", commands.open_command("categories")),
                CommandHandler(["list_stale", "list_reused"], commands.open_command("health")),
                CommandHandler("settings", commands.open_command("settings")),
                CommandHandler("export", commands.open_command("transfer", mode="export")),
                CommandHandler("import", commands.open_command("transfer", mode="import")),
                CommandHandler(["back", "cancel"], commands.cmd_back),
                CommandHandler("lock", commands.cmd_lock),
                CallbackQueryHandler(commands.on_callback),
                MessageHandler(filters.Document.ALL, commands.on_document),
                MessageHandler(filters.TEXT & ~filters.COMMAND, commands.on_text),
            ],
        },
        fallbacks=[CommandHandler("stop", commands.cmd_stop)],
        # /start must work mid-conversation too, e.g. right after an autolock.
        allow_reentry=True,
        name="root",
        persistent=True,
        per_chat=True,
        per_user=False,
        per_message=False,
    )
    application.add_handler(conv)
    application.add_error_handler(common.error_handler)

    if application.job_queue is not None:
        application.job_queue.run_daily(
            _daily_stale_scan,
            time=dtime(hour=9, minute=0),
            name="daily_stale_scan",
        )

    return application
```

`src/password_bot/handlers/common.py` — full replacement:

```python
"""Global error handler."""

from __future__ import annotations

import contextlib
import html
import logging
import traceback

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.ui.navigator import Navigator

log = logging.getLogger(__name__)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("Unhandled exception in handler", exc_info=context.error)
    container = context.application.bot_data.get("container")
    dev_id = getattr(container, "dev_chat_id", None)
    if dev_id is not None:
        tb = "".join(
            traceback.format_exception(
                type(context.error), context.error, context.error.__traceback__
            )
        )
        try:
            await context.bot.send_message(
                chat_id=dev_id, text=f"<pre>{html.escape(tb[:3500])}</pre>", parse_mode=ParseMode.HTML
            )
        except Exception:
            log.exception("Failed to DM dev about prior error")
    if (
        isinstance(update, Update)
        and update.effective_chat is not None
        and context.chat_data is not None
        and "screens" in context.application.bot_data
    ):
        with contextlib.suppress(Exception):
            await Navigator.from_context(context, update.effective_chat.id).show_error()
```

`src/password_bot/state/keys.py` — full replacement:

```python
"""Typed keys for context.chat_data. Never use raw strings."""

from __future__ import annotations

from enum import StrEnum


class ChatDataKey(StrEnum):
    SESSION = "session"
    NAV_STACK = "nav_stack"
    LEGACY_SESSION_EXTRAS = "legacy_session_extras"
    FLOW = "flow"  # in-progress flow drafts (may hold secrets); never persisted
    LIVE_MESSAGE_ID = "live_message_id"  # the single bot message that carries buttons
    LIVE_TOKEN = "live_token"  # bumped on every render; guards auto-close jobs
    RESUME = "resume"  # Frame to reopen after unlocking
```

`src/password_bot/state/fsm.py`:
- delete the methods `get_pending_input`, `set_pending_input`, `clear_pending_input`;
- in `lock()` replace the tuple of keys with:

```python
        for key in (ChatDataKey.FLOW, ChatDataKey.RESUME):
```

`src/password_bot/services/vault_service.py`: delete the `duplicate` method.

`src/password_bot/telegram_utils/callback_data.py`: replace the module docstring with:

```python
"""Legacy callback payload of the old paginated /list.

No longer produced. Kept only because PTB's pickled callback-data cache in an
existing DB.pkl may still reference `ListPageData`; removing it would make
the bot crash while loading persistence.
"""
```

Delete the old handlers and keyboards:

```bash
git rm src/password_bot/handlers/account_edit.py src/password_bot/handlers/account_new.py \
  src/password_bot/handlers/account_view.py src/password_bot/handlers/auth.py \
  src/password_bot/handlers/categories.py src/password_bot/handlers/dispatcher.py \
  src/password_bot/handlers/export.py src/password_bot/handlers/inline_cmd.py \
  src/password_bot/handlers/nav.py src/password_bot/handlers/password_gen.py \
  src/password_bot/handlers/settings.py src/password_bot/telegram_utils/keyboards.py \
  tests/handlers/test_categories_integration.py tests/handlers/test_list_pagination.py \
  tests/handlers/test_password_gen_integration.py tests/handlers/test_dispatcher_locked.py \
  tests/test_keyboards.py tests/test_main_menu_keyboard.py tests/test_password_gen_helpers.py
```

- [ ] **Step 4: Update the remaining old tests**

`tests/test_state_keys.py` — replace `test_required_keys_exist`:

```python
def test_required_keys_exist():
    expected = {
        "SESSION",
        "NAV_STACK",
        "LEGACY_SESSION_EXTRAS",
        "FLOW",
        "LIVE_MESSAGE_ID",
        "LIVE_TOKEN",
        "RESUME",
    }
    assert expected == {k.name for k in ChatDataKey}
```

`tests/test_fsm_context.py` — delete `test_pending_input_set_and_clear` and replace `test_lock_clears_session_and_all_in_progress_state` with:

```python
def test_lock_clears_session_and_all_in_progress_state():
    from password_bot.state.keys import ChatDataKey

    data = {
        ChatDataKey.SESSION.value: object(),
        ChatDataKey.LEGACY_SESSION_EXTRAS.value: object(),
        ChatDataKey.FLOW.value: {"account_new": {"password": "x"}},
        ChatDataKey.RESUME.value: Screen(name="home", data={}),
    }
    fsm = FsmContext(data)
    fsm.push(Screen(name="account_detail", data={}))
    fsm.lock()
    assert fsm.get_session() is None
    assert data == {ChatDataKey.NAV_STACK.value: []}
```

`tests/services/test_vault_service.py` — delete `test_duplicate_account`.

- [ ] **Step 5: Check nothing still references removed code**

Run: `git grep -nE "handlers\.(account_|auth|categories|dispatcher|export|inline_cmd|nav|password_gen|settings)|telegram_utils\.keyboards|pending_input|PENDING_|PW_GEN_|duplicate\(" -- src tests ':!src/password_bot/ui/legacy.py' ':!tests/ui/test_wiring.py'`
Expected: no output (`ui/legacy.py` and `test_wiring.py` name the old keys on purpose and are excluded).

- [ ] **Step 6: Run the whole suite and lint**

Run: `uv run pytest -q && uv run ruff format src tests && uv run ruff check src tests`
Expected: all PASS, `All checks passed!`.

- [ ] **Step 7: Update `CLAUDE.md`**

1. In **Persistence layout**, replace the `DB.pkl` bullet with:

```markdown
- `DB.pkl`     — `PicklePersistence` for python-telegram-bot. Holds `chat_data` (navigation stack, live message id, resume target) and PTB's callback-data cache. `SESSION`, `LEGACY_SESSION_EXTRAS` and `FLOW` (in-progress drafts, may contain secrets) are stripped by `_SessionStrippingPersistence`. Old pickles reference `state.fsm.Screen` and `telegram_utils.callback_data.ListPageData`: both names must stay importable.
```

2. In the package tree, replace the `handlers/`, `state/` and `telegram_utils/` blocks with:

```text
├── handlers/
│   └── common.py                ← error_handler only (DMs the developer, turns the live message into "⚠️ Errore interno")
│
├── ui/                          ← single-live-message UI (see "UI: Navigator + Screens")
│   ├── navigator.py             ← Navigator: stack, live message edit/send, routing, lock, auto-close, reveal
│   ├── screen.py                ← View, Ctx, results (Go/Reveal/Lock) + helpers, Screen base class
│   ├── callbacks.py             ← Act(screen, action, arg) payload + NAV pseudo-screen
│   ├── views.py                 ← btn/nav_btn/copy_btn/url_btn/footer/keyboard, styles, normalize_url, md_date
│   ├── jobs.py                  ← schedule_autolock / autolock_job
│   ├── commands.py              ← PTB handler functions (slash commands, callbacks, text, documents)
│   ├── registry.py              ← build_screens(): every screen by name
│   ├── legacy.py                ← post_init cleanup of old-UI chat_data
│   └── screens/                 ← one module per screen group (home, unlock, help, account_*, search, history,
│                                   generator, password_change, categories, health, settings, transfer, _shared)
│
├── state/
│   ├── keys.py                  ← ChatDataKey (SESSION, NAV_STACK, LEGACY_SESSION_EXTRAS, FLOW, LIVE_MESSAGE_ID, LIVE_TOKEN, RESUME)
│   └── fsm.py                   ← FsmContext + Frame (alias Screen for old pickles): stack, resume, session, lock()
│
└── telegram_utils/
    ├── md.py                    ← escape_md, code_inline (MarkdownV2)
    ├── callback_data.py         ← legacy ListPageData, kept only for unpickling old DB.pkl
    └── delete_message.py        ← schedule_delete for self-destructing secret messages
```

3. Delete the sections **Inline-button UX**, **Paginated `/list` + arbitrary callback_data**, **Conversation state machine** and **Adding a new handler**, and add in their place:

```markdown
### UI: Navigator + Screens

- **One live message.** The bot keeps a single message with buttons (`LIVE_MESSAGE_ID`) and edits it for every screen. Slash commands delete it and send a fresh one at the bottom. User text/documents are deleted after being read. Revealed secrets are separate messages deleted after 30 s.
- **Screens** (`ui/screens/*`) subclass `Screen`: `render(ctx) -> View`, `on_action(ctx, act)`, optional `on_text` / `on_document` / `on_enter` / `render_expired`. They never send messages; they return `Go` (stack moves + notice/toast), `Reveal` or `Lock`. Helpers: `open_screen`, `replace`, `back`, `refresh`, `home`, `pop_to`, `finish`.
- **Stack** frames are `Frame(name, data)`; `data` holds only ids/pages/flags/search queries. `🔙` pops (label = title of the screen below), `🏠` resets to `home`. Flows end with `finish(...)`/`pop_to(...)` so back never re-enters them.
- **Callbacks** are `Act(screen, action, arg)` via `arbitrary_callback_data`. They are pickled into `DB.pkl`: only ids, indices, names — never usernames/passwords/URLs/notes. Values picked from lists live in `FLOW` and are referenced by index. Anything that isn't an `Act` on the live message is "Bottone scaduto" → Home.
- **Flows** keep drafts in `ctx.flow(key)` (`ChatDataKey.FLOW`), never persisted, cleared by `FsmContext.lock()`. The generator returns a password by writing `flow[args["flow"]]["password"]` and `["step"] = args["next_step"]`.
- **Locking.** With no session, any screen with `requires_session` is replaced by `unlock` and the target is parked in `RESUME`; after unlock the Navigator reopens it. Autolock edits the live message into the unlock screen.
- **Auto-close.** A `View(expire_after=60)` (account detail) schedules `expire:<chat_id>`; if the live message still shows that render (`LIVE_TOKEN`), it becomes `render_expired()` (copy buttons disappear).
- **Styles.** `views.PRIMARY` main action, `SUCCESS` confirmations, `DANGER` destructive.

### Adding a new screen

1. Create `ui/screens/<name>.py` with a `Screen` subclass (`name`, `title`, `render`, `on_action`…).
2. Add it to the list in `ui/registry.py::build_screens`.
3. Open it from another screen with `open_screen("<name>", ...)` or from a slash command with `commands.open_command("<name>")` in `bot.py`.
4. Test it with the `env` fixture from `tests/ui/conftest.py` (real services on a temp DB) and helpers from `tests/ui/_helpers.py`.
```

4. In the **Password generator** / **User-saved generator defaults** sections, replace references to `handlers/password_gen.py` with `ui/screens/generator.py`.

- [ ] **Step 8: Commit**

```bash
git add -A src tests CLAUDE.md
git commit -m "Switch the bot to the Navigator UI and remove the old handlers

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 16: Security sweep and final verification

**Files:**
- Create: `tests/ui/test_security_sweep.py`

**Interfaces:**
- Consumes: every screen via `build_screens()`, the `env` fixture.

- [ ] **Step 1: Write the sweep test**

`tests/ui/test_security_sweep.py`:

```python
"""Every screen: no secret in callback payloads; hostile names always escaped."""

from __future__ import annotations

from password_bot.ui.callbacks import Act
from password_bot.ui.registry import build_screens
from password_bot.ui.screen import View
from tests.ui._helpers import buttons

SECRETS = {
    "username": "user-SENTINEL-1",
    "password": "pw-SENTINEL-2",
    "url": "sentinel3.example.com",
    "note": "note-SENTINEL-4",
}
HOSTILE = "a_b*c[d](e)!"


async def _render_everything(env) -> list[tuple[str, View]]:
    cat = await env.category(HOSTILE, icon="💼")
    acc = await env.add(
        HOSTILE,
        username=SECRETS["username"],
        password=SECRETS["password"],
        url=SECRETS["url"],
        note=SECRETS["note"],
        category_id=cat.id,
    )
    await env.add("twin", username=SECRETS["username"], password=SECRETS["password"])
    s = env.session
    await env.container.vault.update_password(
        acc.id, SECRETS["password"] + "-new", aes_key=s.aes_key, hmac_key=s.hmac_key
    )
    screens = build_screens()
    cases = [
        ("home", {}),
        ("help", {}),
        ("account_list", {}),
        ("account_list", {"category": cat.id}),
        ("account_list", {"category": "none"}),
        ("search", {"q": "a_b"}),
        ("account_detail", {"id": acc.id}),
        ("history", {"id": acc.id}),
        ("account_delete", {"id": acc.id}),
        ("account_edit", {"id": acc.id}),
        ("field_edit", {"id": acc.id, "field": "username"}),
        ("field_edit", {"id": acc.id, "field": "url"}),
        ("password_change", {"id": acc.id}),
        ("generator", {"flow": "password_change", "next_step": "confirm"}),
        ("account_new", {}),
        ("categories", {}),
        ("category_pick", {"account_id": acc.id}),
        ("category_form", {"mode": "rename", "cat_id": cat.id}),
        ("category_icon", {"cat_id": cat.id}),
        ("category_delete", {"cat_id": cat.id}),
        ("health", {}),
        ("settings", {}),
        ("transfer", {"mode": "export"}),
    ]
    views: list[tuple[str, View]] = []
    for name, args in cases:
        ctx = env.ctx(args)
        await screens[name].on_enter(ctx)
        views.append((name, await screens[name].render(ctx)))

    change = env.ctx({"id": acc.id})
    change.flow("password_change").update(step="confirm", password=SECRETS["password"])
    views.append(("password_change/confirm", await screens["password_change"].render(change)))

    new = env.ctx({})
    await screens["account_new"].on_enter(new)
    flow = new.flow("account_new")
    flow.update(step="username", name=HOSTILE)
    views.append(("account_new/username", await screens["account_new"].render(new)))
    flow.update(
        step="summary",
        username=SECRETS["username"],
        password=SECRETS["password"],
        url="https://" + SECRETS["url"],
        note=SECRETS["note"],
        category_id=cat.id,
    )
    views.append(("account_new/summary", await screens["account_new"].render(new)))
    return views


async def test_no_secret_in_any_callback_payload(env):
    for name, view in await _render_everything(env):
        for b in buttons(view):
            if isinstance(b.callback_data, Act):
                payload = repr(b.callback_data)
                for secret in SECRETS.values():
                    assert secret not in payload, (name, b.text)


async def test_hostile_name_is_always_escaped(env):
    for name, view in await _render_everything(env):
        assert HOSTILE not in view.text, name
```

- [ ] **Step 2: Run it**

Run: `uv run pytest tests/ui/test_security_sweep.py -v`
Expected: PASS. If it fails, the message names the screen: fix that screen (escape the text with `escape_md`, or replace the value in the `Act` with an index into `ctx.flow(...)`), not the test.

- [ ] **Step 3: Full verification**

Run each and check the output:

```bash
uv run pytest -q
uv run pytest --cov=src/password_bot -q | tail -5
uv run ruff check src tests
uv run ruff format --check src tests
```

Expected: all tests pass; total coverage ≥ 60% (the CI gate); `All checks passed!`; `… files already formatted`.

- [ ] **Step 4: Commit**

```bash
git add tests/ui/test_security_sweep.py
git commit -m "Add security sweep over every screen

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 5: Hand the manual check to the human partner**

The Bot API cannot be exercised from tests. Report back with this checklist for a run against a test bot token (`KEYRING=./keys uv run -m password_bot`), using a **copy** of the production `accounts.db` and `DB.pkl`:

1. Bot starts with the old `DB.pkl` (no unpickling error); an old message's buttons answer "Bottone scaduto" and open Home.
2. `/start` → unlock → Home in one message; navigating edits that message; `/list` moves it to the bottom.
3. Account detail: copy password/username buttons copy to the clipboard; colours visible (primary/red); the "aggiornata il" date renders; after 60 s the detail shows "chiuso".
4. Modifica → Password → Genera → Usa → Sostituisci → back on the detail with "✅ Password aggiornata".
5. ➕ Nuovo: username suggestions appear; summary → Salva opens the new account; 🔙 from it does not re-enter the wizard.
6. Categories: create with icon, assign from detail, open category, delete (accounts kept).
7. `/lock` then tap an old button of the live message → unlock → returns to that screen.
```
