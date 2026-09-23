# Password Bot — Navigation Redesign

**Date:** 2026-09-23
**Branch:** `feature/navigation-redesign` (based on `fix/session-and-alerts`)
**Author:** Claudio (with Claude)
**Status:** Draft — awaiting review

UI strings are Italian (the bot's language); everything else follows the English convention of the v2 spec.

## 1. Goals

### Intent

The user must never get lost in the bot. Every message the bot shows belongs to a conversation and carries an inline keyboard offering *back*, *menu*, or the most useful next action for that exact state. The account detail becomes cleaner and action-oriented, password changes can use the generator, account creation suggests known usernames, and categories become a real feature.

### Requested changes

| # | Change |
|---|--------|
| R1 | Every bot message belongs to a conversation, with a contextual inline keyboard (back / menu / smart action). |
| R2 | Restructure the account detail and its keyboard. |
| R3 | Changing a password can use the password generator, not only manual input. |
| R4 | When creating an account, suggest already-used usernames/emails as inline buttons. |
| R5 | Complete the categories feature (assign, show, browse). |
| R6 | Upgrade python-telegram-bot and adopt useful new Bot API features. |

### Decisions taken during brainstorming

- **Single live message.** Every screen edits one bot message in place; user-typed text is deleted after being read. Revealed secrets are separate self-destructing messages.
- **Architecture: screen router** (`Navigator` + `Screen` units), not nested `ConversationHandler`s nor incremental patching.
- **Account detail: actions up front + "Modifica…" submenu.**
- **Copy uses Telegram's native `CopyTextButton`**, with the detail auto-closing after 60 s.
- **Account creation: 3 required steps + summary** (name → username → password → summary with optional URL/note/category).
- **Home menu reduced to 8 buttons**; delete confirmation by red button (no more typing `ELIMINA`).
- **Vault creation asks for the passphrase twice.**
- **Categories get an icon** (emoji) stored in the existing, so far unused, `categories.color` column.
- **PTB 22.5 → 22.8**, adopting button `style` colours and the `date_time` message entity.

### Out of scope (noted, not implemented)

- Renewing the autolock on activity (`users.autolock_reset_on_activity` exists but is unused).
- Passphrase change UI (`AuthService.change_passphrase` exists, no screen uses it).
- Multiple tags per account.
- Restoring a password from history.
- Bot API 10.1–10.3 features (disabled buttons, `force_reply` on inline keyboards, rich messages) — PTB 22.8 supports Bot API up to 10.0.

## 2. Architecture

### New package `password_bot/ui/`

```
src/password_bot/ui/
├── navigator.py        ← Navigator: stack, live message, routing, lock handling
├── screen.py           ← Screen base class, View, NavResult
├── callbacks.py        ← Act dataclass (typed callback payload)
├── views.py            ← keyboard helpers: button(), copy_button(), url_button(), footer()
└── screens/
    ├── home.py
    ├── unlock.py           ← unlock + vault setup (passphrase twice) + legacy migration
    ├── search.py
    ├── account_list.py     ← paginated list, reused by category screen
    ├── account_detail.py
    ├── account_edit.py     ← "Modifica…" submenu + single-field text edit + category picker
    ├── password_change.py  ← choose generate/manual → confirm (shared with account_new)
    ├── history.py
    ├── account_new.py      ← 3 steps + summary
    ├── generator.py        ← reusable generator, returns to caller
    ├── health.py           ← stale + reused
    ├── categories.py       ← category list, category screen, create/rename/icon/delete
    ├── settings.py
    ├── transfer.py         ← export / import
    └── help.py
```

### `Screen`

Each screen is a small class identified by a stable `name`:

- `async render(ctx) -> View` — pure-ish: reads services and the screen's args, returns `View(text, keyboard, parse_mode)`. Never sends messages.
- `async on_action(ctx, act: Act) -> NavResult` — handles its own buttons.
- `async on_text(ctx, text: str) -> NavResult` — optional; only for screens awaiting input. The screen declares `accepts_text` and `sensitive_input` (passphrase, password).

`NavResult` is one of: `Open(screen, args)`, `Replace(screen, args)`, `Back(notice=None)`, `Home()`, `Refresh(notice=None)`, `PopTo(screen, then=Open|Refresh, notice=None)`, `Reveal(text, seconds=30)`, `Toast(text)`. A `notice` is a one-line banner (`✅ Aggiornato`, `⚠️ Nome obbligatorio`) prepended to the next rendered view.

`ctx` bundles `update`, `context`, `container`, `session`, `chat_id`, `flow` (the non-persisted draft, see below) and the current screen args.

### `Navigator`

The only component that talks to Telegram for UI purposes.

- **Stack**: reuses `FsmContext` with entries `(screen_name, args)`. Args hold only ids, page numbers, flags and search queries (account names are already plaintext in the DB) — never usernames, passwords, URLs or notes. Base of the stack is always `home`. Unknown screen names (e.g. left over from the old UI) are treated as `home`.
- **Live message**: `chat_data[LIVE_MESSAGE_ID]`. Every render **edits** it. If the edit fails because the message is gone or not editable, send a new message and best-effort delete the old one. `BadRequest: message is not modified` is ignored.
- **Commands** (`/list`, `/get X`, …): delete the current live message and send a new one at the bottom, so the active screen is always visible. There is always at most one message with buttons.
- **Text input**: read, delete the user's message (always, not only for sensitive input), dispatch to `on_text` of the top screen. If the top screen does not accept text, re-render it with notice `⚠️ Usa i bottoni qui sotto.`
- **Callbacks**: one `CallbackQueryHandler` for `Act`. It always answers the callback query (with the toast text if any).
- **Reveal**: sends a separate message with the secret in `code` format, schedules deletion after `seconds`, no keyboard.
- **Lock**: before dispatching anything, if there is no session, the navigator remembers the requested target (screen + args, not the action) and renders `unlock`. After a successful unlock it opens the remembered target (or `home`).
- **Autolock job**: calls `FsmContext.lock()` and edits the live message to `🔒 Sessione bloccata` with `[🔓 Sblocca]`.

### Callback payloads

```python
@dataclass(frozen=True, slots=True)
class Act:
    screen: str
    action: str
    arg: str | int | None = None
```

Sent through `arbitrary_callback_data`. **Rule: `Act` carries only ids, indices and enum-like action names — never a username, password, URL or note.** The PTB callback-data cache is persisted to `DB.pkl`. Values chosen by button (e.g. username suggestions) are stored in the flow draft and referenced by index. `CopyTextButton` payloads are not callback data and are not cached.

Stale buttons (`InvalidCallbackData`, or legacy string payloads like `view:…`, `menu:…`, `nav:…`) are caught by a fallback handler: answer `Bottone scaduto`, open `home` in a new live message.

### Flow drafts

In-progress data (new-account draft, pending password, generator draft, username suggestion list, pending import file) lives under a single `ChatDataKey.FLOW` dict, keyed by flow name. `FLOW` is **stripped from persistence** and cleared by `FsmContext.lock()`. This replaces `PENDING_NEW_ACCOUNT`, `PENDING_INPUT`, `PW_GEN_DRAFT`, `PW_GEN_RETURN_TO`, `PENDING_IMPORT_FILE`.

(Today `PENDING_NEW_ACCOUNT` is not stripped, so a new-account draft — plaintext password included — can be written to `DB.pkl`. This design removes that.)

### PTB wiring (`bot.py`)

Root `ConversationHandler` kept (single state, `allow_reentry=True`, `/stop` fallback, persistent). Inside:

- `CommandHandler`s → `navigator.open(...)` / `navigator.command(...)`.
- `CallbackQueryHandler` for `Act`.
- Fallback `CallbackQueryHandler` for invalid/legacy payloads.
- `MessageHandler(TEXT & ~COMMAND)` → `navigator.on_text`.
- `MessageHandler(Document.ALL)` → `transfer` screen (import).

Removed: `handlers/dispatcher.py`, `nav.py`, `account_view.py`, `account_edit.py`, `account_new.py`, `inline_cmd.py`, `categories.py`, `password_gen.py`, `settings.py`. `common.py` keeps only command → navigator glue and `error_handler`. `auth.py` logic moves into `ui/screens/unlock.py`, `export.py` into `ui/screens/transfer.py`.

## 3. Navigation rules and screen map

### General rules

- Every screen's last row: `[🔙 <target>]` `[🏠 Menu]`. The back label names its destination (`🔙 Lista`, `🔙 Dettaglio`). Home has no footer.
- Above it, the **primary action** styled `primary`; confirmations `success`; destructive actions `danger`.
- Button actions report outcomes as a **toast** (callback answer). Text inputs report as a **notice** line on the next view. No standalone confirmation messages.
- **Multi-step flows** (creation, field edit, password change) `Replace`/`PopTo` their own frames at the end, so `🔙` from the result never re-enters the flow. `❌ Annulla` pops back to where the flow started.

### Screen map

| Screen | Primary action | After / Back |
|---|---|---|
| `unlock` (unlock or vault setup) | type passphrase | remembered target or Home |
| `home` | ➕ Nuovo · 🔍 Cerca | — |
| `search` | type a name | 1 result → Detail (replace search); many → result list |
| `account_list` | open account | 🔙 Home |
| `account_detail` | 📋 Copia password | 🔙 wherever it was opened from |
| `account_edit` (submenu / field) | type or pick value | → Detail with `✅ Aggiornato` |
| `password_change` | 🎲 Genera · ⌨️ Scrivila io | → Detail with `✅ Password aggiornata` |
| `history` | 👁 reveal an old password | 🔙 Modifica |
| delete confirm | 🗑 Elimina (danger) | → previous list, toast |
| `account_new` (3 steps + summary) | 💾 Salva (success) | → Detail of new account (flow frames replaced) |
| `generator` | ✅ Usa (success) | returns to caller |
| `health` | open account | Vecchie + Riusate sections; each entry opens Detail |
| `categories` / category | open account · rename · icon · delete | 🔙 Categorie |
| `settings` | autolock, soglia, generatore, export, import | 🔙 Home |
| `help` | — | 🔙 Home |

### Home (8 buttons, 2 columns)

```
[➕ Nuovo]      [🔍 Cerca]
[📚 Lista]      [🏷 Categorie]
[🩺 Salute]     [⚙️ Impostazioni]
[🔒 Blocca]     [❓ Help]
```

`📋 Copia` is removed (native copy in the detail makes it redundant). Export/Import move under Impostazioni. Home text no longer lists all commands (Help does).

### Commands

`/start`, `/menu`, `/add`, `/list`, `/get NOME`, `/categories`, `/settings`, `/export`, `/import`, `/help`, `/lock`, `/stop` open the matching screen. `/list_stale` and `/list_reused` open `health`. `/copy NOME` is an alias of `/get`. `/back` = 🔙, `/cancel` = ❌. Removed: `/skip`, `/cat_add`, `/cat_del`.

### Unlock / vault setup

- Existing user: `Inserisci la passphrase per sbloccare il vault.` Sensitive input. Wrong passphrase → notice `⚠️ Passphrase non corretta.`, stays on screen. Legacy v1 users go through the existing lazy migration with a `Sto migrando il vault…` intermediate render.
- New user: passphrase asked **twice**; mismatch → notice `⚠️ Le passphrase non coincidono.` and restart from the first entry. The first entry is kept only in `FLOW` until the second arrives.

## 4. Account detail, edit, password change

### Detail text

```
🔐 GitHub
🏷 💼 Lavoro                     (only if categorised)
👤 cioscos@mail.com              (or —)
🔑 ••••••••
🌐 github.com                    (or —)
📝 ||2FA: app Authy||            (spoiler; only if present)
♻️ Stessa password di: GitLab    (only if reused)
📅 Password aggiornata il 12/05/2026   (date_time entity, fallback plain date)
```

### Detail keyboard

```
[📋 Copia password] (CopyTextButton, primary)   [👁 Mostra]
[👤 Copia username] (CopyTextButton)            [🌐 Apri URL] (url button)
[✏️ Modifica…]                                  [🗑 Elimina] (danger)
[🔙 <origin>]                                   [🏠 Menu]
```

- `Copia username` / `Apri URL` only when the field is set. URL without scheme gets `https://`; unparsable URL → no button.
- Values longer than 256 chars (CopyTextButton limit): copy button replaced by a reveal button.
- `👁 Mostra` → `Reveal(password, 30)`.

### Auto-close

Each detail render stores a render token in `chat_data`. A job 60 s later edits the live message to `🔐 GitHub — chiuso` with `[🔓 Riapri]` `[🏠 Menu]` **only if** the live message still shows that token. Locking also closes it.

### "Modifica…" submenu

```
[🔑 Password]   [👤 Username]
[📛 Nome]       [🌐 URL]
[📝 Note]       [🏷 Categoria]
[🕘 Storico password (3)]        (only if history non-empty)
[🔙 Dettaglio]  [🏠 Menu]
```

### Single-field text edit (name, username, URL, note)

- Text: `Nuovo username per GitHub?` + `Attuale: <code>` when set.
- Keyboard: `[🗑 Svuota]` (optional fields only), `[❌ Annulla]`. Username edit also shows the suggestions (§5).
- Validation: name non-empty; URL normalised (`https://` added), rejected with notice if unparsable.
- On success: `PopTo(account_detail)` with notice `✅ Aggiornato`.

### Category picker

Buttons for each category (`<icon> <name>`), `[— Nessuna]`, `[➕ Nuova]` (creates and assigns immediately, then returns), `[❌ Annulla]`.

### Password change (shared component with account creation)

1. `Nuova password per GitHub` — `[🎲 Genera]` `[⌨️ Scrivila io]` `[❌ Annulla]`.
2. Generate → `generator` screen (options, 🎲, 🔄 Rigenera) → `[✅ Usa]`. Manual → sensitive text input.
3. Confirm: `Sostituire la password di GitHub? La vecchia finisce nello storico.` + strength line + reuse warning. `[✅ Sostituisci]` (success) `[🔄 Cambia]` (back to 1) `[❌ Annulla]`.
4. `VaultService.update_password` → `PopTo(account_detail)` with notice `✅ Password aggiornata`.

The pending new password lives in `FLOW` only.

### Generator

Existing option keyboard (length, classes, ambiguous, duplicates, save defaults, reset) becomes a screen. The generated password is shown in the live message (`code`) until accepted/cancelled; the next render removes it. `✅ Usa` returns the password to the caller flow through `FLOW`, not via callback data. The caller is recorded in the generator's stack args (`return_to` screen name).

### History

One row per stored version: `[👁 fino al 12/05/2026]` → `Reveal(old_password, 30)`. Footer `[🔙 Modifica]`.

### Delete

`Eliminare GitHub? Non si può annullare.` `[🗑 Elimina]` (danger) `[❌ Annulla]`. On delete: pop detail and its submenus, toast `🗑 Eliminato`, re-render the list/search/category the user came from.

### Removed

`🔁 Duplica` and `VaultService.duplicate`.

## 5. Account creation

### Step 1/3 — name

`➕ Nuovo account — passo 1/3` / `Nome dell'account?` — `[❌ Annulla]`. Empty → notice.

### Step 2/3 — username

`Username o email? Scrivilo oppure scegli:` — up to 5 suggestion buttons, `[⏭ Nessuno]`, `[🔙 Indietro]` `[❌ Annulla]`.

If an account with the same name already exists (case-insensitive), a banner `⚠️ Hai già un account «GitHub»` and a `[👁 Apri esistente]` button are shown; the user can still continue.

**Suggestions:** `VaultService.username_suggestions(chat_id, *, aes_key, limit=5)` decrypts only `username_enc`, groups case-insensitively for values containing `@` (emails) and exactly otherwise, ranks by count desc then most recent `updated_at`. Labels truncated to ~32 chars. The full list is stored in `FLOW`; buttons carry the index.

### Step 3/3 — password

Same component as §4 password change step 1–2 (generate or manual). Manual input is deleted immediately.

### Summary

```
➕ Riepilogo
🔐 GitHub
👤 cioscos@mail.com
🔑 •••••••• — forza 4/4 (ottima)
♻️ Stessa password di: GitLab

[📛 Nome] [👤 Username] [🔑 Password]
[🌐 + URL] [📝 + Note]
[🏷 Categoria: —]
[💾 Salva]  (success)
[❌ Annulla]
```

- Correction and "+" buttons open the matching input and return to the summary. Filled fields change label (`🌐 github.com`, `🏷 💼 Lavoro`).
- Reuse check: `compute_password_hmac(password, session.hmac_key)` + new `AccountRepo.find_by_hmac(chat_id, hmac)`. Same check is used in the password-change confirm.
- Category may be pre-set when creation starts from a category screen.
- `💾 Salva` → `VaultService.add` → `Replace` the flow frames with `account_detail` of the new account.

### Draft lifetime

`FLOW["account_new"]`, not persisted, cleared on lock and on bot restart. Intentional: a plaintext password must not outlive the session.

## 6. Categories

### Category list

```
🏷 Categorie
[🏦 Banche (4)]    [💼 Lavoro (12)]
[👤 Personale (9)] [📱 Social (6)]
[📂 Senza categoria (5)]
[➕ Nuova categoria]
[🔙 Home] [🏠 Menu]
```

### Category screen = filtered account list

`🏷 💼 Lavoro — 12 account`, account buttons (open Detail, back returns here), `◀ 1/2 ▶`, `[➕ Nuovo account qui]` (primary, pre-sets category), `[✏️ Rinomina]` `[🎨 Icona]` `[🗑 Elimina]` (danger), footer `[🔙 Categorie]` `[🏠 Menu]`. "Senza categoria" is the same screen with a filter and without rename/icon/delete.

The main `account_list` gets a `[🏷 Per categoria]` button leading to the category list; there is no separate filter on the main list.

### Create / rename / icon / delete

- Name required, ≤ 32 chars, unique per chat case-insensitively.
- Create asks the name, then the icon picker.
- Icon picker: 12 emoji (`💼 🏦 👤 🎮 🛒 📧 🌐 🏠 💳 📱 🎓 ⭐`) + `[Nessuna]`.
- Delete: `Eliminare «Lavoro»? I 12 account non vengono eliminati: restano senza categoria.` `[🗑 Elimina]` (danger) `[❌ Annulla]`. FK `ON DELETE SET NULL` (with `PRAGMA foreign_keys=ON` already in `connect()`) unassigns accounts.

### Data

- `categories.color` column is reused as the icon; no migration. The model field is renamed `Category.icon` and the repository maps it to/from `color`.
- `CategoryRepo.list_with_counts(chat_id) -> list[tuple[Category, int]]`, `set_icon(cat_id, icon)`; `rename` exists.
- `AccountRepo.list_for_chat(chat_id, *, category: str | None | Literal["none"] = None)`.

### Import fix

`ExportService` import currently sets `category_id=None` although the export contains each account's category name. Import now creates missing categories by name and assigns them.

## 7. PTB upgrade and new Bot API features

- `uv lock --upgrade-package python-telegram-bot` to 22.8; `pyproject.toml` pins `python-telegram-bot[job-queue,callback-data]>=22.8`. PTB 22.7 preserves extra `InlineKeyboardButton` arguments during `arbitrary_callback_data` replacement — required for styled callback buttons.
- **Button `style`** (Bot API 9.4) through `views.button(label, act, style=...)`: `primary`, `success`, `danger`. Exact parameter/constant names to be confirmed against 22.8 during implementation.
- **`date_time` entity** (Bot API 9.5) for "Password aggiornata il …" and history dates. If PTB/MarkdownV2 support is not usable, fall back to `dd/mm/yyyy`.
- **`CopyTextButton`** (already available in 22.5).

## 8. Transition from persisted state

Production `DB.pkl` holds old-UI state.

- One-time cleanup in `post_init`: for every `chat_data`, drop `pending_new_account`, `pending_input`, `pw_gen_draft`, `pw_gen_return_to`, `pending_import_file`, and reset `nav_stack` if it contains unknown screens.
- Old keyboards in chat history hit the fallback callback handler (§2).
- Stack entries with unknown screen names resolve to `home`.

## 9. Error handling

- `error_handler` still DMs the developer. Additionally, if a live message exists, it is edited to `⚠️ Errore interno.` with `[🏠 Menu]` instead of sending a new message.
- Expected Telegram errors never reach the error handler: `message is not modified` (ignored), edit impossible (fallback to send), delete failed (ignored), `Forbidden`/`TelegramError` inside jobs (autolock, auto-close, reveal deletion, daily scan) → logged as warnings.
- Validation errors → notice line on the same screen, which stays awaiting input.

## 10. Testing

TDD with the existing pytest setup (`asyncio_mode=auto`); coverage gate stays at 60%.

- **Screens:** `render` tested with fake services — text, buttons, styles, presence/absence of copy/URL buttons, labels.
- **Navigator:** fake bot — edit in place, fallback to send on edit failure, deletion of user text, stack semantics (back, home, replace at end of flow, `PopTo`), command moves live message to bottom, lock → unlock → resume target, stale callbacks.
- **Flows (driven through the Navigator):** creation with suggestions and reuse warning; password change via generator and via manual input; single-field edit; category lifecycle (create, icon, rename, assign, delete); import restoring categories.
- **Security:** render every screen with accounts containing sentinel username/password/note/URL values; assert no `Act` in any keyboard contains them; assert `FLOW` is stripped from persisted chat_data and cleared by `lock()`.
- **Repositories:** `find_by_hmac`, `username_suggestions`, `list_with_counts`, category filter, icon mapping.

## 11. Delivery

Work happens on `feature/navigation-redesign`, branched from `fix/session-and-alerts` (commit `8762fed`: `/start` re-entry, `FsmContext.lock()`, daily scan resilience, DB-backed reuse clusters). The implementation plan will sequence: PTB upgrade → `ui/` core (Navigator, Screen, Act, views) → screens migrated one area at a time (home/unlock/help → list/search/detail → edit/password/generator/history → creation → categories → health/settings/transfer) → removal of old handlers → persisted-state cleanup → docs (`CLAUDE.md`).
