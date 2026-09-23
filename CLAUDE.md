# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Run / install

Project uses `uv` (see `uv.lock`) with Python 3.13+.

```bash
uv sync --dev                          # install runtime + dev deps from uv.lock
KEYRING=./keys uv run -m password_bot  # run the bot
```

`KEYRING` env var **must** point to a directory containing:
- `telegram.dat` — Telegram bot token (single line)
- `dev_id.dat`   — Telegram chat id for error notifications (single line)

These are loaded once at startup by `password_bot.__main__.main()`. Missing files crash the bot at boot. There is no `.env` mechanism.

### Tests / lint

```bash
uv run pytest -v                        # full suite (~152 tests)
uv run pytest --cov=src/password_bot    # coverage report (gate: 60%)
uv run ruff check src tests             # lint
uv run ruff format src tests            # format
```

CI runs all four on push/PR via `.github/workflows/test.yml`.

### Argon2id tuning (Pi Zero 2W)

Defaults target Pi Zero 2W. Override via env vars:
```
PB_ARGON2_M=65536      # KiB, hash params memory cost
PB_ARGON2_T=3          # iterations
PB_ARGON2_P=1          # parallelism (shared by hash + derive)
PB_ARGON2_DERIVE_M=32768
PB_ARGON2_DERIVE_T=2
```

## Persistence layout

Three on-disk artifacts in the working directory the bot is started from:

- `accounts.db` — SQLite. Schema (v2):
  - `schema_version(version INTEGER PK)` — current target version `2`.
  - `users(chat_id PK, name, passphrase_hash, autolock_minutes, autolock_reset_on_activity, alert_days, crypto_version, legacy_salt, created_at, updated_at, pw_prefs)`. `passphrase_hash` is an Argon2id encoded string (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`). `legacy_salt` is non-NULL only for users still on `crypto_version=1` (pre-migration). `pw_prefs` is a NULLABLE JSON-encoded `PwPrefs` (saved user defaults for the password generator); NULL means "use built-in defaults".
  - `accounts(id PK, chat_id FK, name, username_enc, password_enc, url_enc, note_enc, category_id FK, password_hmac, crypto_version, password_changed_at, created_at, updated_at)`. All `_enc` columns hold **base64-encoded AES-256-GCM ciphertext with a 1-byte crypto-version prefix and 12-byte nonce**, never plaintext. `username_enc`, `url_enc`, `note_enc` are NULLABLE (optional fields). `password_hmac` is HMAC-SHA256 hex of the plaintext password keyed by an HKDF-derived subkey — used for reuse detection without exposing plaintext.
  - `categories(id PK, chat_id FK, name, color, UNIQUE(chat_id, name))`.
  - `password_history(id PK AUTOINCREMENT, account_id FK, password_enc, crypto_version, replaced_at)` — retention `HISTORY_MAX=5` (see `config.py`), pruned on every password update.
- `DB.pkl`     — `PicklePersistence` for python-telegram-bot. Holds `chat_data` minus sensitive runtime keys (`SESSION`, `LEGACY_SESSION_EXTRAS`, `PENDING_IMPORT_FILE`, `PW_GEN_DRAFT`, `PW_GEN_RETURN_TO`) stripped by `_SessionStrippingPersistence`.
- `keys/`      — secrets loaded at startup, gitignored.

`*.db`, `*.db.bak`, `*.pkl`, `*.pkl.bak`, `password_bot.log` are gitignored. Never commit them.

### Schema migration

`repositories.migrator.migrate_to_latest(db_path)` runs on `_post_init`. `TARGET_VERSION = 2`. The migrator walks the version stepwise:

1. **v0 → v1**: if `schema_version < 1`, detect legacy schema by presence of `users.salted_hash`. If legacy, run `migrations/002_legacy_upgrade.sql` (renames columns, adds new ones, sets `crypto_version=1` per row, fills `legacy_salt`). Otherwise run `migrations/001_init.sql` (fresh DB). Set `schema_version = 1`.
2. **v1 → v2**: if `schema_version < 2` and `users.pw_prefs` is missing, run `migrations/003_user_pw_prefs.sql` (`ALTER TABLE users ADD COLUMN pw_prefs TEXT`). Set `schema_version = 2`.

All migration scripts are wrapped in `BEGIN;` / `COMMIT;` for atomicity. The version-check guard makes `migrate_to_latest` idempotent.

## Architecture

### Layered package (src/password_bot/)

```
src/password_bot/
├── __main__.py                  ← entrypoint: KEYRING=./keys uv run -m password_bot
├── config.py                    ← AppConfig (paths, Argon2Params from env)
├── bot.py                       ← Application builder, ConversationHandler tree, daily scan job (skips legacy v1 users; per-user `TelegramError` is logged, never aborts the loop)
├── container.py                 ← DI container; Container.build(config) wires every service
│
├── crypto/
│   ├── kdf.py                   ← Argon2idKdf (hash, verify, derive_key)
│   ├── cipher.py                ← GcmCipher (AES-256-GCM, version byte prefix)
│   ├── hkdf.py                  ← derive_subkey (HKDF-SHA256)
│   └── legacy.py                ← LegacyCfbDecryptor + legacy_derive_key / legacy_verify_passphrase (READ-ONLY, migration only)
│
├── repositories/
│   ├── db.py                    ← aiosqlite connection helper (`async with connect(path)`)
│   ├── migrator.py              ← migrate_to_latest, stepwise v0→v1→v2, legacy detection
│   ├── migrations/              ← 001_init.sql, 002_legacy_upgrade.sql, 003_user_pw_prefs.sql
│   ├── user_repo.py             ← UserRepo (get/create/update_passphrase/update_autolock/update_alert_days/get_pw_prefs/set_pw_prefs)
│   ├── account_repo.py          ← AccountRepo (CRUD + fuzzy search + list_stale + list_reuse_clusters)
│   ├── category_repo.py         ← CategoryRepo
│   └── history_repo.py          ← HistoryRepo (push/list/prune)
│
├── models/                      ← dataclasses (slots=True): Account, AccountRow, User, Category, PasswordHistoryEntry, PwPrefs
│
├── services/
│   ├── result.py                ← Result[T] generic. Factory is `Result.success(value)` (NOT `Result.ok`, see below)
│   ├── errors.py                ← DomainError + subclasses with `user_message` strings
│   ├── password_generator.py    ← PasswordGenerator + PasswordSpec (flag-based: upper/lower/digits/symbols/exclude_ambiguous/no_duplicates) + legacy PasswordCharset preset + entropy_bits + MIN_LENGTH/MAX_LENGTH
│   ├── strength_meter.py        ← zxcvbn wrapper; guards empty input
│   ├── reuse_detector.py        ← compute_password_hmac (reuse clusters come from `AccountRepo.list_reuse_clusters`, grouped by `password_hmac` in SQL)
│   ├── auth_service.py          ← register, unlock, change_passphrase (two-phase: keys returned, persistence deferred), commit_passphrase_change
│   ├── vault_service.py         ← VaultService (add/get_decrypted/list_decrypted/update_fields/update_password+history/duplicate/delete)
│   ├── alert_service.py         ← find_stale (user-specific threshold)
│   ├── migration_service.py     ← unlock_legacy + migrate_user (decrypt CFB → re-encrypt GCM, install Argon2 hash, clear legacy_salt)
│   └── export_service.py        ← JSON export/import with Argon2-derived export key separate from vault key, MergeStrategy enum
│
├── handlers/
│   ├── common.py                ← /start, /menu (inline-button main menu), /stop, /lock, /cancel, /help, /back, on_menu_callback (pattern `^menu:`), error_handler
│   ├── auth.py                  ← handle_passphrase_message (setup / unlock / legacy migration entry)
│   ├── account_new.py           ← multi-step add flow with /skip for optional fields; the "🎲 Genera" button delegates to password_gen.show_options_from_callback; accept_generated_password resumes the flow
│   ├── account_view.py          ← per-field display (show/edit/copy buttons, 🔁 duplicate, 🗑 delete-confirm)
│   ├── account_edit.py          ← handle_pending dispatcher for pending field-edit input
│   ├── inline_cmd.py            ← /get /add /copy /list (paginated via accounts_page_keyboard) /list_stale /list_reused (terminal replies always carry back_menu_keyboard); on_account_callback (pattern `^acc:`); on_list_callback (typed ListPageData payload)
│   ├── export.py                ← /export, /import, on_document for uploaded JSON
│   ├── settings.py              ← /settings (autolock minutes, alert days, password-generator defaults) via inline keyboard, on_callback (pattern `^set:`)
│   ├── categories.py            ← /categories (inline-button flow: list/select/new/delete-confirm); /cat_add /cat_del still exist as shortcuts; on_callback (pattern `^cat:`); handle_pending_name for `_cat_new_name` text input
│   ├── password_gen.py          ← interactive password generator (toggle menu, regenerate, accept, save default, reset); show_options_from_callback (entrypoint), on_callback (pattern `^pwgen:`), handle_pending_length for `_pwgen_length` text input
│   ├── nav.py                   ← nav:back / nav:menu callback handler — re-sends a fresh menu message (does NOT overwrite the originating message with a bare "🔙")
│   └── dispatcher.py            ← MessageHandler text router; checks PENDING_INPUT (handles `_export_passphrase`, `_import_passphrase`, `_cat_new_name`, `_pwgen_length`, `_search_query`, `_copy_query`, account-edit) → session → new-account flow
│
├── state/
│   ├── keys.py                  ← ChatDataKey StrEnum (SESSION, NAV_STACK, PENDING_INPUT, PENDING_NEW_ACCOUNT, PENDING_IMPORT_FILE, LEGACY_SESSION_EXTRAS, AUTOLOCK_JOB_NAME, PW_GEN_DRAFT, PW_GEN_RETURN_TO) — never use raw strings
│   └── fsm.py                   ← FsmContext + Screen dataclass (push/pop/top/depth/pop_to/reset_to/pending_input/session ops)
│
├── i18n/
│   └── it.py                    ← MESSAGES dict, all Italian strings centralized (menu/pw_gen_*/cat_* keys included)
│
└── telegram_utils/
    ├── md.py                    ← escape_md, code_inline (MarkdownV2 helpers)
    ├── keyboards.py             ← single_column, back_menu_keyboard, confirm_cancel_keyboard, main_menu_keyboard (2-column × 6 rows, label-only, driven by MAIN_MENU_ITEMS), accounts_page_keyboard (paginated /list, ACCOUNTS_PAGE_SIZE=8)
    ├── callback_data.py         ← typed payloads for arbitrary_callback_data: ListPageData(page: int) used by /list pagination
    └── delete_message.py        ← schedule_delete via job_queue.run_once for auto-deleting sensitive messages

tests/
├── conftest.py                  ← fast_argon2 (autouse, sets PB_ARGON2_* low), aes_key, tmp_db_path
├── crypto/                      ← test_kdf, test_cipher (incl. hypothesis property), test_legacy_migration, test_hkdf
├── repositories/                ← test_db_migrator (v0→v1, v1→v2, pw_prefs column), test_user_repo (incl. pw_prefs round-trip), test_account_repo, test_category_repo, test_history_repo
├── services/                    ← test_result, test_password_generator (flags, ambiguous exclusion, no-duplicates, entropy), test_strength_meter, test_reuse_detector, test_auth_service, test_vault_service, test_alert_service, test_migration_service, test_export_service
└── handlers/                    ← test_smoke (Application builds with root conversation), test_markdown_escape (regression on `-`/`(`/`)`), test_password_gen_integration, test_categories_integration, test_list_pagination (paginated /list keyboard + on_list_callback)
```

### Result type quirk

`Result[T]` was originally specified with `Result.ok(value)` as factory and `r.ok` as property — these collide at class-level access in Python (the property shadows the classmethod). The factory was renamed:

- `Result.success(value)` ← factory (use this in production code)
- `Result.err(error)` ← error factory
- `r.ok` ← boolean property (`error is None`)

When extending services, always call `Result.success(...)`. Anything in the original plan that says `Result.ok(value)` as a factory call means `Result.success(value)`.

### Crypto model

Three layers:
1. **Argon2id KDF** (`crypto.kdf.Argon2idKdf`): `hash_passphrase` (returns argon2-cffi encoded string), `verify` (False on `VerificationError`, propagates `InvalidHash` on malformed stored hash), `derive_key(passphrase, salt) → 32 bytes` using `hash_secret_raw` with derive params.
2. **AES-256-GCM** (`crypto.cipher.GcmCipher`): wire format = `b64(version_byte(1) || nonce(12) || ciphertext || tag(16))`. `CRYPTO_VERSION_GCM = 2`. Authenticated; tamper → `InvalidTag`. Empty plaintext supported.
3. **HKDF subkey** (`crypto.hkdf.derive_subkey(master_key, *, info, length=32)`): SHA-256, `salt=None`. Used to derive the HMAC key for reuse detection from the session's AES key (`info=b"reuse-detection"`).

### Password generator

`services.password_generator.PasswordSpec` is flag-based:

```python
@dataclass(slots=True, frozen=True)
class PasswordSpec:
    length: int
    upper: bool = True
    lower: bool = True
    digits: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = False
    no_duplicates: bool = False
    charset: PasswordCharset | None = None   # legacy preset path
```

Constants: `MIN_LENGTH = 4`, `MAX_LENGTH = 128`. Ambiguous-character set excluded when the flag is set: `0O1lI|` plus quotes/punctuation/space.

`PasswordGenerator.generate(spec)` guarantees:
- at least one character from each selected pool;
- ambiguous chars filtered from every pool when `exclude_ambiguous=True`;
- when `no_duplicates=True`, the password is sampled without replacement and a `ValueError` is raised if the unique-pool size is too small for the requested length;
- `secrets.choice` + Fisher-Yates shuffle with `secrets.randbelow` everywhere — never `random`.

`entropy_bits(spec)` returns `length * log2(unique_pool_size)` as a fast estimate (used in UI to label the generated password). zxcvbn-based scoring stays in `services.strength_meter`.

Legacy `PasswordCharset` (DIGITS / ALPHANUM / ALPHANUM_SYMBOLS) is retained only for backward compatibility with stored data and old tests — new code must use the flag fields.

### User-saved generator defaults

`models.pw_prefs.PwPrefs` mirrors the configurable fields above and is JSON-serialized into `users.pw_prefs` via `UserRepo.get_pw_prefs(chat_id)` / `set_pw_prefs(chat_id, prefs)`. `PwPrefs.from_json` is tolerant: returns built-in defaults on `None`/empty/invalid JSON.

The interactive generator UI lives in `handlers.password_gen`:
- `show_options_from_callback(update, context, *, return_to)` loads `PwPrefs` from DB, stores a copy in `chat_data[PW_GEN_DRAFT]` and the caller hint in `chat_data[PW_GEN_RETURN_TO]`, then renders the toggle keyboard via `edit_message_text` (falling back to `send_message`).
- `on_callback` (pattern `^pwgen:`) handles `toggle:<flag>`, `len`, `run`, `accept`, `save`, `reset`, `back`, `cancel`.
- `handle_pending_length` is called by the dispatcher when `pending["field"] == "_pwgen_length"` and validates `MIN_LENGTH ≤ n ≤ MAX_LENGTH`.
- `pwgen:accept` reads `PW_GEN_RETURN_TO`:
  - `"account_new"` → calls `handlers.account_new.accept_generated_password(...)` which writes the password into the in-flight draft and advances to the URL step;
  - anything else → simply confirms.
- `PW_GEN_DRAFT` and `PW_GEN_RETURN_TO` are runtime-only and stripped by `_SessionStrippingPersistence` (do NOT survive a restart).

### Inline-button UX

The bot is button-first; slash commands are kept as shortcuts. Key conventions:

- `cmd_start` ends with `await _send_menu(update.effective_chat)` which sends `_menu_body()` plus `main_menu_keyboard()`. The keyboard is a **2-column grid** of 12 buttons (6 rows × 2); each label is the bare `"<emoji+nome>"` (no inline description — the descriptions live only in the text body above the keyboard). The button list is driven by `MAIN_MENU_ITEMS` in `telegram_utils/keyboards.py`. The text body lists the same 12 slash-command shortcuts one per line with a short description (driven by `_QUICK_COMMANDS` in `handlers/common.py`). The same helper is reused by `/menu`, `/back`, and `nav:menu`.
- All callback patterns:
  - `^menu:` → `common.on_menu_callback` (dispatches add/list/search/copy/stale/reused/categories/settings/export/import/lock/help)
  - `^nav:` → `nav.on_callback` (back/menu — always sends a fresh menu message, never overwrites the originating message with a `"🔙"` placeholder)
  - `^view:` → `account_view.on_callback`
  - `^set:` → `settings.on_callback`
  - `^cat:` → `categories.on_callback`
  - `^pwgen:` → `password_gen.on_callback`
  - `^acc:` → `inline_cmd.on_account_callback` (opens an account from a multi-result `/get` and from the paginated `/list`)
  - `^newpw:` → `account_new.callback_generate_password` / `callback_manual_password`
  - typed `ListPageData` payload → `inline_cmd.on_list_callback` (page navigation for `/list`). The handler is registered with a callable `pattern=lambda d: isinstance(d, ListPageData)`, not a regex — PTB accepts callables when `arbitrary_callback_data=True` is enabled on `ApplicationBuilder`.
- Search/copy from the menu work via a one-shot pending input: the callback sets `pending = {"field": "_search_query" | "_copy_query"}` and the dispatcher forwards the next text message back into `cmd_get` / `cmd_copy` by filling `context.args`.
- Handlers reachable from BOTH commands and callbacks (e.g. `settings.cmd_settings`, `inline_cmd.cmd_list`, `categories.cmd_categories`, `export.cmd_export/cmd_import`) MUST use `update.effective_chat.send_message(...)` — `update.message.reply_text` raises on a `CallbackQuery` update.
- Terminal replies (`/list`, `/list_stale`, `/list_reused`, account_saved, etc.) attach `back_menu_keyboard(show_menu=True)` so the user always has a way back to the menu.

### Paginated `/list` + arbitrary callback_data

PTB is installed with the `[callback-data]` extra (`pyproject.toml` → `python-telegram-bot[job-queue,callback-data]`). `ApplicationBuilder().arbitrary_callback_data(True)` is enabled in `bot.build_application`, so handlers can attach Python objects to `InlineKeyboardButton.callback_data` and receive them back unchanged on the next update — bypassing Telegram's 64-byte wire limit. PTB stores the original payload in a per-Bot LRU cache (default 1024 entries) and ships a UUID stand-in on the wire.

`/list` (and the `menu:list` button) renders an interactive paginated keyboard via `telegram_utils.keyboards.accounts_page_keyboard(rows, *, page, page_size=ACCOUNTS_PAGE_SIZE)`:

- One row per account on the current page; each account button uses **string** callback_data `"acc:open:{id}"`, so it flows into the existing `^acc:` regex handler shared with `cmd_get`.
- Nav row `[◀] [N/M] [▶]` uses **typed** `ListPageData(page=...)` callback_data (`telegram_utils/callback_data.py`). Boundary arrows are omitted on first/last page. The middle badge is a no-op (re-renders the same page; `on_list_callback` swallows `BadRequest "message is not modified"`).
- Footer row `[🔙 Indietro] [🏠 Menu]` reuses the standard `nav:back` / `nav:menu` string callbacks.

`handlers.inline_cmd.on_list_callback` re-fetches accounts on every page nav (avoids stale data after an add/edit) and uses `q.edit_message_text(...)` to mutate the existing message rather than spam new ones. Pagination state lives **entirely in `callback_data`** — no new `ChatDataKey`, no chat_data writes, so back/forward survives autolock without leaking.

i18n keys: `list_title` (`📚 *Account* — pagina {cur}/{tot}`) and `list_empty` (`Vault vuoto.`). The page indicator inside the button itself is rendered directly from `page+1` and `total_pages` in the keyboard helper.

When adding more typed callback payloads:
1. Add a `@dataclass(frozen=True, slots=True)` to `telegram_utils/callback_data.py`.
2. Register a `CallbackQueryHandler(handler, pattern=lambda d: isinstance(d, MyPayload))` in `bot.build_application`.
3. In the handler, `q.data` is the restored dataclass instance — `isinstance` check it, then read fields. No `split(":")` parsing.

### MarkdownV2 escaping

`telegram_utils.md.escape_md` escapes every character in `_*[]()~`>#+-=|{}.!`. Two pitfalls that have bitten this codebase:

- Never start a list item with a raw `-` — Telegram rejects it as an unescaped reserved char. Use `•` (not reserved) or `\-`.
- When mixing escaped Italian text and `code_inline(...)` segments, escape the surrounding parens too: `escape_md(" (vecchio: ") + code_inline(old) + escape_md(")")`.

### Legacy v1 reader (`crypto/legacy.py`) — read-only

The previous bot used PBKDF2-HMAC-SHA256 (100k iter) + AES-CFB. Two quirks reproduced exactly for parity:

- `legacy_verify_passphrase(passphrase, stored_hex_hash, salt_hex)` — `bytes.fromhex(salt_hex)` → PBKDF2HMAC SHA256 100k iter, compare hex.
- `legacy_derive_key(passphrase, salt_hex)` — **`base64.b64decode(salt_hex)`** (yes, decode the hex string AS base64 — that's what v1 did because the variable was named `salt_b64` and the call site fed it the hex string directly). Result: 24-byte salt fed to PBKDF2HMAC. This quirk was a known bug in v1 that we MUST reproduce to decrypt existing data.

`LegacyCfbDecryptor.decrypt(ciphertext_b64, key) → str` decodes IV from first 16 bytes, rest is CFB ciphertext, returns utf-8 str.

### Conversation state machine

Single `ConversationHandler` (`name="root"`, persistent, per_chat). Entry point: `/start` returning state `0`. All in-state handlers are registered in `states[0]`. Fallback: `/stop` returns `ConversationHandler.END`.

PTB state stays in `0` forever. Real "navigation state" lives in `chat_data` via the FSM screen stack (see `state.fsm.FsmContext`). Each handler reads/writes via typed `ChatDataKey` enum members — never raw strings.

Critical invariants:
- `cmd_start` MUST `return 0` (entry point returning None ends the conversation).
- `chat_data[ChatDataKey.SESSION.value]` is the live `Session` dataclass (`aes_key`, `hmac_key`, `expires_at`, optional `_legacy_key`/`_new_passphrase_hash` for in-flight migration). NEVER persisted to disk (filtered by `_SessionStrippingPersistence`).
- `chat_data[ChatDataKey.PENDING_INPUT.value]` is `{field, id}` for any in-flight one-shot prompt. `cmd_cancel` clears it.
- `_schedule_autolock` schedules a `run_once` job that calls `_autolock_callback` to wipe session **and every in-progress flow** via `FsmContext.lock()` (pending input, new-account draft, import file, pw-gen draft, nav stack), so the next text can only be a passphrase. `cmd_lock` and `cmd_start` (when locked) do the same, and `dispatcher.on_text` checks the session **before** any pending input. The root conversation has `allow_reentry=True`, so `/start` works mid-conversation (e.g. after an autolock).

### Passphrase lifecycle (security-critical)

- The passphrase is **never** persisted to disk in any form.
- When the user sends it, `handlers.auth.handle_passphrase_message` (a) deletes the inbound message immediately, (b) routes to `register` (no user), `unlock_legacy` + `migrate_user` (user.crypto_version=1), or `unlock` (user.crypto_version=2).
- `AuthService.unlock` derives the AES key from `passphrase + salt-extracted-from-encoded-Argon2-hash` and returns a `Session`. The `Session.hmac_key` is `HKDF(aes_key, info=b"reuse-detection")`.
- Session lifetime: `autolock_minutes * 60` if >0, else 15 minutes default. `_schedule_autolock` job clears the session and notifies the user.
- `Session` is stored in `chat_data[ChatDataKey.SESSION]`. The custom `_SessionStrippingPersistence.update_chat_data` filters this key (and `LEGACY_SESSION_EXTRAS`, `PENDING_IMPORT_FILE`, `PW_GEN_DRAFT`, `PW_GEN_RETURN_TO`) before writing `DB.pkl`.

### Passphrase change (two-phase commit)

`AuthService.change_passphrase` is **two-phase by design**:
1. Verifies the current passphrase, derives both old and new keys, returns `Result[(Session, old_aes_key)]`. **Does NOT persist** the new hash.
2. Caller re-encrypts every vault row using `old_aes_key` → `new_aes_key`.
3. Caller invokes `AuthService.commit_passphrase_change(chat_id, new_passphrase)` which persists the new Argon2 hash.

If you reverse the order (persist first, then re-encrypt), a crash mid-rotation bricks the vault: the user's stored hash verifies the new passphrase but every ciphertext was encrypted with the old key. The two-phase split prevents that.

### Legacy migration on first unlock

When `user.crypto_version == 1`, `handlers.auth.handle_passphrase_message` calls `MigrationService.unlock_legacy` then `migrate_user`:
- `unlock_legacy` verifies the legacy PBKDF2 hash, derives the legacy CFB key, computes a fresh Argon2 hash + GCM key, returns a `Session` carrying both `_legacy_key` and `_new_passphrase_hash` as additional fields (regular dataclass attributes, NOT `__dict__` injection — slots dataclass blocks that).
- `migrate_user` walks every account row of that user: legacy-decrypt → GCM-encrypt with the new key → update row, then installs the new Argon2 hash and clears `legacy_salt` via `users.update_passphrase`.

### Repository conventions

- All user-facing strings are **Italian** and centralized in `password_bot/i18n/it.py` `MESSAGES` dict. Keep tone informal ("tu", short imperative). Never inline Italian text in handlers — import from `MESSAGES`.
- All `chat_data` keys are members of `state.keys.ChatDataKey` enum — never raw strings.
- Repos return `*Row` dataclasses (raw, with `_enc` strings) from queries. Services decrypt `*Row` into domain objects (`Account`, etc.).
- Each repo call opens/closes its own `aiosqlite.connect` via `db.connect()` async context manager. No long-lived connection.
- Fuzzy account search uses `thefuzz.fuzz.partial_ratio` in `AccountRepo.search`; default threshold 60.
- Errors funnel through `handlers.common.error_handler` which DMs the dev (`container.dev_chat_id`) with a redacted traceback. Domain-expected failures use `Result[T]`; unexpected failures propagate.
- Lint config in `pyproject.toml` `[tool.ruff]`: line-length 100, target py313, select `E F I B UP SIM RUF`. Run `uv run ruff check src tests` before commit. Pre-commit format with `uv run ruff format src tests`.
- Test coverage gate: 60% (CI); aspirational 75%. Handler modules ship with smoke tests plus a few targeted lightweight integration tests (`tests/handlers/test_password_gen_integration.py`, `test_categories_integration.py`, `test_markdown_escape.py`); deeper handler coverage is the next bump target.

### Adding a new handler

1. Create `src/password_bot/handlers/foo.py`. Use `from password_bot.container import Container` and `container = context.application.bot_data["container"]` at the start of each handler.
2. Use `update.effective_chat.send_message(...)` so the handler works whether called from a `CommandHandler` (`update.message`) or a `CallbackQueryHandler` (`update.callback_query.message`). `update.message` is `None` on a callback update.
3. Wrap user-supplied strings in `escape_md(...)` from `telegram_utils.md` before sending with `parse_mode=MARKDOWN_V2`. Bullets at the start of lines use `•`, not `-`.
4. End each terminal action with `back_menu_keyboard(show_menu=True)` (or another keyboard) so the user is never stranded without a way back.
5. Register the handler in `bot.build_application` inside the `states[0]` list.
6. If callbacks are involved, pick a unique callback_data prefix (e.g. `foo:`) and add a `CallbackQueryHandler(foo.on_callback, pattern=r"^foo:")` next to the existing ones.
7. If your callback needs free-text input, set `FsmContext(...).set_pending_input({"field": "_foo_xxx"})`, prompt the user, then add a branch in `dispatcher.on_text` matching that field — never re-implement text routing locally.
8. Store any transient draft under a typed `ChatDataKey`. If it must NOT survive a restart, add its `.value` to the strip-list in `_SessionStrippingPersistence.update_chat_data` (`bot.py`).
