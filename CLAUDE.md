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
uv run pytest -v                        # full suite (~100 tests)
uv run pytest --cov=src/password_bot    # coverage report
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

- `accounts.db` — SQLite. Schema (v1):
  - `schema_version(version INTEGER PK)`
  - `users(chat_id PK, name, passphrase_hash, autolock_minutes, autolock_reset_on_activity, alert_days, crypto_version, legacy_salt, created_at, updated_at)`. `passphrase_hash` is an Argon2id encoded string (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`). `legacy_salt` is non-NULL only for users still on `crypto_version=1` (pre-migration).
  - `accounts(id PK, chat_id FK, name, username_enc, password_enc, url_enc, note_enc, category_id FK, password_hmac, crypto_version, password_changed_at, created_at, updated_at)`. All `_enc` columns hold **base64-encoded AES-256-GCM ciphertext with a 1-byte crypto-version prefix and 12-byte nonce**, never plaintext. `username_enc`, `url_enc`, `note_enc` are NULLABLE (optional fields). `password_hmac` is HMAC-SHA256 hex of the plaintext password keyed by an HKDF-derived subkey — used for reuse detection without exposing plaintext.
  - `categories(id PK, chat_id FK, name, color, UNIQUE(chat_id, name))`.
  - `password_history(id PK AUTOINCREMENT, account_id FK, password_enc, crypto_version, replaced_at)` — retention `HISTORY_MAX=5` (see `config.py`), pruned on every password update.
- `DB.pkl`     — `PicklePersistence` for python-telegram-bot. Holds `chat_data` minus sensitive runtime keys (`SESSION`, `REUSE_DETECTOR`, `LEGACY_SESSION_EXTRAS`, `PENDING_IMPORT_FILE`) stripped by `_SessionStrippingPersistence`.
- `keys/`      — secrets loaded at startup, gitignored.

`*.db`, `*.db.bak`, `*.pkl`, `*.pkl.bak`, `password_bot.log` are gitignored. Never commit them.

### Schema migration

`repositories.migrator.migrate_to_latest(db_path)` runs on `_post_init`. It detects a legacy v0 schema by presence of `users.salted_hash` column. If found it runs `migrations/002_legacy_upgrade.sql` (renames columns, adds new ones, sets `crypto_version=1` per row, fills `legacy_salt`). Otherwise it runs `migrations/001_init.sql`. Both scripts are wrapped in `BEGIN;` / `COMMIT;` for atomicity.

## Architecture

### Layered package (src/password_bot/)

```
src/password_bot/
├── __main__.py                  ← entrypoint: KEYRING=./keys uv run -m password_bot
├── config.py                    ← AppConfig (paths, Argon2Params from env)
├── bot.py                       ← Application builder, ConversationHandler tree, daily scan job
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
│   ├── migrator.py              ← migrate_to_latest, legacy detection
│   ├── migrations/              ← 001_init.sql, 002_legacy_upgrade.sql
│   ├── user_repo.py             ← UserRepo (get/create/update_passphrase/update_autolock/update_alert_days)
│   ├── account_repo.py          ← AccountRepo (CRUD + fuzzy search + list_stale)
│   ├── category_repo.py         ← CategoryRepo
│   └── history_repo.py          ← HistoryRepo (push/list/prune)
│
├── models/                      ← dataclasses (slots=True): Account, AccountRow, User, Category, PasswordHistoryEntry
│
├── services/
│   ├── result.py                ← Result[T] generic. Factory is `Result.success(value)` (NOT `Result.ok`, see below)
│   ├── errors.py                ← DomainError + subclasses with `user_message` strings
│   ├── password_generator.py    ← PasswordGenerator + PasswordSpec / PasswordCharset (StrEnum)
│   ├── strength_meter.py        ← zxcvbn wrapper; guards empty input
│   ├── reuse_detector.py        ← compute_password_hmac + in-memory cluster index
│   ├── auth_service.py          ← register, unlock, change_passphrase (two-phase: keys returned, persistence deferred), commit_passphrase_change
│   ├── vault_service.py         ← VaultService (add/get_decrypted/list_decrypted/update_fields/update_password+history/duplicate/delete)
│   ├── alert_service.py         ← find_stale (user-specific threshold)
│   ├── migration_service.py     ← unlock_legacy + migrate_user (decrypt CFB → re-encrypt GCM, install Argon2 hash, clear legacy_salt)
│   └── export_service.py        ← JSON export/import with Argon2-derived export key separate from vault key, MergeStrategy enum
│
├── handlers/
│   ├── common.py                ← /start, /menu (lists commands), /stop, /lock, /cancel, /help, /back, error_handler
│   ├── auth.py                  ← handle_passphrase_message (setup / unlock / legacy migration entry)
│   ├── account_new.py           ← multi-step add flow with /skip for optional fields, generator buttons
│   ├── account_view.py          ← per-field display (show/edit/copy buttons, 🔁 duplicate, 🗑 delete-confirm)
│   ├── account_edit.py          ← handle_pending dispatcher for pending field-edit input
│   ├── inline_cmd.py            ← /get /add /copy /list /list_stale /list_reused
│   ├── export.py                ← /export, /import, on_document for uploaded JSON
│   ├── settings.py              ← /settings (autolock minutes, alert days) via inline keyboard
│   ├── categories.py            ← /categories, /cat_add, /cat_del
│   ├── nav.py                   ← nav:back / nav:menu callback handler
│   └── dispatcher.py            ← MessageHandler text router; checks PENDING_INPUT → session → new-account flow
│
├── state/
│   ├── keys.py                  ← ChatDataKey StrEnum (SESSION, NAV_STACK, PENDING_INPUT, REUSE_DETECTOR, …) — never use raw strings
│   └── fsm.py                   ← FsmContext + Screen dataclass (push/pop/top/depth/pop_to/reset_to/pending_input/session ops)
│
├── i18n/
│   └── it.py                    ← MESSAGES dict, all Italian strings centralized
│
└── telegram_utils/
    ├── md.py                    ← escape_md, code_inline (MarkdownV2 helpers)
    ├── keyboards.py             ← single_column, back_menu_keyboard, confirm_cancel_keyboard
    └── delete_message.py        ← schedule_delete via job_queue.run_once for auto-deleting sensitive messages

tests/
├── conftest.py                  ← fast_argon2 (autouse, sets PB_ARGON2_* low), aes_key, tmp_db_path
├── crypto/                      ← test_kdf, test_cipher (incl. hypothesis property), test_legacy_migration, test_hkdf
├── repositories/                ← test_db_migrator, test_user_repo, test_account_repo, test_category_repo, test_history_repo
├── services/                    ← test_result, test_password_generator, test_strength_meter, test_reuse_detector, test_auth_service, test_vault_service, test_alert_service, test_migration_service, test_export_service
└── handlers/                    ← test_smoke (Application builds with root conversation)
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
- `_schedule_autolock` schedules a `run_once` job that calls `_autolock_callback` to wipe session via `FsmContext.clear_session`.

### Passphrase lifecycle (security-critical)

- The passphrase is **never** persisted to disk in any form.
- When the user sends it, `handlers.auth.handle_passphrase_message` (a) deletes the inbound message immediately, (b) routes to `register` (no user), `unlock_legacy` + `migrate_user` (user.crypto_version=1), or `unlock` (user.crypto_version=2).
- `AuthService.unlock` derives the AES key from `passphrase + salt-extracted-from-encoded-Argon2-hash` and returns a `Session`. The `Session.hmac_key` is `HKDF(aes_key, info=b"reuse-detection")`.
- Session lifetime: `autolock_minutes * 60` if >0, else 15 minutes default. `_schedule_autolock` job clears the session and notifies the user.
- `Session` is stored in `chat_data[ChatDataKey.SESSION]`. The custom `_SessionStrippingPersistence.update_chat_data` filters this key (and `REUSE_DETECTOR`, `LEGACY_SESSION_EXTRAS`, `PENDING_IMPORT_FILE`) before writing `DB.pkl`.

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
- Test coverage gate: 60% (CI); aspirational 75%. Handler modules have only smoke tests currently.

### Adding a new handler

1. Create `src/password_bot/handlers/foo.py`. Use `from password_bot.container import Container` and `container = context.application.bot_data["container"]` at the start of each handler.
2. Use `update.effective_chat.send_message(...)` so the handler works whether called from a CommandHandler (`update.message`) or a CallbackQueryHandler (`update.callback_query.message`).
3. Wrap user-supplied strings in `escape_md(...)` from `telegram_utils.md` before sending with `parse_mode=MARKDOWN_V2`.
4. Register the handler in `bot.build_application` inside the `states[0]` list.
5. If callbacks are involved, pick a unique callback_data prefix (e.g. `foo:`) and add a `CallbackQueryHandler(foo.on_callback, pattern=r"^foo:")` next to the existing ones.
