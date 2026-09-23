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
uv run pytest -v                        # full suite
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
- `DB.pkl`     — `PicklePersistence` for python-telegram-bot. Holds `chat_data` (navigation stack, live message id, resume target) and PTB's callback-data cache. `SESSION`, `LEGACY_SESSION_EXTRAS` and `FLOW` (in-progress drafts, may contain secrets) are stripped by `_SessionStrippingPersistence`. Old pickles reference `state.fsm.Screen` and `telegram_utils.callback_data.ListPageData`: both names must stay importable.
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
│   ├── vault_service.py         ← VaultService (add/get_decrypted/list_decrypted/update_fields/update_password+history/delete)
│   ├── alert_service.py         ← find_stale (user-specific threshold)
│   ├── migration_service.py     ← unlock_legacy + migrate_user (decrypt CFB → re-encrypt GCM, install Argon2 hash, clear legacy_salt)
│   └── export_service.py        ← JSON export/import with Argon2-derived export key separate from vault key, MergeStrategy enum
│
├── handlers/
│   └── common.py                ← error_handler only (DMs the developer, turns the live message into "⚠️ Errore interno")
│
├── ui/                          ← single-live-message UI (see "UI: Navigator + Screens")
│   ├── navigator.py             ← Navigator: stack, live message edit/send, routing, lock, auto-close, reveal
│   ├── screen.py                ← View, Ctx, results (Go/Reveal/Lock) + helpers, Screen base class
│   ├── callbacks.py             ← Act(screen, action, arg, token) payload + NAV pseudo-screen
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
├── i18n/
│   └── it.py                    ← MESSAGES dict: Italian strings shared across services/handlers (error_internal, account_*, passphrase/session prompts, export/import, stale-alert). Screen-specific copy lives inline in `ui/screens/*.py`, not here.
│
└── telegram_utils/
    ├── md.py                    ← escape_md, code_inline (MarkdownV2)
    ├── callback_data.py         ← legacy ListPageData, kept only for unpickling old DB.pkl
    └── delete_message.py        ← schedule_delete for self-destructing secret messages

tests/
├── conftest.py                  ← fast_argon2 (autouse, sets PB_ARGON2_* low), aes_key, tmp_db_path
├── crypto/                      ← test_kdf, test_cipher (incl. hypothesis property), test_legacy_migration, test_hkdf
├── repositories/                ← test_db_migrator (v0→v1, v1→v2, pw_prefs column), test_user_repo (incl. pw_prefs round-trip), test_account_repo, test_category_repo, test_history_repo
├── services/                    ← test_result, test_password_generator (flags, ambiguous exclusion, no-duplicates, entropy), test_strength_meter, test_reuse_detector, test_auth_service, test_vault_service, test_alert_service, test_migration_service, test_export_service
├── ui/                          ← screen tests (env fixture in conftest.py, fakes in _helpers.py), test_navigator, test_wiring
└── handlers/                    ← test_smoke (Application builds with root conversation), test_markdown_escape (regression on `-`/`(`/`)`), test_daily_scan
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

The interactive generator UI lives in `ui/screens/generator.py` (`GeneratorScreen`, name `generator`):
- `on_enter` loads `PwPrefs` from DB into the screen's own `FLOW` draft (`ctx.flow("generator")`).
- `on_action` handles `toggle` (arg = flag), `len` (next text is the length, validated `MIN_LENGTH ≤ n ≤ MAX_LENGTH`), `run`, `use`, `save`, `reset`.
- `use` hands the password to the calling flow: it writes `flow[args["flow"]]["password"]` and `["step"] = args["next_step"]`, then goes back.
- The draft lives in `FLOW`, is stripped by `_SessionStrippingPersistence` and cleared on lock (does NOT survive a restart).

### MarkdownV2 escaping

`telegram_utils.md.escape_md` escapes every character in `_*[]()~`>#+-=|{}.!`. Two pitfalls that have bitten this codebase:

- Never start a list item with a raw `-` — Telegram rejects it as an unescaped reserved char. Use `•` (not reserved) or `\-`.
- When mixing escaped Italian text and `code_inline(...)` segments, escape the surrounding parens too: `escape_md(" (vecchio: ") + code_inline(old) + escape_md(")")`.

### Legacy v1 reader (`crypto/legacy.py`) — read-only

The previous bot used PBKDF2-HMAC-SHA256 (100k iter) + AES-CFB. Two quirks reproduced exactly for parity:

- `legacy_verify_passphrase(passphrase, stored_hex_hash, salt_hex)` — `bytes.fromhex(salt_hex)` → PBKDF2HMAC SHA256 100k iter, compare hex.
- `legacy_derive_key(passphrase, salt_hex)` — **`base64.b64decode(salt_hex)`** (yes, decode the hex string AS base64 — that's what v1 did because the variable was named `salt_b64` and the call site fed it the hex string directly). Result: 24-byte salt fed to PBKDF2HMAC. This quirk was a known bug in v1 that we MUST reproduce to decrypt existing data.

`LegacyCfbDecryptor.decrypt(ciphertext_b64, key) → str` decodes IV from first 16 bytes, rest is CFB ciphertext, returns utf-8 str.

### Passphrase lifecycle (security-critical)

- The passphrase is **never** persisted to disk in any form.
- When the user sends it, the Navigator deletes the inbound message immediately and `UnlockScreen.on_text` (`ui/screens/unlock.py`) routes to `register` (no user), `unlock_legacy` + `migrate_user` (user.crypto_version=1), or `unlock` (user.crypto_version=2).
- `AuthService.unlock` derives the AES key from `passphrase + salt-extracted-from-encoded-Argon2-hash` and returns a `Session`. The `Session.hmac_key` is `HKDF(aes_key, info=b"reuse-detection")`.
- Session lifetime: `autolock_minutes * 60` if >0, else 15 minutes default. `ui.jobs.schedule_autolock` schedules the job that locks the chat (`Navigator.lock`).
- `Session` is stored in `chat_data[ChatDataKey.SESSION]`. The custom `_SessionStrippingPersistence.update_chat_data` filters this key (and `LEGACY_SESSION_EXTRAS`, `FLOW`) before writing `DB.pkl`.

### Passphrase change (two-phase commit)

`AuthService.change_passphrase` is **two-phase by design**:
1. Verifies the current passphrase, derives both old and new keys, returns `Result[(Session, old_aes_key)]`. **Does NOT persist** the new hash.
2. Caller re-encrypts every vault row using `old_aes_key` → `new_aes_key`.
3. Caller invokes `AuthService.commit_passphrase_change(chat_id, new_passphrase)` which persists the new Argon2 hash.

If you reverse the order (persist first, then re-encrypt), a crash mid-rotation bricks the vault: the user's stored hash verifies the new passphrase but every ciphertext was encrypted with the old key. The two-phase split prevents that.

### Legacy migration on first unlock

When `user.crypto_version == 1`, `UnlockScreen` (`ui/screens/unlock.py`) calls `MigrationService.unlock_legacy` then `migrate_user`:
- `unlock_legacy` verifies the legacy PBKDF2 hash, derives the legacy CFB key, computes a fresh Argon2 hash + GCM key, returns a `Session` carrying both `_legacy_key` and `_new_passphrase_hash` as additional fields (regular dataclass attributes, NOT `__dict__` injection — slots dataclass blocks that).
- `migrate_user` walks every account row of that user: legacy-decrypt → GCM-encrypt with the new key → update row, then installs the new Argon2 hash and clears `legacy_salt` via `users.update_passphrase`.

### Repository conventions

- All user-facing strings are **Italian**, informal tone ("tu", short imperative). UI copy lives in the owning screen module under `ui/screens/*.py` (each screen defines its own text inline); `password_bot/i18n/it.py` `MESSAGES` holds only strings shared across services/handlers/screens (e.g. `error_internal`, passphrase/session prompts, export/import outcomes, the stale-password alert). Add a new shared string to `MESSAGES`; add a new screen-only string directly in that screen's module.
- All `chat_data` keys are members of `state.keys.ChatDataKey` enum — never raw strings.
- Repos return `*Row` dataclasses (raw, with `_enc` strings) from queries. Services decrypt `*Row` into domain objects (`Account`, etc.).
- Each repo call opens/closes its own `aiosqlite.connect` via `db.connect()` async context manager. No long-lived connection.
- Fuzzy account search uses `thefuzz.fuzz.partial_ratio` in `AccountRepo.search`; default threshold 60.
- Errors funnel through `handlers.common.error_handler` which DMs the dev (`container.dev_chat_id`) with a redacted traceback. Domain-expected failures use `Result[T]`; unexpected failures propagate.
- Lint config in `pyproject.toml` `[tool.ruff]`: line-length 100, target py313, select `E F I B UP SIM RUF`. Run `uv run ruff check src tests` before commit. Pre-commit format with `uv run ruff format src tests`.
- Test coverage gate: 60% (CI); aspirational 75%. UI screens are tested in `tests/ui/` (one module per screen group, plus `test_navigator.py` and `test_wiring.py` for the handler tree and legacy cleanup).

### UI: Navigator + Screens

- **One live message.** The bot keeps a single message with buttons (`LIVE_MESSAGE_ID`) and edits it for every screen. Slash commands delete it and send a fresh one at the bottom. User text/documents are deleted after being read. Revealed secrets are separate messages deleted after 30 s.
- **Screens** (`ui/screens/*`) subclass `Screen`: `render(ctx) -> View`, `on_action(ctx, act)`, optional `on_text` / `on_document` / `on_enter` / `render_expired`. Navigation returns `Go` (stack moves + notice/toast), `Reveal` or `Lock`. The export screen is an explicit exception: it sends the encrypted document through `ctx.bot`; live-message edits still belong to Navigator. Helpers: `open_screen`, `replace`, `back`, `refresh`, `home`, `pop_to`, `finish`.
- **Stack** frames are `Frame(name, data)`; `data` holds only ids/pages/flags/search queries. `🔙` pops (label = title of the screen below), `🏠` resets to `home`. Flows end with `finish(...)`/`pop_to(...)` so back never re-enters them.
- **Callbacks** are `Act(screen, action, arg, token)` via `arbitrary_callback_data`. Navigator stamps `token` for each render; only the current message and generation may act. Pickled payloads contain ids, indices, names and render tokens, never usernames/passwords/URLs/notes. Values picked from lists live in `FLOW` and are referenced by index. Invalid payloads/non-live messages go to Home; outdated generations only refresh the current screen, preserving a closed detail.
- **Flows** keep drafts in `ctx.flow(key)` (`ChatDataKey.FLOW`), never persisted, cleared by `FsmContext.lock()`. The generator returns a password by writing `flow[args["flow"]]["password"]` and `["step"] = args["next_step"]`.
- **Locking.** Missing or expired sessions go to `unlock`; `RESUME` stores a restartable target, never a pending action. Dependent flows return to their creation root or account detail. Autolock and updates share a per-chat runtime lock; obsolete timer deadlines cannot lock a newer session. Runtime `bot_data` is not persisted.
- **Auto-close.** A `View(expire_after=60)` (account detail) schedules `expire:<chat_id>`; if the live message still shows that render (`LIVE_TOKEN`), it becomes `render_expired()` (copy buttons disappear).
- **Styles.** `views.PRIMARY` main action, `SUCCESS` confirmations, `DANGER` destructive.

### Adding a new screen

1. Create `ui/screens/<name>.py` with a `Screen` subclass (`name`, `title`, `render`, `on_action`…).
2. Add it to the list in `ui/registry.py::build_screens`.
3. Open it from another screen with `open_screen("<name>", ...)` or from a slash command with `commands.open_command("<name>")` in `bot.py`.
4. Test it with the `env` fixture from `tests/ui/conftest.py` (real services on a temp DB) and helpers from `tests/ui/_helpers.py`.
