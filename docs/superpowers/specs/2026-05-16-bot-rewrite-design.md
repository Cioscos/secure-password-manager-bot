# Password Bot — Rewrite v2 Design

**Date:** 2026-05-16
**Branch:** `rewrite/v2`
**Author:** Claudio (with Claude)
**Status:** Approved

## 1. Scope & feature set

### Rewrite goals

- New architecture: layered package (`src/password_bot/`) with clear boundaries between handlers, services, repositories, crypto.
- Crypto upgrade: AES-CFB + PBKDF2 → AES-GCM + Argon2id (Pi Zero 2W tuned).
- Automatic legacy data migration on first unlock (no manual re-entry).
- Solid pytest test suite (crypto, repo, services, smoke handlers).

### New features

| # | Feature | Bucket |
|---|---------|--------|
| 1 | Export/Import vault (encrypted JSON file, portable) | Backup |
| 2 | ~~TOTP / 2FA codes~~ | **Removed** |
| 3 | Account categories / tags | Account ricchi |
| 4 | Free-form encrypted notes per account | Account ricchi |
| 5 | Optional URL per account | Account ricchi |
| 6 | Password history (last N versions encrypted) | Account ricchi |
| 7 | Password strength meter (zxcvbn) on input | Sicurezza |
| 8 | Stale-password alerts (configurable, default 180 days) | Sicurezza |
| 9 | Reuse detector (HMAC index) | Sicurezza |
| 10 | Inline commands `/get`, `/add`, `/copy`, `/list` (bypass menu) | UX |
| 11 | Configurable auto-lock per user (5/15/30/60 min or "never within session") | UX |
| 12 | Optional username on account creation | UX |
| 13 | Per-field edit on account view (no intermediate menu) | UX |
| 14 | New account actions: duplicate, copy single field, show password only, typed-confirm delete | UX |

### Out of scope

- Multi-device sync (manual export is the sync)
- Browser extension / Web UI
- Online breach check (HIBP) — no outbound HTTP without explicit opt-in
- File attachments
- TOTP (removed per user decision)

## 2. Module structure

```
src/password_bot/
├── __main__.py                  # entrypoint
├── config.py                    # AppConfig (paths, Argon2 params, autolock default, log)
├── bot.py                       # build_application(), DI wiring, handler registration
├── container.py                 # DI container (services, repos, crypto)
│
├── crypto/
│   ├── kdf.py                   # Argon2idKdf
│   ├── cipher.py                # GcmCipher
│   └── legacy.py                # LegacyCfbDecryptor + LegacyPbkdf2 (read-only, migration)
│
├── repositories/
│   ├── db.py                    # aiosqlite connection helper + migrations runner
│   ├── user_repo.py
│   ├── account_repo.py
│   ├── category_repo.py
│   ├── history_repo.py
│   └── migrations/              # 001_init.sql, 002_*.sql
│
├── models/
│   ├── account.py
│   ├── user.py
│   ├── category.py
│   └── password_history.py
│
├── services/
│   ├── vault_service.py
│   ├── auth_service.py
│   ├── export_service.py
│   ├── migration_service.py
│   ├── password_generator.py
│   ├── strength_meter.py
│   ├── reuse_detector.py
│   └── alert_service.py
│
├── handlers/
│   ├── common.py                # /start, /help, /stop, /lock, /cancel, error_handler
│   ├── auth.py
│   ├── account_new.py
│   ├── account_view.py
│   ├── account_edit.py
│   ├── inline_cmd.py            # /get, /add, /copy, /list
│   ├── export.py
│   └── settings.py
│
├── state/
│   ├── keys.py                  # ChatDataKey enum
│   ├── fsm.py                   # FsmContext typed wrapper over context.chat_data
│   └── conversations.py         # ConversationHandler builders
│
├── i18n/
│   └── it.py                    # MESSAGES dict + escape_md helper
│
└── telegram_utils/
    ├── keyboards.py
    ├── md.py
    └── delete_message.py

tests/
├── conftest.py                  # tmp_db, fake_user, fast_argon2, frozen_clock
├── crypto/
│   ├── test_kdf.py
│   ├── test_cipher.py
│   └── test_legacy_migration.py
├── repositories/
│   ├── test_account_repo.py
│   └── test_user_repo.py
├── services/
│   ├── test_vault_service.py
│   ├── test_auth_service.py
│   ├── test_export_service.py
│   ├── test_migration_service.py
│   ├── test_alert_service.py
│   ├── test_reuse_detector.py
│   ├── test_password_generator.py
│   └── test_strength_meter.py
└── handlers/
    ├── test_smoke.py
    └── test_inline_cmd.py
```

### Layer notes

- **DI**: `container.py` instantiates each service once, exposed via `application.bot_data['container']`. No external framework.
- **Async DB**: `aiosqlite` (PTB is already async). Each repo opens/closes connection per call.
- **State key safety**: `ChatDataKey` enum prevents typos in `chat_data` keys.
- **i18n centralized**: all Italian strings in `it.py`. Future EN swap without touching handlers.

## 3. Data model & DB schema

### Schema (`migrations/001_init.sql`)

```sql
CREATE TABLE schema_version (version INTEGER PRIMARY KEY);

CREATE TABLE users (
    chat_id                       INTEGER PRIMARY KEY,
    name                          TEXT NOT NULL,
    passphrase_hash               TEXT NOT NULL,      -- argon2id encoded
    autolock_minutes              INTEGER NOT NULL DEFAULT 15,    -- 0 = never within session
    autolock_reset_on_activity    INTEGER NOT NULL DEFAULT 1,     -- bool
    alert_days                    INTEGER NOT NULL DEFAULT 180,
    crypto_version                INTEGER NOT NULL DEFAULT 2,     -- 1=legacy CFB/PBKDF2, 2=GCM/Argon2
    legacy_salt                   TEXT,                            -- set only if crypto_version=1
    created_at                    INTEGER NOT NULL,
    updated_at                    INTEGER NOT NULL
);

CREATE TABLE categories (
    id        TEXT PRIMARY KEY,
    chat_id   INTEGER NOT NULL REFERENCES users(chat_id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    color     TEXT,
    UNIQUE(chat_id, name)
);

CREATE TABLE accounts (
    id                   TEXT PRIMARY KEY,
    chat_id              INTEGER NOT NULL REFERENCES users(chat_id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,
    username_enc         TEXT,                  -- NULLABLE
    password_enc         TEXT NOT NULL,
    url_enc              TEXT,                  -- NULLABLE
    note_enc             TEXT,                  -- NULLABLE, multi-line
    category_id          TEXT REFERENCES categories(id) ON DELETE SET NULL,
    password_hmac        TEXT NOT NULL,         -- HMAC-SHA256 of plaintext password (reuse detection)
    crypto_version       INTEGER NOT NULL DEFAULT 2,
    password_changed_at  INTEGER NOT NULL,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
);

CREATE INDEX idx_accounts_chat ON accounts(chat_id);
CREATE INDEX idx_accounts_name ON accounts(chat_id, name);
CREATE INDEX idx_accounts_category ON accounts(category_id);

CREATE TABLE password_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    password_enc    TEXT NOT NULL,
    crypto_version  INTEGER NOT NULL DEFAULT 2,
    replaced_at     INTEGER NOT NULL
);

CREATE INDEX idx_history_account ON password_history(account_id, replaced_at);

INSERT INTO schema_version (version) VALUES (1);
```

### Key decisions

- `username_enc`, `url_enc`, `note_enc` NULLABLE → username finally optional.
- `password_hmac` instead of plain SHA-256: HMAC keyed with `HKDF(aes_key, info=b"reuse-detection")`. Without passphrase the hash leaks nothing about plaintext.
- `password_history` retention `HISTORY_MAX=5` (in `config.py`). Pruned on every password update.
- `crypto_version` per row: enables lazy migration. Legacy rows decrypted with `LegacyCfbDecryptor`, immediately re-encrypted GCM, version flipped to 2.
- `schema_version` table tracks DB schema upgrades.

## 4. Crypto & passphrase lifecycle

### Algorithms

| Component | Algorithm | Parameters |
|---|---|---|
| KDF passphrase hash | Argon2id (`argon2-cffi`) | m=64 MiB, t=3, p=1, hash_len=32, salt_len=16 |
| KDF derive AES key | Argon2id (low-cost) | m=32 MiB, t=2, p=1, hash_len=32 |
| Cipher | AES-256-GCM | nonce 12 byte random, tag 16 byte |
| Reuse hash | HMAC-SHA256 | key = HKDF-SHA256(aes_key, info=b"reuse-detection") |

**Pi Zero 2W targets** (verified at boot benchmark): Argon2 verify ~300–500 ms (m=64 MiB), derive_key ~150 ms (m=32 MiB). Acceptable for once-per-session unlock.

### Wire format (GCM)

```
b64( crypto_version_byte(1) || nonce(12) || ciphertext || tag(16) )
```

`crypto_version_byte = 2`. Legacy rows discriminated by DB `crypto_version` column (not by prefix byte).

### Passphrase lifecycle

```
user sends passphrase
   │
   ├─ delete msg immediately (handlers.auth.unlock)
   ├─ AuthService.unlock(passphrase):
   │     ├─ verify Argon2 vs users.passphrase_hash
   │     ├─ derive_key(passphrase, user_salt) → aes_key
   │     ├─ derive HMAC key (HKDF from aes_key)
   │     └─ store in FsmContext.session = {aes_key, hmac_key, expires_at}
   ├─ schedule job_queue.run_once(autolock_minutes) → AuthService.lock(chat_id)
   └─ if user.crypto_version=1 → MigrationService.migrate_user(...)
```

`FsmContext.session` lives in `context.chat_data[ChatDataKey.SESSION]`. A custom `PicklePersistence` filter strips `SESSION` before writing `DB.pkl` → keys never persist to disk.

### Lock

- `/lock` manual → clear session, cancel autolock job.
- Autolock job fires → idem.
- Activity reset (configurable, default ON): each user message reschedules the autolock job.

### Passphrase change (re-crypt)

```
1. user → current passphrase   (verify)
2. user → new passphrase x2    (match)
3. derive new_key
4. BEGIN IMMEDIATE
5. SELECT * accounts WHERE chat_id=?
6. for each row: decrypt(old_key) → encrypt(new_key) → UPDATE
7. UPDATE users.passphrase_hash = argon2(new_passphrase), users.crypto_version=2
8. COMMIT
9. context.chat_data session ← new keys
```

Single transaction. Pi Zero 2W tolerates this for N < 1000 accounts (target user has well under that).

## 5. State machine & navigation

### Problem with current bot

Nested `ConversationHandler` trees → users get stuck, `/stop` is the only escape, state lingers.

### New model: explicit screen stack

```python
class Screen(TypedDict):
    name: Literal["menu", "account_list", "account_view", "account_edit",
                  "account_new", "search", "settings", "export", ...]
    data: dict  # screen payload (e.g. account_id, field name)

# chat_data layout
{
    NAV_STACK: [Screen(name="menu"), Screen(name="account_view", data={"id": "..."})],
    SESSION: {aes_key, hmac_key, expires_at} | None,
    PENDING_INPUT: {field: "password", target_id: "..."} | None,
}
```

Single PTB `ConversationHandler` after `/start`. One `MessageHandler` + one `CallbackQueryHandler` dispatch on `NAV_STACK.top().name`. No nesting.

### Global commands

| Command | Effect |
|---|---|
| `/start` | Push menu screen (clears stack) |
| `/menu` | Pop down to menu |
| `/back` | Pop one screen |
| `/cancel` | Clear `PENDING_INPUT`, keep screen |
| `/lock` | Clear session, return to unlock |
| `/help` | Show commands available in current screen |
| `/stop` | Full reset, kill conversation |

Every screen renders an explicit `🔙 Indietro` button + `🏠 Menu` button when stack depth > 1.

### Inline shortcuts (bypass menu)

| Command | Behavior |
|---|---|
| `/get NAME` | Fuzzy search. Single match → show account. Multi → results screen |
| `/add` | Push `account_new` screen |
| `/list [categoria]` | Show filtered list |
| `/copy NAME` | Send only password as separate message (auto-delete 30 s) |

All require active session. Without session, prompt passphrase + stash command in `PENDING_INPUT`, replay after unlock.

### Redesigned account_view (per-field edit)

```
🔐 GitHub
👤 username: claudio       [✏️] [📋]
🔑 password: ••••••••       [👁] [✏️] [📋] [🎲]
🌐 url: https://github.com  [✏️] [📋] [🗑]
📝 note: 2 righe            [👁] [✏️]
🏷  categoria: Lavoro        [✏️]
📅 password vecchia di 245 giorni ⚠️

[🔁 Duplica]  [🗑 Elimina account]  [🔙]
```

`[✏️]` on a field → set `PENDING_INPUT={field, id}` + prompt with old value masked appropriately. Save directly on input; no intermediate confirmation except for delete account.

`[🎲]` on password → password-generator sub-flow → preview → confirm/regenerate → save.

`[👁]` on password/note → temp message with plain value (auto-delete 30 s, configurable).

## 6. Feature implementation details

### F1. Export/Import vault

**Export** (`/export`):
1. Prompt confirm + optional separate export passphrase.
2. Decrypt all accounts; re-encrypt with `export_key` derived from export passphrase (separate Argon2 params).
3. Build JSON:
   ```json
   {
     "format": "password-bot-vault",
     "version": 1,
     "exported_at": "2026-05-16T...",
     "kdf": {"name": "argon2id", "m": 65536, "t": 3, "p": 1, "salt": "b64"},
     "cipher": "aes-256-gcm",
     "items": [
       {"name": "GitHub", "username_enc": "...", "password_enc": "...",
        "url_enc": null, "note_enc": null,
        "category": "Lavoro", "password_changed_at": 1700000000}
     ],
     "categories": ["Lavoro", "Personale"]
   }
   ```
4. Bot sends `vault-YYYYMMDD-HHMM.json` document. Auto-delete the message after 60 s.

**Import** (`/import`):
1. User uploads JSON.
2. Validate schema (pydantic).
3. Prompt export passphrase (the one used at export time, not the local vault passphrase).
4. Decrypt items.
5. Per-batch merge strategy prompt: `[Skip esistenti] [Sovrascrivi] [Mantieni entrambi]`.
6. Re-encrypt with local key, batch INSERT.

### F3. Categories

- Simple CRUD via `categories_manage` screen.
- Default category: none (`category_id = NULL`).
- Filter list: `/list lavoro` or category button on list screen.
- Legacy migration: no category assigned (NULL).

### F4. Notes

- `note_enc` multi-line, up to 4000 chars. `[👁]` shows plaintext (auto-delete 60 s).

### F5. URL

- `url_enc` optional. Render as MarkdownV2 link (escaped). `[📋]` copies raw.

### F6. Password history

- Retention `HISTORY_MAX=5` (`config.py`).
- Trigger on `vault_service.update_password(account_id, new_password)`:
  1. Read current `password_enc, crypto_version`.
  2. INSERT into `password_history`.
  3. DELETE rows beyond N most recent for that account.
  4. UPDATE accounts: new `password_enc`, new `password_hmac`, `password_changed_at=now`.
- View via `[📜 storico (3)]` button → history screen → list with "vecchia di N giorni" + `[👁] [📋]` per entry. Never auto-promote to current (explicit edit required).

### F7. Strength meter (zxcvbn)

- `zxcvbn-python`, ~2–5 ms per check on Pi Zero.
- On password input (manual or post-generator):
  ```
  Forza: 🟢🟢🟢🟢🟡 (4/5 — Forte)
  Tempo crack stimato: 3 secoli
  Suggerimenti: nessuno
  ```
- Score < 3 → warning + `[Usa comunque] [Genera forte]`.

### F8. Stale-password alerts

- `users.alert_days` (default 180).
- `alert_service.daily_scan()` registered via `application.job_queue.run_daily(time=09:00)`.
- Scan: `SELECT id, name FROM accounts WHERE chat_id=? AND password_changed_at < now - alert_days*86400`.
- DM user: "N password sono più vecchie di X giorni. /list_stale per vederle".
- `/list_stale` screen with shortcuts to `[✏️ password]`.

### F9. Reuse detector

- HMAC plaintext with `hmac_key` derived at unlock.
- On unlock: load `SELECT id, name, password_hmac` into `Dict[hmac, List[account_id]]`.
- On add/edit: compare new hmac against index. Match ≥ 1 → warning "Questa password è usata anche per: GitHub, Twitter. Procedere?".
- `/list_reused` screen shows clusters of accounts sharing a password.

### F10. Inline commands

Implemented as standalone `CommandHandler`s independent of nav stack. Honor session: redirect to unlock with `PENDING_INPUT` if session is missing.

### F11. Configurable auto-lock

- `users.autolock_minutes`: 0 (never within session), 5, 15, 30, 60.
- `users.autolock_reset_on_activity` (default ON).
- Settings screen exposes both.

### F12. Optional username

- Schema NULLABLE. UI: in `account_new` username step, button `[Salta]` → `username_enc=NULL`. `account_view` renders `username: —` when NULL.

### F13. Per-field edit

Covered in Section 5 (`account_view` with per-field buttons). No intermediate edit menu.

### F14. New account actions

| Action | Behavior |
|---|---|
| Duplicate | Create copy named `<name> (copia)`, same password (counted in reuse), category preserved |
| Copy single field | Temp message with that field only (auto-delete 30 s) |
| Show password only | Same, formatted as `<code>password</code>` MarkdownV2 |
| Delete with typed confirm | Step: "Scrivi `ELIMINA` per confermare" — no yes/no button → prevents accidental tap |

## 7. Error handling & logging

### Layer policy

| Layer | Strategy |
|---|---|
| `crypto/` | Raise `CryptoError` subtypes (`DecryptionError`, `InvalidPassphraseError`, `LegacyMigrationError`). Never swallow |
| `repositories/` | Raise `RepositoryError` (wraps `aiosqlite.Error`). Connection failure propagates |
| `services/` | Catch expected domain errors, return `Result[T]`. Unexpected errors propagate |
| `handlers/` | Catch `DomainError` (user-safe message). Everything else bubbles to `error_handler` |

### Result type

```python
@dataclass
class Result[T]:
    value: T | None
    error: DomainError | None
    @property
    def ok(self) -> bool: return self.error is None
```

`AuthService.unlock` returns `Result[Session]` with `error=InvalidPassphraseError`. Handler distinguishes "wrong passphrase" (user message) from exceptions (telemetry).

### Global `error_handler` (PTB)

- Catches unhandled exceptions in any handler.
- Logs full traceback to `password_bot.log`.
- DMs `DevId` with **redacted** traceback:
  - Strip: `chat_data`, `user_data`, raw `Update` body (may contain passphrase), KEYRING values.
  - Include: exception type, file:line, function, timestamp, chat_id.
- User reply: "Errore interno. Sviluppatore notificato. /menu per ricominciare." Never expose stack trace to user.

### Logging

- `structlog` (JSON line format).
- Standard fields: `ts, level, event, chat_id, screen, op`.
- Forbidden in logs: passphrase, plain password, derived keys.
- File rotation: `RotatingFileHandler` 5 MB × 3 backups.
- Levels:
  - DEBUG (off in prod): nav transitions, repo queries
  - INFO: unlock, lock, account CRUD (no values), migration progress
  - WARN: passphrase failures, single-row decrypt failures, validation rejects
  - ERROR: unhandled exceptions, DB connection loss, KDF parameter mismatch

### Redaction

Custom `LoggerAdapter` filters known sensitive keys from kwargs.

## 8. Testing strategy

### Stack

- `pytest`, `pytest-asyncio` (PTB is async).
- `pytest-cov` — coverage gate ≥ 75 % overall (CI fails below); aspirational ≥ 80 % on `crypto/`, `services/`, `repositories/`.
- `freezegun` for alert / autolock tests.
- `hypothesis` for crypto property tests.
- PTB `ApplicationBuilder` for smoke handler tests with dummy bot token.

### Fixtures (`conftest.py`)

```python
@pytest.fixture
async def tmp_db(tmp_path):
    db_path = tmp_path / "test.db"
    await migrate_to_latest(db_path)
    yield db_path

@pytest.fixture
def fake_user():
    return User(chat_id=42, name="test", passphrase_hash=..., ...)

@pytest.fixture
def aes_key():
    return secrets.token_bytes(32)

@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch):
    # minimal params for tests (m=8 MiB, t=1)
    monkeypatch.setattr("password_bot.config.ARGON2_HASH", Argon2Params(m=8192, t=1, p=1))
```

### Test coverage

**`tests/crypto/`**
- `test_kdf.py`: hash/verify round-trip, wrong passphrase → False, derive_key deterministic, salt sensitivity.
- `test_cipher.py`: encrypt→decrypt round-trip, tamper byte → `InvalidTag`, nonce uniqueness over 10 000 iter, empty plaintext.
- `test_legacy_migration.py`: legacy vault fixture → unlock → re-encrypted GCM → re-unlock → same plaintext. Mid-migration crash → resumes.
- Property test (hypothesis): `decrypt(encrypt(p, k), k) == p` for any p (bytes < 4 KB).

**`tests/repositories/`**
- `test_account_repo.py`: CRUD, fuzzy search threshold, history retention=5, cascade on user delete.
- `test_user_repo.py`: create/update_passphrase, autolock settings update.

**`tests/services/`**
- `test_vault_service.py`: add with NULL username, edit password → history push + hmac update, duplicate account, delete cascade.
- `test_auth_service.py`: correct unlock → session, wrong → `InvalidPassphraseError`, autolock timer fires → session cleared, reset-on-activity OFF → no reschedule.
- `test_export_service.py`: export → import round-trip, schema invalid → reject, wrong export passphrase → `InvalidPassphraseError`, merge strategies.
- `test_migration_service.py`: legacy user → migrate → all `crypto_version=2`, idempotence (2 calls same result), mid-migration crash via mock → resume.
- `test_alert_service.py`: frozen clock, password 200 days old + threshold 180 → in stale list.
- `test_reuse_detector.py`: 3 accounts same password → cluster of 3; edit 1 → cluster drops to 2.
- `test_password_generator.py`: length param, charset constraint, entropy bounds.
- `test_strength_meter.py`: weak/medium/strong vectors.

**`tests/handlers/`**
- `test_smoke.py`: build app, send `/start`, `/help`, `/lock`, verify reply.
- `test_inline_cmd.py`: `/get NAME` single match → masked-field reply; multi → results screen; no match → "non trovato".

### CI

`.github/workflows/test.yml`:
```yaml
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv sync --dev
      - run: uv run pytest --cov=src/password_bot --cov-fail-under=75
```

### Linting

`ruff` (lint + format). CI step `uv run ruff check && uv run ruff format --check`.

## 9. Branch, deployment, rollout

### Branch

- Name: `rewrite/v2`
- Origin: `master` HEAD (`3f6c464`)
- All rewrite work lives on `rewrite/v2`. PR to `master` when ready.

### Deployment (Pi Zero 2W)

- Runtime stays local (no Docker change).
- Startup command unchanged: `KEYRING=./keys uv run -m password_bot`.
- `__main__.py` replaces `src/main.py` as entrypoint. Old `src/main.py` deleted in rewrite.
- `accounts.db` path unchanged.
- Argon2 params tuned for Pi Zero (m=64 MiB hash, m=32 MiB derive). Override via env: `PB_ARGON2_M`, `PB_ARGON2_T`.

### Rollout flow

```
1. user pulls rewrite/v2
2. uv sync → installs argon2-cffi, aiosqlite, zxcvbn-python, structlog, ruff (dev)
3. KEYRING=./keys uv run -m password_bot
4. boot:
   a. config load
   b. aiosqlite connect
   c. read schema_version:
      - missing/0 + accounts.db exists → run legacy upgrade migration:
        - rename users.salted_hash → users.passphrase_hash (sqlite: CREATE NEW + COPY + DROP + RENAME)
        - ADD users.autolock_minutes (DEFAULT 15), autolock_reset_on_activity (DEFAULT 1),
              alert_days (DEFAULT 180), crypto_version (=1 for existing rows),
              legacy_salt (copied from old users.salt)
        - ADD accounts.url_enc, note_enc, category_id, password_hmac (NULL until first unlock),
              crypto_version (=1), password_changed_at (= created_at fallback or boot timestamp)
        - CREATE TABLE categories, password_history
        - INSERT schema_version=1
      - =1 → up to date
5. start bot
6. user sends /start
7. user sends passphrase → unlock_legacy path:
   a. AuthService detects user.crypto_version=1 → verify with legacy PBKDF2 path
   b. derive AES key with legacy PBKDF2 → decrypt legacy accounts
   c. background MigrationService re-encrypts all rows GCM+Argon2, replaces passphrase_hash with Argon2, fills password_hmac
   d. on completion: users.crypto_version=2, legacy_salt cleared
8. subsequent unlocks use new path only
```

### Pre-rollout backup (user-facing instruction in README)

```
cp accounts.db accounts.db.bak
cp DB.pkl DB.pkl.bak
```

Mandatory step before first switch to `rewrite/v2`.

### Legacy `DB.pkl`

- Legacy `chat_data` keys (`TEMP_SAVED_ACCOUNT`, `TEMP_KEY`, `TEMP_PASSPHRASE`, …) ignored by new bot.
- On `/start`, ConversationHandler rebuilds state from scratch.
- Boot cleanup: log warning + clear legacy keys if found.

### Dependencies

```toml
[project]
dependencies = [
    "python-telegram-bot[job-queue]",
    "cryptography",
    "argon2-cffi",          # new — Argon2id KDF
    "aiosqlite",            # new — async DB
    "thefuzz",
    "python-Levenshtein",
    "zxcvbn-python",        # new — strength meter
    "structlog",            # new — structured logging
    "pydantic",             # new — export schema validation
]

[dependency-groups]
dev = [
    "pytest",
    "pytest-asyncio",
    "pytest-cov",
    "freezegun",
    "hypothesis",
    "ruff",
]
```

All pure-Python or with ARM wheels available → Pi Zero 2W install OK.

### Rollback plan

If rewrite proves broken:
- `git checkout master`
- Restore `accounts.db.bak`, `DB.pkl.bak`.
- Schema migration runs inside a single transaction (rollback on failure).
- Crypto migration is per-row idempotent (Section 4), so partial migration is safe to resume or roll back.
