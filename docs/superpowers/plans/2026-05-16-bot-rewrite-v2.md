# Password Bot Rewrite v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the Telegram password bot on branch `rewrite/v2` with a layered package architecture, AES-GCM + Argon2id crypto (with lazy migration from legacy CFB/PBKDF2 data), screen-stack navigation, and a set of new features (export/import, categories, notes, URL, password history, strength meter, stale-password alerts, reuse detector, inline commands, configurable auto-lock, optional username, per-field editing, richer account actions), backed by a pytest suite.

**Architecture:** Single Python package `src/password_bot/` with clear layers (`crypto/`, `repositories/`, `models/`, `services/`, `handlers/`, `state/`, `i18n/`, `telegram_utils/`). Async I/O via `aiosqlite` + `python-telegram-bot`. A lightweight DI container (`container.py`) wires services once into `application.bot_data`. Legacy data is migrated lazily on first unlock; schema is upgraded once at boot via a tiny migrations runner.

**Tech Stack:** Python 3.13, `python-telegram-bot[job-queue]`, `cryptography` (AES-GCM, HKDF, HMAC), `argon2-cffi` (Argon2id), `aiosqlite`, `pydantic` (export schema), `zxcvbn-python`, `thefuzz` + `python-Levenshtein` (fuzzy search), `structlog`. Dev: `pytest`, `pytest-asyncio`, `pytest-cov`, `freezegun`, `hypothesis`, `ruff`.

**Spec:** `docs/superpowers/specs/2026-05-16-bot-rewrite-design.md`. Read it before starting.

---

## Conventions used throughout

- All file paths are relative to repo root unless absolute.
- Italian user-facing strings live in `src/password_bot/i18n/it.py`. Never hardcode user-facing strings in handlers; import from `MESSAGES`.
- Every `chat_data` key is a member of `ChatDataKey` enum — never raw strings.
- Repos return either `*Row` dataclasses (raw, with `_enc` strings) or domain objects (`Account`, `User`, `Category`, `PasswordHistoryEntry`). Services decrypt `*Row` → domain.
- `Result[T]` is a generic dataclass: `value: T | None`, `error: DomainError | None`, `ok: bool` property. Defined once in `services/result.py` and reused.
- Every test uses the `fast_argon2` autouse fixture (m=8 MiB, t=1) to keep the suite fast.
- TDD: failing test first, minimal impl, refactor, commit. Each task ends with a commit.
- Commit messages follow the existing repo style: short imperative subject, no scope prefix.

---

## File structure (target)

```
src/password_bot/
├── __init__.py
├── __main__.py
├── config.py
├── bot.py
├── container.py
├── crypto/
│   ├── __init__.py
│   ├── kdf.py
│   ├── cipher.py
│   └── legacy.py
├── repositories/
│   ├── __init__.py
│   ├── db.py
│   ├── migrator.py
│   ├── user_repo.py
│   ├── account_repo.py
│   ├── category_repo.py
│   ├── history_repo.py
│   └── migrations/
│       ├── 001_init.sql
│       └── 002_legacy_upgrade.sql
├── models/
│   ├── __init__.py
│   ├── account.py
│   ├── user.py
│   ├── category.py
│   └── password_history.py
├── services/
│   ├── __init__.py
│   ├── result.py
│   ├── errors.py
│   ├── password_generator.py
│   ├── strength_meter.py
│   ├── reuse_detector.py
│   ├── auth_service.py
│   ├── vault_service.py
│   ├── alert_service.py
│   ├── migration_service.py
│   └── export_service.py
├── handlers/
│   ├── __init__.py
│   ├── common.py
│   ├── auth.py
│   ├── account_new.py
│   ├── account_view.py
│   ├── account_edit.py
│   ├── inline_cmd.py
│   ├── export.py
│   ├── settings.py
│   └── dispatcher.py
├── state/
│   ├── __init__.py
│   ├── keys.py
│   ├── fsm.py
│   └── conversations.py
├── i18n/
│   ├── __init__.py
│   └── it.py
└── telegram_utils/
    ├── __init__.py
    ├── md.py
    ├── keyboards.py
    └── delete_message.py

tests/
├── conftest.py
├── crypto/
│   ├── __init__.py
│   ├── test_kdf.py
│   ├── test_cipher.py
│   └── test_legacy_migration.py
├── repositories/
│   ├── __init__.py
│   ├── test_db_migrator.py
│   ├── test_user_repo.py
│   ├── test_account_repo.py
│   ├── test_category_repo.py
│   └── test_history_repo.py
├── services/
│   ├── __init__.py
│   ├── test_password_generator.py
│   ├── test_strength_meter.py
│   ├── test_reuse_detector.py
│   ├── test_auth_service.py
│   ├── test_vault_service.py
│   ├── test_alert_service.py
│   ├── test_migration_service.py
│   └── test_export_service.py
└── handlers/
    ├── __init__.py
    ├── test_smoke.py
    └── test_inline_cmd.py
```

---

## Phase 0 — Bootstrap

### Task 0.1: Update `pyproject.toml` with new dependencies

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Replace `[project]` dependencies + add `[dependency-groups]`**

Replace the existing `[project]` table contents and append a `[dependency-groups]` table so the file reads:

```toml
[project]
name = "password-bot"
version = "0.2.0"
requires-python = ">=3.13"
dependencies = [
    "python-telegram-bot[job-queue]",
    "cryptography",
    "argon2-cffi",
    "aiosqlite",
    "thefuzz",
    "python-Levenshtein",
    "zxcvbn-python",
    "structlog",
    "pydantic",
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

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
pythonpath = ["src"]

[tool.ruff]
line-length = 100
target-version = "py313"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "SIM", "RUF"]
ignore = ["E501"]
```

- [ ] **Step 2: Sync deps**

Run: `uv sync --dev`
Expected: lockfile updates, all packages install without error.

- [ ] **Step 3: Verify pytest is callable**

Run: `uv run pytest --version`
Expected: a pytest version is printed (no traceback).

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "Add v2 deps and pyproject tool config"
```

---

### Task 0.2: Create the package skeleton

**Files:**
- Create: `src/password_bot/__init__.py`
- Create: `src/password_bot/crypto/__init__.py`
- Create: `src/password_bot/repositories/__init__.py`
- Create: `src/password_bot/repositories/migrations/.gitkeep`
- Create: `src/password_bot/models/__init__.py`
- Create: `src/password_bot/services/__init__.py`
- Create: `src/password_bot/handlers/__init__.py`
- Create: `src/password_bot/state/__init__.py`
- Create: `src/password_bot/i18n/__init__.py`
- Create: `src/password_bot/telegram_utils/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/crypto/__init__.py`
- Create: `tests/repositories/__init__.py`
- Create: `tests/services/__init__.py`
- Create: `tests/handlers/__init__.py`

- [ ] **Step 1: Create every `__init__.py` listed above with a single line**

Each file contains exactly:
```python
"""password_bot package."""
```
(test `__init__.py` files may be empty.)

- [ ] **Step 2: Verify import works**

Run: `uv run python -c "import password_bot; print('ok')"`
Expected: `ok`

- [ ] **Step 3: Commit**

```bash
git add src/password_bot tests/__init__.py tests/crypto/__init__.py tests/repositories/__init__.py tests/services/__init__.py tests/handlers/__init__.py
git commit -m "Add password_bot package skeleton"
```

---

### Task 0.3: Base `conftest.py`

**Files:**
- Create: `tests/conftest.py`

- [ ] **Step 1: Write `conftest.py`**

```python
"""Shared pytest fixtures."""
from __future__ import annotations

import secrets
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch):
    """Use minimal Argon2 params in tests so the suite stays fast."""
    monkeypatch.setenv("PB_ARGON2_M", "8192")
    monkeypatch.setenv("PB_ARGON2_T", "1")
    monkeypatch.setenv("PB_ARGON2_P", "1")
    monkeypatch.setenv("PB_ARGON2_DERIVE_M", "8192")
    monkeypatch.setenv("PB_ARGON2_DERIVE_T", "1")


@pytest.fixture
def aes_key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"
```

- [ ] **Step 2: Verify pytest collects 0 tests cleanly**

Run: `uv run pytest -q`
Expected: `no tests ran` (exit code 5 is OK at this stage).

- [ ] **Step 3: Commit**

```bash
git add tests/conftest.py
git commit -m "Add base pytest conftest with fast Argon2 fixture"
```

---

### Task 0.4: Ruff lint baseline

**Files:**
- Modify: `pyproject.toml` (already done in 0.1)

- [ ] **Step 1: Run ruff on the empty package**

Run: `uv run ruff check src tests`
Expected: `All checks passed!` (or zero findings).

- [ ] **Step 2: Run ruff formatter check**

Run: `uv run ruff format --check src tests`
Expected: no diff reported.

No commit needed — this is a verification step.

---

## Phase 1 — Config and models

### Task 1.1: `config.py`

**Files:**
- Create: `src/password_bot/config.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write failing test**

`tests/test_config.py`:
```python
import os

from password_bot.config import AppConfig, Argon2Params


def test_argon2_defaults_when_env_unset(monkeypatch):
    for var in ("PB_ARGON2_M", "PB_ARGON2_T", "PB_ARGON2_P"):
        monkeypatch.delenv(var, raising=False)
    p = Argon2Params.hash_params_from_env()
    assert p.memory_cost == 65536
    assert p.time_cost == 3
    assert p.parallelism == 1


def test_argon2_overrides_from_env(monkeypatch):
    monkeypatch.setenv("PB_ARGON2_M", "32768")
    monkeypatch.setenv("PB_ARGON2_T", "2")
    monkeypatch.setenv("PB_ARGON2_P", "2")
    p = Argon2Params.hash_params_from_env()
    assert (p.memory_cost, p.time_cost, p.parallelism) == (32768, 2, 2)


def test_app_config_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYRING", str(tmp_path / "keys"))
    cfg = AppConfig.load(base_dir=tmp_path)
    assert cfg.db_path == tmp_path / "accounts.db"
    assert cfg.pkl_path == tmp_path / "DB.pkl"
    assert cfg.log_path == tmp_path / "password_bot.log"
    assert cfg.keyring_dir == tmp_path / "keys"
```

- [ ] **Step 2: Run test (should fail with ImportError)**

Run: `uv run pytest tests/test_config.py -v`
Expected: ImportError / ModuleNotFoundError on `password_bot.config`.

- [ ] **Step 3: Implement `config.py`**

```python
"""Application configuration loaded from env and a base dir."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


@dataclass(frozen=True)
class Argon2Params:
    memory_cost: int
    time_cost: int
    parallelism: int
    hash_len: int = 32
    salt_len: int = 16

    @classmethod
    def hash_params_from_env(cls) -> "Argon2Params":
        return cls(
            memory_cost=_env_int("PB_ARGON2_M", 65536),
            time_cost=_env_int("PB_ARGON2_T", 3),
            parallelism=_env_int("PB_ARGON2_P", 1),
        )

    @classmethod
    def derive_params_from_env(cls) -> "Argon2Params":
        return cls(
            memory_cost=_env_int("PB_ARGON2_DERIVE_M", 32768),
            time_cost=_env_int("PB_ARGON2_DERIVE_T", 2),
            parallelism=_env_int("PB_ARGON2_P", 1),
        )


@dataclass(frozen=True)
class AppConfig:
    base_dir: Path
    db_path: Path
    pkl_path: Path
    log_path: Path
    keyring_dir: Path
    argon2_hash: Argon2Params
    argon2_derive: Argon2Params
    history_max: int = 5
    autolock_minutes_default: int = 15
    alert_days_default: int = 180

    @classmethod
    def load(cls, base_dir: Path | None = None) -> "AppConfig":
        base = (base_dir or Path.cwd()).resolve()
        keyring_raw = os.environ.get("KEYRING")
        if not keyring_raw:
            raise RuntimeError("KEYRING env var is required (path to keys directory)")
        keyring = Path(keyring_raw).resolve()
        return cls(
            base_dir=base,
            db_path=base / "accounts.db",
            pkl_path=base / "DB.pkl",
            log_path=base / "password_bot.log",
            keyring_dir=keyring,
            argon2_hash=Argon2Params.hash_params_from_env(),
            argon2_derive=Argon2Params.derive_params_from_env(),
        )
```

- [ ] **Step 4: Run test (should pass)**

Run: `uv run pytest tests/test_config.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/config.py tests/test_config.py
git commit -m "Add AppConfig and Argon2Params with env overrides"
```

---

### Task 1.2: Domain models

**Files:**
- Create: `src/password_bot/models/account.py`
- Create: `src/password_bot/models/user.py`
- Create: `src/password_bot/models/category.py`
- Create: `src/password_bot/models/password_history.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write failing test**

`tests/test_models.py`:
```python
from password_bot.models.account import Account, AccountRow
from password_bot.models.category import Category
from password_bot.models.password_history import PasswordHistoryEntry
from password_bot.models.user import User


def test_account_minimum_fields():
    a = Account(
        id="abc",
        chat_id=1,
        name="GitHub",
        username=None,
        password="pw",
        url=None,
        note=None,
        category_id=None,
        password_hmac="hmac",
        crypto_version=2,
        password_changed_at=10,
        created_at=10,
        updated_at=10,
    )
    assert a.username is None
    assert a.password == "pw"


def test_account_row_holds_encrypted_strings():
    r = AccountRow(
        id="abc",
        chat_id=1,
        name="GitHub",
        username_enc=None,
        password_enc="b64",
        url_enc=None,
        note_enc=None,
        category_id=None,
        password_hmac="hmac",
        crypto_version=2,
        password_changed_at=10,
        created_at=10,
        updated_at=10,
    )
    assert r.username_enc is None
    assert r.password_enc == "b64"


def test_user_defaults():
    u = User(
        chat_id=42,
        name="me",
        passphrase_hash="$argon2id$...",
        autolock_minutes=15,
        autolock_reset_on_activity=True,
        alert_days=180,
        crypto_version=2,
        legacy_salt=None,
        created_at=10,
        updated_at=10,
    )
    assert u.autolock_reset_on_activity is True


def test_category_and_history():
    c = Category(id="cat1", chat_id=1, name="Work", color=None)
    h = PasswordHistoryEntry(
        id=1, account_id="abc", password_enc="b64", crypto_version=2, replaced_at=10
    )
    assert c.name == "Work"
    assert h.account_id == "abc"
```

- [ ] **Step 2: Run test (ImportError expected)**

Run: `uv run pytest tests/test_models.py -v`

- [ ] **Step 3: Implement models**

`src/password_bot/models/account.py`:
```python
from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Account:
    """Decrypted, domain-level account."""
    id: str
    chat_id: int
    name: str
    username: str | None
    password: str
    url: str | None
    note: str | None
    category_id: str | None
    password_hmac: str
    crypto_version: int
    password_changed_at: int
    created_at: int
    updated_at: int


@dataclass(slots=True)
class AccountRow:
    """Raw DB row — all secret fields still encrypted."""
    id: str
    chat_id: int
    name: str
    username_enc: str | None
    password_enc: str
    url_enc: str | None
    note_enc: str | None
    category_id: str | None
    password_hmac: str
    crypto_version: int
    password_changed_at: int
    created_at: int
    updated_at: int
```

`src/password_bot/models/user.py`:
```python
from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class User:
    chat_id: int
    name: str
    passphrase_hash: str
    autolock_minutes: int
    autolock_reset_on_activity: bool
    alert_days: int
    crypto_version: int
    legacy_salt: str | None
    created_at: int
    updated_at: int
```

`src/password_bot/models/category.py`:
```python
from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Category:
    id: str
    chat_id: int
    name: str
    color: str | None
```

`src/password_bot/models/password_history.py`:
```python
from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class PasswordHistoryEntry:
    id: int
    account_id: str
    password_enc: str
    crypto_version: int
    replaced_at: int
```

- [ ] **Step 4: Run test (should pass)**

Run: `uv run pytest tests/test_models.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/models tests/test_models.py
git commit -m "Add Account, User, Category, PasswordHistoryEntry models"
```

---

## Phase 2 — Crypto

### Task 2.1: Argon2id KDF

**Files:**
- Create: `src/password_bot/crypto/kdf.py`
- Create: `tests/crypto/test_kdf.py`

- [ ] **Step 1: Write failing test**

```python
import secrets

import pytest

from password_bot.config import Argon2Params
from password_bot.crypto.kdf import Argon2idKdf


@pytest.fixture
def kdf():
    return Argon2idKdf(
        hash_params=Argon2Params(memory_cost=8192, time_cost=1, parallelism=1),
        derive_params=Argon2Params(memory_cost=8192, time_cost=1, parallelism=1),
    )


def test_hash_and_verify_roundtrip(kdf):
    h = kdf.hash_passphrase("hunter2")
    assert kdf.verify("hunter2", h) is True


def test_verify_rejects_wrong_passphrase(kdf):
    h = kdf.hash_passphrase("hunter2")
    assert kdf.verify("nope", h) is False


def test_derive_key_deterministic(kdf):
    salt = secrets.token_bytes(16)
    k1 = kdf.derive_key("pw", salt)
    k2 = kdf.derive_key("pw", salt)
    assert k1 == k2
    assert len(k1) == 32


def test_derive_key_salt_sensitive(kdf):
    k1 = kdf.derive_key("pw", b"\x00" * 16)
    k2 = kdf.derive_key("pw", b"\x01" * 16)
    assert k1 != k2
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/crypto/test_kdf.py -v`

- [ ] **Step 3: Implement**

```python
"""Argon2id KDF wrapper."""
from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw

from password_bot.config import Argon2Params


class Argon2idKdf:
    def __init__(self, hash_params: Argon2Params, derive_params: Argon2Params) -> None:
        self._hash_params = hash_params
        self._derive_params = derive_params
        self._hasher = PasswordHasher(
            time_cost=hash_params.time_cost,
            memory_cost=hash_params.memory_cost,
            parallelism=hash_params.parallelism,
            hash_len=hash_params.hash_len,
            salt_len=hash_params.salt_len,
            type=Type.ID,
        )

    def hash_passphrase(self, passphrase: str) -> str:
        return self._hasher.hash(passphrase)

    def verify(self, passphrase: str, encoded_hash: str) -> bool:
        try:
            return self._hasher.verify(encoded_hash, passphrase)
        except VerifyMismatchError:
            return False

    def derive_key(self, passphrase: str, salt: bytes) -> bytes:
        p = self._derive_params
        return hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=p.time_cost,
            memory_cost=p.memory_cost,
            parallelism=p.parallelism,
            hash_len=p.hash_len,
            type=Type.ID,
        )
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/crypto/test_kdf.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/crypto/kdf.py tests/crypto/test_kdf.py
git commit -m "Add Argon2idKdf with hash, verify, derive_key"
```

---

### Task 2.2: AES-GCM cipher

**Files:**
- Create: `src/password_bot/crypto/cipher.py`
- Create: `tests/crypto/test_cipher.py`

- [ ] **Step 1: Write failing test**

```python
import base64
import secrets

import pytest
from cryptography.exceptions import InvalidTag

from password_bot.crypto.cipher import CRYPTO_VERSION_GCM, GcmCipher


@pytest.fixture
def cipher():
    return GcmCipher()


def test_encrypt_decrypt_roundtrip(cipher, aes_key):
    ct = cipher.encrypt(b"hello", aes_key)
    assert cipher.decrypt(ct, aes_key) == b"hello"


def test_ciphertext_starts_with_version_byte(cipher, aes_key):
    ct = cipher.encrypt(b"x", aes_key)
    blob = base64.b64decode(ct)
    assert blob[0] == CRYPTO_VERSION_GCM


def test_nonce_uniqueness(cipher, aes_key):
    seen = set()
    for _ in range(2000):
        blob = base64.b64decode(cipher.encrypt(b"x", aes_key))
        nonce = blob[1:13]
        seen.add(nonce)
    assert len(seen) == 2000


def test_tamper_raises_invalid_tag(cipher, aes_key):
    ct = cipher.encrypt(b"hello", aes_key)
    blob = bytearray(base64.b64decode(ct))
    blob[-1] ^= 0xFF
    bad = base64.b64encode(bytes(blob)).decode()
    with pytest.raises(InvalidTag):
        cipher.decrypt(bad, aes_key)


def test_empty_plaintext(cipher, aes_key):
    ct = cipher.encrypt(b"", aes_key)
    assert cipher.decrypt(ct, aes_key) == b""


def test_wrong_key_raises(cipher, aes_key):
    ct = cipher.encrypt(b"hello", aes_key)
    other = secrets.token_bytes(32)
    with pytest.raises(InvalidTag):
        cipher.decrypt(ct, other)
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/crypto/test_cipher.py -v`

- [ ] **Step 3: Implement**

```python
"""AES-256-GCM cipher with a 1-byte version prefix."""
from __future__ import annotations

import base64
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CRYPTO_VERSION_GCM = 2
NONCE_LEN = 12


class GcmCipher:
    def encrypt(self, plaintext: bytes, key: bytes) -> str:
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        nonce = secrets.token_bytes(NONCE_LEN)
        ct = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)
        blob = bytes([CRYPTO_VERSION_GCM]) + nonce + ct
        return base64.b64encode(blob).decode("ascii")

    def decrypt(self, ciphertext_b64: str, key: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        blob = base64.b64decode(ciphertext_b64.encode("ascii"))
        if not blob or blob[0] != CRYPTO_VERSION_GCM:
            raise ValueError(f"Unexpected crypto version byte: {blob[:1]!r}")
        nonce = blob[1 : 1 + NONCE_LEN]
        ct = blob[1 + NONCE_LEN :]
        return AESGCM(key).decrypt(nonce, ct, associated_data=None)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/crypto/test_cipher.py -v`
Expected: 6 passed.

- [ ] **Step 5: Add hypothesis property test**

Append to `tests/crypto/test_cipher.py`:
```python
from hypothesis import given, strategies as st

from password_bot.crypto.cipher import GcmCipher


@given(plaintext=st.binary(max_size=4096))
def test_property_roundtrip(plaintext, aes_key):
    c = GcmCipher()
    assert c.decrypt(c.encrypt(plaintext, aes_key), aes_key) == plaintext
```

Run: `uv run pytest tests/crypto/test_cipher.py -v`
Expected: 7 passed.

- [ ] **Step 6: Commit**

```bash
git add src/password_bot/crypto/cipher.py tests/crypto/test_cipher.py
git commit -m "Add GcmCipher with version-prefixed AES-256-GCM wire format"
```

---

### Task 2.3: Legacy CFB/PBKDF2 decryptor

**Files:**
- Create: `src/password_bot/crypto/legacy.py`
- Create: `tests/crypto/test_legacy_migration.py`

- [ ] **Step 1: Write failing test**

The legacy code (current `src/crypto_service.py`) uses:
- PBKDF2-HMAC-SHA256, 100_000 iterations, salt **hex** for passphrase verification.
- PBKDF2 with salt re-encoded as base64 for key derivation.
- AES-256-CFB with 16-byte IV prepended, full blob base64.

```python
import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from password_bot.crypto.legacy import (
    LegacyCfbDecryptor,
    legacy_derive_key,
    legacy_verify_passphrase,
)


def legacy_encrypt_inline(plaintext: str, key: bytes) -> str:
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
    ct = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()


def legacy_hash_inline(passphrase: str) -> tuple[str, str]:
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100_000)
    return h.hex(), salt.hex()


def test_legacy_verify_passphrase():
    hexhash, salt_hex = legacy_hash_inline("hunter2")
    assert legacy_verify_passphrase("hunter2", hexhash, salt_hex) is True
    assert legacy_verify_passphrase("nope", hexhash, salt_hex) is False


def test_legacy_decrypt_roundtrip():
    salt_hex = os.urandom(16).hex()
    key = legacy_derive_key("hunter2", salt_hex)
    ct = legacy_encrypt_inline("secret", key)
    dec = LegacyCfbDecryptor()
    assert dec.decrypt(ct, key) == "secret"
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/crypto/test_legacy_migration.py -v`

- [ ] **Step 3: Implement legacy module**

```python
"""Read-only access to the v1 (PBKDF2 + AES-CFB) format for migration."""
from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

LEGACY_PBKDF2_ITERATIONS = 100_000


def legacy_verify_passphrase(passphrase: str, stored_hex_hash: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    candidate = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, LEGACY_PBKDF2_ITERATIONS
    )
    return candidate.hex() == stored_hex_hash


def legacy_derive_key(passphrase: str, salt_hex: str) -> bytes:
    """v1 derivation: salt_hex is base64-encoded before being fed to PBKDF2HMAC."""
    salt_b64 = base64.b64encode(salt_hex.encode("utf-8"))
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_b64,
        iterations=LEGACY_PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


class LegacyCfbDecryptor:
    def decrypt(self, ciphertext_b64: str, key: bytes) -> str:
        blob = base64.b64decode(ciphertext_b64)
        iv, ct = blob[:16], blob[16:]
        decryptor = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
        return (decryptor.update(ct) + decryptor.finalize()).decode("utf-8")
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/crypto/test_legacy_migration.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/crypto/legacy.py tests/crypto/test_legacy_migration.py
git commit -m "Add legacy v1 decryptor and PBKDF2 helpers for migration"
```

---

## Phase 3 — Repositories and migrations

### Task 3.1: SQL migrations + migrator

**Files:**
- Create: `src/password_bot/repositories/migrations/001_init.sql`
- Create: `src/password_bot/repositories/migrations/002_legacy_upgrade.sql`
- Create: `src/password_bot/repositories/db.py`
- Create: `src/password_bot/repositories/migrator.py`
- Create: `tests/repositories/test_db_migrator.py`

- [ ] **Step 1: Write `001_init.sql`**

```sql
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);

CREATE TABLE IF NOT EXISTS users (
    chat_id                       INTEGER PRIMARY KEY,
    name                          TEXT NOT NULL,
    passphrase_hash               TEXT NOT NULL,
    autolock_minutes              INTEGER NOT NULL DEFAULT 15,
    autolock_reset_on_activity    INTEGER NOT NULL DEFAULT 1,
    alert_days                    INTEGER NOT NULL DEFAULT 180,
    crypto_version                INTEGER NOT NULL DEFAULT 2,
    legacy_salt                   TEXT,
    created_at                    INTEGER NOT NULL,
    updated_at                    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS categories (
    id        TEXT PRIMARY KEY,
    chat_id   INTEGER NOT NULL REFERENCES users(chat_id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    color     TEXT,
    UNIQUE(chat_id, name)
);

CREATE TABLE IF NOT EXISTS accounts (
    id                   TEXT PRIMARY KEY,
    chat_id              INTEGER NOT NULL REFERENCES users(chat_id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,
    username_enc         TEXT,
    password_enc         TEXT NOT NULL,
    url_enc              TEXT,
    note_enc             TEXT,
    category_id          TEXT REFERENCES categories(id) ON DELETE SET NULL,
    password_hmac        TEXT NOT NULL DEFAULT '',
    crypto_version       INTEGER NOT NULL DEFAULT 2,
    password_changed_at  INTEGER NOT NULL,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_accounts_chat ON accounts(chat_id);
CREATE INDEX IF NOT EXISTS idx_accounts_name ON accounts(chat_id, name);
CREATE INDEX IF NOT EXISTS idx_accounts_category ON accounts(category_id);

CREATE TABLE IF NOT EXISTS password_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    password_enc    TEXT NOT NULL,
    crypto_version  INTEGER NOT NULL DEFAULT 2,
    replaced_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_account ON password_history(account_id, replaced_at);
```

- [ ] **Step 2: Write `002_legacy_upgrade.sql`**

This file is only applied when a legacy `accounts.db` is detected (see migrator logic below).
The migrator detects "legacy" by looking for the old column `users.salted_hash`. The migration **renames** `salted_hash` to `passphrase_hash`, copies `users.salt` into `users.legacy_salt`, sets `crypto_version=1`, and adds the new columns to `accounts`.

```sql
-- Run inside a single transaction by the migrator.
-- Users table: rename + add columns.
ALTER TABLE users RENAME COLUMN salted_hash TO passphrase_hash;
ALTER TABLE users ADD COLUMN autolock_minutes INTEGER NOT NULL DEFAULT 15;
ALTER TABLE users ADD COLUMN autolock_reset_on_activity INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN alert_days INTEGER NOT NULL DEFAULT 180;
ALTER TABLE users ADD COLUMN crypto_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN legacy_salt TEXT;
ALTER TABLE users ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
UPDATE users SET legacy_salt = salt WHERE legacy_salt IS NULL;
ALTER TABLE users DROP COLUMN salt;

-- Accounts table: add new columns.
ALTER TABLE accounts ADD COLUMN url_enc TEXT;
ALTER TABLE accounts ADD COLUMN note_enc TEXT;
ALTER TABLE accounts ADD COLUMN category_id TEXT REFERENCES categories(id) ON DELETE SET NULL;
ALTER TABLE accounts ADD COLUMN password_hmac TEXT NOT NULL DEFAULT '';
ALTER TABLE accounts ADD COLUMN crypto_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE accounts ADD COLUMN password_changed_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
-- Rename legacy `username` column to `username_enc` (already base64-CFB ciphertext).
ALTER TABLE accounts RENAME COLUMN username TO username_enc;
ALTER TABLE accounts RENAME COLUMN password TO password_enc;

CREATE INDEX IF NOT EXISTS idx_accounts_chat ON accounts(chat_id);
CREATE INDEX IF NOT EXISTS idx_accounts_name ON accounts(chat_id, name);
CREATE INDEX IF NOT EXISTS idx_accounts_category ON accounts(category_id);

CREATE TABLE IF NOT EXISTS categories (
    id        TEXT PRIMARY KEY,
    chat_id   INTEGER NOT NULL REFERENCES users(chat_id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    color     TEXT,
    UNIQUE(chat_id, name)
);

CREATE TABLE IF NOT EXISTS password_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    password_enc    TEXT NOT NULL,
    crypto_version  INTEGER NOT NULL DEFAULT 2,
    replaced_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_account ON password_history(account_id, replaced_at);

CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);
INSERT OR REPLACE INTO schema_version (version) VALUES (1);
```

- [ ] **Step 3: Write failing migrator test**

`tests/repositories/test_db_migrator.py`:
```python
import sqlite3
from pathlib import Path

import aiosqlite
import pytest

from password_bot.repositories.migrator import migrate_to_latest


@pytest.mark.asyncio
async def test_migrate_fresh_db(tmp_db_path: Path):
    await migrate_to_latest(tmp_db_path)
    with sqlite3.connect(tmp_db_path) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
    assert {"users", "accounts", "categories", "password_history",
            "schema_version"} <= tables
    assert version == 1


def _create_legacy_db(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE users (
                chat_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                salted_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            );
            CREATE TABLE accounts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                username TEXT,
                password TEXT NOT NULL,
                chat_id INTEGER NOT NULL REFERENCES users(chat_id)
            );
            INSERT INTO users VALUES (42, 'me', 'deadbeef', 'cafebabe');
            INSERT INTO accounts VALUES ('a1', 'GitHub', 'u_enc', 'p_enc', 42);
        """)


@pytest.mark.asyncio
async def test_migrate_legacy_db(tmp_db_path: Path):
    _create_legacy_db(tmp_db_path)
    await migrate_to_latest(tmp_db_path)
    with sqlite3.connect(tmp_db_path) as conn:
        u = conn.execute(
            "SELECT passphrase_hash, legacy_salt, crypto_version, "
            "autolock_minutes FROM users WHERE chat_id=42"
        ).fetchone()
        a = conn.execute(
            "SELECT username_enc, password_enc, password_hmac, crypto_version "
            "FROM accounts WHERE id='a1'"
        ).fetchone()
        version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
    assert u == ("deadbeef", "cafebabe", 1, 15)
    assert a == ("u_enc", "p_enc", "", 1)
    assert version == 1


@pytest.mark.asyncio
async def test_migrate_idempotent(tmp_db_path: Path):
    await migrate_to_latest(tmp_db_path)
    await migrate_to_latest(tmp_db_path)
    with sqlite3.connect(tmp_db_path) as conn:
        version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
    assert version == 1
```

- [ ] **Step 4: Run test (fails — module missing)**

Run: `uv run pytest tests/repositories/test_db_migrator.py -v`

- [ ] **Step 5: Implement `db.py` and `migrator.py`**

`src/password_bot/repositories/db.py`:
```python
"""aiosqlite connection helper."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import aiosqlite


@asynccontextmanager
async def connect(db_path: Path) -> AsyncIterator[aiosqlite.Connection]:
    conn = await aiosqlite.connect(db_path)
    try:
        await conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = aiosqlite.Row
        yield conn
        await conn.commit()
    finally:
        await conn.close()
```

`src/password_bot/repositories/migrator.py`:
```python
"""Schema migrator. Detects legacy v0 schema and upgrades to v1."""
from __future__ import annotations

from pathlib import Path

import aiosqlite

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
TARGET_VERSION = 1


async def _table_exists(conn: aiosqlite.Connection, name: str) -> bool:
    cur = await conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    )
    return await cur.fetchone() is not None


async def _column_exists(conn: aiosqlite.Connection, table: str, column: str) -> bool:
    cur = await conn.execute(f"PRAGMA table_info({table})")
    rows = await cur.fetchall()
    return any(r[1] == column for r in rows)


async def _current_version(conn: aiosqlite.Connection) -> int:
    if not await _table_exists(conn, "schema_version"):
        return 0
    cur = await conn.execute("SELECT version FROM schema_version")
    row = await cur.fetchone()
    return row[0] if row else 0


async def _is_legacy(conn: aiosqlite.Connection) -> bool:
    return (
        await _table_exists(conn, "users")
        and await _column_exists(conn, "users", "salted_hash")
    )


async def migrate_to_latest(db_path: Path) -> None:
    conn = await aiosqlite.connect(db_path)
    try:
        await conn.execute("PRAGMA foreign_keys = OFF")
        version = await _current_version(conn)
        if version >= TARGET_VERSION:
            return
        if await _is_legacy(conn):
            sql = (MIGRATIONS_DIR / "002_legacy_upgrade.sql").read_text()
        else:
            sql = (MIGRATIONS_DIR / "001_init.sql").read_text()
        await conn.executescript(sql)
        if not await _table_exists(conn, "schema_version"):
            await conn.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY)")
        await conn.execute("DELETE FROM schema_version")
        await conn.execute("INSERT INTO schema_version (version) VALUES (?)", (TARGET_VERSION,))
        await conn.commit()
    finally:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.close()
```

- [ ] **Step 6: Run tests**

Run: `uv run pytest tests/repositories/test_db_migrator.py -v`
Expected: 3 passed.

- [ ] **Step 7: Commit**

```bash
git add src/password_bot/repositories tests/repositories/test_db_migrator.py
git commit -m "Add SQL migrator with fresh init and legacy v0 upgrade"
```

---

### Task 3.2: `UserRepo`

**Files:**
- Create: `src/password_bot/repositories/user_repo.py`
- Create: `tests/repositories/test_user_repo.py`

- [ ] **Step 1: Failing test**

```python
import time
from pathlib import Path

import pytest

from password_bot.models.user import User
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo


@pytest.fixture
async def repo(tmp_db_path: Path) -> UserRepo:
    await migrate_to_latest(tmp_db_path)
    return UserRepo(tmp_db_path)


@pytest.mark.asyncio
async def test_create_and_get(repo: UserRepo):
    now = int(time.time())
    u = User(
        chat_id=42, name="me", passphrase_hash="h",
        autolock_minutes=15, autolock_reset_on_activity=True,
        alert_days=180, crypto_version=2, legacy_salt=None,
        created_at=now, updated_at=now,
    )
    await repo.create(u)
    got = await repo.get(42)
    assert got == u


@pytest.mark.asyncio
async def test_get_missing_returns_none(repo: UserRepo):
    assert await repo.get(999) is None


@pytest.mark.asyncio
async def test_update_passphrase_and_version(repo: UserRepo):
    now = int(time.time())
    await repo.create(User(
        chat_id=1, name="x", passphrase_hash="old",
        autolock_minutes=15, autolock_reset_on_activity=True,
        alert_days=180, crypto_version=1, legacy_salt="abc",
        created_at=now, updated_at=now,
    ))
    await repo.update_passphrase(1, "new", crypto_version=2)
    got = await repo.get(1)
    assert got is not None
    assert got.passphrase_hash == "new"
    assert got.crypto_version == 2
    assert got.legacy_salt is None


@pytest.mark.asyncio
async def test_update_autolock(repo: UserRepo):
    now = int(time.time())
    await repo.create(User(
        chat_id=1, name="x", passphrase_hash="h",
        autolock_minutes=15, autolock_reset_on_activity=True,
        alert_days=180, crypto_version=2, legacy_salt=None,
        created_at=now, updated_at=now,
    ))
    await repo.update_autolock(1, minutes=30, reset_on_activity=False)
    got = await repo.get(1)
    assert got is not None
    assert got.autolock_minutes == 30
    assert got.autolock_reset_on_activity is False


@pytest.mark.asyncio
async def test_update_alert_days(repo: UserRepo):
    now = int(time.time())
    await repo.create(User(
        chat_id=1, name="x", passphrase_hash="h",
        autolock_minutes=15, autolock_reset_on_activity=True,
        alert_days=180, crypto_version=2, legacy_salt=None,
        created_at=now, updated_at=now,
    ))
    await repo.update_alert_days(1, 365)
    got = await repo.get(1)
    assert got is not None
    assert got.alert_days == 365
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/repositories/test_user_repo.py -v`

- [ ] **Step 3: Implement**

```python
"""User CRUD."""
from __future__ import annotations

import time
from pathlib import Path

import aiosqlite

from password_bot.models.user import User
from password_bot.repositories.db import connect


def _row_to_user(row: aiosqlite.Row) -> User:
    return User(
        chat_id=row["chat_id"],
        name=row["name"],
        passphrase_hash=row["passphrase_hash"],
        autolock_minutes=row["autolock_minutes"],
        autolock_reset_on_activity=bool(row["autolock_reset_on_activity"]),
        alert_days=row["alert_days"],
        crypto_version=row["crypto_version"],
        legacy_salt=row["legacy_salt"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class UserRepo:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    async def get(self, chat_id: int) -> User | None:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM users WHERE chat_id=?", (chat_id,)
            )
            row = await cur.fetchone()
            return _row_to_user(row) if row else None

    async def create(self, user: User) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                INSERT INTO users (chat_id, name, passphrase_hash, autolock_minutes,
                                   autolock_reset_on_activity, alert_days, crypto_version,
                                   legacy_salt, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user.chat_id, user.name, user.passphrase_hash,
                    user.autolock_minutes, int(user.autolock_reset_on_activity),
                    user.alert_days, user.crypto_version, user.legacy_salt,
                    user.created_at, user.updated_at,
                ),
            )

    async def update_passphrase(
        self, chat_id: int, new_hash: str, *, crypto_version: int
    ) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                UPDATE users
                   SET passphrase_hash=?, crypto_version=?, legacy_salt=NULL, updated_at=?
                 WHERE chat_id=?
                """,
                (new_hash, crypto_version, int(time.time()), chat_id),
            )

    async def update_autolock(
        self, chat_id: int, *, minutes: int, reset_on_activity: bool
    ) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                UPDATE users
                   SET autolock_minutes=?, autolock_reset_on_activity=?, updated_at=?
                 WHERE chat_id=?
                """,
                (minutes, int(reset_on_activity), int(time.time()), chat_id),
            )

    async def update_alert_days(self, chat_id: int, days: int) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                "UPDATE users SET alert_days=?, updated_at=? WHERE chat_id=?",
                (days, int(time.time()), chat_id),
            )
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/repositories/test_user_repo.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/repositories/user_repo.py tests/repositories/test_user_repo.py
git commit -m "Add UserRepo with CRUD and settings updates"
```

---

### Task 3.3: `AccountRepo`

**Files:**
- Create: `src/password_bot/repositories/account_repo.py`
- Create: `tests/repositories/test_account_repo.py`

- [ ] **Step 1: Failing test**

```python
import time
from pathlib import Path

import pytest

from password_bot.models.account import AccountRow
from password_bot.models.user import User
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo


def _make_row(account_id: str, chat_id: int = 1, name: str = "GitHub") -> AccountRow:
    now = int(time.time())
    return AccountRow(
        id=account_id, chat_id=chat_id, name=name,
        username_enc=None, password_enc="p_enc", url_enc=None, note_enc=None,
        category_id=None, password_hmac="hmac", crypto_version=2,
        password_changed_at=now, created_at=now, updated_at=now,
    )


@pytest.fixture
async def repos(tmp_db_path: Path):
    await migrate_to_latest(tmp_db_path)
    users = UserRepo(tmp_db_path)
    now = int(time.time())
    await users.create(User(
        chat_id=1, name="me", passphrase_hash="h",
        autolock_minutes=15, autolock_reset_on_activity=True,
        alert_days=180, crypto_version=2, legacy_salt=None,
        created_at=now, updated_at=now,
    ))
    return AccountRepo(tmp_db_path)


@pytest.mark.asyncio
async def test_insert_and_get(repos: AccountRepo):
    row = _make_row("a1")
    await repos.insert(row)
    got = await repos.get("a1")
    assert got == row


@pytest.mark.asyncio
async def test_list_for_chat(repos: AccountRepo):
    await repos.insert(_make_row("a1", name="GitHub"))
    await repos.insert(_make_row("a2", name="GitLab"))
    rows = await repos.list_for_chat(1)
    assert {r.id for r in rows} == {"a1", "a2"}


@pytest.mark.asyncio
async def test_update_fields(repos: AccountRepo):
    await repos.insert(_make_row("a1"))
    await repos.update_fields("a1", username_enc="new_u_enc", url_enc="url_enc")
    got = await repos.get("a1")
    assert got is not None
    assert got.username_enc == "new_u_enc"
    assert got.url_enc == "url_enc"


@pytest.mark.asyncio
async def test_update_password(repos: AccountRepo):
    await repos.insert(_make_row("a1"))
    await repos.update_password("a1", password_enc="newp", password_hmac="newh",
                                crypto_version=2, password_changed_at=999)
    got = await repos.get("a1")
    assert got is not None
    assert got.password_enc == "newp"
    assert got.password_hmac == "newh"
    assert got.password_changed_at == 999


@pytest.mark.asyncio
async def test_delete(repos: AccountRepo):
    await repos.insert(_make_row("a1"))
    await repos.delete("a1")
    assert await repos.get("a1") is None


@pytest.mark.asyncio
async def test_search_by_name_fuzzy(repos: AccountRepo):
    await repos.insert(_make_row("a1", name="GitHub"))
    await repos.insert(_make_row("a2", name="GitLab"))
    await repos.insert(_make_row("a3", name="Twitter"))
    results = await repos.search(1, "githb", threshold=60)
    names = {r.name for r, _ in results}
    assert "GitHub" in names
    assert "Twitter" not in names


@pytest.mark.asyncio
async def test_list_stale(repos: AccountRepo):
    old = _make_row("a1")
    old.password_changed_at = 100
    new = _make_row("a2")
    new.password_changed_at = 10_000
    await repos.insert(old)
    await repos.insert(new)
    stale = await repos.list_stale(1, older_than_epoch=5_000)
    assert {r.id for r in stale} == {"a1"}
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/repositories/test_account_repo.py -v`

- [ ] **Step 3: Implement**

```python
"""Account CRUD + fuzzy search + stale-password query."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import aiosqlite
from thefuzz import fuzz

from password_bot.models.account import AccountRow
from password_bot.repositories.db import connect


def _row_to_account_row(row: aiosqlite.Row) -> AccountRow:
    return AccountRow(
        id=row["id"], chat_id=row["chat_id"], name=row["name"],
        username_enc=row["username_enc"], password_enc=row["password_enc"],
        url_enc=row["url_enc"], note_enc=row["note_enc"],
        category_id=row["category_id"], password_hmac=row["password_hmac"],
        crypto_version=row["crypto_version"],
        password_changed_at=row["password_changed_at"],
        created_at=row["created_at"], updated_at=row["updated_at"],
    )


_ALLOWED_UPDATE_FIELDS = {"username_enc", "url_enc", "note_enc", "category_id", "name"}


class AccountRepo:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    async def insert(self, row: AccountRow) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                INSERT INTO accounts (id, chat_id, name, username_enc, password_enc,
                                      url_enc, note_enc, category_id, password_hmac,
                                      crypto_version, password_changed_at,
                                      created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row.id, row.chat_id, row.name, row.username_enc, row.password_enc,
                    row.url_enc, row.note_enc, row.category_id, row.password_hmac,
                    row.crypto_version, row.password_changed_at,
                    row.created_at, row.updated_at,
                ),
            )

    async def get(self, account_id: str) -> AccountRow | None:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM accounts WHERE id=?", (account_id,)
            )
            row = await cur.fetchone()
            return _row_to_account_row(row) if row else None

    async def list_for_chat(self, chat_id: int) -> list[AccountRow]:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM accounts WHERE chat_id=? ORDER BY name COLLATE NOCASE",
                (chat_id,),
            )
            return [_row_to_account_row(r) for r in await cur.fetchall()]

    async def update_fields(self, account_id: str, **fields: Any) -> None:
        bad = set(fields) - _ALLOWED_UPDATE_FIELDS
        if bad:
            raise ValueError(f"Cannot update fields via update_fields: {bad}")
        if not fields:
            return
        assignments = ", ".join(f"{k}=?" for k in fields)
        params = [*fields.values(), int(time.time()), account_id]
        async with connect(self._db_path) as conn:
            await conn.execute(
                f"UPDATE accounts SET {assignments}, updated_at=? WHERE id=?",
                params,
            )

    async def update_password(
        self, account_id: str, *, password_enc: str, password_hmac: str,
        crypto_version: int, password_changed_at: int
    ) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                UPDATE accounts
                   SET password_enc=?, password_hmac=?, crypto_version=?,
                       password_changed_at=?, updated_at=?
                 WHERE id=?
                """,
                (password_enc, password_hmac, crypto_version,
                 password_changed_at, int(time.time()), account_id),
            )

    async def delete(self, account_id: str) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))

    async def search(
        self, chat_id: int, query: str, *, threshold: int = 60
    ) -> list[tuple[AccountRow, int]]:
        rows = await self.list_for_chat(chat_id)
        scored: list[tuple[AccountRow, int]] = []
        for r in rows:
            score = fuzz.partial_ratio(query.lower(), r.name.lower())
            if score >= threshold:
                scored.append((r, score))
        scored.sort(key=lambda t: t[1], reverse=True)
        return scored

    async def list_stale(
        self, chat_id: int, *, older_than_epoch: int
    ) -> list[AccountRow]:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM accounts WHERE chat_id=? AND password_changed_at < ?",
                (chat_id, older_than_epoch),
            )
            return [_row_to_account_row(r) for r in await cur.fetchall()]
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/repositories/test_account_repo.py -v`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/repositories/account_repo.py tests/repositories/test_account_repo.py
git commit -m "Add AccountRepo with CRUD, fuzzy search, stale query"
```

---

### Task 3.4: `CategoryRepo`

**Files:**
- Create: `src/password_bot/repositories/category_repo.py`
- Create: `tests/repositories/test_category_repo.py`

- [ ] **Step 1: Failing test**

```python
import time
from pathlib import Path

import pytest

from password_bot.models.category import Category
from password_bot.models.user import User
from password_bot.repositories.category_repo import CategoryRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo


@pytest.fixture
async def repo(tmp_db_path: Path) -> CategoryRepo:
    await migrate_to_latest(tmp_db_path)
    now = int(time.time())
    await UserRepo(tmp_db_path).create(User(
        chat_id=1, name="me", passphrase_hash="h",
        autolock_minutes=15, autolock_reset_on_activity=True,
        alert_days=180, crypto_version=2, legacy_salt=None,
        created_at=now, updated_at=now,
    ))
    return CategoryRepo(tmp_db_path)


@pytest.mark.asyncio
async def test_create_and_list(repo: CategoryRepo):
    await repo.create(Category(id="c1", chat_id=1, name="Work", color=None))
    await repo.create(Category(id="c2", chat_id=1, name="Personal", color="🟢"))
    listed = await repo.list_for_chat(1)
    assert {c.name for c in listed} == {"Work", "Personal"}


@pytest.mark.asyncio
async def test_get_by_name(repo: CategoryRepo):
    await repo.create(Category(id="c1", chat_id=1, name="Work", color=None))
    got = await repo.get_by_name(1, "work")
    assert got is not None
    assert got.id == "c1"


@pytest.mark.asyncio
async def test_rename(repo: CategoryRepo):
    await repo.create(Category(id="c1", chat_id=1, name="Work", color=None))
    await repo.rename("c1", "Job")
    got = await repo.get("c1")
    assert got is not None
    assert got.name == "Job"


@pytest.mark.asyncio
async def test_delete(repo: CategoryRepo):
    await repo.create(Category(id="c1", chat_id=1, name="Work", color=None))
    await repo.delete("c1")
    assert await repo.get("c1") is None
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/repositories/test_category_repo.py -v`

- [ ] **Step 3: Implement**

```python
"""Category CRUD."""
from __future__ import annotations

from pathlib import Path

import aiosqlite

from password_bot.models.category import Category
from password_bot.repositories.db import connect


def _row_to_category(row: aiosqlite.Row) -> Category:
    return Category(
        id=row["id"], chat_id=row["chat_id"], name=row["name"], color=row["color"]
    )


class CategoryRepo:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    async def create(self, cat: Category) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                "INSERT INTO categories (id, chat_id, name, color) VALUES (?, ?, ?, ?)",
                (cat.id, cat.chat_id, cat.name, cat.color),
            )

    async def get(self, cat_id: str) -> Category | None:
        async with connect(self._db_path) as conn:
            cur = await conn.execute("SELECT * FROM categories WHERE id=?", (cat_id,))
            row = await cur.fetchone()
            return _row_to_category(row) if row else None

    async def get_by_name(self, chat_id: int, name: str) -> Category | None:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM categories WHERE chat_id=? AND lower(name)=lower(?)",
                (chat_id, name),
            )
            row = await cur.fetchone()
            return _row_to_category(row) if row else None

    async def list_for_chat(self, chat_id: int) -> list[Category]:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM categories WHERE chat_id=? ORDER BY name COLLATE NOCASE",
                (chat_id,),
            )
            return [_row_to_category(r) for r in await cur.fetchall()]

    async def rename(self, cat_id: str, new_name: str) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                "UPDATE categories SET name=? WHERE id=?", (new_name, cat_id)
            )

    async def delete(self, cat_id: str) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute("DELETE FROM categories WHERE id=?", (cat_id,))
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/repositories/test_category_repo.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/repositories/category_repo.py tests/repositories/test_category_repo.py
git commit -m "Add CategoryRepo with CRUD"
```

---

### Task 3.5: `HistoryRepo`

**Files:**
- Create: `src/password_bot/repositories/history_repo.py`
- Create: `tests/repositories/test_history_repo.py`

- [ ] **Step 1: Failing test**

```python
import time
from pathlib import Path

import pytest

from password_bot.models.account import AccountRow
from password_bot.models.user import User
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.history_repo import HistoryRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo


@pytest.fixture
async def setup(tmp_db_path: Path):
    await migrate_to_latest(tmp_db_path)
    now = int(time.time())
    await UserRepo(tmp_db_path).create(User(
        chat_id=1, name="me", passphrase_hash="h",
        autolock_minutes=15, autolock_reset_on_activity=True,
        alert_days=180, crypto_version=2, legacy_salt=None,
        created_at=now, updated_at=now,
    ))
    accounts = AccountRepo(tmp_db_path)
    await accounts.insert(AccountRow(
        id="a1", chat_id=1, name="GitHub", username_enc=None, password_enc="p0",
        url_enc=None, note_enc=None, category_id=None, password_hmac="h",
        crypto_version=2, password_changed_at=now, created_at=now, updated_at=now,
    ))
    return HistoryRepo(tmp_db_path)


@pytest.mark.asyncio
async def test_push_and_list(setup: HistoryRepo):
    await setup.push("a1", password_enc="p0", crypto_version=2, replaced_at=10)
    await setup.push("a1", password_enc="p1", crypto_version=2, replaced_at=20)
    rows = await setup.list_for_account("a1")
    assert [r.password_enc for r in rows] == ["p1", "p0"]


@pytest.mark.asyncio
async def test_prune_keeps_latest_n(setup: HistoryRepo):
    for i in range(8):
        await setup.push("a1", password_enc=f"p{i}", crypto_version=2, replaced_at=i)
    await setup.prune("a1", keep=5)
    rows = await setup.list_for_account("a1")
    assert [r.password_enc for r in rows] == ["p7", "p6", "p5", "p4", "p3"]
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/repositories/test_history_repo.py -v`

- [ ] **Step 3: Implement**

```python
"""Password history CRUD with retention pruning."""
from __future__ import annotations

from pathlib import Path

import aiosqlite

from password_bot.models.password_history import PasswordHistoryEntry
from password_bot.repositories.db import connect


def _row_to_entry(row: aiosqlite.Row) -> PasswordHistoryEntry:
    return PasswordHistoryEntry(
        id=row["id"], account_id=row["account_id"],
        password_enc=row["password_enc"], crypto_version=row["crypto_version"],
        replaced_at=row["replaced_at"],
    )


class HistoryRepo:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    async def push(
        self, account_id: str, *, password_enc: str, crypto_version: int, replaced_at: int
    ) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                INSERT INTO password_history (account_id, password_enc, crypto_version, replaced_at)
                VALUES (?, ?, ?, ?)
                """,
                (account_id, password_enc, crypto_version, replaced_at),
            )

    async def list_for_account(self, account_id: str) -> list[PasswordHistoryEntry]:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                """
                SELECT * FROM password_history
                 WHERE account_id=? ORDER BY replaced_at DESC, id DESC
                """,
                (account_id,),
            )
            return [_row_to_entry(r) for r in await cur.fetchall()]

    async def prune(self, account_id: str, *, keep: int) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                DELETE FROM password_history
                 WHERE account_id=? AND id NOT IN (
                     SELECT id FROM password_history
                      WHERE account_id=?
                      ORDER BY replaced_at DESC, id DESC LIMIT ?
                 )
                """,
                (account_id, account_id, keep),
            )
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/repositories/test_history_repo.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/repositories/history_repo.py tests/repositories/test_history_repo.py
git commit -m "Add HistoryRepo with push, list, prune"
```

---

## Phase 4 — Services

### Task 4.1: Result type + domain errors

**Files:**
- Create: `src/password_bot/services/result.py`
- Create: `src/password_bot/services/errors.py`
- Create: `tests/services/test_result.py`

- [ ] **Step 1: Failing test**

```python
from password_bot.services.errors import DomainError, InvalidPassphraseError
from password_bot.services.result import Result


def test_ok_result():
    r = Result.ok(42)
    assert r.ok is True
    assert r.value == 42
    assert r.error is None


def test_err_result():
    err = InvalidPassphraseError()
    r: Result[int] = Result.err(err)
    assert r.ok is False
    assert r.error is err
    assert r.value is None


def test_domain_error_hierarchy():
    assert issubclass(InvalidPassphraseError, DomainError)
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/services/test_result.py -v`

- [ ] **Step 3: Implement**

`src/password_bot/services/errors.py`:
```python
"""Domain-level errors raised by services."""
from __future__ import annotations


class DomainError(Exception):
    """Base for errors that handlers translate into user messages."""

    user_message: str = "Errore interno."


class InvalidPassphraseError(DomainError):
    user_message = "Passphrase non valida."


class AccountNotFoundError(DomainError):
    user_message = "Account non trovato."


class DuplicateAccountError(DomainError):
    user_message = "Esiste già un account con questo nome."


class DuplicateCategoryError(DomainError):
    user_message = "Esiste già una categoria con questo nome."


class CategoryNotFoundError(DomainError):
    user_message = "Categoria non trovata."


class InvalidExportFileError(DomainError):
    user_message = "File di import non valido."


class SessionExpiredError(DomainError):
    user_message = "Sessione scaduta. Sbloccala di nuovo."
```

`src/password_bot/services/result.py`:
```python
"""Result type for expected-failure flows."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

from password_bot.services.errors import DomainError

T = TypeVar("T")


@dataclass(slots=True)
class Result(Generic[T]):
    value: T | None
    error: DomainError | None

    @classmethod
    def ok(cls, value: T) -> "Result[T]":
        return cls(value=value, error=None)

    @classmethod
    def err(cls, error: DomainError) -> "Result[T]":
        return cls(value=None, error=error)

    @property
    def ok(self) -> bool:  # type: ignore[override]
        return self.error is None
```

> **Note:** the `ok` classmethod and `ok` property share a name on purpose so callers can write both `Result.ok(x)` (factory) and `r.ok` (boolean check). Mypy may warn — that's acceptable here since there are no other users of `Result.ok`.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/services/test_result.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/services tests/services/test_result.py
git commit -m "Add Result type and domain error hierarchy"
```

---

### Task 4.2: `PasswordGenerator`

**Files:**
- Create: `src/password_bot/services/password_generator.py`
- Create: `tests/services/test_password_generator.py`

- [ ] **Step 1: Failing test**

```python
import string

import pytest

from password_bot.services.password_generator import (
    PasswordCharset,
    PasswordGenerator,
    PasswordSpec,
)


@pytest.fixture
def gen():
    return PasswordGenerator()


def test_length_respected(gen: PasswordGenerator):
    pw = gen.generate(PasswordSpec(length=20, charset=PasswordCharset.ALPHANUM_SYMBOLS))
    assert len(pw) == 20


def test_alphanumeric_only(gen: PasswordGenerator):
    pw = gen.generate(PasswordSpec(length=32, charset=PasswordCharset.ALPHANUM))
    allowed = set(string.ascii_letters + string.digits)
    assert set(pw) <= allowed


def test_digits_only(gen: PasswordGenerator):
    pw = gen.generate(PasswordSpec(length=8, charset=PasswordCharset.DIGITS))
    assert pw.isdigit()


def test_at_least_one_of_each_class_when_symbols(gen: PasswordGenerator):
    pw = gen.generate(PasswordSpec(length=12, charset=PasswordCharset.ALPHANUM_SYMBOLS))
    assert any(c.islower() for c in pw)
    assert any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(not c.isalnum() for c in pw)


def test_length_too_short_raises(gen: PasswordGenerator):
    with pytest.raises(ValueError):
        gen.generate(PasswordSpec(length=2, charset=PasswordCharset.ALPHANUM_SYMBOLS))
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/services/test_password_generator.py -v`

- [ ] **Step 3: Implement**

```python
"""Cryptographically random password generation."""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from enum import Enum

_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase
_DIGITS = string.digits
_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"


class PasswordCharset(str, Enum):
    DIGITS = "digits"
    ALPHANUM = "alphanum"
    ALPHANUM_SYMBOLS = "alphanum_symbols"


@dataclass(slots=True, frozen=True)
class PasswordSpec:
    length: int
    charset: PasswordCharset


_CHARSET_POOLS: dict[PasswordCharset, list[str]] = {
    PasswordCharset.DIGITS: [_DIGITS],
    PasswordCharset.ALPHANUM: [_LOWER, _UPPER, _DIGITS],
    PasswordCharset.ALPHANUM_SYMBOLS: [_LOWER, _UPPER, _DIGITS, _SYMBOLS],
}


class PasswordGenerator:
    def generate(self, spec: PasswordSpec) -> str:
        pools = _CHARSET_POOLS[spec.charset]
        if spec.length < len(pools):
            raise ValueError(f"Length {spec.length} too short for charset {spec.charset}")
        # Guarantee at least one char from each pool.
        chars = [secrets.choice(pool) for pool in pools]
        all_chars = "".join(pools)
        chars.extend(secrets.choice(all_chars) for _ in range(spec.length - len(pools)))
        # Shuffle in place using secrets.
        for i in range(len(chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            chars[i], chars[j] = chars[j], chars[i]
        return "".join(chars)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/services/test_password_generator.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/services/password_generator.py tests/services/test_password_generator.py
git commit -m "Add PasswordGenerator with charset enum and length guarantees"
```

---

### Task 4.3: `StrengthMeter`

**Files:**
- Create: `src/password_bot/services/strength_meter.py`
- Create: `tests/services/test_strength_meter.py`

- [ ] **Step 1: Failing test**

```python
import pytest

from password_bot.services.strength_meter import StrengthMeter, StrengthResult


@pytest.fixture
def meter():
    return StrengthMeter()


def test_weak_password(meter: StrengthMeter):
    r: StrengthResult = meter.evaluate("password")
    assert r.score <= 1
    assert r.crack_time_display is not None


def test_strong_password(meter: StrengthMeter):
    r = meter.evaluate("c0rrect-h0rse_BATTERY-staple-9q!")
    assert r.score >= 3


def test_returns_suggestions(meter: StrengthMeter):
    r = meter.evaluate("abc")
    assert isinstance(r.suggestions, list)
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/services/test_strength_meter.py -v`

- [ ] **Step 3: Implement**

```python
"""zxcvbn-backed strength evaluation."""
from __future__ import annotations

from dataclasses import dataclass

from zxcvbn import zxcvbn


@dataclass(slots=True, frozen=True)
class StrengthResult:
    score: int                  # 0..4
    crack_time_display: str
    suggestions: list[str]
    warning: str


class StrengthMeter:
    def evaluate(self, password: str) -> StrengthResult:
        r = zxcvbn(password or "")
        feedback = r.get("feedback") or {}
        crack_times = r.get("crack_times_display", {})
        return StrengthResult(
            score=int(r.get("score", 0)),
            crack_time_display=str(crack_times.get("offline_slow_hashing_1e4_per_second", "")),
            suggestions=list(feedback.get("suggestions", [])),
            warning=str(feedback.get("warning", "")),
        )
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/services/test_strength_meter.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/services/strength_meter.py tests/services/test_strength_meter.py
git commit -m "Add zxcvbn-backed StrengthMeter"
```

---

### Task 4.4: `ReuseDetector`

**Files:**
- Create: `src/password_bot/services/reuse_detector.py`
- Create: `tests/services/test_reuse_detector.py`

- [ ] **Step 1: Failing test**

```python
import hmac
import hashlib

from password_bot.services.reuse_detector import ReuseDetector, compute_password_hmac


def _hmac(key: bytes, plaintext: str) -> str:
    return hmac.new(key, plaintext.encode(), hashlib.sha256).hexdigest()


def test_compute_password_hmac_matches_reference():
    key = b"\x01" * 32
    assert compute_password_hmac("pw", key) == _hmac(key, "pw")


def test_detector_finds_cluster():
    key = b"\x02" * 32
    d = ReuseDetector(key)
    d.add("a1", "GitHub", "shared")
    d.add("a2", "GitLab", "shared")
    d.add("a3", "Twitter", "other")
    cluster = d.cluster_for("shared")
    assert {(a_id, name) for a_id, name in cluster} == {("a1", "GitHub"), ("a2", "GitLab")}


def test_detector_removes_account():
    key = b"\x02" * 32
    d = ReuseDetector(key)
    d.add("a1", "GitHub", "shared")
    d.add("a2", "GitLab", "shared")
    d.remove("a1")
    assert {a_id for a_id, _ in d.cluster_for("shared")} == {"a2"}


def test_detector_all_clusters():
    key = b"\x02" * 32
    d = ReuseDetector(key)
    d.add("a1", "GitHub", "shared")
    d.add("a2", "GitLab", "shared")
    d.add("a3", "Twitter", "unique")
    clusters = d.all_clusters(min_size=2)
    assert len(clusters) == 1
    assert {a_id for a_id, _ in clusters[0]} == {"a1", "a2"}
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/services/test_reuse_detector.py -v`

- [ ] **Step 3: Implement**

```python
"""HMAC-based password reuse detector. State is in-memory only."""
from __future__ import annotations

import hashlib
import hmac
from collections import defaultdict


def compute_password_hmac(password: str, hmac_key: bytes) -> str:
    return hmac.new(hmac_key, password.encode("utf-8"), hashlib.sha256).hexdigest()


class ReuseDetector:
    def __init__(self, hmac_key: bytes) -> None:
        self._key = hmac_key
        self._by_hmac: dict[str, dict[str, str]] = defaultdict(dict)
        self._account_to_hmac: dict[str, str] = {}

    def add(self, account_id: str, account_name: str, password: str) -> None:
        h = compute_password_hmac(password, self._key)
        self._by_hmac[h][account_id] = account_name
        self._account_to_hmac[account_id] = h

    def add_hmac(self, account_id: str, account_name: str, password_hmac: str) -> None:
        self._by_hmac[password_hmac][account_id] = account_name
        self._account_to_hmac[account_id] = password_hmac

    def remove(self, account_id: str) -> None:
        h = self._account_to_hmac.pop(account_id, None)
        if h is None:
            return
        bucket = self._by_hmac.get(h)
        if bucket and account_id in bucket:
            del bucket[account_id]
            if not bucket:
                del self._by_hmac[h]

    def cluster_for(self, password: str) -> list[tuple[str, str]]:
        h = compute_password_hmac(password, self._key)
        return list(self._by_hmac.get(h, {}).items())

    def cluster_for_hmac(self, password_hmac: str) -> list[tuple[str, str]]:
        return list(self._by_hmac.get(password_hmac, {}).items())

    def all_clusters(self, *, min_size: int = 2) -> list[list[tuple[str, str]]]:
        return [
            list(bucket.items())
            for bucket in self._by_hmac.values()
            if len(bucket) >= min_size
        ]
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/services/test_reuse_detector.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/services/reuse_detector.py tests/services/test_reuse_detector.py
git commit -m "Add ReuseDetector with HMAC-keyed cluster index"
```

---

### Task 4.5: HKDF helper for HMAC key

**Files:**
- Create: `src/password_bot/crypto/hkdf.py`
- Create: `tests/crypto/test_hkdf.py`

- [ ] **Step 1: Failing test**

```python
from password_bot.crypto.hkdf import derive_subkey


def test_derive_subkey_deterministic():
    k = b"\x00" * 32
    a = derive_subkey(k, info=b"reuse-detection")
    b = derive_subkey(k, info=b"reuse-detection")
    assert a == b
    assert len(a) == 32


def test_derive_subkey_info_sensitive():
    k = b"\x00" * 32
    assert derive_subkey(k, info=b"a") != derive_subkey(k, info=b"b")
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/crypto/test_hkdf.py -v`

- [ ] **Step 3: Implement**

```python
"""HKDF-SHA256 subkey derivation."""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_subkey(master_key: bytes, *, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(master_key)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/crypto/test_hkdf.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/crypto/hkdf.py tests/crypto/test_hkdf.py
git commit -m "Add HKDF subkey derivation helper"
```

---

### Task 4.6: `AuthService`

**Files:**
- Create: `src/password_bot/services/auth_service.py`
- Create: `tests/services/test_auth_service.py`

- [ ] **Step 1: Failing test**

```python
import secrets
import time
from pathlib import Path

import pytest

from password_bot.config import Argon2Params
from password_bot.crypto.kdf import Argon2idKdf
from password_bot.models.user import User
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.auth_service import AuthService, Session
from password_bot.services.errors import InvalidPassphraseError


@pytest.fixture
def kdf():
    p = Argon2Params(memory_cost=8192, time_cost=1, parallelism=1)
    return Argon2idKdf(hash_params=p, derive_params=p)


@pytest.fixture
async def auth(tmp_db_path: Path, kdf: Argon2idKdf):
    await migrate_to_latest(tmp_db_path)
    return AuthService(user_repo=UserRepo(tmp_db_path), kdf=kdf)


@pytest.mark.asyncio
async def test_register_creates_user_and_returns_session(auth: AuthService):
    r = await auth.register(chat_id=1, name="me", passphrase="hunter2")
    assert r.ok
    session = r.value
    assert isinstance(session, Session)
    assert len(session.aes_key) == 32
    assert len(session.hmac_key) == 32


@pytest.mark.asyncio
async def test_unlock_correct_passphrase(auth: AuthService):
    await auth.register(chat_id=1, name="me", passphrase="hunter2")
    r = await auth.unlock(chat_id=1, passphrase="hunter2")
    assert r.ok
    assert r.value is not None


@pytest.mark.asyncio
async def test_unlock_wrong_passphrase(auth: AuthService):
    await auth.register(chat_id=1, name="me", passphrase="hunter2")
    r = await auth.unlock(chat_id=1, passphrase="nope")
    assert not r.ok
    assert isinstance(r.error, InvalidPassphraseError)


@pytest.mark.asyncio
async def test_change_passphrase(auth: AuthService):
    await auth.register(chat_id=1, name="me", passphrase="hunter2")
    r = await auth.change_passphrase(
        chat_id=1, current="hunter2", new="newpass"
    )
    assert r.ok
    bad = await auth.unlock(chat_id=1, passphrase="hunter2")
    good = await auth.unlock(chat_id=1, passphrase="newpass")
    assert not bad.ok
    assert good.ok


@pytest.mark.asyncio
async def test_change_passphrase_wrong_current(auth: AuthService):
    await auth.register(chat_id=1, name="me", passphrase="hunter2")
    r = await auth.change_passphrase(chat_id=1, current="x", new="y")
    assert not r.ok
    assert isinstance(r.error, InvalidPassphraseError)
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/services/test_auth_service.py -v`

- [ ] **Step 3: Implement**

```python
"""Auth service: register, unlock, lock, change passphrase."""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

from password_bot.crypto.hkdf import derive_subkey
from password_bot.crypto.kdf import Argon2idKdf
from password_bot.models.user import User
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.errors import InvalidPassphraseError
from password_bot.services.result import Result

# Salt for derive_key is stored alongside the user record. We reuse the Argon2id
# salt-from-passphrase-hash by re-parsing the encoded hash. To keep things simple
# we instead persist a dedicated derive_salt per user. v0 (legacy) users keep
# their legacy_salt and continue using the legacy KDF path.

SESSION_LEN_SECONDS_DEFAULT = 15 * 60


@dataclass(slots=True)
class Session:
    chat_id: int
    aes_key: bytes
    hmac_key: bytes
    expires_at: int


def _derive_salt_from_hash(passphrase_hash: str) -> bytes:
    # argon2-cffi encoded hash format: $argon2id$v=19$m=...,t=...,p=...$<b64-salt>$<b64-hash>
    parts = passphrase_hash.split("$")
    if len(parts) < 6:
        raise ValueError("Unexpected Argon2 hash format")
    salt_b64 = parts[4]
    # argon2 omits b64 padding; restore it.
    salt_b64 += "=" * (-len(salt_b64) % 4)
    import base64

    return base64.b64decode(salt_b64)


class AuthService:
    def __init__(self, *, user_repo: UserRepo, kdf: Argon2idKdf) -> None:
        self._users = user_repo
        self._kdf = kdf

    def _make_session(self, chat_id: int, aes_key: bytes, ttl: int) -> Session:
        hmac_key = derive_subkey(aes_key, info=b"reuse-detection")
        return Session(
            chat_id=chat_id, aes_key=aes_key, hmac_key=hmac_key,
            expires_at=int(time.time()) + ttl,
        )

    async def register(
        self, *, chat_id: int, name: str, passphrase: str,
        autolock_minutes: int = 15, alert_days: int = 180,
    ) -> Result[Session]:
        now = int(time.time())
        passphrase_hash = self._kdf.hash_passphrase(passphrase)
        user = User(
            chat_id=chat_id, name=name, passphrase_hash=passphrase_hash,
            autolock_minutes=autolock_minutes, autolock_reset_on_activity=True,
            alert_days=alert_days, crypto_version=2, legacy_salt=None,
            created_at=now, updated_at=now,
        )
        await self._users.create(user)
        salt = _derive_salt_from_hash(passphrase_hash)
        aes_key = self._kdf.derive_key(passphrase, salt)
        ttl = autolock_minutes * 60 if autolock_minutes > 0 else SESSION_LEN_SECONDS_DEFAULT
        return Result.ok(self._make_session(chat_id, aes_key, ttl))

    async def unlock(self, *, chat_id: int, passphrase: str) -> Result[Session]:
        user = await self._users.get(chat_id)
        if user is None:
            return Result.err(InvalidPassphraseError())
        if user.crypto_version != 2:
            # Legacy users go through MigrationService.unlock_legacy.
            return Result.err(InvalidPassphraseError())
        if not self._kdf.verify(passphrase, user.passphrase_hash):
            return Result.err(InvalidPassphraseError())
        salt = _derive_salt_from_hash(user.passphrase_hash)
        aes_key = self._kdf.derive_key(passphrase, salt)
        ttl = user.autolock_minutes * 60 if user.autolock_minutes > 0 else SESSION_LEN_SECONDS_DEFAULT
        return Result.ok(self._make_session(chat_id, aes_key, ttl))

    async def change_passphrase(
        self, *, chat_id: int, current: str, new: str
    ) -> Result[tuple[Session, bytes]]:
        """Returns the new session and the OLD aes_key (needed by VaultService to re-encrypt)."""
        user = await self._users.get(chat_id)
        if user is None or not self._kdf.verify(current, user.passphrase_hash):
            return Result.err(InvalidPassphraseError())
        old_salt = _derive_salt_from_hash(user.passphrase_hash)
        old_key = self._kdf.derive_key(current, old_salt)
        new_hash = self._kdf.hash_passphrase(new)
        new_salt = _derive_salt_from_hash(new_hash)
        new_key = self._kdf.derive_key(new, new_salt)
        # Caller (VaultService.rotate_all_passwords) re-encrypts all rows BEFORE
        # we persist the new hash. The handler orchestrates the order.
        return Result.ok((
            Session(
                chat_id=chat_id,
                aes_key=new_key,
                hmac_key=derive_subkey(new_key, info=b"reuse-detection"),
                expires_at=int(time.time())
                + (user.autolock_minutes * 60 if user.autolock_minutes > 0 else SESSION_LEN_SECONDS_DEFAULT),
            ),
            old_key,
        ))

    async def commit_passphrase_change(self, *, chat_id: int, new_passphrase: str) -> None:
        """Persist the new passphrase hash. Called after re-encryption completes."""
        new_hash = self._kdf.hash_passphrase(new_passphrase)
        await self._users.update_passphrase(chat_id, new_hash, crypto_version=2)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/services/test_auth_service.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/services/auth_service.py tests/services/test_auth_service.py
git commit -m "Add AuthService with register/unlock/change passphrase"
```

---

### Task 4.7: `VaultService`

**Files:**
- Create: `src/password_bot/services/vault_service.py`
- Create: `tests/services/test_vault_service.py`

- [ ] **Step 1: Failing test**

```python
import secrets
import time
import uuid
from pathlib import Path

import pytest

from password_bot.config import AppConfig, Argon2Params
from password_bot.crypto.cipher import GcmCipher
from password_bot.models.user import User
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.history_repo import HistoryRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.vault_service import NewAccount, UpdatedFields, VaultService


@pytest.fixture
async def vault(tmp_db_path: Path):
    await migrate_to_latest(tmp_db_path)
    now = int(time.time())
    await UserRepo(tmp_db_path).create(User(
        chat_id=1, name="me", passphrase_hash="h",
        autolock_minutes=15, autolock_reset_on_activity=True,
        alert_days=180, crypto_version=2, legacy_salt=None,
        created_at=now, updated_at=now,
    ))
    return VaultService(
        account_repo=AccountRepo(tmp_db_path),
        history_repo=HistoryRepo(tmp_db_path),
        cipher=GcmCipher(),
        history_max=5,
    )


@pytest.mark.asyncio
async def test_add_account_with_username(vault: VaultService, aes_key):
    new = NewAccount(
        chat_id=1, name="GitHub", username="claudio", password="s3cr3t",
        url="https://github.com", note=None, category_id=None,
    )
    acc = await vault.add(new, aes_key=aes_key, hmac_key=b"\x10" * 32)
    assert acc.id
    fetched = await vault.get_decrypted(acc.id, aes_key=aes_key)
    assert fetched is not None
    assert fetched.username == "claudio"
    assert fetched.password == "s3cr3t"


@pytest.mark.asyncio
async def test_add_account_without_username(vault: VaultService, aes_key):
    new = NewAccount(
        chat_id=1, name="GitHub", username=None, password="s3cr3t",
        url=None, note=None, category_id=None,
    )
    acc = await vault.add(new, aes_key=aes_key, hmac_key=b"\x10" * 32)
    fetched = await vault.get_decrypted(acc.id, aes_key=aes_key)
    assert fetched is not None
    assert fetched.username is None


@pytest.mark.asyncio
async def test_update_field(vault: VaultService, aes_key):
    new = NewAccount(chat_id=1, name="GitHub", username="a", password="p",
                     url=None, note=None, category_id=None)
    acc = await vault.add(new, aes_key=aes_key, hmac_key=b"\x10" * 32)
    await vault.update_fields(
        acc.id, UpdatedFields(username="b", url="https://x"), aes_key=aes_key
    )
    fetched = await vault.get_decrypted(acc.id, aes_key=aes_key)
    assert fetched is not None
    assert fetched.username == "b"
    assert fetched.url == "https://x"


@pytest.mark.asyncio
async def test_update_password_pushes_history(vault: VaultService, aes_key):
    new = NewAccount(chat_id=1, name="GitHub", username=None, password="p0",
                     url=None, note=None, category_id=None)
    acc = await vault.add(new, aes_key=aes_key, hmac_key=b"\x10" * 32)
    await vault.update_password(acc.id, "p1", aes_key=aes_key, hmac_key=b"\x10" * 32)
    await vault.update_password(acc.id, "p2", aes_key=aes_key, hmac_key=b"\x10" * 32)
    history = await vault.list_history(acc.id, aes_key=aes_key)
    assert [h.password for h in history] == ["p1", "p0"]
    fetched = await vault.get_decrypted(acc.id, aes_key=aes_key)
    assert fetched is not None
    assert fetched.password == "p2"


@pytest.mark.asyncio
async def test_history_pruned_to_max(vault: VaultService, aes_key):
    new = NewAccount(chat_id=1, name="GitHub", username=None, password="p0",
                     url=None, note=None, category_id=None)
    acc = await vault.add(new, aes_key=aes_key, hmac_key=b"\x10" * 32)
    for i in range(1, 10):
        await vault.update_password(acc.id, f"p{i}", aes_key=aes_key,
                                    hmac_key=b"\x10" * 32)
    history = await vault.list_history(acc.id, aes_key=aes_key)
    assert len(history) == 5
    assert [h.password for h in history] == ["p8", "p7", "p6", "p5", "p4"]


@pytest.mark.asyncio
async def test_duplicate_account(vault: VaultService, aes_key):
    new = NewAccount(chat_id=1, name="GitHub", username="u", password="p",
                     url=None, note=None, category_id=None)
    acc = await vault.add(new, aes_key=aes_key, hmac_key=b"\x10" * 32)
    copy = await vault.duplicate(acc.id, aes_key=aes_key, hmac_key=b"\x10" * 32)
    assert copy.id != acc.id
    assert copy.name == "GitHub (copia)"
    assert copy.password == "p"
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/services/test_vault_service.py -v`

- [ ] **Step 3: Implement**

```python
"""Vault service: account CRUD wrapped around encrypt/decrypt."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from password_bot.crypto.cipher import CRYPTO_VERSION_GCM, GcmCipher
from password_bot.models.account import Account, AccountRow
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.history_repo import HistoryRepo
from password_bot.services.reuse_detector import compute_password_hmac


@dataclass(slots=True, frozen=True)
class NewAccount:
    chat_id: int
    name: str
    username: str | None
    password: str
    url: str | None
    note: str | None
    category_id: str | None


@dataclass(slots=True, frozen=True)
class UpdatedFields:
    name: str | None = None
    username: str | None = None
    url: str | None = None
    note: str | None = None
    category_id: str | None = None
    # Sentinel: None means "leave unchanged". To clear a value, pass an explicit
    # empty string for str fields. Category cleared via category_id="".


@dataclass(slots=True, frozen=True)
class HistoryItem:
    id: int
    password: str
    replaced_at: int


class VaultService:
    def __init__(
        self,
        *,
        account_repo: AccountRepo,
        history_repo: HistoryRepo,
        cipher: GcmCipher,
        history_max: int,
    ) -> None:
        self._accounts = account_repo
        self._history = history_repo
        self._cipher = cipher
        self._history_max = history_max

    def _enc(self, value: str | None, key: bytes) -> str | None:
        if value is None:
            return None
        return self._cipher.encrypt(value.encode("utf-8"), key)

    def _dec(self, value: str | None, key: bytes) -> str | None:
        if value is None:
            return None
        return self._cipher.decrypt(value, key).decode("utf-8")

    def _decrypt_row(self, row: AccountRow, key: bytes) -> Account:
        return Account(
            id=row.id, chat_id=row.chat_id, name=row.name,
            username=self._dec(row.username_enc, key),
            password=self._cipher.decrypt(row.password_enc, key).decode("utf-8"),
            url=self._dec(row.url_enc, key),
            note=self._dec(row.note_enc, key),
            category_id=row.category_id,
            password_hmac=row.password_hmac,
            crypto_version=row.crypto_version,
            password_changed_at=row.password_changed_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    async def add(self, new: NewAccount, *, aes_key: bytes, hmac_key: bytes) -> Account:
        now = int(time.time())
        row = AccountRow(
            id=str(uuid.uuid4()),
            chat_id=new.chat_id,
            name=new.name,
            username_enc=self._enc(new.username, aes_key),
            password_enc=self._cipher.encrypt(new.password.encode("utf-8"), aes_key),
            url_enc=self._enc(new.url, aes_key),
            note_enc=self._enc(new.note, aes_key),
            category_id=new.category_id,
            password_hmac=compute_password_hmac(new.password, hmac_key),
            crypto_version=CRYPTO_VERSION_GCM,
            password_changed_at=now,
            created_at=now,
            updated_at=now,
        )
        await self._accounts.insert(row)
        return self._decrypt_row(row, aes_key)

    async def get_decrypted(self, account_id: str, *, aes_key: bytes) -> Account | None:
        row = await self._accounts.get(account_id)
        if row is None:
            return None
        return self._decrypt_row(row, aes_key)

    async def list_decrypted(self, chat_id: int, *, aes_key: bytes) -> list[Account]:
        rows = await self._accounts.list_for_chat(chat_id)
        return [self._decrypt_row(r, aes_key) for r in rows]

    async def update_fields(
        self, account_id: str, updates: UpdatedFields, *, aes_key: bytes
    ) -> None:
        fields: dict[str, str | None] = {}
        if updates.name is not None:
            fields["name"] = updates.name
        if updates.username is not None:
            fields["username_enc"] = self._enc(updates.username or None, aes_key)
        if updates.url is not None:
            fields["url_enc"] = self._enc(updates.url or None, aes_key)
        if updates.note is not None:
            fields["note_enc"] = self._enc(updates.note or None, aes_key)
        if updates.category_id is not None:
            fields["category_id"] = updates.category_id or None
        if fields:
            await self._accounts.update_fields(account_id, **fields)

    async def update_password(
        self, account_id: str, new_password: str, *, aes_key: bytes, hmac_key: bytes
    ) -> None:
        current = await self._accounts.get(account_id)
        if current is None:
            return
        now = int(time.time())
        await self._history.push(
            account_id,
            password_enc=current.password_enc,
            crypto_version=current.crypto_version,
            replaced_at=now,
        )
        await self._history.prune(account_id, keep=self._history_max)
        new_enc = self._cipher.encrypt(new_password.encode("utf-8"), aes_key)
        new_hmac = compute_password_hmac(new_password, hmac_key)
        await self._accounts.update_password(
            account_id,
            password_enc=new_enc,
            password_hmac=new_hmac,
            crypto_version=CRYPTO_VERSION_GCM,
            password_changed_at=now,
        )

    async def list_history(
        self, account_id: str, *, aes_key: bytes
    ) -> list[HistoryItem]:
        entries = await self._history.list_for_account(account_id)
        return [
            HistoryItem(
                id=e.id,
                password=self._cipher.decrypt(e.password_enc, aes_key).decode("utf-8"),
                replaced_at=e.replaced_at,
            )
            for e in entries
        ]

    async def duplicate(
        self, account_id: str, *, aes_key: bytes, hmac_key: bytes
    ) -> Account:
        original = await self._accounts.get(account_id)
        if original is None:
            raise ValueError(f"Account {account_id} not found")
        plain = self._decrypt_row(original, aes_key)
        new = NewAccount(
            chat_id=plain.chat_id,
            name=f"{plain.name} (copia)",
            username=plain.username,
            password=plain.password,
            url=plain.url,
            note=plain.note,
            category_id=plain.category_id,
        )
        return await self.add(new, aes_key=aes_key, hmac_key=hmac_key)

    async def delete(self, account_id: str) -> None:
        await self._accounts.delete(account_id)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/services/test_vault_service.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/services/vault_service.py tests/services/test_vault_service.py
git commit -m "Add VaultService with encrypt-on-write, history push, duplicate"
```

---

### Task 4.8: `AlertService`

**Files:**
- Create: `src/password_bot/services/alert_service.py`
- Create: `tests/services/test_alert_service.py`

- [ ] **Step 1: Failing test**

```python
import time
from pathlib import Path

import pytest
from freezegun import freeze_time

from password_bot.models.account import AccountRow
from password_bot.models.user import User
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.alert_service import AlertService


@pytest.fixture
async def setup(tmp_db_path: Path):
    await migrate_to_latest(tmp_db_path)
    users = UserRepo(tmp_db_path)
    now = int(time.time())
    await users.create(User(
        chat_id=1, name="me", passphrase_hash="h",
        autolock_minutes=15, autolock_reset_on_activity=True,
        alert_days=180, crypto_version=2, legacy_salt=None,
        created_at=now, updated_at=now,
    ))
    accounts = AccountRepo(tmp_db_path)

    async def insert(account_id: str, changed_at: int):
        await accounts.insert(AccountRow(
            id=account_id, chat_id=1, name=account_id, username_enc=None,
            password_enc="p", url_enc=None, note_enc=None, category_id=None,
            password_hmac="h", crypto_version=2,
            password_changed_at=changed_at, created_at=changed_at,
            updated_at=changed_at,
        ))

    await insert("old", changed_at=int(time.time()) - 200 * 86400)
    await insert("fresh", changed_at=int(time.time()) - 10 * 86400)
    return AlertService(users=users, accounts=accounts)


@pytest.mark.asyncio
async def test_stale_returns_old_only(setup: AlertService):
    stale = await setup.find_stale(chat_id=1)
    assert [a.id for a in stale] == ["old"]


@pytest.mark.asyncio
async def test_stale_threshold_changes_with_user_setting(
    setup: AlertService, tmp_db_path: Path
):
    users = UserRepo(tmp_db_path)
    await users.update_alert_days(1, 365)
    stale = await setup.find_stale(chat_id=1)
    assert stale == []
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/services/test_alert_service.py -v`

- [ ] **Step 3: Implement**

```python
"""Service that finds accounts with stale passwords."""
from __future__ import annotations

import time

from password_bot.models.account import AccountRow
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.user_repo import UserRepo


class AlertService:
    def __init__(self, *, users: UserRepo, accounts: AccountRepo) -> None:
        self._users = users
        self._accounts = accounts

    async def find_stale(self, *, chat_id: int) -> list[AccountRow]:
        user = await self._users.get(chat_id)
        if user is None:
            return []
        cutoff = int(time.time()) - user.alert_days * 86400
        return await self._accounts.list_stale(chat_id, older_than_epoch=cutoff)

    async def find_stale_for_all_users(self) -> dict[int, list[AccountRow]]:
        # Used by daily scan. Caller fetches list of chat_ids elsewhere; this
        # method just dispatches one find_stale per chat_id passed in.
        raise NotImplementedError("Use find_stale per chat_id from the caller")
```

> The daily scan is wired in the bot startup (Task 7.3) using `job_queue.run_daily`. The job iterates over chat IDs it knows about (from `users` table) and calls `find_stale` per user.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/services/test_alert_service.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/services/alert_service.py tests/services/test_alert_service.py
git commit -m "Add AlertService.find_stale using user-specific threshold"
```

---

### Task 4.9: `MigrationService` (legacy → v2 lazy re-encrypt)

**Files:**
- Create: `src/password_bot/services/migration_service.py`
- Create: `tests/services/test_migration_service.py`

- [ ] **Step 1: Failing test**

The test sets up a legacy DB (CFB ciphertext for username + password) and verifies:
1. `unlock_legacy` returns a session when the legacy passphrase verifies.
2. `migrate_user` re-encrypts every row with GCM and flips `crypto_version` to 2.
3. After migration, the new `AuthService.unlock` works with the same passphrase.

```python
import base64
import hashlib
import os
import sqlite3
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from password_bot.config import Argon2Params
from password_bot.crypto.cipher import GcmCipher
from password_bot.crypto.kdf import Argon2idKdf
from password_bot.crypto.legacy import LegacyCfbDecryptor, legacy_derive_key
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.auth_service import AuthService
from password_bot.services.migration_service import MigrationService


def _seed_legacy_db(path: Path, passphrase: str = "hunter2") -> None:
    salt = os.urandom(16)
    salt_hex = salt.hex()
    hexhash = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode(), salt, 100_000
    ).hex()
    key = legacy_derive_key(passphrase, salt_hex)

    def enc(plain: str) -> str:
        iv = os.urandom(16)
        e = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
        ct = e.update(plain.encode()) + e.finalize()
        return base64.b64encode(iv + ct).decode()

    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE users (
                chat_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                salted_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            );
            CREATE TABLE accounts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                username TEXT,
                password TEXT NOT NULL,
                chat_id INTEGER NOT NULL REFERENCES users(chat_id)
            );
        """)
        conn.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?)",
            (1, "me", hexhash, salt_hex),
        )
        conn.execute(
            "INSERT INTO accounts VALUES (?, ?, ?, ?, ?)",
            ("a1", "GitHub", enc("claudio"), enc("legacy-secret"), 1),
        )


@pytest.fixture
def kdf():
    p = Argon2Params(memory_cost=8192, time_cost=1, parallelism=1)
    return Argon2idKdf(hash_params=p, derive_params=p)


@pytest.mark.asyncio
async def test_unlock_legacy_and_migrate(tmp_db_path: Path, kdf: Argon2idKdf):
    _seed_legacy_db(tmp_db_path)
    await migrate_to_latest(tmp_db_path)
    users = UserRepo(tmp_db_path)
    accounts = AccountRepo(tmp_db_path)
    cipher = GcmCipher()
    svc = MigrationService(
        users=users,
        accounts=accounts,
        kdf=kdf,
        cipher=cipher,
        legacy_decryptor=LegacyCfbDecryptor(),
    )

    session_r = await svc.unlock_legacy(chat_id=1, passphrase="hunter2")
    assert session_r.ok
    session = session_r.value
    await svc.migrate_user(chat_id=1, passphrase="hunter2", session=session)

    user = await users.get(1)
    assert user is not None
    assert user.crypto_version == 2
    assert user.legacy_salt is None

    row = await accounts.get("a1")
    assert row is not None
    assert row.crypto_version == 2
    # New ciphertext starts with version byte 2.
    blob = base64.b64decode(row.password_enc)
    assert blob[0] == 2

    auth = AuthService(user_repo=users, kdf=kdf)
    r = await auth.unlock(chat_id=1, passphrase="hunter2")
    assert r.ok


@pytest.mark.asyncio
async def test_unlock_legacy_wrong_passphrase(tmp_db_path: Path, kdf: Argon2idKdf):
    _seed_legacy_db(tmp_db_path)
    await migrate_to_latest(tmp_db_path)
    svc = MigrationService(
        users=UserRepo(tmp_db_path),
        accounts=AccountRepo(tmp_db_path),
        kdf=kdf,
        cipher=GcmCipher(),
        legacy_decryptor=LegacyCfbDecryptor(),
    )
    r = await svc.unlock_legacy(chat_id=1, passphrase="nope")
    assert not r.ok
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/services/test_migration_service.py -v`

- [ ] **Step 3: Implement**

```python
"""Lazy migration from legacy (v1) to current (v2) crypto."""
from __future__ import annotations

import time

from password_bot.crypto.cipher import CRYPTO_VERSION_GCM, GcmCipher
from password_bot.crypto.hkdf import derive_subkey
from password_bot.crypto.kdf import Argon2idKdf
from password_bot.crypto.legacy import (
    LegacyCfbDecryptor,
    legacy_derive_key,
    legacy_verify_passphrase,
)
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.auth_service import Session, _derive_salt_from_hash
from password_bot.services.errors import InvalidPassphraseError
from password_bot.services.reuse_detector import compute_password_hmac
from password_bot.services.result import Result


class MigrationService:
    def __init__(
        self,
        *,
        users: UserRepo,
        accounts: AccountRepo,
        kdf: Argon2idKdf,
        cipher: GcmCipher,
        legacy_decryptor: LegacyCfbDecryptor,
    ) -> None:
        self._users = users
        self._accounts = accounts
        self._kdf = kdf
        self._cipher = cipher
        self._legacy = legacy_decryptor

    async def unlock_legacy(self, *, chat_id: int, passphrase: str) -> Result[Session]:
        user = await self._users.get(chat_id)
        if user is None or user.crypto_version != 1 or user.legacy_salt is None:
            return Result.err(InvalidPassphraseError())
        if not legacy_verify_passphrase(passphrase, user.passphrase_hash, user.legacy_salt):
            return Result.err(InvalidPassphraseError())
        legacy_key = legacy_derive_key(passphrase, user.legacy_salt)
        # We derive a *new* aes_key for the post-migration world too, but we still
        # carry the legacy_key on the session payload via attribute injection.
        new_hash = self._kdf.hash_passphrase(passphrase)
        new_salt = _derive_salt_from_hash(new_hash)
        new_key = self._kdf.derive_key(passphrase, new_salt)
        ttl = user.autolock_minutes * 60 if user.autolock_minutes > 0 else 15 * 60
        session = Session(
            chat_id=chat_id, aes_key=new_key,
            hmac_key=derive_subkey(new_key, info=b"reuse-detection"),
            expires_at=int(time.time()) + ttl,
        )
        # Stash for migrate_user. The handler keeps both around for the duration
        # of unlock; we attach an attribute rather than expanding the dataclass
        # because legacy_key is only ever consumed inside migrate_user.
        session.__dict__["_legacy_key"] = legacy_key
        session.__dict__["_new_passphrase_hash"] = new_hash
        return Result.ok(session)

    async def migrate_user(
        self, *, chat_id: int, passphrase: str, session: Session
    ) -> None:
        user = await self._users.get(chat_id)
        if user is None:
            return
        legacy_key: bytes = session.__dict__.get("_legacy_key")  # type: ignore[assignment]
        if legacy_key is None:
            raise RuntimeError("Session is not the result of unlock_legacy")
        new_hash: str = session.__dict__.get("_new_passphrase_hash")  # type: ignore[assignment]
        if new_hash is None:
            raise RuntimeError("Session is missing new_passphrase_hash")

        rows = await self._accounts.list_for_chat(chat_id)
        now = int(time.time())
        for row in rows:
            if row.crypto_version != 1:
                continue
            username_plain = (
                self._legacy.decrypt(row.username_enc, legacy_key)
                if row.username_enc else None
            )
            password_plain = self._legacy.decrypt(row.password_enc, legacy_key)
            new_username_enc = (
                self._cipher.encrypt(username_plain.encode("utf-8"), session.aes_key)
                if username_plain is not None else None
            )
            new_password_enc = self._cipher.encrypt(
                password_plain.encode("utf-8"), session.aes_key
            )
            new_hmac = compute_password_hmac(password_plain, session.hmac_key)
            # Persist row updates.
            await self._accounts.update_fields(row.id, username_enc=new_username_enc)
            await self._accounts.update_password(
                row.id,
                password_enc=new_password_enc,
                password_hmac=new_hmac,
                crypto_version=CRYPTO_VERSION_GCM,
                password_changed_at=row.password_changed_at or now,
            )
        # Flip the user's crypto_version + clear legacy_salt, install new Argon2 hash.
        await self._users.update_passphrase(chat_id, new_hash, crypto_version=CRYPTO_VERSION_GCM)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/services/test_migration_service.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/services/migration_service.py tests/services/test_migration_service.py
git commit -m "Add MigrationService for legacy v1 unlock and lazy re-encryption"
```

---

### Task 4.10: `ExportService`

**Files:**
- Create: `src/password_bot/services/export_service.py`
- Create: `tests/services/test_export_service.py`

- [ ] **Step 1: Failing test**

```python
import json
import os
import time
from pathlib import Path

import pytest

from password_bot.config import Argon2Params
from password_bot.crypto.cipher import GcmCipher
from password_bot.crypto.kdf import Argon2idKdf
from password_bot.models.user import User
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.category_repo import CategoryRepo
from password_bot.repositories.history_repo import HistoryRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.errors import InvalidExportFileError, InvalidPassphraseError
from password_bot.services.export_service import ExportService, MergeStrategy
from password_bot.services.vault_service import NewAccount, VaultService


@pytest.fixture
def kdf():
    p = Argon2Params(memory_cost=8192, time_cost=1, parallelism=1)
    return Argon2idKdf(hash_params=p, derive_params=p)


@pytest.fixture
async def setup(tmp_db_path: Path, kdf: Argon2idKdf, aes_key: bytes):
    await migrate_to_latest(tmp_db_path)
    now = int(time.time())
    await UserRepo(tmp_db_path).create(User(
        chat_id=1, name="me", passphrase_hash="h",
        autolock_minutes=15, autolock_reset_on_activity=True,
        alert_days=180, crypto_version=2, legacy_salt=None,
        created_at=now, updated_at=now,
    ))
    vault = VaultService(
        account_repo=AccountRepo(tmp_db_path),
        history_repo=HistoryRepo(tmp_db_path),
        cipher=GcmCipher(),
        history_max=5,
    )
    await vault.add(
        NewAccount(chat_id=1, name="GitHub", username="u",
                   password="p", url=None, note=None, category_id=None),
        aes_key=aes_key, hmac_key=b"\x10" * 32,
    )
    export = ExportService(
        accounts=AccountRepo(tmp_db_path),
        categories=CategoryRepo(tmp_db_path),
        vault=vault,
        cipher=GcmCipher(),
        kdf=kdf,
    )
    return export, aes_key, vault


@pytest.mark.asyncio
async def test_export_then_import_roundtrip(setup, tmp_db_path: Path, kdf, aes_key):
    export, vault_key, vault = setup
    payload = await export.export(chat_id=1, vault_key=vault_key, export_passphrase="exp")
    data = json.loads(payload)
    assert data["format"] == "password-bot-vault"
    assert data["version"] == 1
    assert len(data["items"]) == 1

    # Clear and re-import.
    accs = await vault.list_decrypted(1, aes_key=vault_key)
    for a in accs:
        await vault.delete(a.id)

    report = await export.import_payload(
        payload, chat_id=1, vault_key=vault_key, hmac_key=b"\x10" * 32,
        export_passphrase="exp", strategy=MergeStrategy.OVERWRITE,
    )
    assert report.added == 1
    restored = await vault.list_decrypted(1, aes_key=vault_key)
    assert restored[0].password == "p"


@pytest.mark.asyncio
async def test_import_wrong_passphrase(setup, aes_key):
    export, vault_key, _ = setup
    payload = await export.export(chat_id=1, vault_key=vault_key, export_passphrase="exp")
    with pytest.raises(InvalidPassphraseError):
        await export.import_payload(
            payload, chat_id=1, vault_key=vault_key, hmac_key=b"\x10" * 32,
            export_passphrase="wrong", strategy=MergeStrategy.OVERWRITE,
        )


@pytest.mark.asyncio
async def test_import_invalid_schema(setup, aes_key):
    export, vault_key, _ = setup
    with pytest.raises(InvalidExportFileError):
        await export.import_payload(
            '{"format": "wrong"}', chat_id=1, vault_key=vault_key,
            hmac_key=b"\x10" * 32, export_passphrase="x",
            strategy=MergeStrategy.OVERWRITE,
        )
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/services/test_export_service.py -v`

- [ ] **Step 3: Implement**

```python
"""Encrypted JSON export/import."""
from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, ValidationError

from password_bot.crypto.cipher import GcmCipher
from password_bot.crypto.kdf import Argon2idKdf
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.category_repo import CategoryRepo
from password_bot.services.errors import InvalidExportFileError, InvalidPassphraseError
from password_bot.services.vault_service import NewAccount, VaultService

EXPORT_FORMAT = "password-bot-vault"
EXPORT_VERSION = 1
SALT_LEN = 16


class MergeStrategy(str, Enum):
    SKIP = "skip"
    OVERWRITE = "overwrite"
    KEEP_BOTH = "keep_both"


@dataclass(slots=True, frozen=True)
class ImportReport:
    added: int
    skipped: int
    overwritten: int


class _ExportItem(BaseModel):
    name: str
    username_enc: str | None = None
    password_enc: str
    url_enc: str | None = None
    note_enc: str | None = None
    category: str | None = None
    password_changed_at: int


class _ExportSchema(BaseModel):
    format: str
    version: int
    exported_at: str
    kdf: dict
    cipher: str
    salt: str
    items: list[_ExportItem]
    categories: list[str]


class ExportService:
    def __init__(
        self,
        *,
        accounts: AccountRepo,
        categories: CategoryRepo,
        vault: VaultService,
        cipher: GcmCipher,
        kdf: Argon2idKdf,
    ) -> None:
        self._accounts = accounts
        self._categories = categories
        self._vault = vault
        self._cipher = cipher
        self._kdf = kdf

    async def export(
        self, *, chat_id: int, vault_key: bytes, export_passphrase: str
    ) -> str:
        salt = secrets.token_bytes(SALT_LEN)
        export_key = self._kdf.derive_key(export_passphrase, salt)
        accounts_plain = await self._vault.list_decrypted(chat_id, aes_key=vault_key)
        cats = await self._categories.list_for_chat(chat_id)
        cat_name_by_id = {c.id: c.name for c in cats}
        items = []
        for a in accounts_plain:
            items.append({
                "name": a.name,
                "username_enc": self._cipher.encrypt(a.username.encode(), export_key) if a.username else None,
                "password_enc": self._cipher.encrypt(a.password.encode(), export_key),
                "url_enc": self._cipher.encrypt(a.url.encode(), export_key) if a.url else None,
                "note_enc": self._cipher.encrypt(a.note.encode(), export_key) if a.note else None,
                "category": cat_name_by_id.get(a.category_id) if a.category_id else None,
                "password_changed_at": a.password_changed_at,
            })
        payload = {
            "format": EXPORT_FORMAT,
            "version": EXPORT_VERSION,
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "kdf": {"name": "argon2id"},
            "cipher": "aes-256-gcm",
            "salt": base64.b64encode(salt).decode(),
            "items": items,
            "categories": [c.name for c in cats],
        }
        return json.dumps(payload, indent=2)

    async def import_payload(
        self, payload: str, *, chat_id: int, vault_key: bytes, hmac_key: bytes,
        export_passphrase: str, strategy: MergeStrategy,
    ) -> ImportReport:
        try:
            schema = _ExportSchema.model_validate_json(payload)
        except ValidationError as e:
            raise InvalidExportFileError() from e
        if schema.format != EXPORT_FORMAT or schema.version != EXPORT_VERSION:
            raise InvalidExportFileError()
        salt = base64.b64decode(schema.salt)
        export_key = self._kdf.derive_key(export_passphrase, salt)

        try:
            existing = {a.name.lower(): a for a in await self._vault.list_decrypted(chat_id, aes_key=vault_key)}
        except Exception as e:
            raise InvalidPassphraseError() from e

        added = skipped = overwritten = 0
        for item in schema.items:
            try:
                password = self._cipher.decrypt(item.password_enc, export_key).decode("utf-8")
            except Exception as e:
                raise InvalidPassphraseError() from e
            username = self._cipher.decrypt(item.username_enc, export_key).decode("utf-8") if item.username_enc else None
            url = self._cipher.decrypt(item.url_enc, export_key).decode("utf-8") if item.url_enc else None
            note = self._cipher.decrypt(item.note_enc, export_key).decode("utf-8") if item.note_enc else None

            existing_match = existing.get(item.name.lower())
            if existing_match and strategy == MergeStrategy.SKIP:
                skipped += 1
                continue
            if existing_match and strategy == MergeStrategy.OVERWRITE:
                await self._vault.delete(existing_match.id)
                overwritten += 1
                target_name = item.name
            elif existing_match and strategy == MergeStrategy.KEEP_BOTH:
                target_name = f"{item.name} (importato)"
                added += 1
            else:
                target_name = item.name
                added += 1

            await self._vault.add(
                NewAccount(
                    chat_id=chat_id, name=target_name, username=username,
                    password=password, url=url, note=note, category_id=None,
                ),
                aes_key=vault_key, hmac_key=hmac_key,
            )
        return ImportReport(added=added, skipped=skipped, overwritten=overwritten)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/services/test_export_service.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/services/export_service.py tests/services/test_export_service.py
git commit -m "Add ExportService with Argon2-derived export key and merge strategies"
```

---

## Phase 5 — State, i18n, telegram utils

### Task 5.1: `ChatDataKey` enum

**Files:**
- Create: `src/password_bot/state/keys.py`
- Create: `tests/test_state_keys.py`

- [ ] **Step 1: Failing test**

```python
from password_bot.state.keys import ChatDataKey


def test_enum_members_unique_and_strings():
    values = {k.value for k in ChatDataKey}
    assert len(values) == len(ChatDataKey)
    assert all(isinstance(k.value, str) for k in ChatDataKey)


def test_required_keys_exist():
    expected = {
        "SESSION", "NAV_STACK", "PENDING_INPUT", "AUTOLOCK_JOB_NAME",
        "REUSE_DETECTOR", "PENDING_NEW_ACCOUNT", "PENDING_IMPORT_FILE",
    }
    assert expected <= {k.name for k in ChatDataKey}
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/test_state_keys.py -v`

- [ ] **Step 3: Implement**

```python
"""Typed keys for context.chat_data. Never use raw strings."""
from __future__ import annotations

from enum import Enum


class ChatDataKey(str, Enum):
    SESSION = "session"
    NAV_STACK = "nav_stack"
    PENDING_INPUT = "pending_input"
    AUTOLOCK_JOB_NAME = "autolock_job_name"
    REUSE_DETECTOR = "reuse_detector"
    PENDING_NEW_ACCOUNT = "pending_new_account"
    PENDING_IMPORT_FILE = "pending_import_file"
    LEGACY_SESSION_EXTRAS = "legacy_session_extras"
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_state_keys.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/state/keys.py tests/test_state_keys.py
git commit -m "Add ChatDataKey enum for typed chat_data access"
```

---

### Task 5.2: `FsmContext` wrapper

**Files:**
- Create: `src/password_bot/state/fsm.py`
- Create: `tests/test_fsm_context.py`

- [ ] **Step 1: Failing test**

```python
from password_bot.state.fsm import FsmContext, Screen


def test_push_and_top():
    fsm = FsmContext({})
    fsm.push(Screen(name="menu", data={}))
    fsm.push(Screen(name="account_view", data={"id": "a1"}))
    assert fsm.top().name == "account_view"


def test_pop():
    fsm = FsmContext({})
    fsm.push(Screen(name="menu", data={}))
    fsm.push(Screen(name="account_view", data={}))
    fsm.pop()
    assert fsm.top().name == "menu"


def test_pop_to():
    fsm = FsmContext({})
    fsm.push(Screen(name="menu", data={}))
    fsm.push(Screen(name="account_list", data={}))
    fsm.push(Screen(name="account_view", data={}))
    fsm.pop_to("menu")
    assert fsm.top().name == "menu"
    assert fsm.depth() == 1


def test_reset_to():
    fsm = FsmContext({})
    fsm.push(Screen(name="menu", data={}))
    fsm.push(Screen(name="account_view", data={}))
    fsm.reset_to(Screen(name="menu", data={}))
    assert fsm.depth() == 1
    assert fsm.top().name == "menu"


def test_pending_input_set_and_clear():
    fsm = FsmContext({})
    fsm.set_pending_input({"field": "password", "id": "a1"})
    assert fsm.get_pending_input() == {"field": "password", "id": "a1"}
    fsm.clear_pending_input()
    assert fsm.get_pending_input() is None
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/test_fsm_context.py -v`

- [ ] **Step 3: Implement**

```python
"""Typed wrapper over context.chat_data."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from password_bot.state.keys import ChatDataKey


@dataclass(slots=True)
class Screen:
    name: str
    data: dict[str, Any] = field(default_factory=dict)


class FsmContext:
    """Thin wrapper that lets handlers read/write chat_data with typed keys."""

    def __init__(self, chat_data: dict[str, Any]) -> None:
        self._chat_data = chat_data

    def _stack(self) -> list[Screen]:
        raw = self._chat_data.get(ChatDataKey.NAV_STACK.value)
        if raw is None:
            raw = []
            self._chat_data[ChatDataKey.NAV_STACK.value] = raw
        return raw

    def push(self, screen: Screen) -> None:
        self._stack().append(screen)

    def pop(self) -> Screen | None:
        st = self._stack()
        return st.pop() if st else None

    def top(self) -> Screen:
        st = self._stack()
        if not st:
            raise IndexError("Empty nav stack")
        return st[-1]

    def depth(self) -> int:
        return len(self._stack())

    def pop_to(self, screen_name: str) -> None:
        st = self._stack()
        while st and st[-1].name != screen_name:
            st.pop()

    def reset_to(self, screen: Screen) -> None:
        self._chat_data[ChatDataKey.NAV_STACK.value] = [screen]

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
        self._chat_data.pop(ChatDataKey.REUSE_DETECTOR.value, None)
        self._chat_data.pop(ChatDataKey.LEGACY_SESSION_EXTRAS.value, None)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_fsm_context.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/state/fsm.py tests/test_fsm_context.py
git commit -m "Add FsmContext wrapper with screen stack and pending input"
```

---

### Task 5.3: MarkdownV2 helper

**Files:**
- Create: `src/password_bot/telegram_utils/md.py`
- Create: `tests/test_md_helper.py`

- [ ] **Step 1: Failing test**

```python
from password_bot.telegram_utils.md import escape_md, code_inline


def test_escape_md_handles_v2_specials():
    out = escape_md("hello *world* (test) _x_!")
    for ch in r"_*[]()~`>#+-=|{}.!":
        assert ch in r"_*[]()~`>#+-=|{}.!"  # tautology; real check below
    assert out == r"hello \*world\* \(test\) \_x\_\!"


def test_code_inline_escapes_internal_backticks():
    out = code_inline("a`b")
    assert out == "`a\\`b`"
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/test_md_helper.py -v`

- [ ] **Step 3: Implement**

```python
"""MarkdownV2 escaping helpers."""
from __future__ import annotations

_SPECIALS = r"_*[]()~`>#+-=|{}.!"


def escape_md(value: str) -> str:
    out: list[str] = []
    for ch in value:
        out.append("\\" + ch if ch in _SPECIALS else ch)
    return "".join(out)


def code_inline(value: str) -> str:
    inner = value.replace("`", "\\`")
    return f"`{inner}`"
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_md_helper.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/telegram_utils/md.py tests/test_md_helper.py
git commit -m "Add MarkdownV2 escape helpers"
```

---

### Task 5.4: Keyboards helper

**Files:**
- Create: `src/password_bot/telegram_utils/keyboards.py`
- Create: `tests/test_keyboards.py`

- [ ] **Step 1: Failing test**

```python
from telegram import InlineKeyboardMarkup

from password_bot.telegram_utils.keyboards import (
    back_menu_keyboard, confirm_cancel_keyboard, single_column,
)


def test_single_column_builds_inline_keyboard():
    kb = single_column([("Yes", "yes"), ("No", "no")])
    assert isinstance(kb, InlineKeyboardMarkup)
    assert len(kb.inline_keyboard) == 2
    assert kb.inline_keyboard[0][0].callback_data == "yes"


def test_back_menu_keyboard_has_back_and_menu():
    kb = back_menu_keyboard(show_menu=True)
    callbacks = {b.callback_data for row in kb.inline_keyboard for b in row}
    assert "nav:back" in callbacks
    assert "nav:menu" in callbacks


def test_confirm_cancel_keyboard():
    kb = confirm_cancel_keyboard(confirm_data="do_it", cancel_data="cancel_it")
    callbacks = {b.callback_data for row in kb.inline_keyboard for b in row}
    assert callbacks == {"do_it", "cancel_it"}
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/test_keyboards.py -v`

- [ ] **Step 3: Implement**

```python
"""Inline keyboard builders."""
from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup


def single_column(buttons: list[tuple[str, str]]) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text=label, callback_data=data)] for label, data in buttons]
    return InlineKeyboardMarkup(rows)


def back_menu_keyboard(*, show_menu: bool) -> InlineKeyboardMarkup:
    row = [InlineKeyboardButton("🔙 Indietro", callback_data="nav:back")]
    if show_menu:
        row.append(InlineKeyboardButton("🏠 Menu", callback_data="nav:menu"))
    return InlineKeyboardMarkup([row])


def confirm_cancel_keyboard(*, confirm_data: str, cancel_data: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("✅ Conferma", callback_data=confirm_data),
        InlineKeyboardButton("❌ Annulla", callback_data=cancel_data),
    ]])
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_keyboards.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/telegram_utils/keyboards.py tests/test_keyboards.py
git commit -m "Add keyboard helpers: single_column, back/menu, confirm/cancel"
```

---

### Task 5.5: Auto-delete helper

**Files:**
- Create: `src/password_bot/telegram_utils/delete_message.py`

This module wraps `application.job_queue.run_once` to schedule the deletion of a sensitive message after N seconds. No new tests — exercised via handler smoke tests later.

- [ ] **Step 1: Write the module**

```python
"""Schedule auto-deletion of messages that carry sensitive content."""
from __future__ import annotations

import logging
from telegram.error import BadRequest
from telegram.ext import Application, ContextTypes

log = logging.getLogger(__name__)


async def _delete_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    job = context.job
    if job is None:
        return
    chat_id, message_id = job.data  # type: ignore[misc]
    try:
        await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
    except BadRequest as e:
        log.debug("delete_message failed for %s/%s: %s", chat_id, message_id, e)


def schedule_delete(
    application: Application,
    *,
    chat_id: int,
    message_id: int,
    delay_seconds: int = 30,
) -> None:
    if application.job_queue is None:
        return
    application.job_queue.run_once(
        _delete_job,
        when=delay_seconds,
        data=(chat_id, message_id),
        name=f"delete:{chat_id}:{message_id}",
    )
```

- [ ] **Step 2: Lint**

Run: `uv run ruff check src/password_bot/telegram_utils/delete_message.py`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/password_bot/telegram_utils/delete_message.py
git commit -m "Add schedule_delete helper for sensitive auto-delete"
```

---

### Task 5.6: i18n module

**Files:**
- Create: `src/password_bot/i18n/it.py`
- Create: `tests/test_i18n.py`

- [ ] **Step 1: Failing test**

```python
from password_bot.i18n.it import MESSAGES


REQUIRED_KEYS = {
    "welcome",
    "menu_title",
    "ask_passphrase",
    "passphrase_wrong",
    "passphrase_setup_first",
    "session_locked",
    "stop_hint",
    "account_saved",
    "account_deleted",
    "account_not_found",
    "field_updated",
    "delete_confirm_prompt",
    "delete_confirm_word",
    "export_done",
    "import_done",
    "import_wrong_passphrase",
    "import_invalid_file",
    "strength_label",
    "stale_alert_template",
    "reuse_warning",
    "back",
    "menu",
    "error_internal",
}


def test_messages_keys_present():
    missing = REQUIRED_KEYS - set(MESSAGES.keys())
    assert not missing, f"Missing i18n keys: {missing}"


def test_messages_are_italian_strings():
    for k, v in MESSAGES.items():
        assert isinstance(v, str)
        assert v.strip(), f"Empty message for {k}"
```

- [ ] **Step 2: Run test (fails)**

Run: `uv run pytest tests/test_i18n.py -v`

- [ ] **Step 3: Implement**

```python
"""Italian user-facing strings. Keep tone informal (tu)."""
from __future__ import annotations

MESSAGES: dict[str, str] = {
    "welcome": (
        "Ciao! Sono il tuo password bot.\n"
        "Per iniziare imposta una passphrase con /start.\n"
        "Puoi sempre interrompere con /stop."
    ),
    "menu_title": "📋 *Menu principale*",
    "ask_passphrase": "Inviami la passphrase per sbloccare il vault.\n/stop per annullare.",
    "passphrase_wrong": "Passphrase non corretta. Riprova oppure /stop.",
    "passphrase_setup_first": (
        "Non hai ancora un vault. Inviami una passphrase per crearlo.\n"
        "Scegli una passphrase robusta — è l'unica chiave per i tuoi dati."
    ),
    "session_locked": "🔒 Sessione bloccata. /start per sbloccare.",
    "stop_hint": "Suggerimento: /stop in qualsiasi momento.",
    "account_saved": "✅ Account salvato.",
    "account_deleted": "🗑 Account eliminato.",
    "account_not_found": "Account non trovato.",
    "field_updated": "✅ Campo aggiornato.",
    "delete_confirm_prompt": (
        "Per confermare l'eliminazione scrivi esattamente `ELIMINA`.\n"
        "Qualsiasi altra cosa annulla."
    ),
    "delete_confirm_word": "ELIMINA",
    "export_done": "📤 Export pronto. Conserva il file con cura — è cifrato ma la passphrase fa il resto.",
    "import_done": "📥 Import completato: {added} aggiunti, {overwritten} sovrascritti, {skipped} saltati.",
    "import_wrong_passphrase": "Passphrase di export non valida.",
    "import_invalid_file": "File di import non valido o danneggiato.",
    "strength_label": "Forza password: {score}/4 — {label}",
    "stale_alert_template": "⚠️ Hai {count} password più vecchie di {days} giorni. /list_stale per vederle.",
    "reuse_warning": "⚠️ Questa password è già usata per: {names}.",
    "back": "🔙 Indietro",
    "menu": "🏠 Menu",
    "error_internal": "Errore interno. Lo sviluppatore è stato avvisato. /menu per ricominciare.",
}
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_i18n.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/password_bot/i18n/it.py tests/test_i18n.py
git commit -m "Add Italian i18n message catalog"
```

---

## Phase 6 — Handlers and conversations

Handler tests in this phase are kept to smoke level (Phase 8.1). The handler logic is exercised end-to-end manually after Phase 7 wires the bot together.

### Task 6.1: `common.py` — global commands + error handler

**Files:**
- Create: `src/password_bot/handlers/common.py`

- [ ] **Step 1: Write the module**

```python
"""Global commands: /start, /help, /stop, /lock, /cancel, /menu, /back. Plus error handler."""
from __future__ import annotations

import html
import logging
import traceback
from typing import Any

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.state.fsm import FsmContext, Screen
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.md import escape_md

log = logging.getLogger(__name__)

MENU_SCREEN = Screen(name="menu", data={})
UNLOCK_SCREEN = Screen(name="unlock", data={})


def _fsm(context: ContextTypes.DEFAULT_TYPE) -> FsmContext:
    return FsmContext(context.chat_data)  # type: ignore[arg-type]


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    fsm = _fsm(context)
    container: Container = context.application.bot_data["container"]
    user = await container.users.get(update.effective_chat.id)
    if user is None:
        fsm.reset_to(Screen(name="setup_passphrase", data={}))
        await update.message.reply_text(
            escape_md(MESSAGES["passphrase_setup_first"]),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return
    if fsm.get_session() is None:
        fsm.reset_to(UNLOCK_SCREEN)
        await update.message.reply_text(
            escape_md(MESSAGES["ask_passphrase"]),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return
    fsm.reset_to(MENU_SCREEN)
    await update.message.reply_text(
        MESSAGES["menu_title"], parse_mode=ParseMode.MARKDOWN_V2
    )


async def cmd_stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    _fsm(context).clear_session()
    context.chat_data.clear()  # type: ignore[union-attr]
    await update.message.reply_text("👋 A presto.")
    from telegram.ext import ConversationHandler
    return ConversationHandler.END


async def cmd_lock(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    _fsm(context).clear_session()
    await update.message.reply_text(
        escape_md(MESSAGES["session_locked"]),
        parse_mode=ParseMode.MARKDOWN_V2,
    )


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    _fsm(context).clear_pending_input()
    await update.message.reply_text("Annullato.")


async def cmd_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    fsm = _fsm(context)
    fsm.reset_to(MENU_SCREEN)
    await update.message.reply_text(
        MESSAGES["menu_title"], parse_mode=ParseMode.MARKDOWN_V2
    )


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("Unhandled exception in handler", exc_info=context.error)
    container: Container | None = context.application.bot_data.get("container")
    if container is None:
        return
    dev_id = container.dev_chat_id
    if dev_id is None:
        return
    tb = "".join(traceback.format_exception(
        type(context.error), context.error, context.error.__traceback__
    ))
    redacted = html.escape(tb[:3500])
    try:
        await context.bot.send_message(
            chat_id=dev_id,
            text=f"<pre>{redacted}</pre>",
            parse_mode=ParseMode.HTML,
        )
    except Exception:  # noqa: BLE001
        log.exception("Failed to DM dev about prior error")
    if isinstance(update, Update) and update.effective_chat is not None:
        try:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=escape_md(MESSAGES["error_internal"]),
                parse_mode=ParseMode.MARKDOWN_V2,
            )
        except Exception:  # noqa: BLE001
            pass
```

- [ ] **Step 2: Lint**

Run: `uv run ruff check src/password_bot/handlers/common.py`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/password_bot/handlers/common.py
git commit -m "Add common handlers: /start, /stop, /lock, /cancel, /menu, error_handler"
```

---

### Task 6.2: `auth.py` handler

**Files:**
- Create: `src/password_bot/handlers/auth.py`

- [ ] **Step 1: Write module**

```python
"""Passphrase setup, unlock, change. The 'unlock' flow also triggers lazy migration."""
from __future__ import annotations

import logging

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.state.fsm import FsmContext, Screen
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.delete_message import schedule_delete
from password_bot.telegram_utils.md import escape_md

log = logging.getLogger(__name__)


def _fsm(context: ContextTypes.DEFAULT_TYPE) -> FsmContext:
    return FsmContext(context.chat_data)  # type: ignore[arg-type]


async def handle_passphrase_message(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Catch the passphrase the user sent and route to setup or unlock."""
    container: Container = context.application.bot_data["container"]
    chat_id = update.effective_chat.id
    passphrase = update.message.text or ""

    # Always delete the inbound message first.
    try:
        await update.message.delete()
    except Exception:  # noqa: BLE001
        pass

    user = await container.users.get(chat_id)
    if user is None:
        # First-time setup.
        r = await container.auth.register(
            chat_id=chat_id, name=update.effective_user.full_name, passphrase=passphrase,
            autolock_minutes=container.config.autolock_minutes_default,
            alert_days=container.config.alert_days_default,
        )
        if not r.ok or r.value is None:
            await context.bot.send_message(chat_id, MESSAGES["passphrase_wrong"])
            return
        _fsm(context).set_session(r.value)
        _schedule_autolock(context, chat_id, r.value.expires_at)
        await context.bot.send_message(
            chat_id, escape_md("Vault creato. /menu per iniziare."),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return

    if user.crypto_version == 1:
        legacy_r = await container.migration.unlock_legacy(
            chat_id=chat_id, passphrase=passphrase
        )
        if not legacy_r.ok or legacy_r.value is None:
            await context.bot.send_message(chat_id, MESSAGES["passphrase_wrong"])
            return
        await context.bot.send_message(chat_id, escape_md("Sto migrando il vault…"),
                                       parse_mode=ParseMode.MARKDOWN_V2)
        await container.migration.migrate_user(
            chat_id=chat_id, passphrase=passphrase, session=legacy_r.value
        )
        _fsm(context).set_session(legacy_r.value)
        _schedule_autolock(context, chat_id, legacy_r.value.expires_at)
        await context.bot.send_message(chat_id, escape_md("Migrazione completata. /menu per iniziare."),
                                       parse_mode=ParseMode.MARKDOWN_V2)
        return

    r = await container.auth.unlock(chat_id=chat_id, passphrase=passphrase)
    if not r.ok or r.value is None:
        await context.bot.send_message(chat_id, MESSAGES["passphrase_wrong"])
        return
    _fsm(context).set_session(r.value)
    _schedule_autolock(context, chat_id, r.value.expires_at)
    await context.bot.send_message(chat_id, escape_md("Sbloccato. /menu per il menu."),
                                   parse_mode=ParseMode.MARKDOWN_V2)


def _schedule_autolock(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int, expires_at: int
) -> None:
    import time

    if context.application.job_queue is None:
        return
    delay = max(1, expires_at - int(time.time()))
    name = f"autolock:{chat_id}"
    for job in context.application.job_queue.get_jobs_by_name(name):
        job.schedule_removal()
    context.application.job_queue.run_once(
        _autolock_callback, when=delay, chat_id=chat_id, name=name,
    )


async def _autolock_callback(context: ContextTypes.DEFAULT_TYPE) -> None:
    job = context.job
    if job is None or job.chat_id is None:
        return
    chat_data = context.application.chat_data.get(job.chat_id, {})  # type: ignore[union-attr]
    FsmContext(chat_data).clear_session()
    await context.bot.send_message(
        job.chat_id,
        escape_md(MESSAGES["session_locked"]),
        parse_mode=ParseMode.MARKDOWN_V2,
    )
```

- [ ] **Step 2: Lint**

Run: `uv run ruff check src/password_bot/handlers/auth.py`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/password_bot/handlers/auth.py
git commit -m "Add auth handler with setup/unlock/legacy-migration entry point"
```

---

### Task 6.3: `account_new.py` handler

**Files:**
- Create: `src/password_bot/handlers/account_new.py`

This handler walks the user through name → username (with `[Salta]`) → password (generate or type) → optional URL → optional note → optional category → confirm. Each step is stored in `chat_data[ChatDataKey.PENDING_NEW_ACCOUNT]` (a dict). On confirm, calls `VaultService.add`.

- [ ] **Step 1: Write module**

```python
"""Account creation flow with optional username/URL/note/category."""
from __future__ import annotations

from typing import Any

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.services.password_generator import (
    PasswordCharset, PasswordGenerator, PasswordSpec,
)
from password_bot.services.vault_service import NewAccount
from password_bot.state.fsm import FsmContext, Screen
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.keyboards import single_column
from password_bot.telegram_utils.md import escape_md


def _draft(context: ContextTypes.DEFAULT_TYPE) -> dict[str, Any]:
    return context.chat_data.setdefault(  # type: ignore[union-attr]
        ChatDataKey.PENDING_NEW_ACCOUNT.value, {"step": "name"},
    )


async def start_new_account(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    context.chat_data.pop(ChatDataKey.PENDING_NEW_ACCOUNT.value, None)  # type: ignore[union-attr]
    _draft(context)
    FsmContext(context.chat_data).push(Screen(name="account_new", data={}))  # type: ignore[arg-type]
    await update.effective_message.reply_text(
        escape_md("Nome dell'account? /stop per annullare."),
        parse_mode=ParseMode.MARKDOWN_V2,
    )


async def receive_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    draft = _draft(context)
    text = (update.message.text or "").strip()
    if draft["step"] == "name":
        draft["name"] = text
        draft["step"] = "username"
        await update.message.reply_text(
            escape_md("Username (oppure premi /skip per saltarlo)?"),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
    elif draft["step"] == "username":
        draft["username"] = text
        draft["step"] = "password"
        await _ask_password(update, context)
    elif draft["step"] == "password_manual":
        draft["password"] = text
        await _show_strength(update, context, text)
        draft["step"] = "url"
        await update.message.reply_text(
            escape_md("URL? Inviami il link o /skip."),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
    elif draft["step"] == "url":
        draft["url"] = text
        draft["step"] = "note"
        await update.message.reply_text(
            escape_md("Note? Inviami il testo o /skip."),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
    elif draft["step"] == "note":
        draft["note"] = text
        await _confirm_and_save(update, context)


async def cmd_skip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    draft = _draft(context)
    step = draft["step"]
    if step == "username":
        draft["username"] = None
        draft["step"] = "password"
        await _ask_password(update, context)
    elif step == "url":
        draft["url"] = None
        draft["step"] = "note"
        await update.message.reply_text(
            escape_md("Note? Inviami il testo o /skip."),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
    elif step == "note":
        draft["note"] = None
        await _confirm_and_save(update, context)


async def _ask_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    kb = single_column([
        ("🎲 Genera", "newpw:generate"),
        ("⌨️ Scrivila io", "newpw:manual"),
    ])
    await update.message.reply_text("Password?", reply_markup=kb)


async def callback_generate_password(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    await update.callback_query.answer()
    gen = PasswordGenerator()
    pw = gen.generate(PasswordSpec(length=20, charset=PasswordCharset.ALPHANUM_SYMBOLS))
    _draft(context)["password"] = pw
    _draft(context)["step"] = "url"
    await update.callback_query.edit_message_text(
        f"Generata password lunga {len(pw)} caratteri."
    )
    await update.effective_chat.send_message(
        escape_md("URL? Inviami il link o /skip."),
        parse_mode=ParseMode.MARKDOWN_V2,
    )


async def callback_manual_password(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    await update.callback_query.answer()
    _draft(context)["step"] = "password_manual"
    await update.callback_query.edit_message_text(
        "Inviami la password (verrà eliminata subito)."
    )


async def _show_strength(
    update: Update, context: ContextTypes.DEFAULT_TYPE, password: str
) -> None:
    container: Container = context.application.bot_data["container"]
    r = container.strength.evaluate(password)
    msg = MESSAGES["strength_label"].format(
        score=r.score, label=["pessima", "debole", "media", "buona", "ottima"][r.score]
    )
    if r.warning:
        msg += f"\n⚠️ {r.warning}"
    await update.message.reply_text(msg)


async def _confirm_and_save(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    container: Container = context.application.bot_data["container"]
    session = FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]
    if session is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    draft = _draft(context)
    new = NewAccount(
        chat_id=update.effective_chat.id,
        name=draft["name"],
        username=draft.get("username"),
        password=draft["password"],
        url=draft.get("url"),
        note=draft.get("note"),
        category_id=None,
    )
    acc = await container.vault.add(new, aes_key=session.aes_key, hmac_key=session.hmac_key)
    container.chat_reuse_detector(context).add(acc.id, acc.name, draft["password"])
    context.chat_data.pop(ChatDataKey.PENDING_NEW_ACCOUNT.value, None)  # type: ignore[union-attr]
    await update.message.reply_text(MESSAGES["account_saved"])
```

- [ ] **Step 2: Lint**

Run: `uv run ruff check src/password_bot/handlers/account_new.py`

- [ ] **Step 3: Commit**

```bash
git add src/password_bot/handlers/account_new.py
git commit -m "Add account_new flow with optional username/URL/note + generator"
```

---

### Task 6.4: `account_view.py` handler

**Files:**
- Create: `src/password_bot/handlers/account_view.py`

This handler renders the rich account_view screen and dispatches callback buttons (`view:show:<field>:<id>`, `view:edit:<field>:<id>`, `view:copy:<field>:<id>`, `view:dup:<id>`, `view:del:<id>`).

- [ ] **Step 1: Write module**

```python
"""Account view screen with per-field action buttons."""
from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.state.fsm import FsmContext, Screen
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.delete_message import schedule_delete
from password_bot.telegram_utils.md import code_inline, escape_md


def _mask(value: str | None) -> str:
    if value is None:
        return "—"
    return "•" * min(len(value), 8)


async def render(
    update: Update, context: ContextTypes.DEFAULT_TYPE, account_id: str
) -> None:
    container: Container = context.application.bot_data["container"]
    session = FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]
    if session is None:
        await update.effective_chat.send_message(MESSAGES["session_locked"])
        return
    acc = await container.vault.get_decrypted(account_id, aes_key=session.aes_key)
    if acc is None:
        await update.effective_chat.send_message(MESSAGES["account_not_found"])
        return

    text_lines = [
        f"🔐 *{escape_md(acc.name)}*",
        f"👤 username: {escape_md(acc.username or '—')}",
        f"🔑 password: {escape_md(_mask(acc.password))}",
        f"🌐 url: {escape_md(acc.url or '—')}",
        f"📝 note: {escape_md('presenti' if acc.note else '—')}",
    ]
    import time
    age_days = (int(time.time()) - acc.password_changed_at) // 86400
    text_lines.append(f"📅 password vecchia di {age_days} giorni")
    text = "\n".join(text_lines)

    rows = [
        [
            InlineKeyboardButton("👁 password", callback_data=f"view:show:password:{acc.id}"),
            InlineKeyboardButton("✏️", callback_data=f"view:edit:password:{acc.id}"),
            InlineKeyboardButton("📋", callback_data=f"view:copy:password:{acc.id}"),
        ],
        [
            InlineKeyboardButton("✏️ username", callback_data=f"view:edit:username:{acc.id}"),
            InlineKeyboardButton("✏️ url", callback_data=f"view:edit:url:{acc.id}"),
        ],
        [
            InlineKeyboardButton("✏️ note", callback_data=f"view:edit:note:{acc.id}"),
            InlineKeyboardButton("👁 note", callback_data=f"view:show:note:{acc.id}"),
        ],
        [
            InlineKeyboardButton("🔁 Duplica", callback_data=f"view:dup:{acc.id}"),
            InlineKeyboardButton("🗑 Elimina", callback_data=f"view:del:{acc.id}"),
        ],
        [
            InlineKeyboardButton("🔙 Indietro", callback_data="nav:back"),
            InlineKeyboardButton("🏠 Menu", callback_data="nav:menu"),
        ],
    ]
    await update.effective_chat.send_message(
        text, parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=InlineKeyboardMarkup(rows),
    )


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    container: Container = context.application.bot_data["container"]
    q = update.callback_query
    await q.answer()
    parts = q.data.split(":")
    action = parts[1]
    session = FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]
    if session is None:
        await q.edit_message_text(MESSAGES["session_locked"])
        return

    if action == "show":
        field, account_id = parts[2], parts[3]
        acc = await container.vault.get_decrypted(account_id, aes_key=session.aes_key)
        if acc is None:
            return
        value = getattr(acc, field)
        msg = await update.effective_chat.send_message(
            code_inline(value or ""), parse_mode=ParseMode.MARKDOWN_V2
        )
        schedule_delete(
            context.application, chat_id=update.effective_chat.id,
            message_id=msg.message_id, delay_seconds=30,
        )

    elif action == "copy":
        field, account_id = parts[2], parts[3]
        acc = await container.vault.get_decrypted(account_id, aes_key=session.aes_key)
        if acc is None:
            return
        value = getattr(acc, field) or ""
        msg = await update.effective_chat.send_message(
            code_inline(value), parse_mode=ParseMode.MARKDOWN_V2
        )
        schedule_delete(
            context.application, chat_id=update.effective_chat.id,
            message_id=msg.message_id, delay_seconds=30,
        )

    elif action == "edit":
        field, account_id = parts[2], parts[3]
        acc = await container.vault.get_decrypted(account_id, aes_key=session.aes_key)
        FsmContext(context.chat_data).set_pending_input({  # type: ignore[arg-type]
            "field": field, "id": account_id,
        })
        old = getattr(acc, field) if acc else None
        old_view = f" (vecchio: {code_inline(old)})" if old and field != "password" else ""
        await update.effective_chat.send_message(
            f"Nuovo {field}? /cancel per annullare.{old_view}",
            parse_mode=ParseMode.MARKDOWN_V2,
        )

    elif action == "dup":
        account_id = parts[2]
        await container.vault.duplicate(
            account_id, aes_key=session.aes_key, hmac_key=session.hmac_key
        )
        await update.effective_chat.send_message("📋 Duplicato.")

    elif action == "del":
        account_id = parts[2]
        FsmContext(context.chat_data).set_pending_input({  # type: ignore[arg-type]
            "field": "_delete_confirm", "id": account_id,
        })
        await update.effective_chat.send_message(
            escape_md(MESSAGES["delete_confirm_prompt"]),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
```

- [ ] **Step 2: Lint**

Run: `uv run ruff check src/password_bot/handlers/account_view.py`

- [ ] **Step 3: Commit**

```bash
git add src/password_bot/handlers/account_view.py
git commit -m "Add account_view handler with per-field buttons and auto-delete copies"
```

---

### Task 6.5: `account_edit.py` handler

**Files:**
- Create: `src/password_bot/handlers/account_edit.py`

Handles the response to `view:edit:*` prompts. The pending input tells which field, which account.

- [ ] **Step 1: Write module**

```python
"""Receive plain-text input for a pending field edit."""
from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.services.vault_service import UpdatedFields
from password_bot.state.fsm import FsmContext
from password_bot.telegram_utils.md import escape_md


async def handle_pending(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Returns True if the message was consumed by an edit pending."""
    fsm = FsmContext(context.chat_data)  # type: ignore[arg-type]
    pending = fsm.get_pending_input()
    if pending is None:
        return False
    text = (update.message.text or "").strip()
    if pending["field"] == "_delete_confirm":
        if text == MESSAGES["delete_confirm_word"]:
            container: Container = context.application.bot_data["container"]
            await container.vault.delete(pending["id"])
            await update.message.reply_text(MESSAGES["account_deleted"])
        else:
            await update.message.reply_text("Eliminazione annullata.")
        fsm.clear_pending_input()
        return True

    container = context.application.bot_data["container"]
    session = fsm.get_session()
    if session is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return True
    field = pending["field"]
    account_id = pending["id"]
    if field == "password":
        await container.vault.update_password(
            account_id, text, aes_key=session.aes_key, hmac_key=session.hmac_key
        )
    elif field in ("username", "url", "note"):
        await container.vault.update_fields(
            account_id, UpdatedFields(**{field: text}), aes_key=session.aes_key
        )
    elif field == "name":
        await container.vault.update_fields(
            account_id, UpdatedFields(name=text), aes_key=session.aes_key
        )
    fsm.clear_pending_input()
    try:
        await update.message.delete()
    except Exception:  # noqa: BLE001
        pass
    await update.effective_chat.send_message(
        escape_md(MESSAGES["field_updated"]),
        parse_mode=ParseMode.MARKDOWN_V2,
    )
    return True
```

- [ ] **Step 2: Lint**

Run: `uv run ruff check src/password_bot/handlers/account_edit.py`

- [ ] **Step 3: Commit**

```bash
git add src/password_bot/handlers/account_edit.py
git commit -m "Add account_edit handler dispatching pending field updates"
```

---

### Task 6.6: `inline_cmd.py` handler

**Files:**
- Create: `src/password_bot/handlers/inline_cmd.py`

Implements `/get`, `/add`, `/copy`, `/list`, `/list_stale`, `/list_reused`. All require an active session.

- [ ] **Step 1: Write module**

```python
"""Bypass-menu inline commands: /get, /add, /copy, /list, /list_stale, /list_reused."""
from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.handlers.account_new import start_new_account
from password_bot.handlers.account_view import render as render_account
from password_bot.i18n.it import MESSAGES
from password_bot.state.fsm import FsmContext
from password_bot.telegram_utils.delete_message import schedule_delete
from password_bot.telegram_utils.md import code_inline, escape_md


def _require_session(context: ContextTypes.DEFAULT_TYPE):
    return FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]


async def cmd_get(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    args = " ".join(context.args or []).strip()
    if not args:
        await update.message.reply_text("Uso: /get nome")
        return
    container: Container = context.application.bot_data["container"]
    results = await container.accounts.search(update.effective_chat.id, args)
    if not results:
        await update.message.reply_text("Nessun risultato.")
        return
    if len(results) == 1:
        await render_account(update, context, results[0][0].id)
        return
    lines = ["Più risultati:"]
    for row, score in results[:10]:
        lines.append(f"- {row.name} ({score}%) → /get {row.name}")
    await update.message.reply_text("\n".join(lines))


async def cmd_add(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    await start_new_account(update, context)


async def cmd_copy(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    session = _require_session(context)
    if session is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    args = " ".join(context.args or []).strip()
    if not args:
        await update.message.reply_text("Uso: /copy nome")
        return
    container: Container = context.application.bot_data["container"]
    results = await container.accounts.search(update.effective_chat.id, args)
    if not results:
        await update.message.reply_text("Nessun risultato.")
        return
    row, _ = results[0]
    acc = await container.vault.get_decrypted(row.id, aes_key=session.aes_key)
    if acc is None:
        await update.message.reply_text(MESSAGES["account_not_found"])
        return
    msg = await update.effective_chat.send_message(
        code_inline(acc.password), parse_mode=ParseMode.MARKDOWN_V2
    )
    schedule_delete(
        context.application, chat_id=update.effective_chat.id,
        message_id=msg.message_id, delay_seconds=30,
    )


async def cmd_list(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    container: Container = context.application.bot_data["container"]
    rows = await container.accounts.list_for_chat(update.effective_chat.id)
    if not rows:
        await update.message.reply_text("Vault vuoto.")
        return
    lines = ["📚 *Account*"]
    for r in rows:
        lines.append(f"- {escape_md(r.name)}")
    await update.message.reply_text(
        "\n".join(lines), parse_mode=ParseMode.MARKDOWN_V2
    )


async def cmd_list_stale(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    container: Container = context.application.bot_data["container"]
    stale = await container.alerts.find_stale(chat_id=update.effective_chat.id)
    if not stale:
        await update.message.reply_text("Nessuna password vecchia. 🎉")
        return
    lines = ["⚠️ *Password vecchie*"]
    for r in stale:
        lines.append(f"- {escape_md(r.name)} → /get {escape_md(r.name)}")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN_V2)


async def cmd_list_reused(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    session = _require_session(context)
    if session is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    container: Container = context.application.bot_data["container"]
    detector = container.chat_reuse_detector(context)
    clusters = detector.all_clusters(min_size=2)
    if not clusters:
        await update.message.reply_text("Nessuna password riusata. 🎉")
        return
    lines = ["⚠️ *Password riusate*"]
    for cluster in clusters:
        names = ", ".join(escape_md(name) for _, name in cluster)
        lines.append(f"- {names}")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN_V2)
```

- [ ] **Step 2: Lint**

Run: `uv run ruff check src/password_bot/handlers/inline_cmd.py`

- [ ] **Step 3: Commit**

```bash
git add src/password_bot/handlers/inline_cmd.py
git commit -m "Add inline commands /get /add /copy /list /list_stale /list_reused"
```

---

### Task 6.7: `export.py` handler

**Files:**
- Create: `src/password_bot/handlers/export.py`

- [ ] **Step 1: Write module**

```python
"""/export and /import handlers."""
from __future__ import annotations

import io
import time

from telegram import Document, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.services.errors import InvalidExportFileError, InvalidPassphraseError
from password_bot.services.export_service import MergeStrategy
from password_bot.state.fsm import FsmContext
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.md import escape_md


async def cmd_export(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    session = FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]
    if session is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    FsmContext(context.chat_data).set_pending_input({  # type: ignore[arg-type]
        "field": "_export_passphrase", "id": ""
    })
    await update.message.reply_text(
        escape_md("Passphrase per il file di export? (può essere diversa da quella del vault)"),
        parse_mode=ParseMode.MARKDOWN_V2,
    )


async def handle_export_passphrase(
    update: Update, context: ContextTypes.DEFAULT_TYPE, passphrase: str
) -> None:
    container: Container = context.application.bot_data["container"]
    session = FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]
    payload = await container.export.export(
        chat_id=update.effective_chat.id,
        vault_key=session.aes_key, export_passphrase=passphrase,
    )
    filename = f"vault-{time.strftime('%Y%m%d-%H%M', time.gmtime())}.json"
    await context.bot.send_document(
        chat_id=update.effective_chat.id,
        document=io.BytesIO(payload.encode("utf-8")),
        filename=filename,
        caption=MESSAGES["export_done"],
    )


async def cmd_import(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    session = FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]
    if session is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    await update.message.reply_text(escape_md("Inviami il file .json esportato."),
                                   parse_mode=ParseMode.MARKDOWN_V2)


async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    session = FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]
    if session is None:
        return
    doc: Document | None = update.message.document
    if doc is None or not (doc.file_name or "").endswith(".json"):
        return
    f = await context.bot.get_file(doc.file_id)
    payload_bytes = await f.download_as_bytearray()
    context.chat_data[ChatDataKey.PENDING_IMPORT_FILE.value] = bytes(payload_bytes)  # type: ignore[union-attr]
    FsmContext(context.chat_data).set_pending_input({  # type: ignore[arg-type]
        "field": "_import_passphrase", "id": ""
    })
    await update.message.reply_text(escape_md("Passphrase del file di export?"),
                                   parse_mode=ParseMode.MARKDOWN_V2)


async def handle_import_passphrase(
    update: Update, context: ContextTypes.DEFAULT_TYPE, passphrase: str
) -> None:
    container: Container = context.application.bot_data["container"]
    session = FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]
    payload = context.chat_data.pop(ChatDataKey.PENDING_IMPORT_FILE.value, None)  # type: ignore[union-attr]
    if payload is None:
        await update.message.reply_text(MESSAGES["import_invalid_file"])
        return
    try:
        report = await container.export.import_payload(
            payload.decode("utf-8"),
            chat_id=update.effective_chat.id,
            vault_key=session.aes_key,
            hmac_key=session.hmac_key,
            export_passphrase=passphrase,
            strategy=MergeStrategy.SKIP,
        )
    except InvalidPassphraseError:
        await update.message.reply_text(MESSAGES["import_wrong_passphrase"])
        return
    except InvalidExportFileError:
        await update.message.reply_text(MESSAGES["import_invalid_file"])
        return
    await update.message.reply_text(MESSAGES["import_done"].format(
        added=report.added, overwritten=report.overwritten, skipped=report.skipped,
    ))
```

- [ ] **Step 2: Lint**

Run: `uv run ruff check src/password_bot/handlers/export.py`

- [ ] **Step 3: Commit**

```bash
git add src/password_bot/handlers/export.py
git commit -m "Add /export and /import handlers"
```

---

### Task 6.8: `settings.py` handler

**Files:**
- Create: `src/password_bot/handlers/settings.py`

- [ ] **Step 1: Write module**

```python
"""/settings handler for autolock minutes and alert threshold."""
from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.state.fsm import FsmContext


def _settings_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⏰ Autolock", callback_data="set:autolock")],
        [InlineKeyboardButton("⚠️ Soglia password vecchie", callback_data="set:alert")],
        [InlineKeyboardButton("🔙", callback_data="nav:back")],
    ])


async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if FsmContext(context.chat_data).get_session() is None:  # type: ignore[arg-type]
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    await update.message.reply_text("⚙️ Impostazioni", reply_markup=_settings_keyboard())


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    container: Container = context.application.bot_data["container"]
    q = update.callback_query
    await q.answer()
    parts = q.data.split(":")
    if parts[1] == "autolock":
        rows = [[InlineKeyboardButton(f"{m} min", callback_data=f"set:autolock:{m}")]
                for m in (0, 5, 15, 30, 60)]
        await q.edit_message_text("Durata autolock?", reply_markup=InlineKeyboardMarkup(rows))
    elif parts[1] == "autolock" and len(parts) == 3:
        minutes = int(parts[2])
        await container.users.update_autolock(
            update.effective_chat.id, minutes=minutes, reset_on_activity=True
        )
        await q.edit_message_text(f"Autolock impostato a {minutes} min.")
    elif parts[1] == "alert":
        rows = [[InlineKeyboardButton(f"{d} giorni", callback_data=f"set:alert:{d}")]
                for d in (90, 180, 365, 0)]
        await q.edit_message_text("Soglia per password vecchie?", reply_markup=InlineKeyboardMarkup(rows))
    elif parts[1] == "alert" and len(parts) == 3:
        days = int(parts[2])
        await container.users.update_alert_days(update.effective_chat.id, days)
        await q.edit_message_text(f"Soglia impostata a {days} giorni.")
```

- [ ] **Step 2: Lint**

Run: `uv run ruff check src/password_bot/handlers/settings.py`

- [ ] **Step 3: Commit**

```bash
git add src/password_bot/handlers/settings.py
git commit -m "Add /settings handler for autolock and alert threshold"
```

---

### Task 6.9: `dispatcher.py` — central text router

**Files:**
- Create: `src/password_bot/handlers/dispatcher.py`

- [ ] **Step 1: Write module**

```python
"""Text-message dispatcher. Routes to the right sub-handler based on FSM state."""
from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from password_bot.handlers import account_edit, account_new, auth, export
from password_bot.state.fsm import FsmContext
from password_bot.state.keys import ChatDataKey


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    fsm = FsmContext(context.chat_data)  # type: ignore[arg-type]
    pending = fsm.get_pending_input()
    if pending is not None:
        if pending["field"] == "_export_passphrase":
            text = update.message.text or ""
            try:
                await update.message.delete()
            except Exception:  # noqa: BLE001
                pass
            fsm.clear_pending_input()
            await export.handle_export_passphrase(update, context, text)
            return
        if pending["field"] == "_import_passphrase":
            text = update.message.text or ""
            try:
                await update.message.delete()
            except Exception:  # noqa: BLE001
                pass
            fsm.clear_pending_input()
            await export.handle_import_passphrase(update, context, text)
            return
        if await account_edit.handle_pending(update, context):
            return
    if fsm.get_session() is None:
        await auth.handle_passphrase_message(update, context)
        return
    # Otherwise we're inside the account_new flow.
    if ChatDataKey.PENDING_NEW_ACCOUNT.value in context.chat_data:  # type: ignore[operator]
        await account_new.receive_text(update, context)
        return
    # Fallback: tell user to /menu.
    await update.message.reply_text("Non ho capito. /menu per il menu.")
```

- [ ] **Step 2: Commit**

```bash
git add src/password_bot/handlers/dispatcher.py
git commit -m "Add central text dispatcher routing on FSM state"
```

---

### Task 6.10: Navigation callbacks + `/help` + `/back`

**Files:**
- Modify: `src/password_bot/handlers/common.py`
- Create: `src/password_bot/handlers/nav.py`

- [ ] **Step 1: Append `/help` and `/back` to `common.py`**

Add these functions after `cmd_menu`:

```python
async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "Comandi disponibili:\n"
        "/start — apre il bot\n"
        "/menu — menu principale\n"
        "/lock — blocca sessione\n"
        "/stop — esce dalla conversazione\n"
        "/cancel — annulla input corrente\n"
        "/back — torna indietro\n"
        "/add — nuovo account\n"
        "/get NAME — cerca account\n"
        "/copy NAME — copia password\n"
        "/list — elenca account\n"
        "/list_stale — password vecchie\n"
        "/list_reused — password riusate\n"
        "/categories — gestisci categorie\n"
        "/export — esporta vault\n"
        "/import — importa vault\n"
        "/settings — impostazioni"
    )
    await update.message.reply_text(text)


async def cmd_back(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    fsm = _fsm(context)
    fsm.pop()
    if fsm.depth() == 0:
        fsm.reset_to(MENU_SCREEN)
    await update.message.reply_text("🔙")
```

- [ ] **Step 2: Create `nav.py` with the callback handler**

```python
"""Nav callback handler for `nav:back` and `nav:menu`."""
from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from password_bot.handlers.common import MENU_SCREEN
from password_bot.i18n.it import MESSAGES
from password_bot.state.fsm import FsmContext


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    parts = q.data.split(":", 1)
    action = parts[1] if len(parts) > 1 else ""
    fsm = FsmContext(context.chat_data)  # type: ignore[arg-type]
    if action == "back":
        fsm.pop()
        if fsm.depth() == 0:
            fsm.reset_to(MENU_SCREEN)
        await q.edit_message_text("🔙")
    elif action == "menu":
        fsm.reset_to(MENU_SCREEN)
        await q.edit_message_text(MESSAGES["menu_title"])
```

- [ ] **Step 3: Commit**

```bash
git add src/password_bot/handlers/common.py src/password_bot/handlers/nav.py
git commit -m "Add /help, /back commands and nav: callback handler"
```

---

### Task 6.11: Categories UI

**Files:**
- Create: `src/password_bot/handlers/categories.py`

Minimal UI: `/categories` lists, `/cat_add NAME`, `/cat_del NAME`. Per-account category assignment via callback button on account_view (already wired? No — add it here).

- [ ] **Step 1: Write module**

```python
"""Categories management: list, add, delete. Plus per-account assignment helper."""
from __future__ import annotations

import uuid

from telegram import Update
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.models.category import Category
from password_bot.services.errors import (
    CategoryNotFoundError, DuplicateCategoryError,
)
from password_bot.state.fsm import FsmContext
from password_bot.telegram_utils.md import escape_md


def _require_session(context: ContextTypes.DEFAULT_TYPE):
    return FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]


async def cmd_categories(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    container: Container = context.application.bot_data["container"]
    cats = await container.categories.list_for_chat(update.effective_chat.id)
    if not cats:
        await update.message.reply_text(
            "Nessuna categoria. /cat_add NOME per crearne una."
        )
        return
    lines = ["🏷 *Categorie*"]
    for c in cats:
        lines.append(f"- {escape_md(c.name)}")
    await update.message.reply_text("\n".join(lines), parse_mode="MarkdownV2")


async def cmd_cat_add(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    name = " ".join(context.args or []).strip()
    if not name:
        await update.message.reply_text("Uso: /cat_add NOME")
        return
    container: Container = context.application.bot_data["container"]
    existing = await container.categories.get_by_name(update.effective_chat.id, name)
    if existing is not None:
        await update.message.reply_text("Categoria già esistente.")
        return
    await container.categories.create(Category(
        id=str(uuid.uuid4()), chat_id=update.effective_chat.id, name=name, color=None,
    ))
    await update.message.reply_text(f"✅ Categoria '{name}' creata.")


async def cmd_cat_del(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if _require_session(context) is None:
        await update.message.reply_text(MESSAGES["session_locked"])
        return
    name = " ".join(context.args or []).strip()
    if not name:
        await update.message.reply_text("Uso: /cat_del NOME")
        return
    container: Container = context.application.bot_data["container"]
    cat = await container.categories.get_by_name(update.effective_chat.id, name)
    if cat is None:
        await update.message.reply_text("Categoria non trovata.")
        return
    await container.categories.delete(cat.id)
    await update.message.reply_text(f"🗑 Categoria '{name}' eliminata.")
```

- [ ] **Step 2: Commit**

```bash
git add src/password_bot/handlers/categories.py
git commit -m "Add /categories, /cat_add, /cat_del commands"
```

---

## Phase 7 — DI container, bot wiring, entrypoint

### Task 7.1: `container.py`

**Files:**
- Create: `src/password_bot/container.py`

The container builds every service once and exposes them as attributes. A helper `chat_reuse_detector(context)` lazily instantiates a per-chat `ReuseDetector` and stores it in `chat_data[ChatDataKey.REUSE_DETECTOR]`.

- [ ] **Step 1: Write module**

```python
"""DI container. Built once in bot.py and stored under application.bot_data['container']."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from telegram.ext import ContextTypes

from password_bot.config import AppConfig
from password_bot.crypto.cipher import GcmCipher
from password_bot.crypto.kdf import Argon2idKdf
from password_bot.crypto.legacy import LegacyCfbDecryptor
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.category_repo import CategoryRepo
from password_bot.repositories.history_repo import HistoryRepo
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.alert_service import AlertService
from password_bot.services.auth_service import AuthService
from password_bot.services.export_service import ExportService
from password_bot.services.migration_service import MigrationService
from password_bot.services.reuse_detector import ReuseDetector
from password_bot.services.strength_meter import StrengthMeter
from password_bot.services.vault_service import VaultService
from password_bot.state.keys import ChatDataKey


@dataclass(slots=True)
class Container:
    config: AppConfig
    dev_chat_id: int | None
    users: UserRepo
    accounts: AccountRepo
    categories: CategoryRepo
    history: HistoryRepo
    cipher: GcmCipher
    kdf: Argon2idKdf
    legacy_decryptor: LegacyCfbDecryptor
    auth: AuthService
    vault: VaultService
    migration: MigrationService
    export: ExportService
    alerts: AlertService
    strength: StrengthMeter

    @classmethod
    def build(cls, config: AppConfig, dev_chat_id: int | None) -> "Container":
        users = UserRepo(config.db_path)
        accounts = AccountRepo(config.db_path)
        categories = CategoryRepo(config.db_path)
        history = HistoryRepo(config.db_path)
        cipher = GcmCipher()
        kdf = Argon2idKdf(
            hash_params=config.argon2_hash, derive_params=config.argon2_derive
        )
        legacy_decryptor = LegacyCfbDecryptor()
        vault = VaultService(
            account_repo=accounts, history_repo=history,
            cipher=cipher, history_max=config.history_max,
        )
        auth = AuthService(user_repo=users, kdf=kdf)
        migration = MigrationService(
            users=users, accounts=accounts, kdf=kdf,
            cipher=cipher, legacy_decryptor=legacy_decryptor,
        )
        export = ExportService(
            accounts=accounts, categories=categories, vault=vault,
            cipher=cipher, kdf=kdf,
        )
        alerts = AlertService(users=users, accounts=accounts)
        return cls(
            config=config, dev_chat_id=dev_chat_id,
            users=users, accounts=accounts, categories=categories, history=history,
            cipher=cipher, kdf=kdf, legacy_decryptor=legacy_decryptor,
            auth=auth, vault=vault, migration=migration,
            export=export, alerts=alerts, strength=StrengthMeter(),
        )

    def chat_reuse_detector(self, context: ContextTypes.DEFAULT_TYPE) -> ReuseDetector:
        detector = context.chat_data.get(ChatDataKey.REUSE_DETECTOR.value)  # type: ignore[union-attr]
        if isinstance(detector, ReuseDetector):
            return detector
        from password_bot.state.fsm import FsmContext
        session = FsmContext(context.chat_data).get_session()  # type: ignore[arg-type]
        if session is None:
            raise RuntimeError("Cannot build reuse detector without session")
        detector = ReuseDetector(session.hmac_key)
        context.chat_data[ChatDataKey.REUSE_DETECTOR.value] = detector  # type: ignore[union-attr]
        return detector
```

- [ ] **Step 2: Lint + commit**

```bash
uv run ruff check src/password_bot/container.py
git add src/password_bot/container.py
git commit -m "Add DI container building services from AppConfig"
```

---

### Task 7.2: `bot.py` — application + handler registration

**Files:**
- Create: `src/password_bot/bot.py`

- [ ] **Step 1: Write module**

```python
"""Build the PTB Application and register handlers."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from telegram import Update
from telegram.ext import (
    Application, ApplicationBuilder, CallbackQueryHandler, CommandHandler,
    ConversationHandler, MessageHandler, PicklePersistence, filters,
)

from password_bot.config import AppConfig
from password_bot.container import Container
from password_bot.handlers import (
    account_new, account_view, categories, common, dispatcher, export,
    inline_cmd, nav, settings,
)
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.state.keys import ChatDataKey

log = logging.getLogger(__name__)


class _SessionStrippingPersistence(PicklePersistence):
    """Filter out the live SESSION key before writing to disk."""

    async def update_chat_data(self, chat_id: int, data: dict) -> None:  # type: ignore[override]
        clean = {k: v for k, v in data.items()
                 if k not in {ChatDataKey.SESSION.value,
                              ChatDataKey.REUSE_DETECTOR.value,
                              ChatDataKey.LEGACY_SESSION_EXTRAS.value,
                              ChatDataKey.PENDING_IMPORT_FILE.value}}
        await super().update_chat_data(chat_id, clean)


async def _on_post_init(app: Application) -> None:
    config: AppConfig = app.bot_data["config"]
    await migrate_to_latest(config.db_path)
    container = Container.build(config, dev_chat_id=app.bot_data.get("dev_chat_id"))
    app.bot_data["container"] = container
    log.info("Migrations applied, container built. DB: %s", config.db_path)


async def _daily_stale_scan(context) -> None:
    container: Container = context.application.bot_data["container"]
    async with _users_iter(container) as chat_ids:
        for chat_id in chat_ids:
            stale = await container.alerts.find_stale(chat_id=chat_id)
            if stale:
                user = await container.users.get(chat_id)
                if user is None:
                    continue
                from password_bot.i18n.it import MESSAGES
                await context.bot.send_message(
                    chat_id,
                    MESSAGES["stale_alert_template"].format(
                        count=len(stale), days=user.alert_days
                    ),
                )


async def _users_iter(container: Container):
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _ctx():
        import aiosqlite
        async with aiosqlite.connect(container.config.db_path) as conn:
            cur = await conn.execute("SELECT chat_id FROM users")
            yield [r[0] for r in await cur.fetchall()]

    return _ctx()


def build_application(config: AppConfig, *, token: str, dev_chat_id: int | None) -> Application:
    persistence = _SessionStrippingPersistence(filepath=str(config.pkl_path))
    application = (
        ApplicationBuilder()
        .token(token)
        .persistence(persistence)
        .post_init(_on_post_init)
        .build()
    )
    application.bot_data["config"] = config
    application.bot_data["dev_chat_id"] = dev_chat_id

    conv = ConversationHandler(
        entry_points=[CommandHandler("start", common.cmd_start)],
        states={
            0: [
                CommandHandler("menu", common.cmd_menu),
                CommandHandler("help", common.cmd_help),
                CommandHandler("back", common.cmd_back),
                CommandHandler("lock", common.cmd_lock),
                CommandHandler("cancel", common.cmd_cancel),
                CommandHandler("categories", categories.cmd_categories),
                CommandHandler("cat_add", categories.cmd_cat_add),
                CommandHandler("cat_del", categories.cmd_cat_del),
                CommandHandler("add", inline_cmd.cmd_add),
                CommandHandler("get", inline_cmd.cmd_get),
                CommandHandler("copy", inline_cmd.cmd_copy),
                CommandHandler("list", inline_cmd.cmd_list),
                CommandHandler("list_stale", inline_cmd.cmd_list_stale),
                CommandHandler("list_reused", inline_cmd.cmd_list_reused),
                CommandHandler("export", export.cmd_export),
                CommandHandler("import", export.cmd_import),
                CommandHandler("settings", settings.cmd_settings),
                CommandHandler("skip", account_new.cmd_skip),
                CallbackQueryHandler(account_new.callback_generate_password, pattern=r"^newpw:generate$"),
                CallbackQueryHandler(account_new.callback_manual_password, pattern=r"^newpw:manual$"),
                CallbackQueryHandler(account_view.on_callback, pattern=r"^view:"),
                CallbackQueryHandler(settings.on_callback, pattern=r"^set:"),
                CallbackQueryHandler(nav.on_callback, pattern=r"^nav:"),
                MessageHandler(filters.Document.ALL, export.on_document),
                MessageHandler(filters.TEXT & ~filters.COMMAND, dispatcher.on_text),
            ],
        },
        fallbacks=[CommandHandler("stop", common.cmd_stop)],
        name="root",
        persistent=True,
        per_chat=True,
        per_user=False,
        per_message=False,
    )
    application.add_handler(conv)
    application.add_error_handler(common.error_handler)

    if application.job_queue is not None:
        from datetime import time as dtime
        application.job_queue.run_daily(
            _daily_stale_scan, time=dtime(hour=9, minute=0), name="daily_stale_scan",
        )

    return application
```

- [ ] **Step 2: Lint + commit**

```bash
uv run ruff check src/password_bot/bot.py
git add src/password_bot/bot.py
git commit -m "Add bot.py with PTB Application builder, handler tree, daily scan job"
```

> **Note:** the `ConversationHandler` uses a single integer state `0` because the new navigation is driven by `FsmContext` (chat_data nav stack), not by PTB conversation states. PTB still needs at least one state per the API.

---

### Task 7.3: `__main__.py` entrypoint + keyring loader

**Files:**
- Create: `src/password_bot/__main__.py`

- [ ] **Step 1: Write module**

```python
"""Entrypoint: KEYRING=./keys uv run -m password_bot"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from password_bot.bot import build_application
from password_bot.config import AppConfig


def _read_keyring_value(keyring_dir: Path, filename: str) -> str:
    path = keyring_dir / filename
    if not path.is_file():
        raise RuntimeError(f"Missing keyring file: {path}")
    return path.read_text(encoding="utf-8").strip()


def _setup_logging(log_path: Path) -> None:
    handler = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    logging.getLogger("httpx").setLevel(logging.WARNING)


def main() -> None:
    config = AppConfig.load()
    _setup_logging(config.log_path)
    token = _read_keyring_value(config.keyring_dir, "telegram.dat")
    dev_chat_id_raw = _read_keyring_value(config.keyring_dir, "dev_id.dat")
    dev_chat_id = int(dev_chat_id_raw)
    application = build_application(config, token=token, dev_chat_id=dev_chat_id)
    application.run_polling(close_loop=False)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Lint**

Run: `uv run ruff check src/password_bot/__main__.py`

- [ ] **Step 3: Commit**

```bash
git add src/password_bot/__main__.py
git commit -m "Add __main__ entrypoint with keyring loader and rotating log"
```

---

## Phase 8 — Smoke tests, cleanup, docs

### Task 8.1: Handler smoke tests

**Files:**
- Create: `tests/handlers/test_smoke.py`

- [ ] **Step 1: Write tests**

```python
import pytest
from telegram import Bot
from telegram.ext import Application, ApplicationBuilder

from password_bot.bot import build_application
from password_bot.config import AppConfig, Argon2Params


@pytest.fixture
async def app(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYRING", str(tmp_path / "keys"))
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "telegram.dat").write_text("0:dummy")
    (tmp_path / "keys" / "dev_id.dat").write_text("0")
    config = AppConfig.load(base_dir=tmp_path)
    application = build_application(config, token="0:dummy", dev_chat_id=0)
    yield application


def test_application_builds_with_root_conversation(app: Application):
    handlers = app.handlers[0]
    assert any(getattr(h, "name", None) == "root" for h in handlers)


def test_error_handler_registered(app: Application):
    assert app.error_handlers
```

- [ ] **Step 2: Run tests**

Run: `uv run pytest tests/handlers/test_smoke.py -v`
Expected: 2 passed.

- [ ] **Step 3: Commit**

```bash
git add tests/handlers/test_smoke.py
git commit -m "Add smoke test verifying Application builds with root conversation"
```

---

### Task 8.2: CI workflow

**Files:**
- Create: `.github/workflows/test.yml`

- [ ] **Step 1: Write workflow**

```yaml
name: tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv sync --dev
      - run: uv run ruff check src tests
      - run: uv run ruff format --check src tests
      - run: uv run pytest --cov=src/password_bot --cov-fail-under=75 -q
```

- [ ] **Step 2: Run all checks locally**

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest --cov=src/password_bot --cov-fail-under=75 -q
```
Expected: every command exits 0.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/test.yml
git commit -m "Add GitHub Actions CI: ruff lint/format, pytest, coverage"
```

---

### Task 8.3: Remove old `src/*.py` modules

**Files:**
- Delete: `src/main.py`
- Delete: `src/account.py`
- Delete: `src/account_repository.py`
- Delete: `src/crypto_service.py`
- Delete: `src/environment_variables_mg.py`

> **Important:** Only delete these AFTER you have confirmed the new bot boots in a real environment with your backup (`accounts.db.bak`, `DB.pkl.bak`) safely set aside. The legacy crypto path lives in `src/password_bot/crypto/legacy.py` — it does **not** depend on these old files.

- [ ] **Step 1: Confirm the new bot starts**

Run: `KEYRING=./keys uv run -m password_bot &` (in a copy of the working dir with a `accounts.db.bak` already taken)

After verifying you can `/start` and unlock, terminate the process.

- [ ] **Step 2: Delete old modules**

```bash
git rm src/main.py src/account.py src/account_repository.py \
       src/crypto_service.py src/environment_variables_mg.py
```

- [ ] **Step 3: Run full test suite**

Run: `uv run pytest -q`
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git commit -m "Remove legacy flat-module bot in favour of password_bot package"
```

---

### Task 8.4: Update `README.md` with rollout instructions

**Files:**
- Modify: `README.md` (create if missing)

- [ ] **Step 1: Replace README content**

```markdown
# Password Bot v2

Telegram password manager bot. Vault is local-only, encrypted with AES-256-GCM, key derived from Argon2id-hashed passphrase.

## Run

```bash
uv sync
KEYRING=./keys uv run -m password_bot
```

`KEYRING` must point to a directory containing:
- `telegram.dat` — bot token (single line)
- `dev_id.dat` — Telegram chat id that receives error reports (single line)

## Migrating from v1

Before switching to `rewrite/v2`:

```bash
cp accounts.db accounts.db.bak
cp DB.pkl DB.pkl.bak
```

On first boot the bot will:
1. Apply schema migration in a single transaction.
2. On the first `/start`, accept the same passphrase and lazily re-encrypt every row to AES-GCM + Argon2id.

If anything goes wrong, restore the backups and check out the `master` branch.

## Argon2id tuning (Pi Zero 2W)

Defaults are tuned for a Pi Zero 2W. Override via env vars:

```
PB_ARGON2_M=65536      # KiB, default 65536
PB_ARGON2_T=3          # iterations
PB_ARGON2_P=1          # parallelism
PB_ARGON2_DERIVE_M=32768
PB_ARGON2_DERIVE_T=2
```

## Tests

```bash
uv run pytest --cov=src/password_bot
```

## Architecture

See `docs/superpowers/specs/2026-05-16-bot-rewrite-design.md`.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "Document v2 run, migration, Argon2 tuning, tests"
```

---

### Task 8.5: `.gitignore` and ensure backup files are not committed

**Files:**
- Modify: `.gitignore`

- [ ] **Step 1: Ensure these entries are present**

```
*.db
*.db.bak
*.pkl
*.pkl.bak
password_bot.log
__pycache__/
.pytest_cache/
.ruff_cache/
.coverage
htmlcov/
```

- [ ] **Step 2: Commit**

```bash
git add .gitignore
git commit -m "Ignore .db, .pkl, log, and test caches"
```

---

## Verification checklist (final)

Before opening the PR to `master`:

- [ ] `uv run ruff check src tests` → clean
- [ ] `uv run ruff format --check src tests` → clean
- [ ] `uv run pytest --cov=src/password_bot --cov-fail-under=75 -q` → green
- [ ] Manually start the bot against a **copy** of the real `accounts.db`; unlock; pick one legacy account; confirm decryption works; confirm subsequent `/start` enters via the GCM path.
- [ ] `/export` produces a JSON file; `/import` round-trips it.
- [ ] `/copy NAME` sends the password as a separate message that auto-deletes after 30 s.
- [ ] `/lock` clears the session; subsequent message prompts passphrase again.
- [ ] CI green on the pushed branch.

Open PR `rewrite/v2 → master` with the spec link in the description.






