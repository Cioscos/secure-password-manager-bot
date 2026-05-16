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
