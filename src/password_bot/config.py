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
    def hash_params_from_env(cls) -> Argon2Params:
        return cls(
            memory_cost=_env_int("PB_ARGON2_M", 65536),
            time_cost=_env_int("PB_ARGON2_T", 3),
            parallelism=_env_int("PB_ARGON2_P", 1),
        )

    @classmethod
    def derive_params_from_env(cls) -> Argon2Params:
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
    def load(cls, base_dir: Path | None = None) -> AppConfig:
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
