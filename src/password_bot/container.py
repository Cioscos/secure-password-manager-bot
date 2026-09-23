"""DI container. Built once in bot.py and stored under application.bot_data['container']."""

from __future__ import annotations

from dataclasses import dataclass

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
from password_bot.services.strength_meter import StrengthMeter
from password_bot.services.vault_service import VaultService


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
    def build(cls, config: AppConfig, dev_chat_id: int | None) -> Container:
        users = UserRepo(config.db_path)
        accounts = AccountRepo(config.db_path)
        categories = CategoryRepo(config.db_path)
        history = HistoryRepo(config.db_path)
        cipher = GcmCipher()
        kdf = Argon2idKdf(hash_params=config.argon2_hash, derive_params=config.argon2_derive)
        legacy_decryptor = LegacyCfbDecryptor()
        vault = VaultService(
            account_repo=accounts,
            history_repo=history,
            cipher=cipher,
            history_max=config.history_max,
        )
        auth = AuthService(user_repo=users, kdf=kdf)
        migration = MigrationService(
            users=users,
            accounts=accounts,
            kdf=kdf,
            cipher=cipher,
            legacy_decryptor=legacy_decryptor,
        )
        export = ExportService(
            accounts=accounts,
            categories=categories,
            vault=vault,
            cipher=cipher,
            kdf=kdf,
        )
        alerts = AlertService(users=users, accounts=accounts)
        return cls(
            config=config,
            dev_chat_id=dev_chat_id,
            users=users,
            accounts=accounts,
            categories=categories,
            history=history,
            cipher=cipher,
            kdf=kdf,
            legacy_decryptor=legacy_decryptor,
            auth=auth,
            vault=vault,
            migration=migration,
            export=export,
            alerts=alerts,
            strength=StrengthMeter(),
        )
