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
    PersistenceInput,
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
    persistence = _SessionStrippingPersistence(
        filepath=str(config.pkl_path),
        store_data=PersistenceInput(
            bot_data=False, user_data=False, chat_data=True, callback_data=True
        ),
    )

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
        .concurrent_updates(False)
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
