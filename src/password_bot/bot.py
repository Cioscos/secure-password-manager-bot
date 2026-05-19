"""Build the PTB Application and register handlers."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import aiosqlite
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ConversationHandler,
    MessageHandler,
    PicklePersistence,
    filters,
)

from password_bot.config import AppConfig
from password_bot.container import Container
from password_bot.handlers import (
    account_new,
    account_view,
    categories,
    common,
    dispatcher,
    export,
    inline_cmd,
    nav,
    password_gen,
    settings,
)
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.state.keys import ChatDataKey
from password_bot.telegram_utils.callback_data import ListPageData

log = logging.getLogger(__name__)


class _SessionStrippingPersistence(PicklePersistence):
    """Filter out the live SESSION key before writing to disk."""

    async def update_chat_data(self, chat_id: int, data: dict) -> None:  # type: ignore[override]
        clean = {
            k: v
            for k, v in data.items()
            if k
            not in {
                ChatDataKey.SESSION.value,
                ChatDataKey.REUSE_DETECTOR.value,
                ChatDataKey.LEGACY_SESSION_EXTRAS.value,
                ChatDataKey.PENDING_IMPORT_FILE.value,
                ChatDataKey.PW_GEN_DRAFT.value,
                ChatDataKey.PW_GEN_RETURN_TO.value,
            }
        }
        await super().update_chat_data(chat_id, clean)


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
                    MESSAGES["stale_alert_template"].format(count=len(stale), days=user.alert_days),
                )


@asynccontextmanager
async def _users_iter(container: Container):
    async with aiosqlite.connect(container.config.db_path) as conn:
        cur = await conn.execute("SELECT chat_id FROM users")
        yield [r[0] for r in await cur.fetchall()]


def build_application(config: AppConfig, *, token: str, dev_chat_id: int | None) -> Application:
    persistence = _SessionStrippingPersistence(filepath=str(config.pkl_path))

    async def _post_init(app: Application) -> None:
        await migrate_to_latest(config.db_path)
        container = Container.build(config, dev_chat_id=dev_chat_id)
        app.bot_data["container"] = container
        log.info("Migrations applied, container built. DB: %s", config.db_path)

    application = (
        ApplicationBuilder()
        .token(token)
        .persistence(persistence)
        .arbitrary_callback_data(True)
        .post_init(_post_init)
        .build()
    )

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
                CallbackQueryHandler(
                    account_new.callback_generate_password, pattern=r"^newpw:generate$"
                ),
                CallbackQueryHandler(
                    account_new.callback_manual_password, pattern=r"^newpw:manual$"
                ),
                CallbackQueryHandler(account_view.on_callback, pattern=r"^view:"),
                CallbackQueryHandler(settings.on_callback, pattern=r"^set:"),
                CallbackQueryHandler(nav.on_callback, pattern=r"^nav:"),
                CallbackQueryHandler(common.on_menu_callback, pattern=r"^menu:"),
                CallbackQueryHandler(categories.on_callback, pattern=r"^cat:"),
                CallbackQueryHandler(password_gen.on_callback, pattern=r"^pwgen:"),
                CallbackQueryHandler(inline_cmd.on_account_callback, pattern=r"^acc:"),
                CallbackQueryHandler(
                    inline_cmd.on_list_callback,
                    pattern=lambda d: isinstance(d, ListPageData),
                ),
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
            _daily_stale_scan,
            time=dtime(hour=9, minute=0),
            name="daily_stale_scan",
        )

    return application
