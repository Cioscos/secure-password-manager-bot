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
    FsmContext(context.chat_data).set_pending_input(
        {  # type: ignore[arg-type]
            "field": "_export_passphrase",
            "id": "",
        }
    )
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
        vault_key=session.aes_key,
        export_passphrase=passphrase,
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
    await update.message.reply_text(
        escape_md("Inviami il file .json esportato."),
        parse_mode=ParseMode.MARKDOWN_V2,
    )


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
    FsmContext(context.chat_data).set_pending_input(
        {  # type: ignore[arg-type]
            "field": "_import_passphrase",
            "id": "",
        }
    )
    await update.message.reply_text(
        escape_md("Passphrase del file di export?"),
        parse_mode=ParseMode.MARKDOWN_V2,
    )


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
    await update.message.reply_text(
        MESSAGES["import_done"].format(
            added=report.added,
            overwritten=report.overwritten,
            skipped=report.skipped,
        )
    )
