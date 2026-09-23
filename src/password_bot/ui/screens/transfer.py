"""Encrypted vault export and import."""

from __future__ import annotations

import io
import time

from telegram import Document

from password_bot.i18n.it import MESSAGES
from password_bot.services.errors import InvalidExportFileError, InvalidPassphraseError
from password_bot.services.export_service import MergeStrategy
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import TEXT_NOT_ACCEPTED, Ctx, Result, Screen, View, back, refresh
from password_bot.ui.views import btn, keyboard


class TransferScreen(Screen):
    name = "transfer"
    title = "Export/Import"
    accepts_text = True
    accepts_document = True

    def _exporting(self, ctx: Ctx) -> bool:
        return ctx.args.get("mode") == "export"

    async def on_enter(self, ctx: Ctx) -> None:
        ctx.drop_flow(self.name)
        ctx.flow(self.name)["step"] = "passphrase" if self._exporting(ctx) else "file"

    async def render(self, ctx: Ctx) -> View:
        cancel = keyboard([btn("❌ Annulla", self.name, "cancel")])
        if self._exporting(ctx):
            return View(
                "📤 *Export*\n"
                + escape_md(
                    "Inviami la passphrase con cui cifrare il file (può essere diversa da quella "
                    "del vault). Cancellerò subito il messaggio."
                ),
                cancel,
            )
        if ctx.flow(self.name).get("step") == "passphrase":
            return View(
                "📥 *Import*\n" + escape_md("File ricevuto. Inviami la passphrase del file."),
                cancel,
            )
        return View("📥 *Import*\n" + escape_md("Inviami il file .json esportato dal bot."), cancel)

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        if act.action == "cancel":
            ctx.drop_flow(self.name)
            return back()
        return refresh()

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        if not text:
            return refresh()
        session = ctx.session
        if self._exporting(ctx):
            payload = await ctx.container.export.export(
                chat_id=ctx.chat_id, vault_key=session.aes_key, export_passphrase=text
            )
            await ctx.bot.send_document(
                chat_id=ctx.chat_id,
                document=io.BytesIO(payload.encode("utf-8")),
                filename=f"vault-{time.strftime('%Y%m%d-%H%M', time.gmtime())}.json",
                caption=MESSAGES["export_done"],
            )
            ctx.drop_flow(self.name)
            return back(notice="📤 Export inviato qui sotto.")
        flow = ctx.flow(self.name)
        if flow.get("step") != "passphrase" or flow.get("file") is None:
            return refresh(notice=TEXT_NOT_ACCEPTED)
        try:
            report = await ctx.container.export.import_payload(
                flow["file"].decode("utf-8"),
                chat_id=ctx.chat_id,
                vault_key=session.aes_key,
                hmac_key=session.hmac_key,
                export_passphrase=text,
                strategy=MergeStrategy.SKIP,
            )
        except InvalidPassphraseError:
            return refresh(notice=MESSAGES["import_wrong_passphrase"])
        except (InvalidExportFileError, UnicodeDecodeError):
            flow.pop("file", None)
            flow["step"] = "file"
            return refresh(notice=MESSAGES["import_invalid_file"])
        ctx.drop_flow(self.name)
        return back(
            notice=MESSAGES["import_done"].format(
                added=report.added, overwritten=report.overwritten, skipped=report.skipped
            )
        )

    async def on_document(self, ctx: Ctx, document: Document) -> Result:
        flow = ctx.flow(self.name)
        if self._exporting(ctx) or flow.get("step") != "file":
            return refresh(notice="⚠️ Non mi aspettavo un file qui.")
        if not (document.file_name or "").lower().endswith(".json"):
            return refresh(notice="⚠️ Serve il file .json esportato dal bot.")
        tg_file = await ctx.bot.get_file(document.file_id)
        flow["file"] = bytes(await tg_file.download_as_bytearray())
        flow["step"] = "passphrase"
        return refresh()
