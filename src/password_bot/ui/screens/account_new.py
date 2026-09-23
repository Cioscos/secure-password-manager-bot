"""Account creation: name → username → password → summary (URL, note, category, save)."""

from __future__ import annotations

from typing import Any

from password_bot.models.category import Category
from password_bot.services.vault_service import NewAccount
from password_bot.state.fsm import Frame
from password_bot.telegram_utils.md import escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import (
    TEXT_NOT_ACCEPTED,
    Ctx,
    Result,
    Screen,
    View,
    back,
    finish,
    open_screen,
    refresh,
)
from password_bot.ui.screens._shared import reuse_names_for, strength_text, username_suggestions
from password_bot.ui.views import (
    PRIMARY,
    SUCCESS,
    btn,
    category_label,
    keyboard,
    label,
    normalize_url,
)

_EDITABLE = ("name", "username", "password", "url", "note")
_BEFORE_SUMMARY = {"username": "name", "password": "username", "password_manual": "password"}


class AccountNewScreen(Screen):
    name = "account_new"
    title = "Nuovo account"
    accepts_text = True

    async def on_enter(self, ctx: Ctx) -> None:
        ctx.drop_flow(self.name)
        ctx.flow(self.name).update(
            step="name",
            category_id=ctx.args.get("category_id"),
            suggestions=await username_suggestions(ctx),
            reached_summary=False,
        )

    async def _flow(self, ctx: Ctx) -> dict[str, Any]:
        flow = ctx.flow(self.name)
        if "step" not in flow:  # lost after a restart or a lock: start over
            await self.on_enter(ctx)
            flow = ctx.flow(self.name)
        return flow

    @staticmethod
    def _header(step: int) -> str:
        return "➕ *Nuovo account* — " + escape_md(f"passo {step}/3") + "\n"  # noqa: RUF001

    async def _category(self, ctx: Ctx, cat_id: str | None) -> Category | None:
        if not cat_id:
            return None
        cat = await ctx.container.categories.get(cat_id)
        return cat if cat is not None and cat.chat_id == ctx.chat_id else None

    async def render(self, ctx: Ctx) -> View:
        flow = await self._flow(ctx)
        step = flow["step"]
        if step == "summary":
            flow["reached_summary"] = True
            return await self._summary(ctx, flow)
        can_go_back = step != "name" or flow.get("reached_summary")
        nav_row = [
            btn("🔙 Indietro", self.name, "back_step") if can_go_back else None,
            btn("❌ Annulla", self.name, "cancel"),
        ]
        if step == "name":
            return View(self._header(1) + escape_md("Nome dell'account?"), keyboard(nav_row))
        if step == "username":
            lines = [self._header(2)]
            rows = []
            existing = await self._existing(ctx, flow.get("name", ""))
            if existing is not None:
                lines.append(escape_md(f"⚠️ Hai già un account «{existing.name}»."))
                rows.append([btn("👁 Apri esistente", self.name, "existing", existing.id)])
            lines.append(escape_md("Username o email? Scrivilo oppure scegli:"))
            rows += [
                [btn(label(s), self.name, "pick", i)]
                for i, s in enumerate(flow.get("suggestions", []))
            ]
            rows.append([btn("⏭ Nessuno", self.name, "no_user")])
            rows.append(nav_row)
            return View("\n".join(lines), keyboard(*rows))
        if step == "password":
            return View(
                self._header(3) + escape_md("Come vuoi impostare la password?"),
                keyboard(
                    [
                        btn("🎲 Genera", self.name, "gen", style=PRIMARY),
                        btn("⌨️ Scrivila io", self.name, "manual"),
                    ],
                    nav_row,
                ),
            )
        if step == "password_manual":
            return View(
                escape_md("⌨️ Inviami la password. Cancellerò subito il tuo messaggio."),
                keyboard(nav_row),
            )
        prompt = "🌐 URL dell'account?" if step == "url" else "📝 Note per l'account?"
        clear = btn("🗑 Rimuovi", self.name, "clear", step) if flow.get(step) else None
        return View(escape_md(prompt), keyboard([clear], nav_row))

    async def _existing(self, ctx: Ctx, name: str):
        wanted = name.strip().lower()
        for row in await ctx.container.accounts.list_for_chat(ctx.chat_id):
            if row.name.lower() == wanted:
                return row
        return None

    async def _summary(self, ctx: Ctx, flow: dict[str, Any]) -> View:
        password = flow.get("password") or ""
        lines = [
            "➕ *Riepilogo*",  # noqa: RUF001
            f"🔐 {escape_md(flow.get('name') or '—')}",
            f"👤 {escape_md(flow.get('username') or '—')}",
            escape_md(f"🔑 •••••••• — {strength_text(ctx, password)}"),
        ]
        reused = await reuse_names_for(ctx, password) if password else []
        if reused:
            lines.append(escape_md("♻️ Stessa password di: " + ", ".join(reused)))
        if flow.get("url"):
            lines.append(f"🌐 {escape_md(flow['url'])}")
        if flow.get("note"):
            lines.append(escape_md("📝 Note presenti"))
        cat = await self._category(ctx, flow.get("category_id"))
        cat_text = category_label(cat) if cat else "—"
        url_label = f"🌐 {label(flow['url'], 20)}" if flow.get("url") else "🌐 + URL"
        note_label = "📝 Note ✓" if flow.get("note") else "📝 + Note"
        return View(
            "\n".join(lines),
            keyboard(
                [
                    btn("📛 Nome", self.name, "edit", "name"),
                    btn("👤 Username", self.name, "edit", "username"),
                    btn("🔑 Password", self.name, "edit", "password"),
                ],
                [
                    btn(url_label, self.name, "edit", "url"),
                    btn(note_label, self.name, "edit", "note"),
                ],
                [btn(f"🏷 Categoria: {label(cat_text, 24)}", self.name, "category")],
                [btn("💾 Salva", self.name, "save", style=SUCCESS)],
                [btn("❌ Annulla", self.name, "cancel")],
            ),
        )

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        flow = await self._flow(ctx)
        step = flow["step"]
        value = text.strip()
        after = "summary" if flow.get("reached_summary") else None
        if step == "name":
            if not value:
                return refresh(notice="⚠️ Il nome non può essere vuoto.")
            flow["name"] = value
            flow["step"] = after or "username"
        elif step == "username":
            flow["username"] = value or None
            flow["step"] = after or "password"
        elif step == "password_manual":
            if not text:
                return refresh()
            flow["password"] = text  # verbatim
            flow["step"] = "summary"
        elif step == "url":
            url = normalize_url(value)
            if url is None:
                return refresh(notice="⚠️ URL non valido. Esempio: github.com")
            flow["url"] = url
            flow["step"] = "summary"
        elif step == "note":
            flow["note"] = value or None
            flow["step"] = "summary"
        else:
            return refresh(notice=TEXT_NOT_ACCEPTED)
        return refresh()

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        flow = await self._flow(ctx)
        after = "summary" if flow.get("reached_summary") else None
        match act.action:
            case "cancel":
                ctx.drop_flow(self.name)
                return back()
            case "back_step":
                step = flow["step"]
                if step == "password_manual":
                    flow["step"] = "password"
                else:
                    flow["step"] = after or _BEFORE_SUMMARY.get(step, "name")
            case "pick":
                suggestions = flow.get("suggestions", [])
                index = int(act.arg or 0)
                if 0 <= index < len(suggestions):
                    flow["username"] = suggestions[index]
                    flow["step"] = after or "password"
            case "no_user":
                flow["username"] = None
                flow["step"] = after or "password"
            case "existing":
                return open_screen("account_detail", id=act.arg)
            case "gen":
                return open_screen("generator", flow=self.name, next_step="summary")
            case "manual":
                flow["step"] = "password_manual"
            case "edit" if act.arg in _EDITABLE:
                flow["step"] = act.arg
            case "clear" if act.arg in ("url", "note"):
                flow[act.arg] = None
                flow["step"] = "summary"
            case "category":
                return open_screen("category_pick", flow=self.name)
            case "save":
                return await self._save(ctx, flow)
        return refresh()

    async def _save(self, ctx: Ctx, flow: dict[str, Any]) -> Result:
        if not flow.get("name") or not flow.get("password"):
            return refresh(notice="⚠️ Mancano nome o password.")
        cat = await self._category(ctx, flow.get("category_id"))
        session = ctx.session
        acc = await ctx.container.vault.add(
            NewAccount(
                chat_id=ctx.chat_id,
                name=flow["name"],
                username=flow.get("username"),
                password=flow["password"],
                url=flow.get("url"),
                note=flow.get("note"),
                category_id=cat.id if cat else None,
            ),
            aes_key=session.aes_key,
            hmac_key=session.hmac_key,
        )
        ctx.drop_flow(self.name)
        return finish(
            self.name, then=Frame("account_detail", {"id": acc.id}), notice="✅ Account salvato"
        )
