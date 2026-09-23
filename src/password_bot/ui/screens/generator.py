"""Password generator screen, reusable by any flow (creation, password change, settings)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from password_bot.models.pw_prefs import PwPrefs
from password_bot.services.password_generator import (
    MAX_LENGTH,
    MIN_LENGTH,
    PasswordGenerator,
    PasswordSpec,
    entropy_bits,
)
from password_bot.telegram_utils.md import code_inline, escape_md
from password_bot.ui.callbacks import Act
from password_bot.ui.screen import TEXT_NOT_ACCEPTED, Ctx, Result, Screen, View, back, refresh
from password_bot.ui.views import PRIMARY, SUCCESS, btn, footer, keyboard

_FLAGS = (
    ("upper", "Maiuscole"),
    ("lower", "Minuscole"),
    ("digits", "Numeri"),
    ("symbols", "Simboli"),
    ("exclude_ambiguous", "No ambigui"),
    ("no_duplicates", "No duplicati"),
)


def _spec(prefs: PwPrefs) -> PasswordSpec:
    return PasswordSpec(
        length=prefs.length,
        upper=prefs.upper,
        lower=prefs.lower,
        digits=prefs.digits,
        symbols=prefs.symbols,
        exclude_ambiguous=prefs.exclude_ambiguous,
        no_duplicates=prefs.no_duplicates,
    )


class GeneratorScreen(Screen):
    name = "generator"
    title = "Generatore"
    accepts_text = True

    async def on_enter(self, ctx: Ctx) -> None:
        prefs = await ctx.container.users.get_pw_prefs(ctx.chat_id)
        ctx.drop_flow(self.name)
        ctx.flow(self.name).update(prefs=asdict(prefs), password=None, await_len=False)

    async def _state(self, ctx: Ctx) -> dict[str, Any]:
        state = ctx.flow(self.name)
        if "prefs" not in state:  # flow lost (restart or lock): start again from saved defaults
            await self.on_enter(ctx)
            state = ctx.flow(self.name)
        return state

    async def render(self, ctx: Ctx) -> View:
        state = await self._state(ctx)
        prefs = PwPrefs(**state["prefs"])
        password = state.get("password")
        lines = ["🎲 *Generatore password*"]
        if password:
            bits = int(entropy_bits(_spec(prefs)))
            lines += [
                "",
                code_inline(password),
                escape_md(f"{len(password)} caratteri, entropia ≈ {bits} bit"),
            ]
        if state.get("await_len"):
            lines += ["", escape_md(f"Scrivi la lunghezza ({MIN_LENGTH}-{MAX_LENGTH}).")]
        toggles = [
            btn(f"{text} {'✅' if getattr(prefs, flag) else '❌'}", self.name, "toggle", flag)
            for flag, text in _FLAGS
        ]
        rows = [
            [btn(f"📏 Lunghezza: {prefs.length}", self.name, "len")],
            toggles[0:2],
            toggles[2:4],
            toggles[4:6],
            [
                btn(
                    "🔄 Rigenera" if password else "🎲 Genera",
                    self.name,
                    "run",
                    style=None if password else PRIMARY,
                )
            ],
        ]
        if password and ctx.args.get("flow"):
            rows.append([btn("✅ Usa", self.name, "use", style=SUCCESS)])
        rows.append(
            [
                btn("💾 Salva come predefinite", self.name, "save"),
                btn("🔄 Reset", self.name, "reset"),
            ]
        )
        rows.append(footer(ctx.back_label))
        return View("\n".join(lines), keyboard(*rows))

    async def on_text(self, ctx: Ctx, text: str) -> Result:
        state = await self._state(ctx)
        if not state.get("await_len"):
            return refresh(notice=TEXT_NOT_ACCEPTED)
        try:
            length = int(text.strip())
        except ValueError:
            length = 0
        if not MIN_LENGTH <= length <= MAX_LENGTH:
            return refresh(
                notice=f"⚠️ Lunghezza non valida: usa un numero tra {MIN_LENGTH} e {MAX_LENGTH}."
            )
        state["prefs"]["length"] = length
        state["await_len"] = False
        state["password"] = None
        return refresh()

    async def on_action(self, ctx: Ctx, act: Act) -> Result:
        state = await self._state(ctx)
        prefs = state["prefs"]
        match act.action:
            case "toggle" if act.arg in prefs and act.arg != "length":
                prefs[act.arg] = not prefs[act.arg]
                state["password"] = None
            case "len":
                state["await_len"] = True
            case "run":
                try:
                    state["password"] = PasswordGenerator().generate(_spec(PwPrefs(**prefs)))
                except ValueError as e:
                    return refresh(notice=f"⚠️ {e}")
            case "use" if state.get("password") and ctx.args.get("flow"):
                target = ctx.flow(str(ctx.args["flow"]))
                target["password"] = state["password"]
                target["step"] = ctx.args.get("next_step")
                ctx.drop_flow(self.name)
                return back()
            case "save":
                await ctx.container.users.set_pw_prefs(ctx.chat_id, PwPrefs(**prefs))
                return refresh(toast="💾 Preferenze salvate")
            case "reset":
                state["prefs"] = asdict(PwPrefs())
                state["password"] = None
                return refresh(toast="🔄 Valori predefiniti")
        return refresh()
