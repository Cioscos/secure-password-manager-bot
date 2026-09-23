"""Helpers shared by several screens."""

from __future__ import annotations

from password_bot.models.account import Account
from password_bot.services.reuse_detector import compute_password_hmac
from password_bot.ui.screen import Ctx

STRENGTH_LABELS = ("pessima", "debole", "media", "buona", "ottima")


async def load_account(ctx: Ctx, account_id: object) -> Account | None:
    """Decrypted account if it exists, belongs to this chat and the session is open."""
    session = ctx.session
    if session is None or not account_id:
        return None
    acc = await ctx.container.vault.get_decrypted(str(account_id), aes_key=session.aes_key)
    if acc is None or acc.chat_id != ctx.chat_id:
        return None
    return acc


async def reuse_names(ctx: Ctx, password_hmac: str, *, exclude_id: str | None = None) -> list[str]:
    rows = await ctx.container.accounts.find_by_hmac(ctx.chat_id, password_hmac)
    return [r.name for r in rows if r.id != exclude_id]


async def reuse_names_for(ctx: Ctx, password: str, *, exclude_id: str | None = None) -> list[str]:
    digest = compute_password_hmac(password, ctx.session.hmac_key)
    return await reuse_names(ctx, digest, exclude_id=exclude_id)


def strength_text(ctx: Ctx, password: str) -> str:
    score = ctx.container.strength.evaluate(password).score
    return f"forza {score}/4 ({STRENGTH_LABELS[score]})"


async def username_suggestions(ctx: Ctx) -> list[str]:
    return await ctx.container.vault.username_suggestions(ctx.chat_id, aes_key=ctx.session.aes_key)
