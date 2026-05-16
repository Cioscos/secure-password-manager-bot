"""Service that finds accounts with stale passwords."""

from __future__ import annotations

import time

from password_bot.models.account import AccountRow
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.user_repo import UserRepo


class AlertService:
    def __init__(self, *, users: UserRepo, accounts: AccountRepo) -> None:
        self._users = users
        self._accounts = accounts

    async def find_stale(self, *, chat_id: int) -> list[AccountRow]:
        user = await self._users.get(chat_id)
        if user is None:
            return []
        cutoff = int(time.time()) - user.alert_days * 86400
        return await self._accounts.list_stale(chat_id, older_than_epoch=cutoff)

    async def find_stale_for_all_users(self) -> dict[int, list[AccountRow]]:
        # Used by daily scan. Caller fetches list of chat_ids elsewhere; this
        # method just dispatches one find_stale per chat_id passed in.
        raise NotImplementedError("Use find_stale per chat_id from the caller")
