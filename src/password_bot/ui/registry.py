"""Every screen, keyed by name. New screens are added to the list below."""

from __future__ import annotations

from password_bot.ui.screen import Screen
from password_bot.ui.screens.account_delete import AccountDeleteScreen
from password_bot.ui.screens.account_detail import AccountDetailScreen
from password_bot.ui.screens.account_edit import AccountEditScreen, FieldEditScreen
from password_bot.ui.screens.account_list import AccountListScreen
from password_bot.ui.screens.help import HelpScreen
from password_bot.ui.screens.history import HistoryScreen
from password_bot.ui.screens.home import HomeScreen
from password_bot.ui.screens.search import SearchScreen
from password_bot.ui.screens.unlock import UnlockScreen


def build_screens() -> dict[str, Screen]:
    screens: list[Screen] = [
        HomeScreen(),
        UnlockScreen(),
        HelpScreen(),
        AccountListScreen(),
        SearchScreen(),
        AccountDetailScreen(),
        AccountEditScreen(),
        FieldEditScreen(),
        HistoryScreen(),
        AccountDeleteScreen(),
    ]
    return {s.name: s for s in screens}
