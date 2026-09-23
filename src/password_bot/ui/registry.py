"""Every screen, keyed by name. New screens are added to the list below."""

from __future__ import annotations

from password_bot.ui.screen import Screen
from password_bot.ui.screens.help import HelpScreen
from password_bot.ui.screens.home import HomeScreen
from password_bot.ui.screens.unlock import UnlockScreen


def build_screens() -> dict[str, Screen]:
    screens: list[Screen] = [
        HomeScreen(),
        UnlockScreen(),
        HelpScreen(),
    ]
    return {s.name: s for s in screens}
