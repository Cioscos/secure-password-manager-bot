from password_bot.i18n.it import MESSAGES

REQUIRED_KEYS = {
    "welcome",
    "menu_title",
    "ask_passphrase",
    "passphrase_wrong",
    "passphrase_setup_first",
    "session_locked",
    "stop_hint",
    "account_saved",
    "account_deleted",
    "account_not_found",
    "field_updated",
    "delete_confirm_prompt",
    "delete_confirm_word",
    "export_done",
    "import_done",
    "import_wrong_passphrase",
    "import_invalid_file",
    "strength_label",
    "stale_alert_template",
    "reuse_warning",
    "back",
    "menu",
    "error_internal",
}


def test_messages_keys_present():
    missing = REQUIRED_KEYS - set(MESSAGES.keys())
    assert not missing, f"Missing i18n keys: {missing}"


def test_messages_are_italian_strings():
    for k, v in MESSAGES.items():
        assert isinstance(v, str)
        assert v.strip(), f"Empty message for {k}"
