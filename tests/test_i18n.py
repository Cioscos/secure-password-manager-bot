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


# Generator/category UI strings and the /list header/empty strings now live in their
# respective ui/screens/*.py modules (generator.py, categories.py, account_list.py) —
# these MESSAGES keys became dead once the navigator UI replaced the old handlers.
_PRUNED_LEGACY_KEYS = {
    "pw_gen_title",
    "pw_gen_length_prompt",
    "pw_gen_length_invalid",
    "pw_gen_no_class_selected",
    "pw_gen_pool_too_small",
    "pw_gen_saved_defaults",
    "pw_gen_reset_done",
    "pw_gen_generated",
    "pw_gen_accepted",
    "cat_new_prompt",
    "cat_created",
    "cat_duplicate",
    "cat_deleted",
    "cat_empty",
    "list_title",
    "list_empty",
}


def test_pruned_legacy_keys_are_gone():
    assert not (_PRUNED_LEGACY_KEYS & set(MESSAGES.keys()))
