from password_bot.state.keys import ChatDataKey


def test_enum_members_unique_and_strings():
    values = {k.value for k in ChatDataKey}
    assert len(values) == len(ChatDataKey)
    assert all(isinstance(k.value, str) for k in ChatDataKey)


def test_required_keys_exist():
    expected = {
        "SESSION",
        "NAV_STACK",
        "PENDING_INPUT",
        "AUTOLOCK_JOB_NAME",
        "PENDING_NEW_ACCOUNT",
        "PENDING_IMPORT_FILE",
    }
    assert expected <= {k.name for k in ChatDataKey}
