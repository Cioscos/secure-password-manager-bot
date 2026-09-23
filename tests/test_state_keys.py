from password_bot.state.keys import ChatDataKey


def test_enum_members_unique_and_strings():
    values = {k.value for k in ChatDataKey}
    assert len(values) == len(ChatDataKey)
    assert all(isinstance(k.value, str) for k in ChatDataKey)


def test_required_keys_exist():
    expected = {
        "SESSION",
        "NAV_STACK",
        "LEGACY_SESSION_EXTRAS",
        "FLOW",
        "LIVE_MESSAGE_ID",
        "LIVE_TOKEN",
        "RESUME",
    }
    assert expected == {k.name for k in ChatDataKey}
