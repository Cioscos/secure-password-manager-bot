from password_bot.state.fsm import FsmContext, Screen


def test_push_and_top():
    fsm = FsmContext({})
    fsm.push(Screen(name="menu", data={}))
    fsm.push(Screen(name="account_view", data={"id": "a1"}))
    assert fsm.top().name == "account_view"


def test_pop():
    fsm = FsmContext({})
    fsm.push(Screen(name="menu", data={}))
    fsm.push(Screen(name="account_view", data={}))
    fsm.pop()
    assert fsm.top().name == "menu"


def test_pop_to():
    fsm = FsmContext({})
    fsm.push(Screen(name="menu", data={}))
    fsm.push(Screen(name="account_list", data={}))
    fsm.push(Screen(name="account_view", data={}))
    fsm.pop_to("menu")
    assert fsm.top().name == "menu"
    assert fsm.depth() == 1


def test_reset_to():
    fsm = FsmContext({})
    fsm.push(Screen(name="menu", data={}))
    fsm.push(Screen(name="account_view", data={}))
    fsm.reset_to(Screen(name="menu", data={}))
    assert fsm.depth() == 1
    assert fsm.top().name == "menu"


def test_lock_clears_session_and_all_in_progress_state():
    from password_bot.state.keys import ChatDataKey

    data = {
        ChatDataKey.SESSION.value: object(),
        ChatDataKey.LEGACY_SESSION_EXTRAS.value: object(),
        ChatDataKey.FLOW.value: {"account_new": {"password": "x"}},
        ChatDataKey.RESUME.value: Screen(name="home", data={}),
    }
    fsm = FsmContext(data)
    fsm.push(Screen(name="account_detail", data={}))
    fsm.lock()
    assert fsm.get_session() is None
    assert data == {ChatDataKey.NAV_STACK.value: []}
