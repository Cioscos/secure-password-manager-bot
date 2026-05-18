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


def test_pending_input_set_and_clear():
    fsm = FsmContext({})
    fsm.set_pending_input({"field": "password", "id": "a1"})
    assert fsm.get_pending_input() == {"field": "password", "id": "a1"}
    fsm.clear_pending_input()
    assert fsm.get_pending_input() is None
