"""Every screen: no secret in callback payloads; hostile names always escaped."""

from __future__ import annotations

from password_bot.ui.callbacks import Act
from password_bot.ui.registry import build_screens
from password_bot.ui.screen import View
from tests.ui._helpers import buttons

SECRETS = {
    "username": "user-SENTINEL-1",
    "password": "pw-SENTINEL-2",
    "url": "sentinel3.example.com",
    "note": "note-SENTINEL-4",
}
HOSTILE = "a_b*c[d](e)!"


async def _render_everything(env) -> list[tuple[str, View]]:
    cat = await env.category(HOSTILE, icon="💼")
    acc = await env.add(
        HOSTILE,
        username=SECRETS["username"],
        password=SECRETS["password"],
        url=SECRETS["url"],
        note=SECRETS["note"],
        category_id=cat.id,
    )
    await env.add("twin", username=SECRETS["username"], password=SECRETS["password"])
    s = env.session
    await env.container.vault.update_password(
        acc.id, SECRETS["password"] + "-new", aes_key=s.aes_key, hmac_key=s.hmac_key
    )
    screens = build_screens()
    cases = [
        ("home", {}),
        ("help", {}),
        ("account_list", {}),
        ("account_list", {"category": cat.id}),
        ("account_list", {"category": "none"}),
        ("search", {"q": "a_b"}),
        ("account_detail", {"id": acc.id}),
        ("history", {"id": acc.id}),
        ("account_delete", {"id": acc.id}),
        ("account_edit", {"id": acc.id}),
        ("field_edit", {"id": acc.id, "field": "username"}),
        ("field_edit", {"id": acc.id, "field": "url"}),
        ("password_change", {"id": acc.id}),
        ("generator", {"flow": "password_change", "next_step": "confirm"}),
        ("account_new", {}),
        ("categories", {}),
        ("category_pick", {"account_id": acc.id}),
        ("category_form", {"mode": "rename", "cat_id": cat.id}),
        ("category_icon", {"cat_id": cat.id}),
        ("category_delete", {"cat_id": cat.id}),
        ("health", {}),
        ("settings", {}),
        ("transfer", {"mode": "export"}),
    ]
    views: list[tuple[str, View]] = []
    for name, args in cases:
        ctx = env.ctx(args)
        await screens[name].on_enter(ctx)
        views.append((name, await screens[name].render(ctx)))

    change = env.ctx({"id": acc.id})
    change.flow("password_change").update(step="confirm", password=SECRETS["password"])
    views.append(("password_change/confirm", await screens["password_change"].render(change)))

    new = env.ctx({})
    await screens["account_new"].on_enter(new)
    flow = new.flow("account_new")
    flow.update(step="username", name=HOSTILE)
    views.append(("account_new/username", await screens["account_new"].render(new)))
    flow.update(
        step="summary",
        username=SECRETS["username"],
        password=SECRETS["password"],
        url="https://" + SECRETS["url"],
        note=SECRETS["note"],
        category_id=cat.id,
    )
    views.append(("account_new/summary", await screens["account_new"].render(new)))
    return views


async def test_no_secret_in_any_callback_payload(env):
    for name, view in await _render_everything(env):
        for b in buttons(view):
            if isinstance(b.callback_data, Act):
                payload = repr(b.callback_data)
                for secret in SECRETS.values():
                    assert secret not in payload, (name, b.text)


async def test_hostile_name_is_always_escaped(env):
    for name, view in await _render_everything(env):
        assert HOSTILE not in view.text, name
