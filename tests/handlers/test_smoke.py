import pytest
from telegram.ext import Application

from password_bot.bot import build_application
from password_bot.config import AppConfig


@pytest.fixture
async def app(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYRING", str(tmp_path / "keys"))
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "telegram.dat").write_text("0:dummy")
    (tmp_path / "keys" / "dev_id.dat").write_text("0")
    config = AppConfig.load(base_dir=tmp_path)
    application = build_application(config, token="0:dummy", dev_chat_id=0)
    yield application


def test_application_builds_with_root_conversation(app: Application):
    handlers = app.handlers[0]
    assert any(getattr(h, "name", None) == "root" for h in handlers)


def test_error_handler_registered(app: Application):
    assert app.error_handlers


def test_root_conversation_allows_reentry_via_start(app: Application):
    root = next(h for h in app.handlers[0] if getattr(h, "name", None) == "root")
    assert root.allow_reentry is True
