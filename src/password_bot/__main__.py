"""Entrypoint: KEYRING=./keys uv run -m password_bot"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from password_bot.bot import build_application
from password_bot.config import AppConfig


def _read_keyring_value(keyring_dir: Path, filename: str) -> str:
    path = keyring_dir / filename
    if not path.is_file():
        raise RuntimeError(f"Missing keyring file: {path}")
    return path.read_text(encoding="utf-8").strip()


def _setup_logging(log_path: Path) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    file_handler = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3)
    file_handler.setFormatter(fmt)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    logging.basicConfig(level=logging.INFO, handlers=[file_handler, stream_handler])
    logging.getLogger("httpx").setLevel(logging.WARNING)


def main() -> None:
    config = AppConfig.load()
    _setup_logging(config.log_path)
    token = _read_keyring_value(config.keyring_dir, "telegram.dat")
    dev_chat_id_raw = _read_keyring_value(config.keyring_dir, "dev_id.dat")
    dev_chat_id = int(dev_chat_id_raw)
    application = build_application(config, token=token, dev_chat_id=dev_chat_id)
    application.run_polling(close_loop=False)


if __name__ == "__main__":
    main()
