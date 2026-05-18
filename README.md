# Password Bot v2

Telegram password manager bot. Vault is local-only, encrypted with AES-256-GCM, key derived from Argon2id-hashed passphrase.

## Run

```bash
uv sync
KEYRING=./keys uv run -m password_bot
```

`KEYRING` must point to a directory containing:
- `telegram.dat` — bot token (single line)
- `dev_id.dat` — Telegram chat id that receives error reports (single line)

## Migrating from v1

Before switching to `rewrite/v2`:

```bash
cp accounts.db accounts.db.bak
cp DB.pkl DB.pkl.bak
```

On first boot the bot will:
1. Apply schema migration in a single transaction.
2. On the first `/start`, accept the same passphrase and lazily re-encrypt every row to AES-GCM + Argon2id.

If anything goes wrong, restore the backups and check out the `master` branch.

## Argon2id tuning (Pi Zero 2W)

Defaults are tuned for a Pi Zero 2W. Override via env vars:

```
PB_ARGON2_M=65536      # KiB, default 65536
PB_ARGON2_T=3          # iterations
PB_ARGON2_P=1          # parallelism
PB_ARGON2_DERIVE_M=32768
PB_ARGON2_DERIVE_T=2
```

## Tests

```bash
uv run pytest --cov=src/password_bot
```

## Architecture

See `docs/superpowers/specs/2026-05-16-bot-rewrite-design.md`.
