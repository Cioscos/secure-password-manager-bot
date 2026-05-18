from password_bot.config import AppConfig, Argon2Params


def test_argon2_defaults_when_env_unset(monkeypatch):
    for var in ("PB_ARGON2_M", "PB_ARGON2_T", "PB_ARGON2_P"):
        monkeypatch.delenv(var, raising=False)
    p = Argon2Params.hash_params_from_env()
    assert p.memory_cost == 65536
    assert p.time_cost == 3
    assert p.parallelism == 1


def test_argon2_overrides_from_env(monkeypatch):
    monkeypatch.setenv("PB_ARGON2_M", "32768")
    monkeypatch.setenv("PB_ARGON2_T", "2")
    monkeypatch.setenv("PB_ARGON2_P", "2")
    p = Argon2Params.hash_params_from_env()
    assert (p.memory_cost, p.time_cost, p.parallelism) == (32768, 2, 2)


def test_app_config_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYRING", str(tmp_path / "keys"))
    cfg = AppConfig.load(base_dir=tmp_path)
    assert cfg.db_path == tmp_path / "accounts.db"
    assert cfg.pkl_path == tmp_path / "DB.pkl"
    assert cfg.log_path == tmp_path / "password_bot.log"
    assert cfg.keyring_dir == tmp_path / "keys"
