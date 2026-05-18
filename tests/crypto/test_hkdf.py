from password_bot.crypto.hkdf import derive_subkey


def test_derive_subkey_deterministic():
    k = b"\x00" * 32
    a = derive_subkey(k, info=b"reuse-detection")
    b = derive_subkey(k, info=b"reuse-detection")
    assert a == b
    assert len(a) == 32


def test_derive_subkey_info_sensitive():
    k = b"\x00" * 32
    assert derive_subkey(k, info=b"a") != derive_subkey(k, info=b"b")
