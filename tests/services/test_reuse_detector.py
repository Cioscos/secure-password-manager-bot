import hashlib
import hmac

from password_bot.services.reuse_detector import compute_password_hmac


def _hmac(key: bytes, plaintext: str) -> str:
    return hmac.new(key, plaintext.encode(), hashlib.sha256).hexdigest()


def test_compute_password_hmac_matches_reference():
    key = b"\x01" * 32
    assert compute_password_hmac("pw", key) == _hmac(key, "pw")
