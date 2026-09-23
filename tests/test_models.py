from password_bot.models.account import Account, AccountRow
from password_bot.models.category import Category
from password_bot.models.password_history import PasswordHistoryEntry
from password_bot.models.user import User


def test_account_minimum_fields():
    a = Account(
        id="abc",
        chat_id=1,
        name="GitHub",
        username=None,
        password="pw",
        url=None,
        note=None,
        category_id=None,
        password_hmac="hmac",
        crypto_version=2,
        password_changed_at=10,
        created_at=10,
        updated_at=10,
    )
    assert a.username is None
    assert a.password == "pw"


def test_account_row_holds_encrypted_strings():
    r = AccountRow(
        id="abc",
        chat_id=1,
        name="GitHub",
        username_enc=None,
        password_enc="b64",
        url_enc=None,
        note_enc=None,
        category_id=None,
        password_hmac="hmac",
        crypto_version=2,
        password_changed_at=10,
        created_at=10,
        updated_at=10,
    )
    assert r.username_enc is None
    assert r.password_enc == "b64"


def test_user_defaults():
    u = User(
        chat_id=42,
        name="me",
        passphrase_hash="$argon2id$...",
        autolock_minutes=15,
        autolock_reset_on_activity=True,
        alert_days=180,
        crypto_version=2,
        legacy_salt=None,
        created_at=10,
        updated_at=10,
    )
    assert u.autolock_reset_on_activity is True


def test_category_and_history():
    c = Category(id="cat1", chat_id=1, name="Work", icon=None)
    h = PasswordHistoryEntry(
        id=1, account_id="abc", password_enc="b64", crypto_version=2, replaced_at=10
    )
    assert c.name == "Work"
    assert h.account_id == "abc"
