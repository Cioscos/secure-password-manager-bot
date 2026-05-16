from password_bot.services.errors import DomainError, InvalidPassphraseError
from password_bot.services.result import Result


def test_ok_result():
    r = Result.success(42)
    assert r.ok is True
    assert r.value == 42
    assert r.error is None


def test_err_result():
    err = InvalidPassphraseError()
    r: Result[int] = Result.err(err)
    assert r.ok is False
    assert r.error is err
    assert r.value is None


def test_domain_error_hierarchy():
    assert issubclass(InvalidPassphraseError, DomainError)
