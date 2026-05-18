"""Domain-level errors raised by services."""

from __future__ import annotations


class DomainError(Exception):
    """Base for errors that handlers translate into user messages."""

    user_message: str = "Errore interno."


class InvalidPassphraseError(DomainError):
    user_message = "Passphrase non valida."


class AccountNotFoundError(DomainError):
    user_message = "Account non trovato."


class DuplicateAccountError(DomainError):
    user_message = "Esiste già un account con questo nome."


class DuplicateCategoryError(DomainError):
    user_message = "Esiste già una categoria con questo nome."


class CategoryNotFoundError(DomainError):
    user_message = "Categoria non trovata."


class InvalidExportFileError(DomainError):
    user_message = "File di import non valido."


class SessionExpiredError(DomainError):
    user_message = "Sessione scaduta. Sbloccala di nuovo."
