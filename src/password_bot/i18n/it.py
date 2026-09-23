"""Italian user-facing strings. Keep tone informal (tu)."""

from __future__ import annotations

MESSAGES: dict[str, str] = {
    "welcome": (
        "Ciao! Sono il tuo password bot.\n"
        "Per iniziare imposta una passphrase con /start.\n"
        "Puoi sempre interrompere con /stop."
    ),
    "menu_title": "📋 *Menu principale*",
    "ask_passphrase": "Inviami la passphrase per sbloccare il vault.\n/stop per annullare.",
    "passphrase_wrong": "Passphrase non corretta. Riprova oppure /stop.",
    "passphrase_setup_first": (
        "Non hai ancora un vault. Inviami una passphrase per crearlo.\n"
        "Scegli una passphrase robusta — è l'unica chiave per i tuoi dati."
    ),
    "session_locked": "🔒 Sessione bloccata. /start per sbloccare.",
    "stop_hint": "Suggerimento: /stop in qualsiasi momento.",
    "account_saved": "✅ Account salvato.",
    "account_deleted": "🗑 Account eliminato.",
    "account_not_found": "Account non trovato.",
    "field_updated": "✅ Campo aggiornato.",
    "delete_confirm_prompt": (
        "Per confermare l'eliminazione scrivi esattamente `ELIMINA`.\nQualsiasi altra cosa annulla."
    ),
    "delete_confirm_word": "ELIMINA",
    "export_done": "📤 Export pronto. Conserva il file con cura — è cifrato ma la passphrase fa il resto.",
    "import_done": "📥 Import completato: {added} aggiunti, {overwritten} sovrascritti, {skipped} saltati.",
    "import_wrong_passphrase": "Passphrase di export non valida.",
    "import_invalid_file": "File di import non valido o danneggiato.",
    "strength_label": "Forza password: {score}/4 — {label}",
    "stale_alert_template": "⚠️ Hai {count} password più vecchie di {days} giorni. /list_stale per vederle.",
    "reuse_warning": "⚠️ Questa password è già usata per: {names}.",
    "back": "🔙 Indietro",
    "menu": "🏠 Menu",
    "error_internal": "Errore interno. Lo sviluppatore è stato avvisato. /menu per ricominciare.",
}
