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
    "list_title": "📚 *Account* — pagina {cur}/{tot}",
    "list_empty": "Vault vuoto.",
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
    "pw_gen_title": "🎲 *Generatore password*",
    "pw_gen_length_prompt": "Inserisci la nuova lunghezza (4-128).",
    "pw_gen_length_invalid": "Lunghezza non valida. Usa un numero tra 4 e 128.",
    "pw_gen_no_class_selected": "⚠️ Seleziona almeno una classe di caratteri.",
    "pw_gen_pool_too_small": "⚠️ Pool troppo piccolo per la lunghezza con no-duplicati.",
    "pw_gen_saved_defaults": "💾 Preferenze salvate.",
    "pw_gen_reset_done": "🔄 Reset ai valori predefiniti.",
    "pw_gen_generated": "🔑 Password generata ({length} car, entropia ≈ {entropy} bit).",
    "pw_gen_accepted": "✅ Password accettata.",
    "cat_new_prompt": "Nome della nuova categoria? /cancel per annullare.",
    "cat_created": "✅ Categoria '{name}' creata.",
    "cat_duplicate": "Categoria già esistente.",
    "cat_deleted": "🗑 Categoria eliminata.",
    "cat_empty": "Nessuna categoria ancora creata.",
}
