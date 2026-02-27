import html
import logging
import string
import secrets
import traceback
from typing import List, Any, Dict, Optional

from warnings import filterwarnings

from telegram import Update, ReplyKeyboardMarkup, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton, \
    ReplyKeyboardRemove
from telegram.constants import ParseMode
from telegram.error import BadRequest, TelegramError
from telegram.ext import (
    Application,
    CommandHandler,
    ConversationHandler,
    ContextTypes,
    PicklePersistence, MessageHandler, filters, CallbackQueryHandler
)
from telegram.helpers import escape_markdown
from telegram.warnings import PTBUserWarning
from thefuzz import fuzz

from account_repository import (
    create_database,
    insert_account,
    insert_user,
    is_account_name_present,
    is_user_registered,
    get_accounts_for_chat_id,
    get_account_for_id,
    get_hash_and_salt_for_id,
    delete_account_by_id,
    get_users_id,
    update_account,
    update_account_encryption,
    update_user_passphrase,
)
from crypto_service import (
    store_passphrase_hash,
    verify_passphrase,
    derive_key,
    encrypt,
    decrypt,
)
from environment_variables_mg import keyring_initialize, keyring_get
from account import Account

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%y-%m-%d %H:%M:%S',
    filename='password_bot.log'
)

filterwarnings(action="ignore", message=r".*CallbackQueryHandler", category=PTBUserWarning)
logging.getLogger("httpx").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Chat-data keys
# ---------------------------------------------------------------------------

TEMP_SAVED_ACCOUNT = 'temp_saved_account'
PSW_OPTIONS = 'psw_options_key'
CURRENT_ACCOUNT_PAGE = 'current_account_page'
CURRENT_ACCOUNT_ID_SELECTED = 'current_account_id_selected'
TEMP_KEY = 'temp_key'
TEMP_PASSPHRASE = 'passphrase'
TEMP_VALID_RESULTS = 'temp_valid_results'
TEMP_OLD_KEY = 'temp_old_key'

# ---------------------------------------------------------------------------
# Callback data constants
# ---------------------------------------------------------------------------

CALLBACK_BACK = "back"
CALLBACK_DELETE = "delete"
CALLBACK_PREV_PAGE = "prev_page"
CALLBACK_NEXT_PAGE = "next_page"
CALLBACK_GENERATE_NEW = "generate_new_password"
CALLBACK_CONFIRM_PASSWORD = "confirm_password"
CALLBACK_EDIT = "edit"

# Account edit field choices
CALLBACK_EDIT_NAME = "edit_field_name"
CALLBACK_EDIT_USERNAME = "edit_field_username"
CALLBACK_EDIT_PASSWORD = "edit_field_password"

# Options callback data
CALLBACK_OPTION_NAME = 'option_selected'
CALLBACK_PSW_LENGHT = 'psw_lenght'
CALLBACK_UPPER = 'upper'
CALLBACK_LOWER = 'lower'
CALLBACK_NUMERIC = 'numeric'
CALLBACK_SPECIALS = 'specials'
CALLBACK_DUPLICATES = 'duplicates'
CALLBACK_GENERATE = 'generate'

CALLBACK_ACCOUNT_NAME = 'selected_account'

MAP_CALLBACK_TO_OPTIONS_KEYS = {
    CALLBACK_PSW_LENGHT: 'lunghezza',
    CALLBACK_UPPER: 'maiuscole',
    CALLBACK_LOWER: 'minuscole',
    CALLBACK_NUMERIC: 'numerici',
    CALLBACK_SPECIALS: 'speciali',
    CALLBACK_DUPLICATES: 'duplicati'
}

# ---------------------------------------------------------------------------
# Conversation states
# ---------------------------------------------------------------------------

# Top-level
MAIN_MENU, ADD_ACCOUNT, SHOW_ACCOUNT, DELETE_ACCOUNT = map(chr, range(4))

# New account sub-flow
(INSERT_NAME, INSERT_USERNAME, DECIDE_PASSWORD_METHOD,
 GENERATE_PASSWORD_TYPE_CHOICE, ASK_PASSPHRASE_INSERT,
 INSERT_USER_CHOSEN_PASSWORD) = map(chr, range(4, 10))

OPTION_CHOICE, ASK_PASSPHRASE_READ, INSERT_PSW_LENGHT, ACCEPT_PSW = map(chr, range(10, 14))

ACCOUNT_CHOICE, ACCOUNT_DETAIL, ACCOUNT_ACTIONS = map(chr, range(14, 17))

ASK_SERVICE_NAME = 17
PASSPHRASE_SAVING = 18

# Edit account sub-flow states
EDIT_ACCOUNT_FIELD_CHOICE = 19
EDIT_ACCOUNT_NAME = 20
EDIT_ACCOUNT_USERNAME = 21
EDIT_ACCOUNT_PASSWORD_METHOD = 22

# Change passphrase sub-flow states
CHANGE_PASSPHRASE_VERIFY_OLD = 23
CHANGE_PASSPHRASE_INSERT_NEW = 24
CHANGE_PASSPHRASE_CONFIRM_NEW = 25

STOPPING = 99


# ===========================================================================
# Helper utilities
# ===========================================================================


async def _resolve_and_verify_passphrase(
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
        manual_call: bool = False
) -> Optional[tuple]:
    """
    Resolves the passphrase from ``context.chat_data`` or from the incoming message,
    then verifies it against the stored hash.

    If the passphrase is taken from the user's message and ``manual_call`` is False,
    the message is immediately deleted for security.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.
        manual_call (bool): When True the function was called programmatically
            (passphrase already in chat_data), so no message deletion is performed.

    Returns:
        Optional[tuple[str, str, str]]: ``(passphrase, stored_hash, stored_salt)`` if the
        passphrase is valid, or ``None`` if it is invalid (an error reply is sent automatically).
    """
    if not manual_call:
        await update.message.delete()

    passphrase_dict = context.chat_data.get(TEMP_PASSPHRASE)
    if not passphrase_dict:
        passphrase: str = update.message.text
        stored_hash, stored_salt = get_hash_and_salt_for_id(update.effective_message.chat_id)
    else:
        passphrase = passphrase_dict['passphrase']
        stored_hash = passphrase_dict['hash']
        stored_salt = passphrase_dict['salt']

    if verify_passphrase(passphrase, stored_salt, stored_hash):
        if not context.chat_data.get(TEMP_PASSPHRASE):
            context.chat_data[TEMP_PASSPHRASE] = {
                'passphrase': passphrase,
                'hash': stored_hash,
                'salt': stored_salt
            }
        return passphrase, stored_hash, stored_salt

    await update.effective_message.reply_text(
        "*PASSPHRASE SBAGLIATA!*\n\nProva di nuovo o premi /stop per uscire",
        parse_mode=ParseMode.MARKDOWN
    )
    return None


# ===========================================================================
# Password generation helpers
# ===========================================================================


def generate_password(lunghezza: int, maiuscole: bool, minuscole: bool, numerici: bool,
                      speciali: bool, duplicati: bool) -> str:
    """
    Genera una password sicura seguendo i criteri specificati.

    Args:
        lunghezza (int): La lunghezza desiderata della password.
        maiuscole (bool): Includi lettere maiuscole se True.
        minuscole (bool): Includi lettere minuscole se True.
        numerici (bool): Includi numeri se True.
        speciali (bool): Includi caratteri speciali se True.
        duplicati (bool): Consenti duplicati nella password se True.

    Returns:
        str: La password generata.

    Raises:
        ValueError: Se non ci sono abbastanza caratteri unici per soddisfare la richiesta
            senza duplicati.
    """
    alfabeto = ''
    password_base = []

    if maiuscole:
        alfabeto += string.ascii_uppercase
        password_base.append(secrets.choice(string.ascii_uppercase))
    if minuscole:
        alfabeto += string.ascii_lowercase
        password_base.append(secrets.choice(string.ascii_lowercase))
    if numerici:
        alfabeto += string.digits
        password_base.append(secrets.choice(string.digits))
    if speciali:
        alfabeto += string.punctuation
        password_base.append(secrets.choice(string.punctuation))

    if not duplicati and len(alfabeto) < lunghezza:
        raise ValueError(
            "Non ci sono abbastanza caratteri unici per soddisfare la lunghezza richiesta senza duplicati.")

    while len(password_base) < lunghezza:
        password_base.append(secrets.choice(alfabeto))

    secrets.SystemRandom().shuffle(password_base)
    return ''.join(password_base[:lunghezza])


def generate_password_options_keyboard(lunghezza: int = 10, maiuscole: bool = False,
                                       minuscole: bool = False, numerici: bool = False,
                                       speciali: bool = False, duplicati: bool = False) -> InlineKeyboardMarkup:
    """
    Builds the inline keyboard for the password-generation options screen.

    Args:
        lunghezza (int): Current password length setting.
        maiuscole (bool): Whether uppercase letters are enabled.
        minuscole (bool): Whether lowercase letters are enabled.
        numerici (bool): Whether numeric characters are enabled.
        speciali (bool): Whether special characters are enabled.
        duplicati (bool): Whether duplicate characters are allowed.

    Returns:
        InlineKeyboardMarkup: The constructed keyboard markup.
    """
    keyboard: List[List[InlineKeyboardButton]] = []

    password_lenght_option = InlineKeyboardButton(
        f'Lunghezza: {lunghezza}',
        callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_PSW_LENGHT}"
    )
    upper_option = InlineKeyboardButton(
        f"Maiuscole {'✅' if maiuscole else '❌'}",
        callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_UPPER}"
    )
    keyboard.append([password_lenght_option, upper_option])

    lower_option = InlineKeyboardButton(
        f"Minuscole {'✅' if minuscole else '❌'}",
        callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_LOWER}"
    )
    numeric_option = InlineKeyboardButton(
        f"Numerici {'✅' if numerici else '❌'}",
        callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_NUMERIC}"
    )
    keyboard.append([lower_option, numeric_option])

    special_option = InlineKeyboardButton(
        f"Speciali {'✅' if speciali else '❌'}",
        callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_SPECIALS}"
    )
    duplicates_option = InlineKeyboardButton(
        f"Duplicati {'✅' if duplicati else '❌'}",
        callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_DUPLICATES}"
    )
    keyboard.append([special_option, duplicates_option])

    generate_button = InlineKeyboardButton(
        'Genera', callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_GENERATE}"
    )
    keyboard.append([generate_button])

    return InlineKeyboardMarkup(keyboard)


def generate_account_list_keyboard(accounts: List[Account],
                                   draw_navigation_buttons: bool = True) -> InlineKeyboardMarkup:
    """
    Generates an inline keyboard markup for the provided list of accounts.

    Args:
        accounts (List[Account]): List of Account objects.
        draw_navigation_buttons (bool): Whether to append Prev/Next navigation buttons.

    Returns:
        InlineKeyboardMarkup: The generated inline keyboard markup.
    """
    keyboard: List[List[InlineKeyboardButton]] = []

    row: List[InlineKeyboardButton] = []
    for account in accounts:
        button = InlineKeyboardButton(account.name, callback_data=f"{CALLBACK_ACCOUNT_NAME}:{account.id}")
        row.append(button)

        if len(row) == 2:
            keyboard.append(row)
            row = []

    if row:
        keyboard.append(row)

    if draw_navigation_buttons:
        navigation_buttons = [
            InlineKeyboardButton("Previous", callback_data=CALLBACK_PREV_PAGE),
            InlineKeyboardButton("Next", callback_data=CALLBACK_NEXT_PAGE)
        ]
        keyboard.append(navigation_buttons)

    return InlineKeyboardMarkup(keyboard)


def _build_account_detail_keyboard() -> InlineKeyboardMarkup:
    """
    Builds the inline keyboard displayed on the account detail view.

    Returns:
        InlineKeyboardMarkup: Keyboard with Indietro, Modifica, and Cancella buttons.
    """
    navigation_buttons = [
        InlineKeyboardButton("Indietro 🔙", callback_data=CALLBACK_BACK),
        InlineKeyboardButton("Modifica ✏️", callback_data=CALLBACK_EDIT),
        InlineKeyboardButton("Cancella 🗑", callback_data=CALLBACK_DELETE),
    ]
    return InlineKeyboardMarkup([navigation_buttons])


# ===========================================================================
# Lifecycle & utility handlers
# ===========================================================================


async def clear_temp_passphrase(context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Clear the temporary passphrase from chat_data if it exists.

    Intended to be scheduled as a repeating job every 10 minutes.

    Args:
        context (ContextTypes.DEFAULT_TYPE): The context object from the Telegram bot.
    """
    if TEMP_PASSPHRASE in context.chat_data:
        del context.chat_data[TEMP_PASSPHRASE]


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Global error callback. Logs the exception and forwards a formatted traceback
    to the developer chat ID if one is configured.

    Args:
        update (Update): The Telegram update that triggered the error.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context containing the error.
    """
    logger.error("Exception while handling an update:", exc_info=context.error)

    dev_id = keyring_get('DevId')
    if dev_id:
        tb_string = "".join(traceback.format_exception(None, context.error, context.error.__traceback__))
        message = f"⚠️ An exception was raised:\n<pre>{html.escape(tb_string[:3500])}</pre>"
        try:
            await context.bot.send_message(chat_id=dev_id, text=message, parse_mode=ParseMode.HTML)
        except TelegramError as e:
            logger.error(f"Could not send error report to developer: {e}")


async def send_welcome_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Sends the main menu welcome message listing all available commands.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.
    """
    welcome_message: str = (
        f"Ciao {update.effective_user.name}!\n\n"
        f"Come posso aiutarti? Usa i seguenti comandi per interagire con me:\n"
        f"/newAccount - Inserisci un nuovo account da memorizzare\n"
        f"/accounts - Mostra tutti gli account\n"
        f"/search - Cerca un account memorizzato inserendo il nome\n"
        f"/passphrase - Imposta la passphrase per criptare i tuoi dati\n"
        f"/changePassphrase - Modifica la tua passphrase e re-cripta gli account"
    )
    await context.bot.send_message(update.effective_chat.id, welcome_message)


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Entry point for the /start command. Sends the welcome message and
    schedules the periodic passphrase-clearing job.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: MAIN_MENU state.
    """
    await send_welcome_message(update, context)

    context.job_queue.run_repeating(
        clear_temp_passphrase,
        chat_id=update.message.chat_id,
        interval=600,
        first=0,
        name="clear_temp_passphrase_job"
    )
    logger.info("Stored passphrase job scheduled")

    return MAIN_MENU


async def stop_nested(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Stops a nested conversation and returns to the main menu.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: STOPPING state.
    """
    await update.message.reply_text("Comando stoppato")

    context.chat_data.pop(TEMP_KEY, None)
    context.chat_data.pop(CURRENT_ACCOUNT_PAGE, None)
    context.chat_data.pop(TEMP_VALID_RESULTS, None)

    await send_welcome_message(update, context)
    return STOPPING


async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Completely ends the top-level conversation and clears all temporary data.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ConversationHandler.END
    """
    await update.message.reply_text("Okay, Ciao.")
    context.chat_data.clear()

    for job in context.job_queue.jobs():
        if job.name == 'clear_temp_passphrase_job':
            job.schedule_removal()

    return ConversationHandler.END


async def default_inline_query_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Fallback handler for inline keyboard buttons pressed outside an active conversation.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.
    """
    query = update.callback_query
    await query.answer(
        "Hai usato un bottone di una conversazione vecchia. Avvia nuovamente il comando per interagire con il bot."
    )


async def post_stop_callback(application: Application) -> None:
    """
    Called when the bot is gracefully shut down. Notifies all registered users.

    Args:
        application (Application): The running Application instance.
    """
    for chat_id in get_users_id():
        try:
            await application.bot.send_message(chat_id, "🔴 The bot was switched off... someone switched off the power 🔴")
        except (BadRequest, TelegramError) as e:
            logger.error(f"CHAT_ID: {chat_id} Telegram error stopping the bot: {e}")


# ===========================================================================
# Passphrase setup flow
# ===========================================================================


async def passphrase_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Entry point for /passphrase. Allows new users to register a passphrase.
    Redirects already-registered users to /changePassphrase.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: PASSPHRASE_SAVING or ConversationHandler.END.
    """
    if not is_user_registered(update.message.chat_id):
        await update.message.reply_text(
            "Inserisci una passphrase per criptare i tuoi dati.\n\n"
            "L'inserimento di una passphrase è obbligatoria per i fini di utilizzo\n"
            "dell'applicazione. Più lunga è la passphrase più sicura sarà la crittografia"
        )
        return PASSPHRASE_SAVING

    else:
        await update.message.reply_text(
            "Sei già registrato!\n"
            "Usa /changePassphrase per modificare la tua passphrase esistente."
        )
        return ConversationHandler.END


async def get_passphrase_and_store_to_db(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Stores the passphrase hash for a newly registered user.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ConversationHandler.END.
    """
    salted_hash, salt = store_passphrase_hash(update.message.text)

    await update.message.reply_text(
        "Si suggerisce di cancellare questo messaggio per sicurezza.\n"
        "*Salva la password in un luogo sicuro!!*",
        parse_mode=ParseMode.MARKDOWN
    )

    insert_user(update.message.chat_id, update.message.from_user.name, salted_hash, salt)
    logger.info("Passphrase saved in the DB")

    return ConversationHandler.END


# ===========================================================================
# Change Passphrase flow
# ===========================================================================


async def change_passphrase_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Entry point for /changePassphrase. Verifies the user is registered before proceeding.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: CHANGE_PASSPHRASE_VERIFY_OLD or ConversationHandler.END.
    """
    chat_id = update.message.chat_id

    if not is_user_registered(chat_id):
        await update.message.reply_text(
            "Non hai ancora impostato una passphrase.\n"
            "Usa /passphrase per registrarne una."
        )
        return ConversationHandler.END

    await update.message.reply_text(
        "Per procedere, inserisci la tua *passphrase attuale*:",
        parse_mode=ParseMode.MARKDOWN
    )
    return CHANGE_PASSPHRASE_VERIFY_OLD


async def change_passphrase_verify_old(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Verifies the user's current passphrase during the change-passphrase flow.

    Deletes the passphrase message immediately. If valid, derives and temporarily
    stores the old encryption key so accounts can be re-encrypted later.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: CHANGE_PASSPHRASE_INSERT_NEW if valid, stays in CHANGE_PASSPHRASE_VERIFY_OLD otherwise.
    """
    await update.message.delete()

    old_passphrase = update.message.text
    stored_hash, stored_salt = get_hash_and_salt_for_id(update.message.chat_id)

    if not verify_passphrase(old_passphrase, stored_salt, stored_hash):
        await update.message.reply_text(
            "*PASSPHRASE SBAGLIATA!*\n\nProva di nuovo o premi /stop per uscire.",
            parse_mode=ParseMode.MARKDOWN
        )
        del old_passphrase
        return CHANGE_PASSPHRASE_VERIFY_OLD

    # Store old key temporarily for re-encryption
    context.chat_data[TEMP_OLD_KEY] = derive_key(old_passphrase, stored_salt)
    del old_passphrase

    await update.message.reply_text(
        "Passphrase verificata ✅\n\nInserisci la *nuova passphrase*:",
        parse_mode=ParseMode.MARKDOWN
    )
    return CHANGE_PASSPHRASE_INSERT_NEW


async def change_passphrase_insert_new(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Receives the new passphrase and asks for confirmation.

    Deletes the message containing the new passphrase immediately.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: CHANGE_PASSPHRASE_CONFIRM_NEW.
    """
    await update.message.delete()

    new_passphrase = update.message.text
    context.chat_data['_new_passphrase_pending'] = new_passphrase
    del new_passphrase

    await update.message.reply_text(
        "Conferma la *nuova passphrase* (riscrivila):",
        parse_mode=ParseMode.MARKDOWN
    )
    return CHANGE_PASSPHRASE_CONFIRM_NEW


async def change_passphrase_confirm_new(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Confirms the new passphrase, then re-encrypts all accounts atomically.

    Steps performed:
    - Deletes the confirmation message.
    - Compares new passphrase with the stored pending value.
    - Decrypts every account with the old key, re-encrypts with the new key.
    - Updates all account rows and the user passphrase hash/salt in the DB.
    - Clears all sensitive data from memory and context.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ConversationHandler.END on success, CHANGE_PASSPHRASE_CONFIRM_NEW on mismatch.
    """
    await update.message.delete()

    confirmation = update.message.text
    new_passphrase = context.chat_data.get('_new_passphrase_pending')

    if confirmation != new_passphrase:
        del confirmation
        await update.message.reply_text(
            "❌ Le passphrase non corrispondono. Reinserisci la *nuova passphrase*:",
            parse_mode=ParseMode.MARKDOWN
        )
        return CHANGE_PASSPHRASE_INSERT_NEW

    del confirmation

    chat_id = update.message.chat_id
    old_key: bytes = context.chat_data.get(TEMP_OLD_KEY)

    # Derive new key from new passphrase
    new_salted_hash, new_salt = store_passphrase_hash(new_passphrase)
    new_key = derive_key(new_passphrase, new_salt)

    del new_passphrase
    context.chat_data.pop('_new_passphrase_pending', None)

    # Re-encrypt all accounts atomically
    accounts: List[Account] = get_accounts_for_chat_id(chat_id, page_size=0)

    try:
        for account in accounts:
            plain_username = decrypt(account.user_name, old_key)
            plain_password = decrypt(account.password, old_key)

            new_username_enc = encrypt(plain_username, new_key)
            new_password_enc = encrypt(plain_password, new_key)

            update_account_encryption(account.id, new_username_enc, new_password_enc)

        # Update passphrase hash in users table
        update_user_passphrase(chat_id, new_salted_hash, new_salt)

    except Exception as e:
        logger.error(f"Re-encryption failed for chat_id {chat_id}: {e}")
        await update.message.reply_text(
            "❌ Si è verificato un errore durante la re-criptazione degli account.\n"
            "La tua passphrase *non* è stata modificata.",
            parse_mode=ParseMode.MARKDOWN
        )
        del old_key, new_key
        context.chat_data.pop(TEMP_OLD_KEY, None)
        return ConversationHandler.END

    # Clear all sensitive data
    del old_key, new_key, new_salted_hash, new_salt
    context.chat_data.pop(TEMP_OLD_KEY, None)
    context.chat_data.pop(TEMP_KEY, None)
    context.chat_data.pop(TEMP_PASSPHRASE, None)

    await update.message.reply_text(
        "✅ Passphrase aggiornata con successo! Tutti gli account sono stati re-criptati."
    )
    await send_welcome_message(update, context)
    return ConversationHandler.END


# ===========================================================================
# New account flow
# ===========================================================================


async def new_account_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Entry point for /newAccount. Checks registration and starts the account creation flow.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: INSERT_NAME or stops the conversation.
    """
    if not is_user_registered(update.message.chat_id):
        await update.message.reply_text(
            "Non hai ancora inserito la passphrase!\n\nPremi /passphrase per impostarla."
        )
        return await stop_nested(update, context)

    await update.message.reply_text(
        "Che nome vuoi assegnare al nuovo account?\n\nPremi /stop per tornare al menù principale"
    )
    return INSERT_NAME


async def get_name_ask_username_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Receives the account name and asks for the username/email.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: INSERT_USERNAME, or recurses to INSERT_NAME if name is already taken.
    """
    message: str = update.message.text

    if is_account_name_present(message, update.message.chat_id):
        await update.message.reply_text(
            f"L'account con il nome \"{message}\" già esiste. Inserisci uno nuovo\n\n"
            "Premi /stop per tornare al menù principale"
        )
        return await new_account_callback(update, context)

    account: Account = Account()
    account.name = message
    context.chat_data[TEMP_SAVED_ACCOUNT] = account

    await update.message.reply_text(
        "Che username o email vuoi assegnare?\n\nPremi /stop per tornare al menù principale"
    )
    return INSERT_USERNAME


async def get_username_ask_password_selection_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Receives the username/email and asks the user to choose a password method.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: DECIDE_PASSWORD_METHOD.
    """
    message: str = update.message.text

    account: Account = context.chat_data[TEMP_SAVED_ACCOUNT]
    account.user_name = message

    reply_keyboard: List[List[str]] = [['Genera una password', 'Inserisci una password']]
    reply_markup = ReplyKeyboardMarkup(
        reply_keyboard,
        resize_keyboard=True,
        one_time_keyboard=True,
        input_field_placeholder='Scegli cosa fare...'
    )
    await update.message.reply_text(
        "Vuoi generare un password sicura casuale o vuoi inserire tu una password?\n\n"
        "Premi /stop per tornare al menù principale",
        reply_markup=reply_markup
    )
    return DECIDE_PASSWORD_METHOD


async def get_password_decision_from_query_call_right_password_handler(
        update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Routes the user to either the password generator or the manual password entry sub-flow.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: GENERATE_PASSWORD_TYPE_CHOICE or ASK_PASSPHRASE_INSERT.
    """
    data: str = update.message.text

    if data == 'Genera una password':
        message = await update.effective_message.reply_text('.', reply_markup=ReplyKeyboardRemove())
        await message.delete()

        options = {
            'lunghezza': 10,
            'speciali': False,
            'minuscole': True,
            'maiuscole': True,
            'duplicati': True,
            'numerici': True
        }
        context.chat_data[PSW_OPTIONS] = options

        reply_markup = generate_password_options_keyboard(**options)
        await update.message.reply_text(
            "Scegli le opzioni di generazione della password\n\nPremi /stop per tornare al menù principale",
            reply_markup=reply_markup
        )
        return GENERATE_PASSWORD_TYPE_CHOICE

    elif data == 'Inserisci una password':
        message = await update.effective_message.reply_text('.', reply_markup=ReplyKeyboardRemove())
        await message.delete()

        await update.message.reply_text(
            "Inserisci la password che più preferisci per il tuo account\n\n"
            "Premi /stop per tornare al menù principale"
        )
        return ASK_PASSPHRASE_INSERT

    else:
        await update.message.reply_text(
            "Rispondi scegliendo una delle due opzioni offerte dai pulsanti.\n\n"
            "Premi /stop per tornare al menù principale"
        )


async def get_callback_data_from_psw_options_and_save_password(update: Update,
                                                               context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Handles callback queries from the password-generation options keyboard.

    Toggles boolean options, handles length input redirection, or triggers password generation.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: One of INSERT_PSW_LENGHT, OPTION_CHOICE, or ACCEPT_PSW.
    """
    query: CallbackQuery = update.callback_query
    data: str = query.data
    chat_id = update.effective_chat.id
    message_id = update.effective_message.message_id

    if data.startswith(f"{CALLBACK_OPTION_NAME}:"):
        option: str = data.split(':')[1]
        options: Dict[str, Any] = context.chat_data[PSW_OPTIONS]

        if option == CALLBACK_PSW_LENGHT:
            await context.bot.send_message(chat_id, 'Inserisci la lunghezza della password desiderata')
            await query.answer()
            return INSERT_PSW_LENGHT

        elif option in MAP_CALLBACK_TO_OPTIONS_KEYS.keys():
            value: bool = options[MAP_CALLBACK_TO_OPTIONS_KEYS[option]]
            options[MAP_CALLBACK_TO_OPTIONS_KEYS[option]] = not value
            reply_markup = generate_password_options_keyboard(**options)
            status = "abilitati" if not value else "disabilitati"
            await context.bot.edit_message_reply_markup(chat_id=chat_id, message_id=message_id,
                                                        reply_markup=reply_markup)
            await query.answer(f'Caratteri {MAP_CALLBACK_TO_OPTIONS_KEYS[option]} {status}')
            return OPTION_CHOICE

        elif option == CALLBACK_GENERATE:
            await query.answer()
            try:
                generated_password = generate_password(**options)
                context.chat_data['temp_password'] = generated_password

                keyboard = [
                    [InlineKeyboardButton('Genera di nuovo', callback_data=CALLBACK_GENERATE_NEW)],
                    [InlineKeyboardButton('Conferma', callback_data=CALLBACK_CONFIRM_PASSWORD)]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)

                await context.bot.send_message(
                    chat_id,
                    f"Password generata:\n\n{generated_password}\n\nPremi /stop per tornare al menù principale",
                    reply_markup=reply_markup
                )
                return ACCEPT_PSW

            except ValueError as e:
                await context.bot.send_message(chat_id, str(e))
                return OPTION_CHOICE

    else:
        await context.bot.send_message(
            chat_id, "Per favore premi uno dei bottoni\n\nPremi /stop per tornare al menù principale"
        )


async def get_psw_lenght_return_to_options_choice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Reads the desired password length from the user and returns to the options screen.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: OPTION_CHOICE or INSERT_PSW_LENGHT on invalid input.
    """
    options: Dict[str, Any] = context.chat_data[PSW_OPTIONS]

    try:
        psw_length = int(update.message.text)
        options['lunghezza'] = psw_length

        reply_markup = generate_password_options_keyboard(**options)
        await update.message.reply_text(
            "Scegli le opzioni di generazione della password\n\nPremi /stop per tornare al menù principale",
            reply_markup=reply_markup
        )
        return OPTION_CHOICE

    except ValueError:
        await update.message.reply_text("Impossibile convertire il valore in numero: Inserisci un valore valido")

    return INSERT_PSW_LENGHT


async def get_callback_data_from_generate_new_password_or_confirm(update: Update,
                                                                  context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Handles the 'Genera di nuovo' / 'Conferma' inline buttons on the generated-password screen.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ACCEPT_PSW or ASK_PASSPHRASE_INSERT or delegates to get_passphrase_and_save_account.
    """
    query: CallbackQuery = update.callback_query
    data: str = query.data
    await query.answer()
    chat_id = update.effective_chat.id
    message_id = update.effective_message.message_id

    options: Dict[str, Any] = context.chat_data[PSW_OPTIONS]

    if data == CALLBACK_GENERATE_NEW:
        try:
            generated_password = generate_password(**options)
            context.chat_data['temp_password'] = generated_password

            keyboard = [
                [InlineKeyboardButton('Genera di nuovo', callback_data=CALLBACK_GENERATE_NEW)],
                [InlineKeyboardButton('Conferma', callback_data=CALLBACK_CONFIRM_PASSWORD)]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)

            await context.bot.edit_message_text(
                f"Password generata:\n\n{generated_password}\n\nPremi /stop per tornare al menù principale",
                chat_id, message_id,
                reply_markup=reply_markup
            )
            return ACCEPT_PSW

        except ValueError as e:
            await context.bot.send_message(chat_id, str(e))

    elif data == CALLBACK_CONFIRM_PASSWORD:
        account: Account = context.chat_data[TEMP_SAVED_ACCOUNT]
        account.password = context.chat_data['temp_password']

        await context.bot.delete_message(chat_id, message_id)

        if not context.chat_data.get(TEMP_PASSPHRASE):
            await context.bot.send_message(chat_id, "Inserisci la passphrase")
            return ASK_PASSPHRASE_INSERT
        else:
            return await get_passphrase_and_save_account(update, context, manual_call=True)

    else:
        await context.bot.send_message(chat_id, "Per favore premi uno dei bottoni")


async def get_manual_password_and_ask_passphrase(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Stores the manually entered password and asks for the passphrase (or auto-proceeds if cached).

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: INSERT_USER_CHOSEN_PASSWORD or delegates to get_passphrase_and_save_account.
    """
    password = update.message.text

    account: Account = context.chat_data[TEMP_SAVED_ACCOUNT]
    account.password = password

    if not context.chat_data.get(TEMP_PASSPHRASE):
        await update.message.reply_text("Inserisci la passphrase")
        return INSERT_USER_CHOSEN_PASSWORD
    else:
        return await get_passphrase_and_save_account(update, context, manual_call=True)


async def get_passphrase_and_save_account(update: Update, context: ContextTypes.DEFAULT_TYPE,
                                          manual_call: bool = False) -> int:
    """
    Verifies the passphrase and, if valid, encrypts and saves the new account.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.
        manual_call (bool): If True, passphrase is taken from chat_data instead of the message.

    Returns:
        int: ConversationHandler.END on success, stays on current state otherwise.
    """
    chat_id = update.effective_message.chat_id

    result = await _resolve_and_verify_passphrase(update, context, manual_call=manual_call)
    if result is None:
        return  # error message already sent

    passphrase, _hash, stored_salt = result

    key = derive_key(passphrase, stored_salt)
    del passphrase

    account: Account = context.chat_data[TEMP_SAVED_ACCOUNT]
    account.user_name = encrypt(account.user_name, key)
    account.password = encrypt(account.password, key)

    insert_account(account, chat_id)
    logger.info("Account saved successfully")

    # Update TEMP_KEY with the freshly derived key
    context.chat_data[TEMP_KEY] = key
    del key
    del account
    context.chat_data.pop(TEMP_SAVED_ACCOUNT, None)

    await context.bot.send_message(chat_id, "Account creato con successo")
    await send_welcome_message(update, context)
    return ConversationHandler.END


# ===========================================================================
# Accounts browsing flow
# ===========================================================================


async def accounts_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Entry point for /accounts. Checks registration and asks for the passphrase if needed.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ASK_PASSPHRASE_READ or routes directly to account choice.
    """
    chat_id = update.message.chat_id

    if is_user_registered(chat_id):
        if not context.chat_data.get(TEMP_PASSPHRASE):
            await update.message.reply_text("Inserisci la passphrase")
            return ASK_PASSPHRASE_READ
        else:
            return await get_passphrase_and_call_account_choice(update, context, manual_call=True)
    else:
        await update.message.reply_text(
            'Non hai ancora inserito nessun account. Usa /newAccount per registrarne uno'
        )
        return ConversationHandler.END


async def get_passphrase_and_call_account_choice(update: Update, context: ContextTypes.DEFAULT_TYPE,
                                                 manual_call: bool = False) -> int:
    """
    Verifies the passphrase and shows the paginated account list if valid.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.
        manual_call (bool): If True, passphrase is taken from chat_data.

    Returns:
        int: ACCOUNT_CHOICE or stops the conversation if no accounts exist.
    """
    chat_id = update.effective_message.chat_id

    result = await _resolve_and_verify_passphrase(update, context, manual_call=manual_call)
    if result is None:
        return ASK_PASSPHRASE_READ

    passphrase, _hash, stored_salt = result

    key = derive_key(passphrase, stored_salt)
    context.chat_data[TEMP_KEY] = key
    del passphrase, key

    accounts: List[Account] = get_accounts_for_chat_id(chat_id)

    for account in accounts:
        account.user_name = decrypt(account.user_name, context.chat_data[TEMP_KEY])
        account.password = decrypt(account.password, context.chat_data[TEMP_KEY])

    if accounts:
        if CURRENT_ACCOUNT_PAGE not in context.chat_data:
            context.chat_data[CURRENT_ACCOUNT_PAGE] = 0

        reply_markup = generate_account_list_keyboard(accounts)
        await update.message.reply_text(
            "Che account vuoi aprire?\n\nPremi /stop per tornare al menù principale",
            reply_markup=reply_markup
        )
        return ACCOUNT_CHOICE
    else:
        await update.message.reply_text(
            "Non ci sono account memorizzati!\n\nInseriscine prima uno utilizzando /newAccount"
        )
        return await stop_nested(update, context)


async def get_callback_data_from_account_button_call_account_detail(
        update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Handles selection of an account from the list or page navigation.

    Shows account detail with Indietro/Modifica/Cancella buttons, or navigates pages.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ACCOUNT_ACTIONS after showing detail, or ACCOUNT_CHOICE on navigation.
    """
    query = update.callback_query
    data = query.data
    chat_id = update.effective_chat.id
    message_id = update.effective_message.message_id

    if TEMP_KEY not in context.chat_data:
        await query.answer("Sessione scaduta. Reinserisci la passphrase con /accounts")
        return ConversationHandler.END

    if data.startswith(CALLBACK_ACCOUNT_NAME):
        await query.answer()
        account_id = data.split(':')[1]

        account: Account = get_account_for_id(account_id)
        account_string = (
            f"*Nome account:* {account.name}\n\n"
            f"*Username/email:* {decrypt(account.user_name, context.chat_data[TEMP_KEY])}\n\n"
            f"*Password:* {escape_markdown(decrypt(account.password, context.chat_data[TEMP_KEY]))}"
        )

        context.chat_data[CURRENT_ACCOUNT_ID_SELECTED] = account_id
        reply_markup = _build_account_detail_keyboard()

        await context.bot.edit_message_text(
            account_string,
            chat_id=chat_id,
            message_id=message_id,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=reply_markup
        )
        return ACCOUNT_ACTIONS

    elif data == CALLBACK_PREV_PAGE:
        if context.chat_data[CURRENT_ACCOUNT_PAGE] == 0:
            await query.answer("Sei alla prima pagina")
            return ACCOUNT_CHOICE
        context.chat_data[CURRENT_ACCOUNT_PAGE] -= 1

    elif data == CALLBACK_NEXT_PAGE:
        context.chat_data[CURRENT_ACCOUNT_PAGE] += 1

    accounts: List[Account] = get_accounts_for_chat_id(chat_id, page=context.chat_data[CURRENT_ACCOUNT_PAGE])

    if not accounts:
        await query.answer("Non ci sono altre pagine")
        return ACCOUNT_CHOICE

    reply_markup = generate_account_list_keyboard(accounts)
    await query.answer()
    await query.edit_message_text(
        "Che account vuoi aprire?\n\nPremi /stop per tornare al menù principale",
        reply_markup=reply_markup
    )
    return ACCOUNT_CHOICE


async def get_callback_data_from_detail_buttons_call_actions(update: Update,
                                                             context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Handles actions on the account detail view: back, delete, or edit.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ACCOUNT_CHOICE on back/delete, or EDIT_ACCOUNT_FIELD_CHOICE on edit.
    """
    query = update.callback_query
    data = query.data
    chat_id = update.effective_chat.id

    if data == CALLBACK_DELETE:
        current_account_id = context.chat_data[CURRENT_ACCOUNT_ID_SELECTED]
        delete_account_by_id(current_account_id)
        await query.answer("Account rimosso")

        accounts: List[Account] = get_accounts_for_chat_id(chat_id, page=context.chat_data[CURRENT_ACCOUNT_PAGE])
        reply_markup = generate_account_list_keyboard(accounts)
        await query.answer()
        await query.edit_message_text(
            'Che account vuoi aprire?\n\nPremi /stop per tornare al menù principale',
            reply_markup=reply_markup
        )
        return ACCOUNT_CHOICE

    elif data == CALLBACK_EDIT:
        await query.answer()
        keyboard = [
            [InlineKeyboardButton("Nome account", callback_data=CALLBACK_EDIT_NAME)],
            [InlineKeyboardButton("Username / Email", callback_data=CALLBACK_EDIT_USERNAME)],
            [InlineKeyboardButton("Password", callback_data=CALLBACK_EDIT_PASSWORD)],
        ]
        await query.edit_message_text(
            "Quale campo vuoi modificare?",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return EDIT_ACCOUNT_FIELD_CHOICE

    else:  # CALLBACK_BACK or anything else
        accounts: List[Account] = get_accounts_for_chat_id(chat_id, page=context.chat_data[CURRENT_ACCOUNT_PAGE])
        reply_markup = generate_account_list_keyboard(accounts)
        await query.answer()
        await query.edit_message_text(
            'Che account vuoi aprire?\n\nPremi /stop per tornare al menù principale',
            reply_markup=reply_markup
        )
        return ACCOUNT_CHOICE


# ===========================================================================
# Edit account flow
# ===========================================================================


async def edit_account_field_choice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Handles the field-choice callback from the edit menu.

    Routes to the appropriate editing state based on which field was selected.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: EDIT_ACCOUNT_NAME, EDIT_ACCOUNT_USERNAME, or EDIT_ACCOUNT_PASSWORD_METHOD.
    """
    query = update.callback_query
    data = query.data
    await query.answer()

    if data == CALLBACK_EDIT_NAME:
        await query.edit_message_text("Inserisci il nuovo nome per l'account:")
        return EDIT_ACCOUNT_NAME

    elif data == CALLBACK_EDIT_USERNAME:
        await query.edit_message_text("Inserisci il nuovo username / email:")
        return EDIT_ACCOUNT_USERNAME

    elif data == CALLBACK_EDIT_PASSWORD:
        reply_keyboard: List[List[str]] = [['Genera una password', 'Inserisci una password']]
        reply_markup = ReplyKeyboardMarkup(
            reply_keyboard,
            resize_keyboard=True,
            one_time_keyboard=True,
            input_field_placeholder='Scegli cosa fare...'
        )
        await query.edit_message_text(
            "Vuoi generare una password sicura o inserirne una manualmente?"
        )
        await update.effective_chat.send_message(
            "Scegli il metodo:",
            reply_markup=reply_markup
        )
        return EDIT_ACCOUNT_PASSWORD_METHOD

    return EDIT_ACCOUNT_FIELD_CHOICE


async def edit_account_name(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Receives the new account name, validates uniqueness, and updates the DB.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ACCOUNT_ACTIONS to return to the detail view, or stays in EDIT_ACCOUNT_NAME on error.
    """
    new_name: str = update.message.text
    chat_id = update.message.chat_id
    account_id = context.chat_data[CURRENT_ACCOUNT_ID_SELECTED]

    if is_account_name_present(new_name, chat_id, exclude_id=account_id):
        await update.message.reply_text(
            f"Un account con il nome \"{new_name}\" esiste già. Scegli un nome diverso:"
        )
        return EDIT_ACCOUNT_NAME

    update_account(account_id, name=new_name)

    # Reload and display updated account detail
    return await _show_account_detail_after_edit(update, context)


async def edit_account_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Receives the new username/email, encrypts it, and updates the DB.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ACCOUNT_ACTIONS to return to the detail view.
    """
    if TEMP_KEY not in context.chat_data:
        await update.message.reply_text("Sessione scaduta. Reinserisci la passphrase con /accounts")
        return ConversationHandler.END

    new_username: str = update.message.text
    account_id = context.chat_data[CURRENT_ACCOUNT_ID_SELECTED]

    encrypted_username = encrypt(new_username, context.chat_data[TEMP_KEY])
    del new_username

    update_account(account_id, username=encrypted_username)

    return await _show_account_detail_after_edit(update, context)


async def edit_account_password_method(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Handles the password-method choice (generate or manual) during account editing.

    For generated passwords, routes into the password generator sub-flow.
    For manual passwords, asks the user to type the new password directly.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: GENERATE_PASSWORD_TYPE_CHOICE or EDIT_ACCOUNT_PASSWORD_METHOD.
    """
    data: str = update.message.text

    if data == 'Genera una password':
        message = await update.effective_message.reply_text('.', reply_markup=ReplyKeyboardRemove())
        await message.delete()

        options = {
            'lunghezza': 10,
            'speciali': False,
            'minuscole': True,
            'maiuscole': True,
            'duplicati': True,
            'numerici': True
        }
        context.chat_data[PSW_OPTIONS] = options
        context.chat_data['_edit_password_mode'] = True  # flag to route back after generation

        reply_markup = generate_password_options_keyboard(**options)
        await update.message.reply_text(
            "Scegli le opzioni di generazione della password\n\nPremi /stop per tornare al menù principale",
            reply_markup=reply_markup
        )
        return GENERATE_PASSWORD_TYPE_CHOICE

    elif data == 'Inserisci una password':
        message = await update.effective_message.reply_text('.', reply_markup=ReplyKeyboardRemove())
        await message.delete()

        await update.message.reply_text(
            "Inserisci la nuova password per questo account:"
        )
        return EDIT_ACCOUNT_PASSWORD_METHOD  # wait for plain text in next handler level

    else:
        await update.message.reply_text("Scegli una delle opzioni proposte.")
        return EDIT_ACCOUNT_PASSWORD_METHOD


async def edit_account_save_new_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Saves the manually entered new password (encrypted) for the account being edited.

    This handler is reached when the user chose 'Inserisci una password' in the edit flow
    and then typed the new password.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ACCOUNT_ACTIONS to return to the detail view.
    """
    if TEMP_KEY not in context.chat_data:
        await update.message.reply_text("Sessione scaduta. Reinserisci la passphrase con /accounts")
        return ConversationHandler.END

    new_password: str = update.message.text
    account_id = context.chat_data[CURRENT_ACCOUNT_ID_SELECTED]

    encrypted_password = encrypt(new_password, context.chat_data[TEMP_KEY])
    del new_password

    update_account(account_id, password=encrypted_password)
    context.chat_data.pop('_edit_password_mode', None)

    return await _show_account_detail_after_edit(update, context)


async def _show_account_detail_after_edit(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Reloads and displays the updated account detail after a successful edit.

    Sends the account detail as a new message (since we may be coming from a MessageHandler).

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ACCOUNT_ACTIONS.
    """
    if TEMP_KEY not in context.chat_data:
        await update.effective_message.reply_text("Sessione scaduta. Reinserisci la passphrase con /accounts")
        return ConversationHandler.END

    account_id = context.chat_data[CURRENT_ACCOUNT_ID_SELECTED]
    account: Account = get_account_for_id(account_id)

    account_string = (
        f"✅ Account aggiornato!\n\n"
        f"*Nome account:* {account.name}\n\n"
        f"*Username/email:* {decrypt(account.user_name, context.chat_data[TEMP_KEY])}\n\n"
        f"*Password:* {escape_markdown(decrypt(account.password, context.chat_data[TEMP_KEY]))}"
    )

    reply_markup = _build_account_detail_keyboard()

    await update.effective_message.reply_text(
        account_string,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=reply_markup
    )
    return ACCOUNT_ACTIONS


# ===========================================================================
# Search flow
# ===========================================================================


async def search_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Entry point for /search. Checks registration and asks for the passphrase if needed.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ASK_PASSPHRASE_READ or routes directly to account search.
    """
    chat_id = update.message.chat_id

    if is_user_registered(chat_id):
        if not context.chat_data.get(TEMP_PASSPHRASE):
            await update.message.reply_text("Inserisci la passphrase")
            return ASK_PASSPHRASE_READ
        else:
            return await get_passphrase_and_call_account_search(update, context, manual_call=True)
    else:
        await update.message.reply_text(
            'Non hai ancora inserito nessun account. Usa /newAccount per registrarne uno'
        )
        return ConversationHandler.END


async def get_passphrase_and_call_account_search(update: Update, context: ContextTypes.DEFAULT_TYPE,
                                                 manual_call: bool = False) -> int:
    """
    Verifies the passphrase and asks for the account name to search.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.
        manual_call (bool): If True, passphrase is taken from chat_data.

    Returns:
        int: ASK_SERVICE_NAME on success, stays on ASK_PASSPHRASE_READ otherwise.
    """
    result = await _resolve_and_verify_passphrase(update, context, manual_call=manual_call)
    if result is None:
        return ASK_PASSPHRASE_READ

    passphrase, _hash, stored_salt = result
    context.chat_data[TEMP_KEY] = derive_key(passphrase, stored_salt)
    del passphrase

    await update.message.reply_text(
        "Inserisci il nome dell'account che hai memorizzato.\n\n"
        "Il nome dell'account *può* anche non essere preciso.\n\n"
        "Premi /stop per tornare al menù principale",
        parse_mode=ParseMode.MARKDOWN
    )
    return ASK_SERVICE_NAME


async def get_account_name_and_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Performs a fuzzy search on the user's accounts using the provided name.

    Decrypts all accounts and filters by fuzzy token_set_ratio > 55.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ACCOUNT_DETAIL with matching results shown.
    """
    if TEMP_KEY not in context.chat_data:
        await update.message.reply_text("Sessione scaduta. Reinserisci la passphrase con /accounts")
        return ConversationHandler.END

    chat_id = update.message.chat_id
    account_name = update.message.text
    valid_accounts: List[Account] = []

    accounts: List[Account] = get_accounts_for_chat_id(chat_id, page_size=0)

    for account in accounts:
        account.user_name = decrypt(account.user_name, context.chat_data[TEMP_KEY])
        account.password = decrypt(account.password, context.chat_data[TEMP_KEY])

        if fuzz.token_set_ratio(account_name, account.name) > 55:
            valid_accounts.append(account)

    context.chat_data[TEMP_VALID_RESULTS] = valid_accounts
    reply_markup = generate_account_list_keyboard(valid_accounts, draw_navigation_buttons=False)

    await update.message.reply_text("Sono stati trovati i seguenti accounts:", reply_markup=reply_markup)
    return ACCOUNT_DETAIL


async def get_callback_data_from_detail_buttons_call_actions_search(update: Update,
                                                                    context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Handles Indietro/Modifica/Cancella actions from the account detail view in the search flow.

    Args:
        update (Update): The Telegram update object.
        context (ContextTypes.DEFAULT_TYPE): The Telegram context object.

    Returns:
        int: ACCOUNT_DETAIL after updating the list, or EDIT_ACCOUNT_FIELD_CHOICE on edit.
    """
    query = update.callback_query
    data = query.data

    if data == CALLBACK_DELETE:
        current_account_id = context.chat_data[CURRENT_ACCOUNT_ID_SELECTED]
        delete_account_by_id(current_account_id)
        await query.answer("Account rimosso")

    elif data == CALLBACK_EDIT:
        await query.answer()
        keyboard = [
            [InlineKeyboardButton("Nome account", callback_data=CALLBACK_EDIT_NAME)],
            [InlineKeyboardButton("Username / Email", callback_data=CALLBACK_EDIT_USERNAME)],
            [InlineKeyboardButton("Password", callback_data=CALLBACK_EDIT_PASSWORD)],
        ]
        await query.edit_message_text(
            "Quale campo vuoi modificare?",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return EDIT_ACCOUNT_FIELD_CHOICE

    reply_markup = generate_account_list_keyboard(
        context.chat_data.get(TEMP_VALID_RESULTS, []),
        draw_navigation_buttons=False
    )
    await query.answer()
    await query.edit_message_text(
        'Che account vuoi aprire?\n\nPremi /stop per tornare al menù principale',
        reply_markup=reply_markup
    )
    return ACCOUNT_DETAIL


# ===========================================================================
# Bot assembly
# ===========================================================================


def main():
    """
    Initializes and runs the Telegram password-manager bot.

    Sets up keyring, database, persistence, all ConversationHandlers, and starts polling.
    """
    if not keyring_initialize():
        exit(0xFF)

    create_database()

    persistence = PicklePersistence(filepath='DB.pkl')

    application = (
        Application.builder()
        .token(keyring_get('Telegram'))
        .post_stop(post_stop_callback)
        .persistence(persistence)
        .build()
    )

    application.add_error_handler(error_handler)

    # ------------------------------------------------------------------
    # Password generator sub-handler (shared across flows)
    # ------------------------------------------------------------------
    generate_password_conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(get_callback_data_from_psw_options_and_save_password)],
        states={
            INSERT_PSW_LENGHT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_psw_lenght_return_to_options_choice)
            ],
            OPTION_CHOICE: [CallbackQueryHandler(get_callback_data_from_psw_options_and_save_password)],
            ACCEPT_PSW: [CallbackQueryHandler(get_callback_data_from_generate_new_password_or_confirm)],
            ASK_PASSPHRASE_INSERT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_passphrase_and_save_account)
            ]
        },
        fallbacks=[CommandHandler("stop", stop_nested)],
        map_to_parent={
            STOPPING: STOPPING,
            ConversationHandler.END: STOPPING
        }
    )

    # ------------------------------------------------------------------
    # Password generator for edit flow (saves result as account password)
    # ------------------------------------------------------------------
    generate_password_for_edit_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(get_callback_data_from_psw_options_and_save_password)],
        states={
            INSERT_PSW_LENGHT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_psw_lenght_return_to_options_choice)
            ],
            OPTION_CHOICE: [CallbackQueryHandler(get_callback_data_from_psw_options_and_save_password)],
            ACCEPT_PSW: [CallbackQueryHandler(get_callback_data_from_generate_new_password_or_confirm)],
        },
        fallbacks=[CommandHandler("stop", stop_nested)],
        map_to_parent={
            STOPPING: STOPPING,
            ConversationHandler.END: ACCOUNT_ACTIONS
        }
    )

    # ------------------------------------------------------------------
    # New account handler
    # ------------------------------------------------------------------
    new_account_handler = ConversationHandler(
        entry_points=[CommandHandler('newAccount', new_account_callback)],
        states={
            INSERT_NAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_name_ask_username_handler)
            ],
            INSERT_USERNAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_username_ask_password_selection_handler)
            ],
            DECIDE_PASSWORD_METHOD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND,
                               get_password_decision_from_query_call_right_password_handler)
            ],
            GENERATE_PASSWORD_TYPE_CHOICE: [generate_password_conv_handler],
            ASK_PASSPHRASE_INSERT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_manual_password_and_ask_passphrase)
            ],
            INSERT_USER_CHOSEN_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_passphrase_and_save_account)
            ]
        },
        fallbacks=[CommandHandler("stop", stop_nested)],
        map_to_parent={
            STOPPING: MAIN_MENU
        }
    )

    # ------------------------------------------------------------------
    # Accounts browser handler (with edit sub-flow)
    # ------------------------------------------------------------------
    accounts_handler = ConversationHandler(
        entry_points=[CommandHandler('accounts', accounts_callback)],
        states={
            ASK_PASSPHRASE_READ: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_passphrase_and_call_account_choice)
            ],
            ACCOUNT_CHOICE: [
                CallbackQueryHandler(get_callback_data_from_account_button_call_account_detail)
            ],
            ACCOUNT_ACTIONS: [
                CallbackQueryHandler(get_callback_data_from_detail_buttons_call_actions)
            ],
            EDIT_ACCOUNT_FIELD_CHOICE: [
                CallbackQueryHandler(edit_account_field_choice)
            ],
            EDIT_ACCOUNT_NAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, edit_account_name)
            ],
            EDIT_ACCOUNT_USERNAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, edit_account_username)
            ],
            EDIT_ACCOUNT_PASSWORD_METHOD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, edit_account_password_method),
                MessageHandler(filters.TEXT & ~filters.COMMAND, edit_account_save_new_password),
                generate_password_for_edit_handler,
            ],
        },
        fallbacks=[CommandHandler("stop", stop_nested)],
        map_to_parent={
            STOPPING: MAIN_MENU
        }
    )

    # ------------------------------------------------------------------
    # Passphrase setup handler
    # ------------------------------------------------------------------
    passphrase_handler = ConversationHandler(
        entry_points=[CommandHandler('passphrase', passphrase_callback)],
        states={
            PASSPHRASE_SAVING: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_passphrase_and_store_to_db)
            ]
        },
        fallbacks=[]
    )

    # ------------------------------------------------------------------
    # Change passphrase handler
    # ------------------------------------------------------------------
    change_passphrase_handler = ConversationHandler(
        entry_points=[CommandHandler('changePassphrase', change_passphrase_callback)],
        states={
            CHANGE_PASSPHRASE_VERIFY_OLD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, change_passphrase_verify_old)
            ],
            CHANGE_PASSPHRASE_INSERT_NEW: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, change_passphrase_insert_new)
            ],
            CHANGE_PASSPHRASE_CONFIRM_NEW: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, change_passphrase_confirm_new)
            ],
        },
        fallbacks=[CommandHandler("stop", stop_nested)],
        map_to_parent={
            STOPPING: MAIN_MENU
        }
    )

    # ------------------------------------------------------------------
    # Account search handler (with edit sub-flow)
    # ------------------------------------------------------------------
    account_search_handler = ConversationHandler(
        entry_points=[CommandHandler('search', search_callback)],
        states={
            ASK_PASSPHRASE_READ: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_passphrase_and_call_account_search)
            ],
            ASK_SERVICE_NAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_account_name_and_search)
            ],
            ACCOUNT_DETAIL: [
                CallbackQueryHandler(get_callback_data_from_account_button_call_account_detail)
            ],
            ACCOUNT_ACTIONS: [
                CallbackQueryHandler(get_callback_data_from_detail_buttons_call_actions_search)
            ],
            EDIT_ACCOUNT_FIELD_CHOICE: [
                CallbackQueryHandler(edit_account_field_choice)
            ],
            EDIT_ACCOUNT_NAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, edit_account_name)
            ],
            EDIT_ACCOUNT_USERNAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, edit_account_username)
            ],
            EDIT_ACCOUNT_PASSWORD_METHOD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, edit_account_password_method),
                MessageHandler(filters.TEXT & ~filters.COMMAND, edit_account_save_new_password),
                generate_password_for_edit_handler,
            ],
        },
        map_to_parent={
            STOPPING: MAIN_MENU
        },
        fallbacks=[CommandHandler("stop", stop_nested)],
    )

    # ------------------------------------------------------------------
    # Top-level main handler
    # ------------------------------------------------------------------
    main_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start_handler)],
        states={
            MAIN_MENU: [
                new_account_handler,
                accounts_handler,
                passphrase_handler,
                change_passphrase_handler,
                account_search_handler,
            ]
        },
        fallbacks=[CommandHandler("stop", stop)]
    )

    application.add_handler(main_handler)

    # Fallback for stale inline buttons pressed outside an active conversation
    inline_button_handler = CallbackQueryHandler(default_inline_query_button_handler)
    application.add_handler(inline_button_handler)

    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
