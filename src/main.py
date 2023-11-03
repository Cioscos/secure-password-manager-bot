import json
import secrets
import string
import traceback
from pydoc import html
from typing import Dict, List, Any

from icecream import ic, install

from repository.account_repository import *
from model.account import *
from crypto.crypto_service import *
from environment_variables_mg import *

install()
from telegram import Update, ReplyKeyboardMarkup, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    ConversationHandler,
    ContextTypes,
    PicklePersistence, MessageHandler, filters, CallbackQueryHandler
)
from telegram.helpers import escape_markdown

TEMP_SAVED_ACCOUNT = 'temp_saved_account'

# Options callback data
CALLBACK_OPTION_NAME = 'option_selected'
CALLBACK_PSW_LENGHT = 'psw_lenght'
CALLBACK_UPPER = 'upper'
CALLBACK_LOWER = 'lower'
CALLBACK_NUMERIC = 'numeric'
CALLBACK_SPECIALS = 'specials'
CALLBACK_DUPLICATES = 'duplicates'
CALLBACK_GENERATE = 'generate'

PSW_OPTIONS = 'psw_options_key'

MAP_CALLBACK_TO_OPTIONS_KEYS = {
    CALLBACK_PSW_LENGHT: 'lunghezza',
    CALLBACK_UPPER: 'maiuscole',
    CALLBACK_LOWER: 'minuscole',
    CALLBACK_NUMERIC: 'numerici',
    CALLBACK_SPECIALS: 'speciali',
    CALLBACK_DUPLICATES: 'duplicati'
}

CURRENT_ACCOUNT_PAGE = 'current_account_page'
CURRENT_ACCOUNT_ID_SELECTED = 'current_account_id_selected'

CALLBACK_ACCOUNT_NAME = 'selected_account'

TEMP_KEY = 'temp_key'

# State definitions for top-level conv handler
MAIN_MENU, ADD_ACCOUNT, SHOW_ACCOUNT, DELETE_ACCOUNT = map(chr, range(4))
# State definitions for add account handler
INSERT_NAME, INSERT_USERNAME, DECIDE_PASSWORD_METHOD, GENERATE_PASSWORD_TYPE_CHOICE, ASK_PASSPHRASE_INSERT, INSERT_USER_CHOSEN_PASSWORD = map(
    chr, range(4, 10))

OPTION_CHOICE, ASK_PASSPHRASE_READ, INSERT_PSW_LENGHT, ACCEPT_PSW = map(chr, range(10, 14))

ACCOUNT_CHOICE, ACCOUNT_DETAIL, ACCOUNT_ACTIONS = map(chr, range(14, 17))

PASSPHRASE_SAVING = 17

STOPPING = 99


def log_to_file(log: Any) -> None:
    with open('password_bot.log', 'a') as f:
        f.write(log + '\n')


ic.configureOutput(prefix='Debug| ', outputFunction=log_to_file, includeContext=True)


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    The error callback function.
    This function is used to handle possible Telegram API errors that aren't handled.

    :param update: The Telegram update.
    :param context: The Telegram context.
    """
    # Log the error before we do anything else, so we can see it even if something breaks.
    # ic(f"Exception while handling an update: {context.error}")

    # traceback.format_exception returns the usual python message about an exception, but as a
    # list of strings rather than a single string, so we have to join them together.
    tb_list = traceback.format_exception(None, context.error, context.error.__traceback__)
    tb_string = "".join(tb_list)

    # Split the traceback into smaller parts
    tb_parts = [tb_string[i: i + 4096] for i in range(0, len(tb_string), 4096)]

    # Build the message with some markup and additional information about what happened.
    update_str = update.to_dict() if isinstance(update, Update) else str(update)
    base_message = (
        f"An exception was raised while handling an update\n"
        f"<pre>update = {html.escape(json.dumps(update_str, indent=2, ensure_ascii=False))}"
        "</pre>\n\n"
        f"<pre>context.chat_data = {html.escape(str(context.chat_data))}</pre>\n\n"
        f"<pre>context.user_data = {html.escape(str(context.user_data))}</pre>\n\n"
    )

    # Send base message
    await context.bot.send_message(
        chat_id=keyring_get('DevId'), text=base_message, parse_mode=ParseMode.HTML
    )

    # Send each part of the traceback as a separate message
    for part in tb_parts:
        await context.bot.send_message(
            chat_id=keyring_get('DevId'), text=f"<pre>{html.escape(part)}</pre>", parse_mode=ParseMode.HTML
        )


async def send_welcome_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    welcome_message: str = (f"Ciao {update.effective_user.name}!\n\n"
                            f"Come posso aiutarti? Usa i seguenti comandi per interagire con me:\n"
                            f"/newAccount - Inserisci un nuovo account da memorizzare\n"
                            f"/accounts - Mostra tutti gli account\n"
                            f"/passphrase - Imposta la passphrase per criptare i tuoi dati")

    await context.bot.send_message(update.effective_chat.id, welcome_message)


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await send_welcome_message(update, context)

    return MAIN_MENU


async def new_account_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_user_registered(update.message.chat_id):
        await update.message.reply_text("Non hai ancora inserito la passphrase!\n\n"
                                        "Premi /passphrase per impostarla.")

        return await stop_nested(update, context)

    await update.message.reply_text("Che nome vuoi assegnare al nuovo account?\n\n"
                                    "Premi /stop per tornare al menù principale")

    return INSERT_NAME


async def get_name_ask_username_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    # get the response message and use it as account name
    message: str = update.message.text

    if is_account_name_present(message):
        await update.message.reply_text(f"L'account con il nome \"{message}\" già esiste. Inserisci uno nuovo\n\n"
                                        "Premi /stop per tornare al menù principale")
        return await new_account_callback(update, context)

    # Create the account object
    account: Account = Account()
    account.name = message

    # save the account object temporary in context_data
    context.chat_data[TEMP_SAVED_ACCOUNT] = account

    await update.message.reply_text("Che username o email vuoi assegnare?\n\n"
                                    "Premi /stop per tornare al menù principale")

    # go to get_username_ask_password_selection_handler
    return INSERT_USERNAME


async def get_username_ask_password_selection_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    # get the response message and use it as account username
    message: str = update.message.text

    # Update the account object
    account: Account = context.chat_data[TEMP_SAVED_ACCOUNT]
    account.user_name = message

    # Create inline keyboard
    reply_keyboard: List[List[str]] = [['Genera una password', 'Inserisci una password']]
    reply_markup = ReplyKeyboardMarkup(
        reply_keyboard,
        resize_keyboard=True,
        one_time_keyboard=True,
        input_field_placeholder='Scegli cosa fare...'
    )
    await update.message.reply_text("Vuoi generare un password sicura casuale o vuoi inserire tu una password?\n\n"
                                    "Premi /stop per tornare al menù principale",
                                    reply_markup=reply_markup)

    # go to get_password_decision_from_query_call_right_password_handler
    return DECIDE_PASSWORD_METHOD


async def get_password_decision_from_query_call_right_password_handler(update: Update,
                                                                       context: ContextTypes.DEFAULT_TYPE) -> int:
    # get query from the update
    data: str = update.message.text

    if data == 'Genera una password':
        # Generates default option values
        options = {
            'lunghezza': 10,
            'speciali': False,
            'minuscole': True,
            'maiuscole': True,
            'duplicati': True,
            'numerici': True
        }
        # Save default options in chat data
        context.chat_data[PSW_OPTIONS] = options

        reply_markup = generate_password_options_keyboard(**options)
        await update.message.reply_text("Scegli le opzioni di generazione della password\n\n"
                                        "Premi /stop per tornare al menù principale", reply_markup=reply_markup)

        # go to get_callback_data_from_psw_options_and_save_password
        return GENERATE_PASSWORD_TYPE_CHOICE

    elif data == 'Inserisci una password':
        await update.message.reply_text("Inserisci la password che più preferisci per il tuo account\n\n"
                                        "Premi /stop per tornare al menù principale")

        # go to get_manual_password_and_ask_passphrase
        return ASK_PASSPHRASE_INSERT
    else:
        await update.message.reply_text("Rispondi scegliendo una delle due opzioni offerte dai pulsanti.\n\n"
                                        "Premi /stop per tornare al menù principale")


async def get_callback_data_from_psw_options_and_save_password(update: Update,
                                                               context: ContextTypes.DEFAULT_TYPE) -> int:
    # get query from the update
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
            options[MAP_CALLBACK_TO_OPTIONS_KEYS[option]] = False if value else True
            reply_markup = generate_password_options_keyboard(**options)
            status = "abilitati" if not value else "disabilitati"
            await context.bot.edit_message_reply_markup(chat_id=chat_id, message_id=message_id,
                                                        reply_markup=reply_markup)
            await query.answer(f'Caratteri {MAP_CALLBACK_TO_OPTIONS_KEYS[option]} {status}')

            return OPTION_CHOICE

        elif option == CALLBACK_GENERATE:
            await query.answer()
            # generate password
            try:
                generated_password = generate_password(**options)
                # save the password as temporary
                context.chat_data['temp_password'] = generated_password

                # Generate inline keyboard to generate another password
                keyboard = [[InlineKeyboardButton('Genera di nuovo', callback_data='generate_new_password')],
                            [InlineKeyboardButton('Conferma', callback_data='confirm_password')]]
                reply_markup = InlineKeyboardMarkup(keyboard)

                await context.bot.send_message(chat_id, f"Password generata:\n\n{generated_password}\n\n"
                                                        "Premi /stop per tornare al menù principale",
                                               reply_markup=reply_markup)

                # go to get_callback_data_from_generate_new_password_or_confirm
                return ACCEPT_PSW
            except ValueError as e:
                await context.bot.send_message(chat_id, str(e))
                return OPTION_CHOICE

    else:
        await context.bot.send_message(chat_id, "Per favore premi uno dei bottoni\n\n"
                                                "Premi /stop per tornare al menù principale")


async def get_psw_lenght_return_to_options_choice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    options: Dict[str, Any] = context.chat_data[PSW_OPTIONS]

    try:
        psw_length = int(update.message.text)
        options['lunghezza'] = psw_length

        reply_markup = generate_password_options_keyboard(**options)
        await update.message.reply_text("Scegli le opzioni di generazione della password\n\n"
                                        "Premi /stop per tornare al menù principale", reply_markup=reply_markup)

        return OPTION_CHOICE

    except ValueError:
        await update.message.reply_text("Impossibile convertire il valore in numero: Inserisci un valore valido")

    return INSERT_PSW_LENGHT


async def get_callback_data_from_generate_new_password_or_confirm(update: Update,
                                                                  context: ContextTypes.DEFAULT_TYPE) -> int:
    # get query from the update
    query: CallbackQuery = update.callback_query
    data: str = query.data
    await query.answer()
    chat_id = update.effective_chat.id
    message_id = update.effective_message.message_id

    options: Dict[str, Any] = context.chat_data[PSW_OPTIONS]

    if data == 'generate_new_password':
        try:
            # generate password
            generated_password = generate_password(**options)
            # save the password as temporary
            context.chat_data['temp_password'] = generated_password

            # Generate inline keyboard to generate another password
            keyboard = [[InlineKeyboardButton('Genera di nuovo', callback_data='generate_new_password')],
                        [InlineKeyboardButton('Conferma', callback_data='confirm_password')]]
            reply_markup = InlineKeyboardMarkup(keyboard)

            await context.bot.edit_message_text(f"Password generata:\n\n{generated_password}\n\n"
                                                "Premi /stop per tornare al menù principale", chat_id, message_id,
                                                reply_markup=reply_markup)

            # go to get_callback_data_from_generate_new_password_or_confirm
            return ACCEPT_PSW

        except ValueError as e:
            await context.bot.send_message(chat_id, str(e))

    elif data == 'confirm_password':
        account: Account = context.chat_data[TEMP_SAVED_ACCOUNT]
        account.password = context.chat_data['temp_password']

        await context.bot.send_message(chat_id, "Inserisci la passphrase")

        return ASK_PASSPHRASE_INSERT

    else:
        await context.bot.send_message(chat_id, "Per favore premi uno dei bottoni")


async def get_manual_password_and_ask_passphrase(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    password = update.message.text

    account: Account = context.chat_data[TEMP_SAVED_ACCOUNT]
    account.password = password

    await update.message.reply_text("Inserisci la passphrase")

    return INSERT_USER_CHOSEN_PASSWORD


async def get_passphrase_and_save_account(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    passphrase = update.message.text

    # get salted_hash and salt
    stored_hash, stored_salt = get_hash_and_salt_for_id(update.message.chat_id)

    # Verify the passphrase
    is_valid = verify_passphrase(passphrase, stored_salt, stored_hash)

    if is_valid:
        # Derive encryption key from the passphrase
        key = derive_key(passphrase, stored_salt)

        # Encrypt the data
        account: Account = context.chat_data[TEMP_SAVED_ACCOUNT]
        account.user_name = encrypt(account.user_name, key)
        account.password = encrypt(account.password, key)

        # Save the account on DB
        insert_account(account, update.message.chat_id)

        del key
        del passphrase
        del account
        context.chat_data.pop(TEMP_SAVED_ACCOUNT)

        await update.message.reply_text("Account creato con successo")
        await send_welcome_message(update, context)

        return ConversationHandler.END

    else:
        await update.message.reply_text("*PASSPHRASE SBAGLIATA!*\n\nProva di nuovo o premi /stop per uscire",
                                        parse_mode=ParseMode.MARKDOWN)


def generate_password_options_keyboard(lunghezza: int = 10, maiuscole: bool = False, minuscole: bool = False,
                                       numerici: bool = False,
                                       speciali: bool = False, duplicati: bool = False) -> InlineKeyboardMarkup:
    keyboard: List[List[InlineKeyboardButton]] = []

    password_lenght_option = InlineKeyboardButton(f'Lunghezza: {lunghezza}',
                                                  callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_PSW_LENGHT}")
    upper_option = InlineKeyboardButton(f"Maiuscole {'✅' if maiuscole else '❌'}",
                                        callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_UPPER}")
    first_line: List[InlineKeyboardButton] = [password_lenght_option, upper_option]
    keyboard.append(first_line)

    lower_option = InlineKeyboardButton(f"Minuscole {'✅' if minuscole else '❌'}",
                                        callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_LOWER}")
    numeric_option = InlineKeyboardButton(f"Numerici {'✅' if numerici else '❌'}",
                                          callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_NUMERIC}")
    second_line: List[InlineKeyboardButton] = [lower_option, numeric_option]
    keyboard.append(second_line)

    special_option = InlineKeyboardButton(f"Speciali {'✅' if speciali else '❌'}",
                                          callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_SPECIALS}")
    duplicates_option = InlineKeyboardButton(f"Duplicati {'✅' if duplicati else '❌'}",
                                             callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_DUPLICATES}")
    third_line: List[InlineKeyboardButton] = [special_option, duplicates_option]
    keyboard.append(third_line)

    generate_button = InlineKeyboardButton('Genera', callback_data=f"{CALLBACK_OPTION_NAME}:{CALLBACK_GENERATE}")
    keyboard.append([generate_button])

    return InlineKeyboardMarkup(keyboard)


def generate_password(lunghezza: int, maiuscole: bool, minuscole: bool, numerici: bool, speciali: bool,
                      duplicati: bool) -> str:
    # Inizializza l'alfabeto vuoto
    alfabeto = ''

    # Aggiungi le diverse categorie di caratteri all'alfabeto, se richiesto
    if maiuscole:
        alfabeto += string.ascii_uppercase
    if minuscole:
        alfabeto += string.ascii_lowercase
    if numerici:
        alfabeto += string.digits
    if speciali:
        alfabeto += string.punctuation

    if duplicati:
        password = ''.join(secrets.choice(alfabeto) for _ in range(lunghezza))
    else:
        if len(alfabeto) < lunghezza:
            raise ValueError(
                "Non ci sono abbastanza caratteri unici per soddisfare la lunghezza richiesta senza duplicati.")
        alfabeto_list = list(alfabeto)
        secrets.SystemRandom().shuffle(alfabeto_list)
        password = ''.join(alfabeto_list[:lunghezza])

    return password


async def accounts_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    chat_id = update.message.chat_id

    # check if the user is registered
    if is_user_registered(chat_id):
        await update.message.reply_text("Inserisci la passphrase")

        # go to get_passphrase_and_call_account_choice
        return ASK_PASSPHRASE_READ

    else:
        await update.message.reply_text('Non hai ancora inserito nessun account. Usa /newAccount per registrarne uno')
        return ConversationHandler.END


async def get_passphrase_and_call_account_choice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    chat_id = update.message.chat_id
    passphrase = update.message.text

    # get salted_hash and salt
    stored_hash, stored_salt = get_hash_and_salt_for_id(update.message.chat_id)
    # Verify the passphrase
    is_valid = verify_passphrase(passphrase, stored_salt, stored_hash)

    if is_valid:
        # Derive encryption key from the passphrase
        key = derive_key(passphrase, stored_salt)
        context.chat_data[TEMP_KEY] = key
        del passphrase

        # Get one page of accounts associated with the user in the DB
        accounts: List[Account] = get_accounts_for_chat_id(chat_id)

        for account in accounts:
            account.user_name = decrypt(account.user_name, key)
            account.password = decrypt(account.password, key)

        if CURRENT_ACCOUNT_PAGE not in context.chat_data.keys():
            context.chat_data[CURRENT_ACCOUNT_PAGE] = 0

        reply_markup = generate_account_list_keyboard(accounts)

        await update.message.reply_text("Che account vuoi aprire?\n\n"
                                        "Premi /stop per tornare al menù principale", reply_markup=reply_markup)

        return ACCOUNT_CHOICE

    else:
        await update.message.reply_text("*PASSPHRASE SBAGLIATA!*\n\nProva di nuovo o premi /stop per uscire",
                                        parse_mode=ParseMode.MARKDOWN)


async def get_callback_data_from_account_button_call_account_detail(update: Update,
                                                                    context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    data = query.data
    chat_id = update.effective_chat.id

    if data.startswith(CALLBACK_ACCOUNT_NAME):
        await query.answer()
        account_id = data.split(':')[1]

        # Retrive account from DB
        account: Account = get_account_for_id(account_id)
        account_string = (f"*Nome account:* {account.name}\n\n"
                          f"*Username/email:* {decrypt(account.user_name, context.chat_data[TEMP_KEY])}\n\n"
                          f"*Password:* {escape_markdown(decrypt(account.password, context.chat_data[TEMP_KEY]))}")

        context.chat_data[CURRENT_ACCOUNT_ID_SELECTED] = account_id

        # Add navigation buttons
        navigation_buttons = [InlineKeyboardButton("Indietro 🔙", callback_data="back"),
                              InlineKeyboardButton("Cancella 🗑", callback_data="delete")]
        reply_markup = InlineKeyboardMarkup([navigation_buttons])

        await context.bot.send_message(chat_id, account_string, parse_mode=ParseMode.MARKDOWN,
                                       reply_markup=reply_markup)

        # go to get_callback_data_from_detail_buttons_call_actions
        return ACCOUNT_DETAIL

    elif data == "prev_page":
        if context.chat_data[CURRENT_ACCOUNT_PAGE] == 0:
            await query.answer("Sei alla prima pagina")
            return ACCOUNT_CHOICE

        context.chat_data[CURRENT_ACCOUNT_PAGE] -= 1

    elif data == "next_page":
        context.chat_data[CURRENT_ACCOUNT_PAGE] += 1

    # Retrieve other account from the database
    accounts: List[Account] = get_accounts_for_chat_id(chat_id, page=context.chat_data[CURRENT_ACCOUNT_PAGE])

    if not accounts:
        await query.answer("Non ci sono altre pagine")
        return ACCOUNT_CHOICE

    # Update the InlineKeyboard with the new page data
    reply_markup = generate_account_list_keyboard(accounts)
    await query.answer()
    await query.edit_message_text("Che account vuoi aprire?\n\n"
                                  "Premi /stop per tornare al menù principale", reply_markup=reply_markup)


async def get_callback_data_from_detail_buttons_call_actions(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    data = query.data
    chat_id = update.effective_chat.id

    if data == 'delete':
        current_account_id = context.chat_data[CURRENT_ACCOUNT_ID_SELECTED]
        delete_account_by_id(current_account_id)
        await query.answer("Account rimosso")

    # Retrieve other account from the database
    accounts: List[Account] = get_accounts_for_chat_id(chat_id, page=context.chat_data[CURRENT_ACCOUNT_PAGE])

    # Update the InlineKeyboard with the new page data
    reply_markup = generate_account_list_keyboard(accounts)
    await query.answer()
    await query.edit_message_text('Che account vuoi aprire?\n\nPremi /stop per tornare al menù principale',
                                  reply_markup=reply_markup)

    return ACCOUNT_CHOICE


def generate_account_list_keyboard(accounts: List[Account]) -> InlineKeyboardMarkup:
    """
    Generates an inline keyboard markup for the provided list of accounts.

    Args:
        accounts (List[Account]): List of Account objects.

    Returns:
        InlineKeyboardMarkup: The generated inline keyboard markup.
    """
    keyboard = []

    row = []
    for account in accounts:
        button = InlineKeyboardButton(account.name, callback_data=f"{CALLBACK_ACCOUNT_NAME}:{account.id}")
        row.append(button)

        if len(row) == 2:
            keyboard.append(row)
            row = []

    # Append any remaining buttons if the total is an odd number
    if row:
        keyboard.append(row)

    # Add navigation buttons
    navigation_buttons = [InlineKeyboardButton("Previous", callback_data="prev_page"),
                          InlineKeyboardButton("Next", callback_data="next_page")]
    keyboard.append(navigation_buttons)

    return InlineKeyboardMarkup(keyboard)


async def passphrase_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Inserisci una passphrase per criptare i tuoi dati.\n\n"
                                    "L'inserimento di una passphrase è obbligatoria per i fini di utilizzo\n"
                                    "dell'applicazione. Più lunga è la passphrase più sicura sarà la crittografia")

    # go to get_passphrase_and_store_to_db
    return PASSPHRASE_SAVING


async def get_passphrase_and_store_to_db(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    salted_hash, salt = store_passphrase_hash(update.message.text)

    await update.message.reply_text("Si suggerisce di cancellare questo messaggio per sicurezza.\n"
                                    "*Salva la password in un luogo sicuro!!*", parse_mode=ParseMode.MARKDOWN)

    insert_user(update.message.chat_id,
                update.message.from_user.name,
                salted_hash,
                salt)

    return ConversationHandler.END


async def stop_nested(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Comando stoppato")

    context.chat_data.pop(TEMP_KEY, None)

    await send_welcome_message(update, context)

    return STOPPING


async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Okay, bye.")

    return ConversationHandler.END


def main():
    # Initialize the keyring
    if not keyring_initialize():
        exit(0xFF)

    # Create database
    create_database()

    # Initialize the Pickle database
    persistence = PicklePersistence(filepath='DB.pkl')

    application = Application.builder().token(keyring_get('Telegram')).persistence(persistence).build()

    application.add_error_handler(error_handler)

    generate_password_conv_handler = ConversationHandler(
        persistent=True,
        name='generate_password_handler_v1',
        entry_points=[CallbackQueryHandler(get_callback_data_from_psw_options_and_save_password)],
        states={
            INSERT_PSW_LENGHT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_psw_lenght_return_to_options_choice)],
            OPTION_CHOICE: [CallbackQueryHandler(get_callback_data_from_psw_options_and_save_password)],
            ACCEPT_PSW: [CallbackQueryHandler(get_callback_data_from_generate_new_password_or_confirm)],
            ASK_PASSPHRASE_INSERT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_passphrase_and_save_account)]
        },
        fallbacks=[CommandHandler("stop", stop_nested)],
        map_to_parent={
            STOPPING: STOPPING,
            ConversationHandler.END: STOPPING
        }
    )

    new_account_handler = ConversationHandler(
        persistent=True,
        name='new_account_handler_v1',
        entry_points=[CommandHandler('newAccount', new_account_callback)],
        states={
            INSERT_NAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_name_ask_username_handler)],
            INSERT_USERNAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_username_ask_password_selection_handler)],
            DECIDE_PASSWORD_METHOD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND,
                               get_password_decision_from_query_call_right_password_handler)],
            GENERATE_PASSWORD_TYPE_CHOICE: [generate_password_conv_handler],
            ASK_PASSPHRASE_INSERT: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_manual_password_and_ask_passphrase)],
            INSERT_USER_CHOSEN_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, get_passphrase_and_save_account)]
        },
        fallbacks=[CommandHandler("stop", stop_nested)],
        map_to_parent={
            STOPPING: MAIN_MENU
        }
    )

    accounts_handler = ConversationHandler(
        persistent=True,
        name='accounts_handler_v1',
        entry_points=[CommandHandler('accounts', accounts_callback)],
        states={
            ASK_PASSPHRASE_READ: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_passphrase_and_call_account_choice)],
            ACCOUNT_CHOICE: [CallbackQueryHandler(get_callback_data_from_account_button_call_account_detail)],
            ACCOUNT_DETAIL: [CallbackQueryHandler(get_callback_data_from_detail_buttons_call_actions)]
        },
        fallbacks=[CommandHandler("stop", stop_nested)],
        map_to_parent={
            STOPPING: MAIN_MENU
        }
    )

    passphrase_handler = ConversationHandler(
        persistent=True,
        name='passphrase_handler_v1',
        entry_points=[CommandHandler('passphrase', passphrase_callback)],
        states={
            PASSPHRASE_SAVING: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_passphrase_and_store_to_db)]
        },
        fallbacks=[]
    )

    main_handler = ConversationHandler(
        persistent=True,
        name='main_handler_v1',
        entry_points=[CommandHandler('start', start_handler)],
        states={
            MAIN_MENU: [new_account_handler,
                        accounts_handler,
                        passphrase_handler]
        },
        fallbacks=[]
    )
    application.add_handler(main_handler)

    # Start the bot polling
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
