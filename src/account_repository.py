import sqlite3
from typing import List, Tuple, Optional, Union

from account import Account

DB_NAME = 'accounts.db'


def create_database():
    """
    Creates a database and sets up the necessary tables if they don't already exist.
    """
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            chat_id  INTEGER,
            FOREIGN KEY (chat_id) REFERENCES users(chat_id),
            UNIQUE (id, name)
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            chat_id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            salted_hash TEXT,
            salt TEXT
        )  
        ''')

        conn.commit()


def insert_account(account: Account, chat_id: int):
    """
    Inserts a new account into the database.

    Args:
        account (Account): The account object to insert.
        chat_id (int): The chat_id to use as foreign key.

    Raises:
        sqlite3.DatabaseError: If there's a constraint violation or operational error.
    """
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            cursor.execute('''
            INSERT INTO accounts (id, name, username, password, chat_id)
            VALUES (?, ?, ?, ?, ?)
            ''', (account.id, account.name, account.user_name, account.password, chat_id))

            conn.commit()

    except sqlite3.IntegrityError:
        raise sqlite3.DatabaseError("Failed to insert account due to integrity constraints violation.")
    except sqlite3.OperationalError:
        raise sqlite3.DatabaseError("Failed to insert account due to an operational error.")
    except sqlite3.DatabaseError:
        raise sqlite3.DatabaseError("A database error occurred while trying to insert the account.")


def insert_user(chat_id: int, name: str, salted_hash: str, salt: str) -> None:
    """
    Inserts a new user into the database.

    Args:
        chat_id (int): The Telegram chat ID of the user.
        name (str): The user's Telegram display name.
        salted_hash (str): The PBKDF2 salted hash of the passphrase.
        salt (str): The hex-encoded salt used to produce the hash.

    Raises:
        sqlite3.DatabaseError: If the insertion fails.
    """
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            cursor.execute('''
            INSERT INTO users (chat_id, name, salted_hash, salt)
            VALUES (?, ?, ?, ?)
            ''', (chat_id, name, salted_hash, salt))

            conn.commit()

    except sqlite3.IntegrityError:
        raise sqlite3.DatabaseError("Failed to insert user due to integrity constraints violation.")
    except sqlite3.OperationalError:
        raise sqlite3.DatabaseError("Failed to insert user due to an operational error.")
    except sqlite3.DatabaseError:
        raise sqlite3.DatabaseError("A database error occurred while trying to insert the user.")


def is_account_name_present(account_name: str, chat_id: int, exclude_id: Optional[str] = None) -> bool:
    """
    Checks if a given account name is already present in the database for a specific user.

    Args:
        account_name (str): The name of the account to check.
        chat_id (int): The chat ID of the user who owns the accounts.
        exclude_id (Optional[str]): An account ID to exclude from the check (useful during edits).

    Returns:
        bool: True if the account name is already taken by this user, False otherwise.
    """
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        if exclude_id:
            cursor.execute(
                'SELECT 1 FROM accounts WHERE name = ? AND chat_id = ? AND id != ?',
                (account_name, chat_id, exclude_id)
            )
        else:
            cursor.execute(
                'SELECT 1 FROM accounts WHERE name = ? AND chat_id = ?',
                (account_name, chat_id)
            )

        return cursor.fetchone() is not None


def is_user_registered(chat_id: int) -> bool:
    """
    Checks if a given chat id is already present in the user table.

    Args:
        chat_id (int): The chat_id of the account to check.

    Returns:
        bool: True if the user is registered, False otherwise.
    """
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        cursor.execute('SELECT 1 FROM users WHERE chat_id = ?', (chat_id,))

        return cursor.fetchone() is not None


def get_accounts_for_chat_id(chat_id: int, page: Optional[int] = 0, page_size: Optional[int] = 6) -> List[Account]:
    """
    Fetches a paginated list of accounts associated with a given chat_id.

    Args:
        chat_id (int): The chat ID to fetch accounts for.
        page (int): The page number (starting from 0).
        page_size (int): The number of accounts to retrieve per page. Use 0 to fetch all.

    Returns:
        List[Account]: A list of Account objects.
    """
    query: str = '''
    SELECT id, name, username, password
    FROM accounts
    WHERE chat_id = ?
    '''
    parameters: Union[Tuple[int], Tuple[int, int, int]]

    if page_size != 0:
        offset = page * page_size
        query += ' LIMIT ? OFFSET ?'
        parameters = (chat_id, page_size, offset)
    else:
        parameters = (chat_id,)

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        cursor.execute(query, parameters)
        accounts = cursor.fetchall()

    return_list: List[Account] = []
    for account_tuple in accounts:
        account: Account = Account()
        account.id = account_tuple[0]
        account.name = account_tuple[1]
        account.user_name = account_tuple[2]
        account.password = account_tuple[3]
        return_list.append(account)

    return return_list


def get_account_for_id(account_id: str) -> Account:
    """
    Get an account from a given account id.

    Args:
        account_id (str): The given account id.

    Returns:
        Account: The corresponding Account object.
    """
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT name, username, password
            FROM accounts
            WHERE id = ?
            ''', (account_id,))

        account_tuple = cursor.fetchone()

    account = Account()
    account.name = account_tuple[0]
    account.user_name = account_tuple[1]
    account.password = account_tuple[2]

    return account


def get_hash_and_salt_for_id(chat_id: int) -> Tuple[str, str]:
    """
    Get hash and salt generated from the user passphrase.

    Args:
        chat_id (int): The given chat_id.

    Returns:
        Tuple[str, str]: A tuple with the salted_hash and salt saved from the passphrase.
    """
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT salted_hash, salt
            FROM users
            WHERE chat_id = ?
            ''', (chat_id,))

        return cursor.fetchone()


def delete_account_by_id(account_id: str) -> None:
    """
    Deletes an account from the database based on its ID.

    Args:
        account_id (str): The ID of the account to delete.

    Raises:
        sqlite3.DatabaseError: If there's an error during the database operation.
    """
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            cursor.execute('DELETE FROM accounts WHERE id = ?', (account_id,))

            conn.commit()
    except sqlite3.DatabaseError:
        raise sqlite3.DatabaseError("An error occurred while trying to delete the account.")


def get_users_id() -> List[int]:
    """
    Get all the chat_ids stored in the DB.

    Returns:
        List[int]: A list of chat_id integers.
    """
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        cursor.execute('SELECT chat_id FROM users')

        result = cursor.fetchall()

    return [row[0] for row in result]


def update_account(
        account_id: str,
        name: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None
) -> None:
    """
    Updates one or more fields of an existing account. Only non-None fields are updated.

    Uses dynamic parameterized SQL to safely build the SET clause, avoiding SQL injection.

    Args:
        account_id (str): The UUID of the account to update.
        name (Optional[str]): The new account name, or None to leave unchanged.
        username (Optional[str]): The new (encrypted) username/email, or None to leave unchanged.
        password (Optional[str]): The new (encrypted) password, or None to leave unchanged.

    Raises:
        ValueError: If no fields are provided to update.
        sqlite3.DatabaseError: If a database error occurs.
    """
    fields: dict = {}
    if name is not None:
        fields['name'] = name
    if username is not None:
        fields['username'] = username
    if password is not None:
        fields['password'] = password

    if not fields:
        raise ValueError("Nessun campo fornito per l'aggiornamento.")

    set_clause = ', '.join(f"{col} = ?" for col in fields.keys())
    values = list(fields.values()) + [account_id]

    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE accounts SET {set_clause} WHERE id = ?", values)
            conn.commit()
    except sqlite3.DatabaseError as e:
        raise sqlite3.DatabaseError(f"Errore durante l'aggiornamento dell'account: {e}")


def update_account_encryption(account_id: str, new_username: str, new_password: str) -> None:
    """
    Updates the encrypted username and password of an account.

    This is used during the re-encryption phase when the user changes their passphrase.

    Args:
        account_id (str): The UUID of the account to update.
        new_username (str): The newly re-encrypted username/email (base64 string).
        new_password (str): The newly re-encrypted password (base64 string).

    Raises:
        sqlite3.DatabaseError: If a database error occurs.
    """
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE accounts SET username = ?, password = ? WHERE id = ?',
                (new_username, new_password, account_id)
            )
            conn.commit()
    except sqlite3.DatabaseError as e:
        raise sqlite3.DatabaseError(f"Errore durante l'aggiornamento della crittografia dell'account: {e}")


def update_user_passphrase(chat_id: int, new_salted_hash: str, new_salt: str) -> None:
    """
    Updates the passphrase hash and salt for a user.

    Called after a successful passphrase change and full re-encryption of all accounts.

    Args:
        chat_id (int): The Telegram chat ID identifying the user.
        new_salted_hash (str): The new PBKDF2 salted hash of the new passphrase.
        new_salt (str): The new hex-encoded salt.

    Raises:
        sqlite3.DatabaseError: If a database error occurs.
    """
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET salted_hash = ?, salt = ? WHERE chat_id = ?',
                (new_salted_hash, new_salt, chat_id)
            )
            conn.commit()
    except sqlite3.DatabaseError as e:
        raise sqlite3.DatabaseError(f"Errore durante l'aggiornamento della passphrase utente: {e}")
