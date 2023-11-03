import sqlite3
from typing import List, Tuple

from ..model.account import Account

DB_NAME = 'accounts.db'


def create_database():
    """
    Creates a database and sets up the necessary tables if they don't already exist.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Create a new table named 'accounts' if it doesn't already exist
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
    conn.close()


def insert_account(account: Account, chat_id: int):
    """
    Inserts a new account into the database.

    Args:
        account (Account): The account object to insert.
        chat_id (int): The chat_id to use as foreign key
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute('''
        INSERT INTO accounts (id, name, username, password, chat_id)
        VALUES (?, ?, ?, ?, ?)
        ''', (account.id, account.name, account.user_name, account.password, chat_id))

        conn.commit()
        conn.close()

    except sqlite3.IntegrityError:
        raise sqlite3.DatabaseError("Failed to insert account due to integrity constraints violation.")
    except sqlite3.OperationalError:
        raise sqlite3.DatabaseError("Failed to insert account due to an operational error.")
    except sqlite3.DatabaseError:
        raise sqlite3.DatabaseError("A database error occurred while trying to insert the account.")


def insert_user(chat_id: int, name: str, salted_hash: str, salt: str) -> None:
    """
    Inserts a new user into the database.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute('''
        INSERT INTO users (chat_id, name, salted_hash, salt)
        VALUES (?, ?, ?, ?)
        ''', (chat_id, name, salted_hash, salt))

        conn.commit()
        conn.close()

    except sqlite3.IntegrityError:
        raise sqlite3.DatabaseError("Failed to insert account due to integrity constraints violation.")
    except sqlite3.OperationalError:
        raise sqlite3.DatabaseError("Failed to insert account due to an operational error.")
    except sqlite3.DatabaseError:
        raise sqlite3.DatabaseError("A database error occurred while trying to insert the account.")


def is_account_name_present(account_name: str) -> bool:
    """
    Checks if a given account name is already present in the database.

    Args:
        account_name (str): The name of the account to check.

    Returns:
        bool: True if the account name is present, False otherwise.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
    SELECT 1 FROM accounts WHERE name = ?
    ''', (account_name,))

    result = cursor.fetchone()
    conn.close()

    return result is not None


def is_user_registered(chat_id: int) -> bool:
    """
        Checks if a given chat id is already present in the user table.

        Args:
            chat_id (int): The chat_id of the account to check.

        Returns:
            bool: True if the account name is present, False otherwise.
        """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
    SELECT 1 FROM users WHERE chat_id = ?
    ''', (chat_id,))

    result = cursor.fetchone()
    conn.close()

    return result is not None


def get_accounts_for_chat_id(chat_id: int, page: int = 0, page_size: int = 6) -> List[Account]:
    """
    Fetches a paginated list of accounts associated with a given chat_id.

    Args:
        chat_id (int): The chat ID to fetch accounts for.
        page (int): The page number (starting from 1).
        page_size (int): The number of accounts to retrieve per page.

    Returns:
        List[Tuple[str, str, str, str]]: A list of tuples, each representing an account.
        Each tuple contains (id, name, username, password).
    """
    offset = page * page_size  # Calculate the starting point based on the page number

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
    SELECT id, name, username, password
    FROM accounts
    WHERE chat_id = ?
    LIMIT ? OFFSET ?
    ''', (chat_id, page_size, offset))

    accounts = cursor.fetchall()
    conn.close()

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
    Get an account from a given account id
    
    :param account_id: The given account id
    :return: The account object 
    """
    conn = sqlite3.connect(DB_NAME)
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
    Get hash and salt generated from the user passphrase

    :param chat_id: The given chat_id
    :return: A tuple with the salted_hash and salt saved from the passphrase
    """
    conn = sqlite3.connect(DB_NAME)
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
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute('''
        DELETE FROM accounts WHERE id = ?
        ''', (account_id,))

        conn.commit()
        conn.close()
    except sqlite3.DatabaseError:
        raise sqlite3.DatabaseError("An error occurred while trying to delete the account.")
