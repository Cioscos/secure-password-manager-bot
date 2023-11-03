from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import hashlib
import base64


def store_passphrase_hash(passphrase: str) -> Tuple[str, str]:
    """
    Generate a salted hash of the passphrase and return the hash and salt.

    Args:
        passphrase (str): The user's passphrase.

    Returns:
        Tuple[str, str]: The salted hash and the salt.
    """
    salt = os.urandom(16).hex()  # Generate a unique salt for each user
    salted_hash = hashlib.pbkdf2_hmac('sha256', passphrase.encode('utf-8'), bytes.fromhex(salt), 100000).hex()
    return salted_hash, salt


def verify_passphrase(passphrase: str, salt: str, stored_hash: str) -> bool:
    """
    Verify if the provided passphrase matches the stored hash.

    Args:
        passphrase (str): The passphrase provided by the user.
        salt (str): The salt stored in the database.
        stored_hash (str): The salted hash stored in the database.

    Returns:
        bool: True if the passphrase is correct, False otherwise.
    """
    computed_hash = hashlib.pbkdf2_hmac('sha256', passphrase.encode('utf-8'), bytes.fromhex(salt), 100000).hex()
    return computed_hash == stored_hash


def derive_key(passphrase: str, salt_b64: str) -> bytes:
    """
    Derive an encryption key from the given passphrase.

    Args:
        passphrase (str): The user's passphrase.
        salt_b64 (str): A salt for the key derivation. If None, a new salt is generated.

    Returns:
        Tuple[bytes, bytes]: The derived key and the salt used for derivation.
    """
    # Decode the salt from base64 to bytes
    salt = base64.b64decode(salt_b64)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = kdf.derive(passphrase.encode())
    return key


def encrypt(data: str, key: bytes) -> str:
    """
    Encrypt the given data using the provided key.

    Args:
        data (str): Data to be encrypted.
        key (bytes): Encryption key.

    Returns:
        bytes: Encrypted data.
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()

    # Combine IV with encrypted data and encode as base64
    combined_data = iv + encrypted_data
    return base64.b64encode(combined_data).decode('utf-8')


def decrypt(encrypted_data_b64: str, key: bytes) -> str:
    """
    Decrypt the given encrypted data using the provided key.

    Args:
        encrypted_data (bytes): Data to be decrypted.
        key (bytes): Encryption key.

    Returns:
        str: Decrypted data.
    """
    try:
        combined_data = base64.b64decode(encrypted_data_b64)
        iv, ciphertext = combined_data[:16], combined_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data.decode()
    except UnicodeDecodeError:
        raise ValueError("Decryption failed due to invalid data or key.")
