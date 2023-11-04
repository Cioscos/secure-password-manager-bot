import os
from typing import Union, Optional, Dict

KEYRING: Dict[str, Optional[str]] = {
    'Telegram': None,
    'DevId': None
}


def keyring_initialize() -> Union[bool, None]:
    """
    Initialize the keyring.
    This functions load from decrypted partition the keys needed.

    :return: True if everything went fine, False otherwise.
    """
    root_path = os.environ.get('KEYRING')
    if root_path is None:
        ic('Root directory is not set')
        return None

    # Get the telegram token key
    with open(os.path.join(root_path, 'telegram.dat')) as file:
        KEYRING['Telegram'] = file.read().strip()
        ic("Telegram token read")

    # Get the dev chat id
    with open(os.path.join(root_path, 'dev_id.dat')) as file:
        KEYRING['DevId'] = file.read().strip()
        ic("DevId read")

    return True


def keyring_get(service: str) -> Union[str, None]:
    """
    Get the key related to a service from the keyring.

    :param service: The service which get the key.
    :return: The keyring in the keyring. None if it's not present.
    """
    if service not in KEYRING:
        ic('Key of service %s not found in keyring' % service)
        return None

    return KEYRING[service]
