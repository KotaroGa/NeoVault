
"""
NeoVault Core Module
Secure file Vault encryption engine.
"""
from .key_derivation import derive_key, generate_salt
from .crypto import (
    encrypt_data, decrypt_data,
    encrypt_to_json, decrypt_from_json
    # encrypt_file, decrypt_file # not implemented yet
)
from .vault import NeoVault, VaultEntry


__version__ = "0.2.0"
__all_ = [
    # Key derivation
    'derive_key',
    'generate_salt',

    # Cryptography
    'encrypt_data',
    'decrypt_data',
    'encrypt_to_json',
    'decrypt_from_json',
    # 'encrypt_file', not implemented yet
    # 'decrypt_file', not implemented yet

    # Vault
    'NeoVault',
    'VaultEntry'
]

# Initialize logging
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())
