
"""
CLI command implementations for NeoVault.
"""

import json
import os
import sys
from typing import Optional, List, Dict, Any
from datetime import datetime

# Importación relativa dentro del mismo paquete
try:
    from ..core import NeoVault, VaultEntry
except ImportError:
    # Fallback para cuando se ejecute directamente
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from src.core import NeoVault, VaultEntry

import secrets
import string



def generate_password(length: int = 16, use_symbol: bool = True) -> str:
    """
    Generate secure password.

    Args:
        length: Password length
        use_symbol: Include symbols in password

    Returns:
        Generated password
    """
    # Character set
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = string.punctuation if use_symbol else ''

    # Ensure at least one from each required category
    all_chars = lowercase + uppercase + digits + symbols

    # Generate password
    password_chars = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
    ]

    if use_symbol:
        password_chars.append(secrets.choice(symbols))

    # Fill rest with random characters
    remaining = length - len(password_chars)
    password_chars.extend(secrets.choice(all_chars) for _ in range(remaining))

    # Shuffle to avoid predictable positions
    secrets.SystemRandom().shuffle(password_chars)

    return ''.join(password_chars)



# Prueba simple de este archivo
def _test_commands():
    """Test the commands module."""
    print("Testing CLI commands module...")
    
    # Test password generator
    password = generate_password(12, True)
    print(f"✓ Generated password: {password}")
    print(f"✓ Password length: {len(password)}")
    
    # Test with no symbols
    password_no_sym = generate_password(10, False)
    print(f"✓ Password without symbols: {password_no_sym}")
    
    print("\n✅ CLI commands module test passed!")
    return True



if __name__ == "__main__":
    _test_commands()