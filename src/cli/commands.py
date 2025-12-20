
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



def generate_password(length: int = 16, use_symbols: bool = True) -> str:
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
    symbols = string.punctuation if use_symbols else ''

    # Ensure at least one from each required category
    all_chars = lowercase + uppercase + digits + symbols

    # Generate password
    password_chars = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
    ]

    if use_symbols:
        password_chars.append(secrets.choice(symbols))

    # Fill rest with random characters
    remaining = length - len(password_chars)
    password_chars.extend(secrets.choice(all_chars) for _ in range(remaining))

    # Shuffle to avoid predictable positions
    secrets.SystemRandom().shuffle(password_chars)

    return ''.join(password_chars)



def create_vault(vault_path: str, password: str, description: str = "My secure vault") -> bool:
    """
    Create a new encrypted vault.

    Args:
        vault_path to create vault file (e.g., 'secrets.nvault')
        password: Master password for the vault
        description: Description of the vault

    Returns:
        True if successful, False otherwise

    Example:
        create_vault("my_vault.nvault", "MyPassword123", ""Personal secrets)
    """
    try:
        # Import here to avoid circular imports
        from ..core import NeoVault

        # Create new vault
        vault = NeoVault(vault_path)
        vault.metadata['description'] = description

        # Save vault with encryption
        success = vault.save_vault(password, vault_path)

        if success:
            print(f"✅ Vault created: {vault_path}")
            print(f"   Description: {description}")
            print(f"   Entries: 0")
            return True
        else:
            print(f"❌ Failed to create vault: {vault_path}")
            return False
        
    except FileExistsError:
        print(f"❌ File already exists: {vault_path}")
        return False
    except PermissionError:
        print(f"❌ Permission denied: {vault_path}")
        return False
    except Exception as e:
        print(f"❌ Error creating vault: {str(e)}")
        return False



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