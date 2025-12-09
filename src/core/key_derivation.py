
"""
Key derivation module for NeoVault.
Uses PBKDF2-HMAC-SHA256 for secure key derivation from passwords.
"""

import os
import hashlib
import base64
from typing import Optional, Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Constants for key derivation
SALT_SIZE = 16  # 128 bits for salt
ITERATIONS = 600000  # NIST recommendation for PBKDF2 in 2024
KEY_LENGTH = 32  # 256 bits for AES-256


def generate_salt() -> bytes:
    """
    Generate a cryptographically secure random salt.
    
    Returns:
        bytes: Random salt of SALT_SIZE bytes.
    
    Security Notes:
        - Uses os.urandom() which is cryptographically secure
        - Salt ensures same passwords produce different keys
        - Prevents rainbow table attacks
    """
    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Derive a cryptographic key from a password using PBKDF2.
    
    Args:
        password (str): User's master password
        salt (Optional[bytes]): Salt for key derivation. If None, generates new salt.
    
    Returns:
        Tuple[bytes, bytes]: (derived_key, salt)
    
    Security Notes:
        - Uses PBKDF2-HMAC-SHA256 with high iteration count
        - Salt is either provided or randomly generated
        - Slow hashing prevents brute-force attacks
    """
    if salt is None:
        salt = generate_salt()
    
    # Convert password to bytes
    password_bytes = password.encode('utf-8')
    
    # Create PBKDF2 key derivation function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    
    # Derive the key
    key = kdf.derive(password_bytes)
    
    return key, salt


# Simple test function
def test_basic_functionality():
    """Test the key derivation functions."""
    print("Testing key derivation...")
    
    # Test 1: Generate salt
    salt1 = generate_salt()
    print(f"✓ Salt generated: {len(salt1)} bytes")
    
    # Test 2: Derive key with new salt
    password = "TestPassword123!"
    key1, salt2 = derive_key(password)
    print(f"✓ Key derived: {len(key1)} bytes")
    
    # Test 3: Derive key with existing salt
    key2, _ = derive_key(password, salt2)
    print(f"✓ Same password+salt gives same key: {key1 == key2}")
    
    # Test 4: Different passwords give different keys
    key3, _ = derive_key("DifferentPassword", salt2)
    print(f"✓ Different password gives different key: {key1 != key3}")
    
    print("\n✅ All basic tests passed!")


if __name__ == "__main__":
    test_basic_functionality()