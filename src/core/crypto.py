
"""
Cryptography module for NeoVault.
Uses AES-256-GCM for authenticated encryption.
"""

import os
import json
from typing import Union, Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Constants
NONCE_SIZE = 12  # 96 bits recommended for GCM
TAG_SIZE = 16    # 128 bits for GCM authentication tag


def encrypt_data(plaintext: Union[str, bytes], key: bytes) -> Dict[str, Any]:
    """
    Encrypt data using AES-256-GCM.
    
    Args:
        plaintext: Data to encrypt (string or bytes)
        key: 256-bit encryption key
    
    Returns:
        dict: Dictionary containing ciphertext, nonce, and tag
    
    Security Notes:
        - Uses AES-256-GCM (authenticated encryption)
        - Random nonce for each encryption
        - Includes authentication tag to detect tampering
    """
    # Convert string to bytes if necessary
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode('utf-8')
    else:
        plaintext_bytes = plaintext
    
    # Generate random nonce (IV for GCM)
    nonce = os.urandom(NONCE_SIZE)
    
    # Create cipher object
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    
    # Encrypt the data
    encryptor = cipher.encryptor()
    
    # Pad the data (AES works with 16-byte blocks)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Get authentication tag
    tag = encryptor.tag
    
    return {
        'ciphertext': ciphertext,
        'nonce': nonce,
        'tag': tag,
        'algorithm': 'AES-256-GCM'
    }


def decrypt_data(encryption_result: Dict[str, Any], key: bytes) -> bytes:
    """
    Decrypt data using AES-256-GCM.
    
    Args:
        encryption_result: Dictionary from encrypt_data()
        key: 256-bit encryption key (same as used for encryption)
    
    Returns:
        bytes: Decrypted data
    
    Raises:
        ValueError: If authentication fails (tampering detected)
    """
    # Extract components
    ciphertext = encryption_result['ciphertext']
    nonce = encryption_result['nonce']
    tag = encryption_result['tag']
    
    # Create cipher object
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    
    # Decrypt the data
    decryptor = cipher.decryptor()
    
    try:
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}. Possible tampering detected.")


# Simple test function
def test_basic_encryption():
    """Test basic encryption and decryption."""
    print("Testing basic cryptography...")
    
    # Import here to avoid circular imports
    from .key_derivation import derive_key
    
    # Test 1: Basic string encryption
    password = "TestPassword"
    key, salt = derive_key(password)
    
    test_string = "Hello, NeoVault!"
    encrypted = encrypt_data(test_string, key)
    
    print(f"✓ String encrypted: {len(encrypted['ciphertext'])} bytes ciphertext")
    
    # Test 2: Decryption
    decrypted = decrypt_data(encrypted, key)
    decrypted_string = decrypted.decode('utf-8')
    
    print(f"✓ Decryption successful: {decrypted_string == test_string}")
    
    # Test 3: Tampering detection
    import copy
    tampered = copy.deepcopy(encrypted)
    tampered['ciphertext'] = tampered['ciphertext'][:-5] + b'xxxxx'
    
    try:
        decrypt_data(tampered, key)
        print("✗ Tampering not detected!")
    except ValueError as e:
        print(f"✓ Tampering detected: {str(e)[:50]}...")
    
    # Test 4: Bytes encryption
    test_bytes = b"Binary data \x00\x01\x02\x03"
    encrypted_bytes = encrypt_data(test_bytes, key)
    decrypted_bytes = decrypt_data(encrypted_bytes, key)
    
    print(f"✓ Bytes encryption: {test_bytes == decrypted_bytes}")
    
    print("\n✅ All crypto tests passed!")


if __name__ == "__main__":
    test_basic_encryption()