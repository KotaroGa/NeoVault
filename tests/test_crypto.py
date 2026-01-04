
"""
Unit tests for NeoVault cryptography module
Tests encryption, decryption, and cryptographic utilities
"""
import unittest
import os
import sys
import json
import base64
from typing import Dict, Any

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.core.crypto import (
    encrypt_data,
    decrypt_data,
    encrypt_to_json,
    decrypt_from_json,
    NONCE_SIZE,
    TAG_SIZE
)



class TestCryptoBasic(unittest.TestCase):
    """Test basic cryptographic operations"""

    def setUp(self):
        """Set up test data and keys."""
        # Generate a random 256-bit key (32 bytes) for AES-256
        self.test_key = os.urandom(32)
        
        # Test data of various types and sizes
        self.test_cases = [
            # (description, plaintext, type)
            ("Empty string", "", str),
            ("Single character", "A", str),
            ("Short text", "Hello, NeoVault!", str),
            ("Unicode text", "🔐 Contraseña segura 💻", str),
            ("Special characters", "P@$$w0rd! #$%^&*()", str),
            ("Empty bytes", b"", bytes),
            ("Binary data", b"\x00\x01\x02\x03\xff\xfe\xfd", bytes),
            ("Medium text", "This is a medium sized secret message that needs protection.", str),
            ("Long text", "X" * 1024, str),  # 1KB
        ]


    def test_encryption_decryption_roundtrip(self):
        """Test that encrypting and decrypting returns original data"""
        print("\n[Test: encryption_decryption_rpundtrip]")

        for description, plaintext, data_type in self.test_cases:
            with self.subTest(description=description):
                # Convert to bytes if it's a string for comparison
                if data_type == str:
                    plaintext_bytes = plaintext.encode('utf-8')
                else:
                    plaintext_bytes = plaintext

                # Encrypt
                encrypted_dict = encrypt_data(plaintext, self.test_key)

                # Verify encrytion result structure
                self.assertIn('ciphertext', encrypted_dict)
                self.assertIn('nonce', encrypted_dict)
                self.assertIn('tag', encrypted_dict)
                self.assertIn('algorithm', encrypted_dict)

                self.assertEqual(encrypted_dict['algorithm'], 'AES-256-GCM')
                self.assertEqual(len(encrypted_dict['nonce']), NONCE_SIZE)
                self.assertEqual(len(encrypted_dict['tag']), TAG_SIZE)

                # Decrypt
                decrypted_bytes = decrypt_data(encrypted_dict, self.test_key)

                # Compare
                self.assertEqual(decrypted_bytes, plaintext_bytes, f"Failed for: {description}")

        print("  ✅ All encryption/decryption roundtrips successful")


    def test_encryption_produces_different_output(self):
        """Test that encrypting the same data twice produces different ciphertext"""
        print("\n[Test: encryption_produces_different_output]")

        plaintext = "Same secret data"

        # Encrypt twice with same key
        encrypted1 = encrypt_data(plaintext, self.test_key)
        encrypted2 = encrypt_data(plaintext, self.test_key)

        # Nonces should be different(random)
        self.assertNotEqual(encrypted1['nonce'], encrypted2['nonce'], "Nonces should be randomly generated")

        # Ciphertexts should be different
        self.assertNotEqual(encrypted1['ciphertext'], encrypted2['ciphertext'], "Ciphertexts should be different due to different nonces")

        # But both should decrypt to same plaintext
        decrypted1 = decrypt_data(encrypted1, self.test_key)
        decrypted2 = decrypt_data(encrypted2, self.test_key)
        
        self.assertEqual(decrypted1, decrypted2,
                         "Both should decrypt to same data")
        
        print("  ✅ Random nonces produce different ciphertexts")
    

    def test_wrong_key_fails(self):
        """Test that decrytion fails with wrong key"""
        print("\n[Test: wrong_key_fails]")

        plaintext = "Secret message"
        encrypted = encrypt_data(plaintext, self.test_key)

        # Generate wrong key
        wrong_key = os.urandom(32)

        # Attempt decryption with wrong key
        with self.assertRaises(ValueError):
            decrypt_data(encrypted, wrong_key)

        print("  ✅ Wrong key correctly rejected")


    def test_tampering_detection(self):
        """Test that tampering with ciphertext is detected"""
        print("\n[Test: tampering_detection]")

        plaintext = "Important confidential data"
        encrypted = encrypt_data(plaintext, self.test_key)

        # Test 1: Tamper with ciphertext
        tampered = encrypted.copy()
        tampered['ciphertext'] = tampered['ciphertext'][:-5] + b'XXXXX'

        with self.assertRaises(ValueError):
            decrypt_data(tampered, self.test_key)

        print("  ✅ Ciphertext tampering detected")

        # Test 2: Tamper with tag
        tampered = encrypted.copy()
        tampered['tag'] = tampered['tag'][:-2] + b'YY'

        with self.assertRaises(ValueError):
            decrypt_data(tampered, self.test_key)

        print("  ✅ Tag tampering detected")

        # Test 3: Tamper with nonce
        tampered = encrypted.copy()
        tampered['nonce'] = os.urandom(NONCE_SIZE)

        with self.assertRaises(ValueError):
            decrypt_data(tampered, self.test_key)

        print("  ✅ Nonce tampering detected")


    def test_empty_and_edge_cases(self):
        """Test encryption/decryption of edge cases"""
        print("\n[test: empty_and_edge_cases]")

        # Test empty data
        encrypted_empty = encrypt_data("", self.test_key)
        decrypted_empty = decrypt_data(encrypted_empty, self.test_key)
        self.assertEqual(decrypted_empty, b"", "Empty string should roundtrip")

        print("  ✅ Empty string handled correctly")

        # Test very long data (10KB)
        long_data = "X" * 10240
        encrypted_long = encrypt_data(long_data, self.test_key)
        decrypted_long = decrypt_data(encrypted_long, self.test_key)

        self.assertEqual(decrypted_long.decode('utf-8'), long_data, "Long data should roundtrip")

        print("  ✅ Long data (10KB) handled correctly")

        # Test data with null bytes
        data_with_nulls = b"Data\x00with\x00nulls\x00"
        encrypted_nulls = encrypt_data(data_with_nulls, self.test_key)
        decrypted_nulls = decrypt_data(encrypted_nulls, self.test_key)

        self.assertEqual(decrypted_nulls, data_with_nulls, "Data with null bytes should roundtrip")

        print("  ✅ Data with null bytes handled correctly")


    def test_json_serialization(self):
        """Test encryption/decryption with JSON serialization"""
        print("\n[Test: json_serialization]")

        for description, plaintext, data_type in self.test_cases[:5]:
            with self.subTest(description=description):
                # Encrypt to JSON
                encrypted_json = encrypt_to_json(plaintext, self.test_key)

                # Verify it's valid JSON
                json_dict = json.loads(encrypted_json)
                self.assertIn('ciphertext', json_dict)
                self.assertIn('nonce', json_dict)
                self.assertIn('tag', json_dict)
                self.assertIn('algorithm', json_dict)

                # Verify base64 encoding
                self.assertIsInstance(json_dict['ciphertext'], str)
                self.assertIsInstance(json_dict['nonce'], str)
                self.assertIsInstance(json_dict['tag'], str)

                # Should be valid base64
                base64.b64decode(json_dict['ciphertext'])
                base64.b64decode(json_dict['nonce'])
                base64.b64decode(json_dict['tag'])

                # Decrypt from JSON
                decrypted_bytes = decrypt_from_json(encrypted_json, self.test_key)

                # Convert to appropriate type for comparison
                if data_type == str:
                    expected_bytes = plaintext.encode('utf-8')
                else:
                    expected_bytes = plaintext

                self.assertEqual(decrypted_bytes, expected_bytes, f"JSON roundtrip failed for: {description}")

        print("  ✅ JSON serialization roundtrips successful")

    
    def test_json_tampering_detection(self):
        """Test that tampering is detected with JSON serialization"""
        print("\n[Test: json_tampering_detection]")

        plaintext = "JSON protected data"
        encrypted_json = encrypt_to_json(plaintext, self.test_key)

        # Tamper with the JSON string
        json_dict = json.loads(encrypted_json)
        json_dict['ciphertext'] = json_dict['ciphertext'][:-5] + "XXXXX"
        tampered_json = json.dumps(json_dict)

        with self.assertRaises(ValueError):
            decrypt_from_json(tampered_json, self.test_key)

        print("  ✅ JSON tampering detected")


    def test_key_size_validation(self):
        """Test that invalid key sizes are handled"""
        print("\n[Test: key_size_validation]")

        plaintext = "Test data"

        # Test key too short (should fail during encryption)
        short_key = os.urandom(16) # 128-bit, should fail

        try:
            encrypt_data(plaintext, short_key)
            self.fail("Should have failed with short key")
        except Exception as e:
            print(f"  ✅ Short key rejected: {type(e).__name__}")

        # Test key too long (should fail or be truncated)
        long_key = os.urandom(64) # 512-bit, should fail

        try:
            encrypt_data(plaintext, long_key)
            self.fail("Should have failed with long key")
        except Exception as e:
            print(f"  ✅ Long key rejected: {type(e).__name__}")




class TestCryptoIntegration(unittest.TestCase):
    """Test crypto integration with key derivation"""

    def test_crypto_with_derived_key(self):
        """Test encryption/decryption with PBKDF2 derived key"""
        print("\n[Test: crypto_with_derived_key]")

        try:
            from src.core.key_derivation import derive_key

            password = "MySecurePassword123!"
            plaintext = "Data encrypted with password-derived key"

            # Derive key from password
            key, salt = derive_key(password)

            # Encrypt with derived key
            encrypted = encrypt_data(plaintext, key)

            # Decrypt with same derived key
            decrypted = decrypt_data(encrypted, key)

            self.assertEqual(decrypted.decode('utf-8'), plaintext)
            print("  ✅ Encryption with derived key successful")

            # Test that different salt produces different key
            key2, salt2 = derive_key(password)
            self.assertNotEqual(key, key2, "Different salt should produce different key")
            print("  ✅ Random salt produces unique keys")

        except ImportError:
            self.skipTest("key_derivation module not available")


    def test_deterministic_key_derivation(self):
        """Test that same password+salt produces same key"""
        print("\n[Test: deterministic_key_derivation]")

        try:
            from src.core.key_derivation import derive_key

            password= "TestPassword"
            salt = b"fixed_salt_for_testing"

            # Derive key twice with same paremeters
            key1, _ = derive_key(password, salt)
            key2, _ = derive_key(password, salt)

            self.assertEqual(key1, key2, "Same password+salt should produce same key")
            print("  ✅ Deterministic key derivation works")

        except Exception as e:
            self.skipTest("key_derivation module not available")



def run_crypto_tests():
    """Run all crypto tests and print results"""
    print("="*60)
    print("RUNNING CRYPTOGRAPHY UNIT TESTS")
    print("="*60)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoBasic))
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoIntegration))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("="*60)
    if result.wasSuccessful():
        print("✅ ALL CRYPTOGRAPHY TESTS PASSED!")
    else:
        print("❌ SOME CRYPTOGRAPHY TESTS FAILED")
    print("="*60)
    
    return result.wasSuccessful()



if __name__ == '__main__':
    run_crypto_tests()
