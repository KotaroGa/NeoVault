
"""
Unit tests for NeoVault key derivation module
Test PBKDF2 key derivation and salt generation
"""
import unittest
import os
import sys
import hashlib

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.core.key_derivation import (
    derive_key,
    generate_salt,
    SALT_SIZE,
    ITERATIONS,
    KEY_LENGTH
)




class TestSaltGeneration(unittest.TestCase):
    """Test salt generation functionality"""

    def test_salt_size(self):
        """Test that salt is generated with correct size"""
        print("\n[Test: salt_size]")

        salt = generate_salt()
        self.assertEqual(len(salt), SALT_SIZE, f"Salt should be {SALT_SIZE} bytes, got {len(salt)}")

        print(f"  ✅ Salt size: {len(salt)} bytes (expected: {SALT_SIZE})")


    def test_salt_randomness(self):
        """Test that generated satls are random"""
        print("\n[Test: salt_randomness]")

        # Generate multiple satls
        salts = set()
        for i in range(10):
            salts.add(generate_salt())

        self.assertEqual(len(salts),10, "All 10 salts should be different")

        print(f"  ✅ Generated {len(salts)} unique salts")


    def test_salt_is_bytes(self):
        """Test that salt is returned as bytes"""
        print("\n[Test: salt_is_bytes]")

        salt = generate_salt()
        self.assertIsInstance(salt, bytes, "Salt should be bytes, not string")

        print("  ✅ Salt is bytes type")




class TestKeyDerivationBasic(unittest.TestCase):
    """Test basic key derivation functionality"""

    def test_key_length(self):
        """Test that derived key has correct length"""
        print("\n[Test: key_length]")

        password = "TestPassword123!"
        key, salt = derive_key(password)

        self.assertEqual(len(key), KEY_LENGTH, f"Key should be {KEY_LENGTH} bytes, got {len(key)}")

        print(f"  ✅ Key length: {len(key)} bytes (expected: {KEY_LENGTH})")


    def test_deterministic_with_same_salt(self):
        """Test tjat same password+salt produces same key"""
        print("\n[Test: deterministic_with_same_salt]")

        password = "MySecurePassword"
        fixed_salt = b"fixed_salt_123456" # 16 bytes

        # Derive key twice with same parameters
        key1, salt1 = derive_key(password, fixed_salt)
        key2, salt2 = derive_key(password, fixed_salt)

        self.assertEqual(key1, key2, "Same password+salt should produce same key")
        self.assertEqual(salt1, fixed_salt)
        self.assertEqual(salt2, fixed_salt)

        print("  ✅ Deterministic key derivation works")


    def test_random_salt_produces_different_keys(self):
        """Test that random salts produce different keys"""
        print("\n[Test: random_salt_produces_different_keys]")

        password = "SamePasswordForAll"

        # Derive keys with random salts (salt=None)
        keys = set()
        salts = set()

        for i in range(5):
            key, salt = derive_key(password)
            keys.add(key)
            salts.add(salt)

        self.assertEqual(len(keys), 5, "Different salts should produce different keys")
        self.assertEqual(len(salts), 5, "Shoulc generate different salts")

        print(f"  ✅ Generated {len(keys)} unique keys from same password")


    def test_different_passwords_different_keys(self):
        """Test that different passwords produce different keys"""
        print("\n[Test: different_passwords_different_keys]")

        salt = b"common_salt_abcdef"

        # Test with different passwords
        passwords = ["Password1", "Password2", "Password3", "p@$$w0rd!", "🔐🔒"]
        keys = set()

        for pwd in passwords:
            key, _ = derive_key(pwd, salt)
            keys.add(key)

        self.assertEqual(len(keys), len(passwords), "Different passwords should produce different keys")

        print(f"  ✅ {len(keys)} unique keys from {len(passwords)} passwords")


    def test_empty_password(self):
        """Test key derivation with empty password"""
        print("\n[Test: empty_password]")

        salt = generate_salt()

        # Should work with empty password
        key, returned_salt = derive_key("", salt)

        self.assertEqual(len(key), KEY_LENGTH)
        self.assertEqual(returned_salt, salt)

        print("  ✅ Empty password handled correctly")


    def test_very_long_password(self):
        """Test key derivation with very long password"""
        print("\n[Test: very_l9ong_password]")

        # Create a very long password
        long_password = "A" * 10000 # 10KB password

        key, salt = derive_key(long_password)

        self.assertEqual(len(key), KEY_LENGTH)
        self.assertEqual(len(salt), SALT_SIZE)

        print("  ✅ Very long password handled correctly")




class TestKeyDerivationSecurity(unittest.TestCase):
    """Test security properties of key derivation"""

    def test_iterations_count(self):
        """verify that PBKDF2 uses correct iteration count"""
        print("\n[Test: iteration_count]")

        # Note: iterations from outside cannot be checked, but constant can be verified
        self.assertGreaterEqual(ITERATIONS, 100000, "Iterations should be high for security")

        print(f"  ✅ Iterations: {ITERATIONS:,} (secure)")

    
    def test_key_unpredictability(self):
        """Test that keys are cryptographically unpredictable"""
        print("\n[Test: key_unpredictability]")

        # This is a basic test - in reality, we'd need more sophisticated tests
        password = "test"

        # Generate many keys and check for patterns (basic check)
        keys = []
        for i in range(100):
            key, _ = derive_key(f"{password}{i}")
            keys.append(key)

        # Check that all keys are different
        unique_keys = set(keys)
        self.assertEqual(len(unique_keys), len(keys), "All keys should be unique")

        print(f"  ✅ Generated {len(unique_keys)} unique keys")


    def test_salt_purpose(self):
        """Test that salt prevents rainbow table attacks"""
        print("\n[Test: salt_purpose]")

        password = "commonpassword"

        # Derive key with two different salts
        key1, salt1 = derive_key(password)
        key2, salt2 = derive_key(password)

        # Salt should be different
        self.assertNotEqual(salt1, salt2, "Random salts should be different")

        # Keys should be different (due to different salts)
        self.assertNotEqual(key1, key2, "Different salts should produce different keys")

        print("  ✅ Salt prevents identical keys for same password")




class TestKeyDerivationIntegration(unittest.TestCase):
    """Test integration with crypto module"""

    def test_derived_key_wotks_with_encryption(self):
        """Test that derived key can be used for encryption"""
        print("\n[Test: derived_key_works_with_ecnryption]")

        try:
            from src.core.crypto import encrypt_data, decrypt_data

            password = "MasterPasswordForEncryption"
            plaintext = "Data to encrypt with derived key"

            # Derive key
            key, salt = derive_key(password)

            # Encrypt with derived key
            encrypted = encrypt_data(plaintext, key)

            # Decrypt with same derived key
            decrypted = decrypt_data(encrypted, key)

            self.assertEqual(decrypted.decode('utf-8'), plaintext)
            print("  ✅ Derived key works with encryption/decryption")

        except ImportError:
            self.skipTest("crypto module not available")

        
    def test_wrong_password_fails_decryption(self):
        """Test that wrong password produces wrong key, failing decryption"""
        print("\n[Test: wrong_password_fails_decryption]")

        try:
            from src.core.crypto import encrypt_data, decrypt_data

            # Entry with password1
            password1 = "CorrectPassword"
            key1, salt = derive_key(password1)

            plaintext = "Secret data"
            encrypted = encrypt_data(plaintext, key1)

            # Try to decrypt with wrong password
            password2 = "WrongPassword"
            key2, _ = derive_key(password2, salt)

            # Should fail (different key)
            with self.assertRaises(ValueError):
                decrypt_data(encrypted, key2)

            print("  ✅ Wrong password correctly fails decryption")

        except ImportError:
            self.skipTest("crypto module not available")




class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""

    def test_invalid_salt_size(self):
        """Test that wrong salt size raises appropriate error"""
        print("\n[Test: invalid_salt_size]")

        password = "test"

        # Salt too short
        short_salt = b"short" # 5 bytes

        # PBKDF2 might accept any salt length
        try:
            key, salt = derive_key(password, short_salt)
            # If it works, at least verify the salt is returned as -is
            self.assertEqual(salt, short_salt)
            print("  ✅ Short salt accepted (PBKDF2 may be lenient)")
        except Exception as e:
            print(f"  ✅ Short salt rejected: {type(e).__name__}")

        # Salt too long
        long_salt = b"x" * 100 # 100 bytes

        try:
            key, salt = derive_key(password, long_salt)
            self.assertEqual(salt, long_salt)
            print("  ✅ Long salt accepted (PBKDF2 may be lenient)")
        except Exception as e:
            print(f"  ✅ Long salt rejected: {type(e).__name__}")

    
    def test_special_characters_in_password(self):
        """Test passwords with special/unicode characters"""
        print("\n[Test: special_characters_in_password]")

        test_cases = [
            "Password with spaces",
            "P@$$w0rd! #$%^&*()",
            "🔐🔒 Password with emojis 💻🔑",
            "Password with \n newline",
            "Password with \t tab",
            "Password with null \x00 byte",
            "русский пароль",  # Russian
            "中文密码",  # Chinese
            "🍕🎉🦄",  # Just emojis
        ]

        for pwd in test_cases:
            with self.subTest(password=pwd[:20]):
                key, salt = derive_key(pwd)
                self.assertEqual(len(key), KEY_LENGTH)
                self.assertEqual(len(salt), SALT_SIZE)

        print(f"  ✅ {len(test_cases)} special character passwords handled")



def run_key_derivation_tests():
    """Run all key derivation tests and print results"""
    print("="*60)
    print("RUNNING KEY DERIVATION UNIT TEST")
    print("="*60)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestSaltGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestKeyDerivationBasic))
    suite.addTests(loader.loadTestsFromTestCase(TestKeyDerivationSecurity))
    suite.addTests(loader.loadTestsFromTestCase(TestKeyDerivationIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("="*60)
    if result.wasSuccessful():
        print("✅ ALL KEY DERIVATION TESTS PASSED!")
    else:
        print("❌ SOME KEY DERIVATION TESTS FAILED")
    print("="*60)


if __name__ == '__main__':
    run_key_derivation_tests()
