"""
Comprehensive unit tests for NeoVault vault functionality.
"""

import unittest
import tempfile
import os
import sys

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.core import NeoVault, VaultEntry


class TestVaultFunctionality(unittest.TestCase):
    """Test vault creation, management, and encryption."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_password = "TestMasterPassword123!"
        self.vault = NeoVault()
        
        # Add some test entries
        self.vault.add_entry(VaultEntry(
            "test_note",
            content="This is a test note",
            metadata={"type": "note", "category": "personal"}
        ))
        
        self.vault.add_entry(VaultEntry(
            "test_config",
            content="database_url=localhost:5432",
            metadata={"type": "config", "env": "development"}
        ))
    
    def test_entry_creation(self):
        """Test VaultEntry creation and properties."""
        # Test text entry
        text_entry = VaultEntry("text_entry", content="Some text content")
        self.assertEqual(text_entry.name, "text_entry")
        self.assertEqual(text_entry.content, "Some text content")
        self.assertIsNone(text_entry.file_path)
        self.assertIsInstance(text_entry.metadata, dict)
        
        # Test file entry
        file_entry = VaultEntry("file_entry", file_path="/path/to/file.txt")
        self.assertEqual(file_entry.name, "file_entry")
        self.assertEqual(file_entry.file_path, "/path/to/file.txt")
        self.assertIsNone(file_entry.content)
        
        # Test with metadata
        meta_entry = VaultEntry(
            "meta_entry", 
            content="data",
            metadata={"important": True, "tags": ["work", "urgent"]}
        )
        self.assertEqual(meta_entry.metadata["important"], True)
        self.assertEqual(meta_entry.metadata["tags"], ["work", "urgent"])
    
    def test_entry_validation(self):
        """Test that entries require either content or file_path."""
        with self.assertRaises(ValueError):
            VaultEntry("invalid_entry")  # No content or file_path
    
    def test_entry_serialization(self):
        """Test VaultEntry serialization/deserialization."""
        original = VaultEntry(
            "serializable",
            content="Test content",
            metadata={"key": "value", "number": 42}
        )
        
        # Convert to dict and back
        entry_dict = original.to_dict()
        restored = VaultEntry.from_dict(entry_dict)
        
        # Check all attributes match
        self.assertEqual(original.name, restored.name)
        self.assertEqual(original.content, restored.content)
        self.assertEqual(original.metadata, restored.metadata)
        self.assertEqual(original.created_at, restored.created_at)
    
    def test_vault_add_remove(self):
        """Test adding and removing entries from vault."""
        # Test successful add
        new_entry = VaultEntry("new_entry", content="New content")
        added = self.vault.add_entry(new_entry)
        self.assertTrue(added)
        self.assertIn("new_entry", self.vault.list_entries())
        self.assertEqual(self.vault.metadata['entry_count'], 3)
        
        # Test duplicate rejection
        duplicate = VaultEntry("new_entry", content="Different content")
        added_dup = self.vault.add_entry(duplicate)
        self.assertFalse(added_dup)
        self.assertEqual(self.vault.metadata['entry_count'], 3)
        
        # Test successful remove
        removed = self.vault.remove_entry("new_entry")
        self.assertTrue(removed)
        self.assertNotIn("new_entry", self.vault.list_entries())
        self.assertEqual(self.vault.metadata['entry_count'], 2)
        
        # Test remove non-existent
        removed_none = self.vault.remove_entry("non_existent")
        self.assertFalse(removed_none)
    
    def test_vault_retrieval(self):
        """Test getting entries from vault."""
        # Get existing entry
        entry = self.vault.get_entry("test_note")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.content, "This is a test note")
        
        # Get non-existent entry
        none_entry = self.vault.get_entry("does_not_exist")
        self.assertIsNone(none_entry)
    
    def test_vault_listing(self):
        """Test listing all entries."""
        entries = self.vault.list_entries()
        self.assertIsInstance(entries, list)
        self.assertEqual(len(entries), 2)
        self.assertIn("test_note", entries)
        self.assertIn("test_config", entries)
    
    def test_vault_search(self):
        """Test searching entries by name and metadata."""
        # Search by name (partial match)
        results = self.vault.search_entries("note")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].name, "test_note")
        
        # Search by name (exact match)
        results = self.vault.search_entries("test_note")
        self.assertEqual(len(results), 1)
        
        # Search by metadata value
        results = self.vault.search_entries("development")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].name, "test_config")
        
        # Search with no results
        results = self.vault.search_entries("nonexistent")
        self.assertEqual(len(results), 0)
    
    def test_vault_save_load(self):
        """Test saving and loading vault with encryption."""
        with tempfile.NamedTemporaryFile(suffix='.nvault', delete=False) as f:
            temp_path = f.name
        
        try:
            # Save vault
            saved = self.vault.save_vault(self.test_password, temp_path)
            self.assertTrue(saved)
            self.assertTrue(os.path.exists(temp_path))
            
            # Verify file is not plain text (should contain encrypted data markers)
            with open(temp_path, 'r') as f:
                content = f.read()
                self.assertIn('ciphertext', content)  # Should be encrypted JSON structure
                self.assertIn('salt', content)
            
            # Load into new vault
            new_vault = NeoVault()
            loaded = new_vault.load_vault(temp_path, self.test_password)
            self.assertTrue(loaded)
            
            # Verify all data matches
            self.assertEqual(len(new_vault.list_entries()), 2)
            
            original_note = self.vault.get_entry("test_note")
            loaded_note = new_vault.get_entry("test_note")
            self.assertEqual(original_note.content, loaded_note.content)
            self.assertEqual(original_note.metadata, loaded_note.metadata)
            
        finally:
            # Cleanup
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_wrong_password_fails(self):
        """Test that wrong password fails decryption."""
        with tempfile.NamedTemporaryFile(suffix='.nvault', delete=False) as f:
            temp_path = f.name
        
        try:
            # Save with correct password
            self.vault.save_vault(self.test_password, temp_path)
            
            # Try to load with wrong password
            wrong_vault = NeoVault()
            loaded = wrong_vault.load_vault(temp_path, "WrongPassword123!")
            
            self.assertFalse(loaded)
            self.assertEqual(len(wrong_vault.list_entries()), 0)
            
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_vault_info(self):
        """Test vault information retrieval."""
        info = self.vault.get_vault_info()
        
        self.assertIn('path', info)
        self.assertIn('metadata', info)
        self.assertIn('entry_count', info)
        self.assertIn('entries', info)
        
        self.assertEqual(info['entry_count'], 2)
        self.assertEqual(len(info['entries']), 2)
        
        # Check metadata structure
        metadata = info['metadata']
        self.assertIn('version', metadata)
        self.assertIn('created_at', metadata)
        self.assertIn('modified_at', metadata)
    
    def test_clear_vault(self):
        """Test clearing all entries from vault."""
        self.assertEqual(len(self.vault.list_entries()), 2)
        
        self.vault.clear_vault()
        
        self.assertEqual(len(self.vault.list_entries()), 0)
        self.assertEqual(self.vault.metadata['entry_count'], 0)


def run_vault_tests():
    """Run all vault tests and print results."""
    print("="*60)
    print("RUNNING FORMAL VAULT UNIT TESTS")
    print("="*60)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestVaultFunctionality)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("="*60)
    if result.wasSuccessful():
        print("✅ ALL VAULT UNIT TESTS PASSED!")
    else:
        print("❌ SOME TESTS FAILED")
    print("="*60)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    run_vault_tests()
    