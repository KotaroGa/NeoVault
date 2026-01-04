
"""
Integration tests for NeoVault complete workflows.
Tests real vault operations with temporary files.
"""

import unittest
import tempfile
import os
import sys
from typing import cast, List, Dict, Any

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.cli.commands import create_vault, add_entry, list_entries, search_entries
from src.cli.commands import generate_password as generate_pwd_func # Avoid conflicts
from src.core import NeoVault, VaultEntry



class TestIntegrationWorkflows(unittest.TestCase):
    """Test complete workflows with real vault files"""
    
    def setUp(self):
        """Create temporary directory for test vaults"""
        self.temp_dir = tempfile.mkdtemp(prefix="neovault_test_")
        print(f"\n[Test directory: {self.temp_dir}]")
    

    def tearDown(self):
        """Clean up temporary directory"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    

    def test_vault_creation_and_basic_operations(self):
        """Test creating a vault and performing basic operations"""
        print("\n[Test: vault_creation_and_basic_operations]")
        
        # Create vault path
        vault_path = os.path.join(self.temp_dir, "test_vault.nvault")
        password = "SecureMasterPass123!"
        description = "Test integration vault"
        
        print(f"  • Vault path: {vault_path}")
        print(f"  • Password: {password}")
        
        # Create vault using CLI command
        success = create_vault(vault_path, password, description)
        self.assertTrue(success, "Vault creation should succeed")
        
        # Verify vault file was created
        self.assertTrue(os.path.exists(vault_path), "Vault file should exist")
        self.assertGreater(os.path.getsize(vault_path), 0, "Vault file should not be empty")
        
        print("  ✅ Vault created and file exists")
        
        # Add a text entry
        entry_name = "email_account"
        entry_content = "myemail@example.com"
        entry_metadata = {"type": "email", "service": "gmail"}
        
        add_success = add_entry(
            vault_path=vault_path,
            password=password,
            name=entry_name,
            content=entry_content,
            metadata=entry_metadata
        )
        
        self.assertTrue(add_success, "Should add text entry successfully")
        print("  ✅ Text entry added")
        
        # Add a password entry
        password_entry_name = "bank_password"
        generated_password = generate_pwd_func(length=20, use_symbols=True)
        
        add_success = add_entry(
            vault_path=vault_path,
            password=password,
            name=password_entry_name,
            content=generated_password,
            metadata={"type": "password", "account": "bank"}
        )
        
        self.assertTrue(add_success, "Should add password entry successfully")
        print("  ✅ Password entry added")
        
        # List entries (basic list)
        entries = list_entries(vault_path, password, show_details=False)
        self.assertIsNotNone(entries, "Should retrieve entries list")
        
        # Cast para type checking
        entries_list = cast(List[str], entries)
        self.assertEqual(len(entries_list), 2, "Should have 2 entries")
        
        expected_entries = [entry_name, password_entry_name]
        for expected in expected_entries:
            self.assertIn(expected, entries_list, f"Should contain {expected}")
        
        print(f"  ✅ List entries: {entries_list}")
        
        # List entries with details
        detailed_entries = list_entries(vault_path, password, show_details=True)
        self.assertIsNotNone(detailed_entries, "Should retrieve detailed entries")
        print("  ✅ Detailed list works")
        
        # Search for entries
        search_results = search_entries(
            vault_path=vault_path,
            password=password,
            query="email",
            search_in_content=False
        )
        
        self.assertIsNotNone(search_results, "Search should return results")
        
        # Cast para type checking
        search_results_list = cast(List[Dict[str, Any]], search_results)
        self.assertEqual(len(search_results_list), 1, "Should find 1 email entry")
        
        if search_results_list:
            self.assertEqual(search_results_list[0]['name'], entry_name, "Should find email entry")
        
        print("  ✅ Search functionality works")
        
        # Test vault loading directly with NeoVault class
        vault = NeoVault()
        load_success = vault.load_vault(vault_path, password)
        self.assertTrue(load_success, "Should load vault with NeoVault class")
        
        # Verify entries are loaded correctly
        loaded_entries = vault.list_entries()
        self.assertEqual(len(loaded_entries), 2, "NeoVault should load 2 entries")
        
        # Verify specific entry content
        email_entry = vault.get_entry(entry_name)
        self.assertIsNotNone(email_entry, "Should retrieve email entry")
        
        # Cast para type checking
        email_entry_obj = cast(VaultEntry, email_entry)
        self.assertEqual(email_entry_obj.content, entry_content, "Entry content should match")
        
        print("  ✅ Direct NeoVault loading works")
        print("  ✅ All integration tests passed!")



if __name__ == '__main__':
    print("=" * 60)
    print("RUNNING NEOVAULT INTEGRATION TESTS")
    print("=" * 60)
    unittest.main(verbosity=2)
