"""
Unit tests for NeoVault CLI functionality
Test command parsing, execution, and error handling
"""

import unittest
import tempfile
import os
import sys
import json
from unittest.mock import patch, MagicMock
from io import StringIO

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.cli.main import main, create_parser, get_password
from src.cli.commands import generate_password


class TestCLIParser(unittest.TestCase):
    """Test CLI argument parser functionality"""
    
    def setUp(self):
        self.parser = create_parser()
    
    def test_parser_creation(self):
        """Test that parser is created successfully"""
        self.assertIsNotNone(self.parser)
        self.assertEqual(self.parser.prog, 'main.py')
    
    def test_version_argument(self):
        """Test --version argument"""
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            with self.assertRaises(SystemExit) as cm:
                self.parser.parse_args(['--version'])
            self.assertEqual(cm.exception.code, 0)
    
    def test_help_argument(self):
        """Test --help argument"""
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            with self.assertRaises(SystemExit) as cm:
                self.parser.parse_args(['--help'])
            self.assertEqual(cm.exception.code, 0)
            output = mock_stdout.getvalue()
            self.assertIn('usage:', output)
            self.assertIn('commands:', output)
    
    def test_create_command_parsing(self):
        """Test create command argument parsing"""
        args = self.parser.parse_args(['create', 'test_nvault', '--description', 'Test vault'])
        self.assertEqual(args.command, 'create')
        self.assertEqual(args.vault_path, 'test_nvault')
        self.assertEqual(args.description, 'Test vault')
    
    def test_add_command_parsing(self):
        """Test add command argument parsing"""
        args = self.parser.parse_args([
            'add', 'test_entry', 
            '--content', 'secret content',
            '--vault', 'myvault.nvault',
            '--metadata', '{"type":"password"}'
        ])
        self.assertEqual(args.command, 'add')
        self.assertEqual(args.name, 'test_entry')
        self.assertEqual(args.content, 'secret content')
        self.assertEqual(args.vault, 'myvault.nvault')
        self.assertEqual(args.metadata, '{"type":"password"}')
    
    def test_list_command_parsing(self):
        """Test list command argument parsing"""
        # Basic list
        args = self.parser.parse_args(['list', '--vault', 'test.nvault'])
        self.assertEqual(args.command, 'list')
        self.assertEqual(args.vault, 'test.nvault')
        self.assertFalse(args.details)
        
        # List with details
        args = self.parser.parse_args(['list', '--vault', 'test.nvault', '--details'])
        self.assertEqual(args.command, 'list')
        self.assertEqual(args.vault, 'test.nvault')
        self.assertTrue(args.details)
    
    def test_generate_command_parsing(self):
        """Test generate command argument parsing"""
        # Default generate
        args = self.parser.parse_args(['generate'])
        self.assertEqual(args.command, 'generate')
        self.assertEqual(args.length, 16)
        self.assertFalse(args.no_symbols)
        
        # Generate with options
        args = self.parser.parse_args(['generate', '--length', '20', '--no-symbols'])
        self.assertEqual(args.command, 'generate')
        self.assertEqual(args.length, 20)
        self.assertTrue(args.no_symbols)


class TestCLIFunctions(unittest.TestCase):
    """Test individual CLI functions."""
    
    def test_generate_password_function(self):
        """Test password generator function."""
        # Test with symbols
        password = generate_password(length=12, use_symbols=True)
        self.assertEqual(len(password), 12)
        self.assertRegex(password, r'[a-z]')  # Has lowercase
        self.assertRegex(password, r'[A-Z]')  # Has uppercase
        self.assertRegex(password, r'[0-9]')  # Has digits
        self.assertRegex(password, r'[^a-zA-Z0-9]')  # Has symbols
        
        # Test without symbols
        password = generate_password(length=10, use_symbols=False)
        self.assertEqual(len(password), 10)
        self.assertRegex(password, r'[a-z]')
        self.assertRegex(password, r'[A-Z]')
        self.assertRegex(password, r'[0-9]')
        self.assertNotRegex(password, r'[^a-zA-Z0-9]')  # No symbols
    
    @patch('getpass.getpass')
    def test_get_password_function(self, mock_getpass):
        """Test secure password input function."""
        mock_getpass.return_value = 'testpassword123'
        result = get_password("Enter password: ")
        self.assertEqual(result, 'testpassword123')
        mock_getpass.assert_called_once_with("Enter password: ")


class TestCLICommandExecution(unittest.TestCase):
    """Test CLI command execution with mocked dependencies."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_vault = os.path.join(self.temp_dir, 'test_vault.nvault')
    
    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    @patch('src.cli.commands.create_vault')
    @patch('src.cli.main.get_password')
    def test_main_create_command(self, mock_get_password, mock_create_vault):
        """Test main function with create command."""
        mock_get_password.side_effect = ['TestPass123!', 'TestPass123!']
        mock_create_vault.return_value = True
        
        # Test successful creation
        result = main(['create', self.test_vault, '--description', 'Test vault'])
        self.assertEqual(result, 0)
        mock_create_vault.assert_called_once_with(
            vault_path=self.test_vault,
            password='TestPass123!',
            description='Test vault'
        )
    
    @patch('src.cli.commands.create_vault')
    @patch('src.cli.main.get_password')
    def test_main_create_password_mismatch(self, mock_get_password, mock_create_vault):
        """Test create command with password mismatch."""
        mock_get_password.side_effect = ['Password1', 'Password2']
        
        result = main(['create', self.test_vault])
        self.assertEqual(result, 1)  # Should fail
        mock_create_vault.assert_not_called()
    
    @patch('src.cli.commands.generate_password')
    def test_main_generate_command(self, mock_generate_password):
        """Test main function with generate command."""
        mock_generate_password.return_value = 'GeneratedPassword123!'
        
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = main(['generate', '--length', '20'])
            self.assertEqual(result, 0)
            output = mock_stdout.getvalue()
            self.assertIn('GeneratedPassword123!', output)
            mock_generate_password.assert_called_once_with(length=20, use_symbols=True)
    
    @patch('src.cli.commands.generate_password')
    def test_main_generate_no_symbols(self, mock_generate_password):
        """Test generate command with --no-symbols flag."""
        mock_generate_password.return_value = 'GeneratedPassword123'
        
        result = main(['generate', '--length', '16', '--no-symbols'])
        self.assertEqual(result, 0)
        mock_generate_password.assert_called_once_with(length=16, use_symbols=False)
    
    @patch('src.cli.commands.add_entry')
    @patch('src.cli.main.get_password')
    def test_main_add_command(self, mock_get_password, mock_add_entry):
        """Test main function with add command."""
        mock_get_password.return_value = 'TestPass123!'
        mock_add_entry.return_value = True
        
        result = main([
            'add', 'test_entry',
            '--content', 'secret data',
            '--vault', self.test_vault,
            '--metadata', '{"type":"password"}'
        ])
        self.assertEqual(result, 0)
        mock_add_entry.assert_called_once_with(
            vault_path=self.test_vault,
            password='TestPass123!',
            name='test_entry',
            content='secret data',
            file_path=None,
            metadata={'type': 'password'}
        )
    
    @patch('src.cli.commands.add_entry')
    @patch('src.cli.main.get_password')
    def test_main_add_invalid_metadata(self, mock_get_password, mock_add_entry):
        """Test add command with invalid JSON metadata."""
        mock_get_password.return_value = 'TestPass123!'
        
        result = main([
            'add', 'test_entry',
            '--vault', self.test_vault,
            '--metadata', '{invalid json'
        ])
        self.assertEqual(result, 1)  # Should fail due to invalid JSON
        mock_add_entry.assert_not_called()
    
    @patch('src.cli.commands.list_entries')
    @patch('src.cli.main.get_password')
    def test_main_list_command(self, mock_get_password, mock_list_entries):
        """Test main function with list command."""
        mock_get_password.return_value = 'TestPass123!'
        mock_list_entries.return_value = ['entry1', 'entry2']
        
        result = main(['list', '--vault', self.test_vault])
        self.assertEqual(result, 0)
        mock_list_entries.assert_called_once_with(
            vault_path=self.test_vault,
            password='TestPass123!',
            show_details=False
        )
    
    @patch('src.cli.commands.list_entries')
    @patch('src.cli.main.get_password')
    def test_main_list_with_details(self, mock_get_password, mock_list_entries):
        """Test list command with --details flag."""
        mock_get_password.return_value = 'TestPass123!'
        mock_list_entries.return_value = ['entry1', 'entry2']
        
        result = main(['list', '--vault', self.test_vault, '--details'])
        self.assertEqual(result, 0)
        mock_list_entries.assert_called_once_with(
            vault_path=self.test_vault,
            password='TestPass123!',
            show_details=True
        )
    
    @patch('src.cli.commands.search_entries')
    @patch('src.cli.main.get_password')
    def test_main_search_command(self, mock_get_password, mock_search_entries):
        """Test main function with search command."""
        mock_get_password.return_value = 'TestPass123!'
        mock_search_entries.return_value = []
        
        result = main(['search', 'test', '--vault', self.test_vault])
        self.assertEqual(result, 0)
        mock_search_entries.assert_called_once_with(
            vault_path=self.test_vault,
            password='TestPass123!',
            query='test',
            search_in_content=False
        )
    
    @patch('src.cli.commands.get_entry')
    @patch('src.cli.main.get_password')
    def test_main_get_command(self, mock_get_password, mock_get_entry):
        """Test main function with get command."""
        mock_get_password.return_value = 'TestPass123!'
        mock_get_entry.return_value = {'name': 'test_entry', 'content': 'secret'}
        
        result = main(['get', 'test_entry', '--vault', self.test_vault])
        self.assertEqual(result, 0)
        mock_get_entry.assert_called_once_with(
            vault_path=self.test_vault,
            password='TestPass123!',
            name='test_entry',
            show_password=False
        )
    
    @patch('src.cli.commands.remove_entry')
    @patch('src.cli.main.get_password')
    def test_main_remove_command(self, mock_get_password, mock_remove_entry):
        """Test main function with remove command."""
        mock_get_password.return_value = 'TestPass123!'
        mock_remove_entry.return_value = True
        
        result = main(['remove', 'test_entry', '--vault', self.test_vault, '--force'])
        self.assertEqual(result, 0)
        mock_remove_entry.assert_called_once_with(
            vault_path=self.test_vault,
            password='TestPass123!',
            name='test_entry',
            force=True
        )
    
    @patch('src.cli.commands.interactive_shell')
    def test_main_shell_command(self, mock_interactive_shell):
        """Test main function with shell command."""
        result = main(['shell', '--vault', self.test_vault])
        self.assertEqual(result, 0)
        mock_interactive_shell.assert_called_once_with(vault_path=self.test_vault)
    
    def test_main_no_arguments(self):
        """Test main function with no arguments (should show help)."""
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = main([])
            self.assertEqual(result, 0)
            output = mock_stdout.getvalue()
            self.assertIn('NeoVault CLI', output)
            self.assertIn('usage:', output)
    
    @patch('src.cli.commands.generate_password')
    def test_main_keyboard_interrupt(self, mock_generate_password):
        """Test handling of KeyboardInterrupt."""
        mock_generate_password.side_effect = KeyboardInterrupt()
        
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = main(['generate'])
            self.assertEqual(result, 130)  # SIGINT exit code
            output = mock_stdout.getvalue()
            self.assertIn('Operation cancelled', output)
    
    @patch('src.cli.commands.generate_password')
    def test_main_general_exception(self, mock_generate_password):
        """Test handling of general exceptions."""
        mock_generate_password.side_effect = Exception("Test error")
        
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = main(['generate'])
            self.assertEqual(result, 1)
            output = mock_stdout.getvalue()
            self.assertIn('Error:', output)
            self.assertIn('Test error', output)


class TestCLIErrorConditions(unittest.TestCase):
    """Test CLI error conditions and edge cases."""
    
    def test_invalid_command(self):
        """Test that invalid command returns help."""
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = main(['invalidcommand'])
            self.assertEqual(result, 0)  # Should show help, not crash
            output = mock_stdout.getvalue()
            self.assertIn('usage:', output)
    
    def test_missing_required_arguments(self):
        """Test commands with missing required arguments."""
        # Create without path
        with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
            with self.assertRaises(SystemExit):
                main(['create'])
        
        # Add without name
        with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
            with self.assertRaises(SystemExit):
                main(['add'])
        
        # Search without query
        with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
            with self.assertRaises(SystemExit):
                main(['search'])
        
        # Get without name
        with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
            with self.assertRaises(SystemExit):
                main(['get'])
        
        # Remove without name
        with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
            with self.assertRaises(SystemExit):
                main(['remove'])


if __name__ == '__main__':
    # Run tests
    print("Running CLI tests...")
    unittest.main(verbosity=2)
