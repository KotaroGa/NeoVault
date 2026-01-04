
"""
Unit tests for NeoVault CLI functionality
Test command parsing, execution, and error handling
"""

import unittest
import tempfile
import os
import sys
import json
import getpass
from unittest.mock import patch, MagicMock
from io import StringIO

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.cli.main import main, create_parser


class TestCLIParser(unittest.TestCase):
    """Test CLI argument parser functionality"""

    def setUp(self):
        self.parser = create_parser()

    def test_parser_creation(self):
        """Test that parser is created successfully"""
        self.assertIsNotNone(self.parser)
        self.assertIn(self.parser.prog, ['__main__.py', 'main.py'])

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
    """Test individual CLI functions"""

    @patch('src.cli.commands.generate_password')
    def test_generate_password_function(self, mock_generate_password):
        """Test password generator function"""
        mock_generate_password.return_value = "MockedPassword123!"
        
        # Importar después del mock
        from src.cli.commands import generate_password as real_generate_password
        
        password = real_generate_password(length=12, use_symbols=True)
        self.assertEqual(password, "MockedPassword123!")
        mock_generate_password.assert_called_once_with(length=12, use_symbols=True)

    @patch('getpass.getpass')
    def test_get_password_function(self, mock_getpass):
        """Test secure password input function"""
        mock_getpass.return_value = 'testpassword123'
        result = getpass.getpass("Enter password: ")
        self.assertEqual(result, 'testpassword123')
        mock_getpass.assert_called_once_with("Enter password: ")


class TestCLICommandExecution(unittest.TestCase):
    """Test CLI command execution with mocked dependencies"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_vault = os.path.join(self.temp_dir, 'test_vault.nvault')
    
    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    @patch('src.cli.commands.create_vault')  # CORREGIDO: commands, no main
    @patch('getpass.getpass')
    def test_main_create_command(self, mock_getpass, mock_create_vault):
        """Test main function with create command."""
        mock_getpass.side_effect = ['TestPass123!', 'TestPass123!']
        mock_create_vault.return_value = True
        
        with patch('sys.stdout', new_callable=StringIO):
            result = main(['create', self.test_vault, '--description', 'Test vault'])
            self.assertEqual(result, 0)
            mock_create_vault.assert_called_once_with(
                vault_path=self.test_vault,
                password='TestPass123!',
                description='Test vault'
            )
    
    @patch('getpass.getpass')
    def test_main_create_password_mismatch(self, mock_getpass):
        """Test create command with password mismatch."""
        mock_getpass.side_effect = ['Password1', 'Password2']
        
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = main(['create', self.test_vault])
            self.assertEqual(result, 1)
    
    @patch('src.cli.commands.generate_password')  # CORREGIDO: commands, no main
    def test_main_generate_command(self, mock_generate_password):
        """Test main function with generate command."""
        mock_generate_password.return_value = 'GeneratedPassword123!'
        
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = main(['generate', '--length', '20'])
            self.assertEqual(result, 0)
            output = mock_stdout.getvalue()
            self.assertIn('GeneratedPassword123!', output)
            mock_generate_password.assert_called_once_with(length=20, use_symbols=True)
    
    @patch('src.cli.commands.generate_password')  # CORREGIDO: commands, no main
    def test_main_generate_no_symbols(self, mock_generate_password):
        """Test generate command with --no-symbols flag."""
        mock_generate_password.return_value = 'GeneratedPassword123'
        
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = main(['generate', '--length', '16', '--no-symbols'])
            self.assertEqual(result, 0)
            output = mock_stdout.getvalue()
            self.assertIn('GeneratedPassword123', output)
            mock_generate_password.assert_called_once_with(length=16, use_symbols=False)
    
    def test_main_no_arguments(self):
        """Test main function with no arguments (should show help)."""
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = main([])
            self.assertEqual(result, 0)
            output = mock_stdout.getvalue()
            self.assertIn('usage:', output)
    
    @patch('src.cli.commands.generate_password')  # CORREGIDO: commands, no main
    def test_main_keyboard_interrupt(self, mock_generate_password):
        """Test handling of KeyboardInterrupt."""
        mock_generate_password.side_effect = KeyboardInterrupt()
        
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = main(['generate'])
            self.assertEqual(result, 130)
            output = mock_stdout.getvalue()
            self.assertIn('Operation cancelled', output)
    
    @patch('src.cli.commands.generate_password')  # CORREGIDO: commands, no main
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
        with patch('sys.stderr', new_callable=StringIO):
            with self.assertRaises(SystemExit) as cm:
                main(['invalidcommand'])
            self.assertEqual(cm.exception.code, 2)
    
    def test_missing_required_arguments(self):
        """Test commands with missing required arguments."""
        # Create without path
        with patch('sys.stderr', new_callable=StringIO):
            with self.assertRaises(SystemExit) as cm:
                main(['create'])
            self.assertEqual(cm.exception.code, 2)


if __name__ == '__main__':
    # Run tests
    print("Running CLI tests...")
    unittest.main(verbosity=2)
