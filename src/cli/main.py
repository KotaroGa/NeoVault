
"""
Main CLI entry point for NeoVault.
Provides command-line interface for vault operations.
"""

import sys
import os
import argparse
from typing import Optional

# Configurar path para importaciones ANTES de cualquier import relativa
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(current_dir)  # Sube de cli/ a src/
project_root = os.path.dirname(src_dir)  # Sube de src/ a proyecto/

# Añadir ambos al path de Python
for path in [src_dir, project_root]:
    if path not in sys.path:
        sys.path.insert(0, path)

# AHORA importar desde src.cli
from src.cli.commands import generate_password


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for CLI"""
    parser = argparse.ArgumentParser(
        description="🔐 NeoVault CLI - Secure File Vault Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nvault create myvault.nvault            Create new vault
  nvault add password --content "secret"  Add password entry
  nvault list                             List all entries
  nvault shell                            Enter interactive mode

Matrix Edition - Encryption Enabled
        """
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version='NeoVault CLI v0.3.0'
    )

    # Create subparsers for commands
    subparsers = parser.add_subparsers(
        title='commands',
        dest='command',
        help='Available commands'
    )

    # Create vault commands
    create_parser = subparsers.add_parser(
        'create',
        help='Create a new encrypted vault'
    )
    create_parser.add_argument(
        'vault_path',
        help='Path to create vault file (e.g., secrets.nvault)'
    )
    create_parser.add_argument(
        '--description',
        default='My secure vault',
        help='Description for the vault'
    )

    # Add entry command
    add_parser = subparsers.add_parser(
        'add',
        help='Add a new entry to vault'
    )
    add_parser.add_argument(
        'name',
        help='Name of the entry'
    )
    add_parser.add_argument(
        '--content',
        help='Text content for the entry'
    )
    add_parser.add_argument(
        '--file',
        help='File to reference (instead of content)'
    )
    add_parser.add_argument(
        '--metadata',
        help='Metadata as JSON string (e.g., \'{"type":"password"}\')'
    )
    add_parser.add_argument(
        '--vault',
        default='vault.nvault',
        help='Vault file path (default: vault.nvault)'
    )

    # List entries command
    list_parser = subparsers.add_parser(
        'list',
        help='List all entries in vault'
    )
    list_parser.add_argument(
        '--vault',
        default='vault.nvault',
        help='Vault file path (default: vault.nvault)'
    )

    # Search entries command
    search_parser = subparsers.add_parser(
        'search',
        help='Search entries in vault'
    )
    search_parser.add_argument(
        'query',
        help='Search query'
    )
    search_parser.add_argument(
        '--vault',
        default='vault.nvault',
        help='Vault file path (default: vault.nvault)'
    )

    # Get entry command
    get_parser = subparsers.add_parser(
        'get',
        help='Get specific entry from vault'
    )
    get_parser.add_argument(
        'name',
        help='Name of entry to retrieve'
    )
    get_parser.add_argument(
        '--vault',
        default='vault.nvault',
        help='Vault file path (default: vault.nvault)'
    )

    # Remove entry command
    remove_parser = subparsers.add_parser(
        'remove',
        help='Remove entry from vault'
    )
    remove_parser.add_argument(
        'name',
        help='Name of entry to remove'
    )
    remove_parser.add_argument(
        '--vault',
        default='vault.nvault',
        help='Vault file path (default: vault.nvault)'
    )

    # Generate password command
    generate_parser = subparsers.add_parser(
        'generate',
        help='Generate secure password'
    )
    generate_parser.add_argument(
        '--length',
        type=int,
        default=16,
        help='Password length (default: 16)'
    )
    generate_parser.add_argument(
        '--no-symbols',
        action='store_true',
        help='Exclude symbols from password'
    )

    # Interactive shell command
    shell_parser = subparsers.add_parser(
        'shell',
        help='Enter interactive shell mode'
    )
    shell_parser.add_argument(
        '--vault',
        default='vault.nvault',
        help='Vault file path (default: vault.nvault)'
    )

    return parser


def get_password(prompt: str = "Enter master password: ") -> str:
    """Get password from user securely"""
    import getpass
    return getpass.getpass(prompt)


def print_banner():
    """Print NeoVault banner"""
    banner = """
    ╔═══════════════════════════════════════╗
    ║        🔐 NEOVAULT CLI v0.3.0         ║
    ║    Secure File Vault - Matrix Edition ║
    ╚═══════════════════════════════════════╝
    """
    print(banner)


def main(args: Optional[list] = None) -> int:
    """Main CLI entry point."""
    if args is None:
        args = sys.argv[1:]

    parser = create_parser()

    if not args:
        print_banner()
        parser.print_help()
        return 0
    
    try:
        parsed_args = parser.parse_args(args)

        # Handle commands
        if parsed_args.command == 'generate':
            password = generate_password(
                length=parsed_args.length,
                use_symbols=not parsed_args.no_symbols
            )
            print(f"🔑 Generated password: {password}")
            return 0
        
        elif parsed_args.command:
            # For other commands, we'll implement them later
            print(f"Command '{parsed_args.command}' will be implemented in the next step")
            print("Current available command: 'generate'")
            return 0
        
        else:
            parser.print_help()
            return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        return 130
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1


# Test function for this module
def _test_main():
    """Test the main CLI module."""
    print("Testing CLI main module...")

    # Test parser creation
    parser = create_parser()
    print("✓ Argument parser created successfully")

    # Test banner
    print_banner()
    print("✓ Banner prints without errors")
    
    # Test password input (simulated)
    print("✓ Password input function defined")
    
    # Test main function with help
    print("\nTesting --help flag:")
    result = main(["--help"])
    print(f"✓ Help command returned: {result}")
    
    print("\n✅ CLI main module test passed!")
    return True


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        _test_main()
    else:
        sys.exit(main())
