
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




def add_entry(vault_path: str, password: str, name: str, content: Optional[str] = None,
              file_path: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> bool:
    """
    Add a new entry to an existing vault.

    Args:
        vault_path: Path to vault file
        password: Master password
        name: unique name for the entry
        content: Text content (optional)
        file_path: Path to file (optiona, alternative to content)
        metadata: Additional metadata as dictionaty

    Returns:
        True if successful, False otherwise

    Example:
        add_entry('vault.nvault', 'password', 'email', content='my@email.com', metadata={'type': 'email'})
    """
    try:
        # Import here
        from ..core import NeoVault, VaultEntry

        # Load existing vault
        vault = NeoVault()
        if not vault.load_vault(vault_path, password):
            print(f"❌ Failed to load vault. Wrong password or corrupt file.")
            return False
        
        # Check if entry already exists
        if vault.get_entry(name):
            print(f"❌ Entry '{name}' already exists in vault")
            return False
        
        # Create and add entry
        entry = VaultEntry(
            name=name,
            content=content,
            file_path=file_path,
            metadata=metadata or {}
        )

        if not vault.add_entry(entry):
            print(f"❌ Failed to add entry '{name}'")
            return False
        
        # Save updated vault
        if vault.save_vault(password, vault_path):
            print(f"✅ Entry added: '{name}'")

            # Show entry
            if content:
                preview = content[:50] + ('...' if len(content) > 50 else '')
                print(f"  Content: {preview}")
            if file_path:
                print(f"  File: {file_path}")
            if metadata:
                print(f"  Metadata: {metadata}")

            return True
        else:
            print(f"❌ Failed to save vault after adding entry")
            return False

    except Exception as e:
        print(f"❌ Error adding entry: {str(e)}")
        return False



def list_entries(vault_path: str, password: str, show_details: bool = False) -> Optional[List[str]]:
    """
    List all entries in a vault.

    Args:
        vault_path: Path to vault file
        password: Master password
        show_details: If True, show entry details (content preview, metadata)

    Returns:
    List of entry names if successful, None on error

    Example:
        entries = list_entries('vault.nvault', 'password')
        # Returns: ['email', 'ssh_key_note', 'bank_account']
    """
    try:
        # Import here
        from ..core import NeoVault

        # Load vault
        vault = NeoVault()
        if not vault.load_vault(vault_path, password):
            print(f"❌ Failed to load vault. Wrong password or corrupt file.")
            return None
        
        # Get all entries
        entries = vault.list_entries()

        if not entries:
            print("📭 Vault is empty")
            return []
        
        # Display entries
        print(f"📋 Entries in vault ({len(entries)}):")

        if show_details:
            for i, entry_name in enumerate(entries, 1):
                entry = vault.get_entry(entry_name)
                if entry:
                    print(f"\n {i}. {entry_name}")
                    print(f"    Created: {entry.created_at[:10]}") # Just date

                    if entry.content:
                        preview = entry.content[:40]
                        if len(entry.content) > 40:
                            preview += "..."
                        print(f"     Content: {preview}")

                    if entry.file_path:
                        print(f"     File: {entry.file_path}")

                    if entry.metadata:
                        meta_str = ", ".join([f"{k}:{v}" for k, v in entry.metadata.items()])
                        print(f"     Metadata: {meta_str}")

        else:
            # SImple list
            for i, entry_name in enumerate(entries, 1):
                print(f"  {i}. {entry_name}") 

        return entries
    
    except Exception as e:
        print(f"❌ Error listing entries: {str(e)}")
        return None



def search_entries(vault_path: str, password: str, query: str, search_in_content: bool = False) -> Optional[List[Dict[str, Any]]]:
    """
    Search entries in a vault by name or metadata

    Args:
        vault_path: Path to vault file
        password: Master password
        query: Search term (case-insensitive)
        search_in_content: If True, also search in entry content

    Returns:
        List of matching entries with details, None or error

    Example:
        results = search_entries('vault.nvault', 'password', 'email')
        # Returns list of entries containing 'email' in name or metadata
    """
    try:
        # Import here
        from ..core import NeoVault

        # Load vault
        vault = NeoVault()
        if not vault.load_vault(vault_path, password):
            print(f"❌ Failed to load vault. Wrong password or corrupt file.")
            return None
        
        # Get all entries for searching
        all_entries = vault.list_entries()
        if not all_entries:
            print("📭 Vault is empty")
            return []
        
        query_lower = query.lower()
        matches = []

        # Search in each entry
        for entry_name in all_entries:
            entry = vault.get_entry(entry_name)
            if not entry:
                continue

            match_found = False

            # 1. Search in entry name
            if query_lower in entry.name.lower():
                match_found = True

            # 2. Search in metadata values (string values only)
            if not match_found and entry.metadata:
                for value in entry.metadata.values():
                    if isinstance(value, str) and query_lower in value.lower():
                        match_found = True
                        break

            # 3. Search in content (if enabled)
            if not match_found and search_in_content and entry.content:
                if query_lower in entry.content.lower():
                    match_found = True

            # Add to results if match found
            if match_found:
                matches.append({
                    'name': entry_name,
                    'content_preview': entry.content[:60] + '...' if entry.content and len(entry.content) > 60 else entry.content,
                    'file_path': entry.file_path,
                    'metadata': entry.metadata,
                    'created_at': entry.created_at,
                    'match_type': 'name' if query_lower in entry.name.lower() else
                                'metadata' if entry.metadata and any(
                                    isinstance(v, str) and query_lower in v.lower()
                                    for v in entry.metadata.values()
                                ) else 'content'
                })

        # Display resutls
        if matches:
            print(f"🔍 Search results for '{query}' ({len(matches)} matches):")

            for i, match in enumerate(matches, 1):
                print(f"\n  {i}. {match['name']}")
                print(f"     Match in: {match['match_type']}")
                print(f"     Created: {match['created_at'][:10]}")

                if match['content_preview']:
                    print(f"      Content: {match['content_preview']}")

                if match['metadata']:
                    meta_str = ", ".join([f"{k}:{v}" for k, v in match['metadata'].items()])
                    print(f"     Metadata: {meta_str}")
    
        else:
            print(f"🔍 No results found for '{query}'")
            if not search_in_content:
                print("   Tip: Use --content flag to search in entry content as well")

        return matches

    except Exception as e:
        print(f"❌ Error searching entries: {str(e)}")
        return None




def get_entry(vault_path: str, password: str, name: str, show_password: bool = False) -> Optional[Dict[str, Any]]:
    """
    Get detailed information about a specific entry.

    Args:
        vault_path: Path to vault file
        password: Master password+
        name: Name of entry to retrieve
        show_password: If True, show full content (useful for passwords)

    Returns:
        Dictionary with entry details if found, None otherwise

    Example:
        entry = get_entry('vault.nvault', 'password', 'email')
        # Returns detailed information about 'email' entry
    """
    try:
        # Import here
        from ..core import NeoVault

        # Load vault
        vault = NeoVault()
        if not vault.load_vault(vault_path, password):
            print(f"❌ Failed to load vault. Wrong password or corrupt file.")
            return None
        
        # Get the entry
        entry = vault.get_entry(name)
        if not entry:
            print(f"❌ Entry '{name}' not found in vault")
            # Suggest simular entries
            all_entries = vault.list_entries()
            if all_entries:
                print(f"    Available entries: {', '.join(all_entries)}")
            return None
        
        # Prepare entry details
        entry_details = {
            'name': entry.name,
            'content': entry.content if show_password else None,
            'content_preview': None,
            'file_path': entry.file_path,
            'metadata': entry.metadata,
            'created_at': entry.created_at,
            'modified_at': entry.modified_at,
            'exists': True
        }

        # Create content preview (masked if not showing password)
        if entry.content:
            if show_password:
                entry_details['content_preview'] = entry.content
            else:
                if len(entry.content) <= 20:
                    # For short content, show asterisks
                    entry_details['content_preview'] = '*' * len(entry.content)
                else:
                    # For longer content, show first and last chars
                    first_part = entry.content[:8]
                    last_part = entry.content[-4:] if len(entry.content) > 12 else ''
                    middle = '*' * max(3, len(entry.content) - 12)
                    entry_details['content_preview'] = f"{first_part}{middle}{last_part}"
        
        # Display entry information
        print(f"📄 Entry: {entry.name}")
        print(f"  Created:  {entry.created_at}")
        print(f"  Modified: {entry.modified_at}")

        if entry_details['content_preview']:
            print(f"    Content: {entry_details['content_preview']}")
            if not show_password and entry.content and len(entry.content) > 0:
                print(f"    Length:    {len(entry.content)} characters")

        if entry.file_path:
            print(f"   File:   {entry.file_path}")

        if entry.metadata:
            print(f"  Metadata:")
            for key, value in entry.metadata.items():
                print(f"   {key}: {value}")

        # Security note if content is hidden
        if entry.content and not show_password:
            print(f"\n  🔒 Content is hidden. Use --show flag to reveal.")

        return entry_details
    
    except Exception as e:
        print(f"❌ Error retrieving entry: {str(e)}")
        return None



def remove_entry(vault_path: str, password: str, name: str, force: bool = False) -> bool:
    """
    Remove an entry from a vault.

    Args:
        vault_path: Path to vault file
        password: Master password
        name: Name of the entry to remove
        force: If True, skip confirmation prompt

    Returns:
        True if removed, False otherwise

    Example:
        remove_entry('vault.nvault', 'password', 'old_entry')
        # Removes 'old_entry' after confirmation
    """
    try:
        # Import here
        from ..core import NeoVault

        # Load vault
        vault = NeoVault()
        if not vault.load_vault(vault_path, password):
            print(f"❌ Failed to load vault. Wrong password or corrupt file.")
            return False
        
        # Check if entry exists
        entry = vault.get_entry(name)
        if not entry:
            print(f"❌ Entry '{name}' not found in vault")
            # Show available entries
            all_entries = vault.list_entries()
            if all_entries:
                print(f"    Available entries: {', '.join(all_entries[:5])}")
                if len(all_entries) > 5:
                    print(f"   ... and {len(all_entries) - 5} more")
            return False
        
        # Show entry info before removal
        print(f"🗑️  Entry to remove: {name}")
        print(f"   Created:  {entry.created_at[:10]}")

        if entry.metadata:
            meta_str = ", ".join([f"{k}:{v}" for k, v in entry.metadata.items()][:3])
            print(f"    Metadata: {meta_str}")

        # Confirmation (unless forced)
        if not force:
            try:
                response = input(f"\n⚠️  Are you sure you want to remove '{name}'? (y/N): ").strip().lower()
                if response not in ['y', 'yes']:
                    print("❌ Removal cancelled")
                    return False
            except KeyboardInterrupt:
                print("\n❌ Removal cancelled by user")
                return False
            
        # Remove the entry
        if vault.remove_entry(name):
            # Save the update vault
            if vault.save_vault(password, vault_path):
                print(f"✅ Entry '{name}' removed successfully")
                print(f"   Remaining entries: {len(vault.list_entries())}")
                return True
            else:
                print(f"❌ Failed to save vault after removal")
                return False
        else:
            print(f"❌ Failed to remove entry '{name}'")
            return False
        
    except Exception as e:
        print(f"❌ Error removing entry: {str(e)}")
        return False
                    


def interactive_shell(vault_path: str = "vault.nvault") -> None:
    """
    Start an interactive shell for NeoVault operations.

    Args:
        vault_path: Path to vault file (default: 'vault.nvault')

    Example:
        interactive_shell('my_vault.nvault')
        # Starts interactive session with the vault
    """
    print("\n" + "="*60)
    print("🔐 NEOVAULT INTERACTIVE SHELL")
    print("="*60)
    print("Type 'help' for commands, 'exit' to quit\n")

    #State
    vault = None
    password = None
    vault_loaded = False


    def print_prompt():
        """Print the shell prompt"""
        status = "🔓" if vault_loaded else "🔒"
        vault_name = vault_path.split('/')[-1] if '/' in vault_path else vault_path
        return f"{status} neo:{vault_name}> "
    

    def show_help():
        """Show available commands"""
        print("\nAvailable commands:")
        print("  login                          - Unlock vault with password")
        print("  logout                         - Lock the vault")
        print("  create                         - Create new vault (overwrites existing)")
        print("  add <name>                     - Add new entry")
        print("  list [--details]               - List all entries")
        print("  get <name> [--show]            - Get entry details")
        print("  search <query>                 - Search entries")
        print("  remove <name> [--force]        - Remove entry")
        print("  generate [--length N]          - Generate password")
        print("  info                           - Show vault information")
        print("  help                           - Show this help")
        print("  exit, quit                     - Exit shell")
        print("\nArguments in [brackets are optional]")
        print("Use --help with any command for more details")


    def parse_args(cmd_line: str):
        """Simple argument parser for shel commands"""
        parts = []
        current = []
        in_quotes = False
        quote_char = None

        for char in cmd_line:
            if char in ['"', "'"]:
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    if current:
                        parts.append(''.join(current))
                        current = []
                else:
                    current.append(char)
            elif char == ' ' and not in_quotes:
                if current:
                    parts.append(''.join(current))
                    current = []
            else:
                current.append(char)

        if current:
            parts.append(''.join(current))

        return parts
    
    # Main shell loop
    while True:
        try:
            # Get command
            cmd_line = input(print_prompt()).strip()

            if not cmd_line:
                continue

            # Parse command and arguments
            parts = parse_args(cmd_line)
            if not parts:
                continue

            command = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []

            # Handle commands
            if command in ['exit', 'quit', 'q']:
                print("Exiting NeoVault shell...")
                if vault_loaded:
                    print("Vault locked 🔒")
                break

            elif command in ['help', '?', 'h']:
                if vault_loaded:
                    print("⚠️  Already logged in. Use 'logout' first.")
                    continue

                from getpass import getpass
                password = getpass("Master password: ")

                try:
                    from ..core import NeoVault
                    vault = NeoVault()
                    if vault.load_vault(vault_path, password):
                        vault_loaded = True
                        print(f"✅ Vault unlocked: {vault_path}")
                        info = vault.get_vault_info()
                        print(f"   Entries: {info['entry_count']}")
                    else:
                        print("❌ Failed to load vault. Wrong password?")
                        password = None
                except Exception as e:
                    print(f"❌ Error: {e}")
                    vault = None
                    password = None

            elif command == 'logout':
                if not vault_loaded:
                    print("⚠️  Not logged in")
                else:
                    vault = None
                    password = None
                    vault_loaded = False
                    print("✅ Vault locked 🔒")

            elif command == 'create':
                if vault_loaded:
                    print("⚠️  Please logout first before creating new vault")
                    continue

                from getpass import getpass
                print(f"Creating new vault: {vault_path}")
                print("⚠️  WARNING: This will overwrite existing vault!")

                password1 = getpass("New master password: ")
                password2 = getpass("Confirmed password: ")

                if password1 != password2:
                    print("❌ Passwords do not match")
                    continue

                description = input("Vault description (optional): ").strip() or "My secure vault"

                if create_vault(vault_path, password1, description):
                    print(f"✅ Vault created successfully")
                    print("   Use 'login' to unlock it")
                else:
                    print("❌ Failed to create vault")

            elif command == 'add':
                if not vault_loaded:
                    print("⚠️  Please login first (use 'login' command)")
                    continue

                if password is None:
                    print("❌ Password not available. Please login again.")
                    continue

                if len(args) < 1:
                    print("Usage: add <entry_name>")
                    continue

                name = args[0]
                content = input(f"Content for '{name}': ").strip()

                metadata_str = input("Metadata as JSON (optional, e.g., {\"type\": \"password\"}): ").strip()
                metadata = {}
                if metadata_str:
                    try:
                        metadata = json.loads(metadata_str)
                    except json.JSONDecodeError:
                        print("❌ Invalid JSON. Using empty metadata.")

                if add_entry(vault_path, password, name, content, None, metadata):
                    print(f"✅ Entry '{name}' added")
                else:
                    print(f"❌ Failed to add entry '{name}'")

            elif command == 'list':
                if not vault_loaded:
                    print("⚠️  Please login first (use 'login' command)")
                    continue

                if password is None:
                    print("❌ Password not available. Please login again.")
                    continue

                show_details = '--details' in args or '--verbose' in args
                list_entries(vault_path, password, show_details)

            elif command == 'get':
                if not vault_loaded:
                    print("⚠️  Please login first (use 'login' command)")
                    continue

                if len(args) < 1:
                    print("Usage: get <entry_name> [--show]")
                    continue

                if password is None:
                    print("❌ Password not available. Please login again.")
                    continue

                name = args[0]
                show_password = '--show' in args or '--reveal' in args
                get_entry(vault_path, password, name, show_password)
            
            elif command == 'search':
                if not vault_loaded:
                    print("⚠️  Please login first (use 'login' command)")
                    continue
                
                if len(args) < 1:
                    print("Usage: search <query> [--content]")
                    continue

                if password is None:
                    print("❌ Password not available. Please login again.")
                    continue

                query = args[0]
                search_in_content = '--content' in args
                search_entries(vault_path, password, query, search_in_content)

            elif command == 'remove':
                if not vault_loaded:
                    print("⚠️  Please login first (use 'login' command)")
                    continue
                
                if len(args) < 1:
                    print("Usage: remove <entry_name> [--force]")
                    continue

                if password is None:
                    print("❌ Password not available. Please login again.")
                    continue

                name = args[0]
                force = '--force' in args or '-f' in args
                remove_entry(vault_path, password, name, force)
            
            elif command == 'generate':
                # Generate password doesn't require login
                length = 16
                use_symbols = True
                
                # Parse arguments
                for i, arg in enumerate(args):
                    if arg == '--length' and i + 1 < len(args):
                        try:
                            length = int(args[i + 1])
                        except ValueError:
                            print(f"❌ Invalid length: {args[i + 1]}")
                    elif arg == '--no-symbols':
                        use_symbols = False

                password_gen = generate_password(length, use_symbols)
                print(f"🔑 Generated password: {password_gen}")
                print(f"   Length: {length}, Symbols: {'Yes' if use_symbols else 'No'}")
            
            elif command == 'info':
                if not vault_loaded:
                    print("⚠️  Please login first (use 'login' command)")
                    continue

                if vault is None:
                    print("❌ Vault not loaded. Please login again.")
                    continue

                try:
                    info = vault.get_vault_info()
                    print(f"\n📊 Vault Information:")
                    print(f"  Path:     {info['path']}")
                    print(f"  Entries:  {info['entry_count']}")
                    print(f"  Created:  {info['metadata'].get('created_at', 'Unknown')}")
                    print(f"  Modified: {info['metadata'].get('modified_at', 'Unknown')}")
                    print(f"  Version:  {info['metadata'].get('version', 'Unknown')}")

                    if 'description' in info['metadata']:
                        print(f"  Description: {info['metadata']['description']}")
                except AttributeError as e:
                    print(f"❌ Error getting vault info: {e}")
                
            else:
                print(f"❌ Unknown command: {command}")
                print("   Type 'help' for available commands")

        except KeyboardInterrupt:
            print("\n\nUse 'exit' to quit the shell")
        except EOFError:
            print("\n\nExiting NeoVault shell...")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print("\n" + "="*60)
    print("Goodbye! 🔒")
    print("="*60)




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