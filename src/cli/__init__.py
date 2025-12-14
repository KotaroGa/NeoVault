
"""
NeoValut CLI Module
Command Line Interface for NeoVault secure file vault
"""

from .main import main
from .commands import (
    create_vault, add_entry, list_entries, search_entries,
    remove_entry, get_entry, export_vault, import_vault,
    generate_password, interactive_shell
)


__version__ = "0.3.0"
__all__ = [
    'main',
    'create_vault',
    'add_entry',
    'list_entries',
    'search_entries',
    'remove_entry',
    'get_entry',
    'export_vault',
    'import_vault',
    'generate_password',
    'interactive_shell'
]
