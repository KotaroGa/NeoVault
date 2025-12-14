
"""
NeoVault CLI Module
Command Line Interface for NeoVault secure file vault.
"""

__version__ = "0.3.0"

# These will be available when we implement the full commands
# from .commands import (
#     create_vault, add_entry, list_entries, search_entries,
#     remove_entry, get_entry, generate_password, interactive_shell
# )
# from .main import main

# __all__ = [
#     'main',
#     'create_vault',
#     'add_entry', 
#     'list_entries',
#     'search_entries',
#     'remove_entry',
#     'get_entry',
#     'generate_password',
#     'interactive_shell'
# ]

# Temporary exports for current functionality
from .commands import generate_password
from .main import main

__all__ = ['main', 'generate_password']
