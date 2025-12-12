"""
Vault structure module for NeoVault.
Manages the encrypted vault containing file metadata and secrets.
"""
import json
import base64
from datetime import datetime
from typing import Dict, Any, Optional, List


class VaultEntry:
    """
    Represents a single entry in the vault (a protected file/secret).
    
    Each entry can be:
    - A text secret (password, note, etc.)
    - A reference to an encrypted file
    - Any binary data
    """
    
    def __init__(self, name: str, 
                 file_path: Optional[str] = None, 
                 content: Optional[str] = None,
                 metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize a vault entry.
        
        Args:
            name: Unique name for the entry
            file_path: Path to file (if entry is a file)
            content: Direct content (if entry is a text secret)
            metadata: Additional metadata as key-value pairs
        """
        self.name = name
        self.file_path = file_path
        self.content = content
        self.metadata = metadata or {}
        
        # Set timestamps
        self.created_at = datetime.now().isoformat()
        self.modified_at = self.created_at
        
        # Validate that entry has either file_path or content
        if file_path is None and content is None:
            raise ValueError("VaultEntry must have either file_path or content")
    
    def update_modified_time(self) -> None:
        """Update the modification timestamp to current time."""
        self.modified_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert entry to dictionary for serialization.
        
        Returns:
            Dictionary representation of the entry
        """
        return {
            'name': self.name,
            'file_path': self.file_path,
            'content': self.content,
            'metadata': self.metadata,
            'created_at': self.created_at,
            'modified_at': self.modified_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VaultEntry':
        """
        Create a VaultEntry from a dictionary.
        
        Args:
            data: Dictionary with entry data
            
        Returns:
            New VaultEntry instance
        """
        entry = cls(
            name=data['name'],
            file_path=data.get('file_path'),
            content=data.get('content'),
            metadata=data.get('metadata', {})
        )
        # Override timestamps if present in data
        if 'created_at' in data:
            entry.created_at = data['created_at']
        if 'modified_at' in data:
            entry.modified_at = data['modified_at']
        
        return entry
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return (f"VaultEntry(name='{self.name}', "
                f"file_path={self.file_path}, "
                f"content_length={len(self.content) if self.content else 0}, "
                f"metadata_keys={len(self.metadata)})")


class NeoVault:
    """
    Main vault class managing all encrypted entries.
    
    The vault is a collection of VaultEntry objects that can be
    encrypted and saved as a single file.
    """
    
    VAULT_VERSION = "1.0"
    VAULT_EXTENSION = ".nvault"
    
    def __init__(self, vault_path: Optional[str] = None):
        """
        Initialize a NeoVault.
        
        Args:
            vault_path: Optional path to vault file
        """
        self.vault_path = vault_path
        self.entries: Dict[str, VaultEntry] = {}
        self.metadata = {
            'version': self.VAULT_VERSION,
            'created_at': datetime.now().isoformat(),
            'modified_at': datetime.now().isoformat(),
            'entry_count': 0,
            'description': 'NeoVault secure storage'
        }
    
    def add_entry(self, entry: VaultEntry) -> bool:
        """
        Add an entry to the vault.
        
        Args:
            entry: VaultEntry to add
            
        Returns:
            True if successful, False if entry with same name exists
        """
        if entry.name in self.entries:
            print(f"Warning: Entry '{entry.name}' already exists")
            return False
        
        self.entries[entry.name] = entry
        self._update_vault_metadata()
        return True
    
    def remove_entry(self, name: str) -> bool:
        """
        Remove an entry from the vault.
        
        Args:
            name: Name of entry to remove
            
        Returns:
            True if removed, False if not found
        """
        if name not in self.entries:
            print(f"Warning: Entry '{name}' not found")
            return False
        
        del self.entries[name]
        self._update_vault_metadata()
        return True
    
    def get_entry(self, name: str) -> Optional[VaultEntry]:
        """
        Get an entry by name.
        
        Args:
            name: Name of entry to retrieve
            
        Returns:
            VaultEntry if found, None otherwise
        """
        return self.entries.get(name)
    
    def list_entries(self) -> List[str]:
        """
        List all entry names in the vault.
        
        Returns:
            List of entry names
        """
        return list(self.entries.keys())
    
    def search_entries(self, query: str) -> List[VaultEntry]:
        """
        Search entries by name or metadata.
        
        Args:
            query: Search string (case-insensitive)
            
        Returns:
            List of matching VaultEntry objects
        """
        results = []
        query_lower = query.lower()
        
        for entry in self.entries.values():
            # Search in name
            if query_lower in entry.name.lower():
                results.append(entry)
                continue
            
            # Search in metadata values
            for value in entry.metadata.values():
                if isinstance(value, str) and query_lower in value.lower():
                    results.append(entry)
                    break
        
        return results
    
    def save_vault(self, password: str, output_path: Optional[str] = None) -> bool:
        """
        Save the vault encrypted with a password.
        
        Args:
            password: Master password for encryption
            output_path: Path to save vault (uses self.vault_path if None)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if output_path is None:
                output_path = self.vault_path
            
            if output_path is None:
                raise ValueError("No output path specified for vault")
            
            # Import here to avoid circular imports
            from .key_derivation import derive_key
            from .crypto import encrypt_to_json
            
            # Prepare vault data
            vault_data = {
                'metadata': self.metadata,
                'entries': {name: entry.to_dict() for name, entry in self.entries.items()}
            }
            
            # Convert to JSON
            vault_json = json.dumps(vault_data, indent=2)
            
            # Derive key and encrypt
            key, salt = derive_key(password)
            encrypted_vault = encrypt_to_json(vault_json, key)
            
            # Add salt to vault file
            vault_dict = json.loads(encrypted_vault)
            vault_dict['salt'] = base64.b64encode(salt).decode('utf-8')
            vault_dict['vault_info'] = {
                'version': self.VAULT_VERSION,
                'encryption': 'AES-256-GCM',
                'key_derivation': 'PBKDF2-HMAC-SHA256'
            }
            
            # Save to file
            with open(output_path, 'w') as f:
                json.dump(vault_dict, f, indent=2)
            
            self.vault_path = output_path
            return True
            
        except Exception as e:
            print(f"Error saving vault: {e}")
            return False
    
    def load_vault(self, vault_path: str, password: str) -> bool:
        """
        Load and decrypt a vault from file.
        
        Args:
            vault_path: Path to vault file
            password: Master password for decryption
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Import here to avoid circular imports
            from .key_derivation import derive_key
            from .crypto import decrypt_from_json
            
            # Read vault file
            with open(vault_path, 'r') as f:
                vault_dict = json.load(f)
            
            # Extract salt and encrypted data
            salt = base64.b64decode(vault_dict.pop('salt'))
            vault_info = vault_dict.pop('vault_info', {})
            
            # Derive key using password and salt
            key, _ = derive_key(password, salt)
            
            # Decrypt vault data
            encrypted_json = json.dumps(vault_dict)
            decrypted_data = decrypt_from_json(encrypted_json, key)
            
            # Parse vault data
            vault_data = json.loads(decrypted_data.decode('utf-8'))
            
            # Load metadata and entries
            self.metadata = vault_data['metadata']
            self.entries = {}
            
            for name, entry_dict in vault_data['entries'].items():
                self.entries[name] = VaultEntry.from_dict(entry_dict)
            
            self.vault_path = vault_path
            return True
            
        except Exception as e:
            print(f"Error loading vault: {e}")
            # Clear vault on error
            self.entries = {}
            self.metadata['entry_count'] = 0
            return False
    
    def _update_vault_metadata(self) -> None:
        """Update vault metadata after changes."""
        self.metadata['entry_count'] = len(self.entries)
        self.metadata['modified_at'] = datetime.now().isoformat()
    
    def get_vault_info(self) -> Dict[str, Any]:
        """
        Get information about the vault.
        
        Returns:
            Dictionary with vault information
        """
        return {
            'path': self.vault_path,
            'metadata': self.metadata.copy(),
            'entry_count': len(self.entries),
            'entries': list(self.entries.keys())
        }
    
    def clear_vault(self) -> None:
        """Clear all entries from the vault."""
        self.entries.clear()
        self._update_vault_metadata()
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return (f"NeoVault(entries={len(self.entries)}, "
                f"path={self.vault_path})")


def test_vault_complete():
    """Test complete vault functionality with debug information."""
    print("="*60)
    print("TESTING COMPLETE VAULT FUNCTIONALITY (WITH DEBUG)")
    print("="*60)
    
    import tempfile
    import os
    
    # Test 1: VaultEntry creation
    print("\n[1/5] Testing VaultEntry...")
    entry1 = VaultEntry("test_note", content="Secret note")
    entry2 = VaultEntry("test_file", file_path="/path/to/file.txt")
    
    print(f"  ✓ Text entry: {entry1.name} - '{entry1.content}'")
    print(f"  ✓ File entry: {entry2.name} - {entry2.file_path}")
    
    # Test serialization
    entry_dict = entry1.to_dict()
    entry3 = VaultEntry.from_dict(entry_dict)
    print(f"  ✓ Serialization: {entry1.content == entry3.content}")
    
    # Test 2: NeoVault basic operations
    print("\n[2/5] Testing NeoVault operations...")
    vault = NeoVault()
    
    vault.add_entry(entry1)
    vault.add_entry(entry2)
    vault.add_entry(VaultEntry(
        "with_meta", 
        content="data",
        metadata={"type": "password", "category": "bank"}
    ))
    
    print(f"  ✓ Entries added: {vault.list_entries()}")
    print(f"  ✓ Entry count: {vault.metadata['entry_count']}")
    
    # Test search
    results = vault.search_entries("bank")
    print(f"  ✓ Search 'bank': {len(results)} results")
    
    # Test 3: Save vault - CON MÁS DETALLE
    print("\n[3/5] Testing vault save (with debug)...")
    password = "TestMasterPassword123!"
    
    with tempfile.NamedTemporaryFile(suffix='.nvault', delete=False) as f:
        temp_path = f.name
    
    print(f"  Temp file: {temp_path}")
    saved = vault.save_vault(password, temp_path)
    print(f"  ✓ save_vault() returned: {saved}")
    
    if os.path.exists(temp_path):
        file_size = os.path.getsize(temp_path)
        print(f"  ✓ File exists. Size: {file_size} bytes")
        
        # Muestra un poco del contenido del archivo para depuración
        with open(temp_path, 'r') as f:
            content_preview = f.read(200)  # Lee primeros 200 caracteres
            print(f"  File preview (first 200 chars):\n  {content_preview}")
    else:
        print("  ✗ ERROR: File was not created!")
        return  # Detener la prueba si el archivo no se creó
    
    # Test 4: Load vault - CON VERIFICACIÓN PASO A PASO
    print("\n[4/5] Testing vault load (step-by-step)...")
    new_vault = NeoVault()
    
    print(f"  Attempting to load from: {temp_path}")
    print(f"  Using password: '{password}'")
    
    loaded = new_vault.load_vault(temp_path, password)
    print(f"  ✓ load_vault() returned: {loaded}")
    
    if loaded:
        entries_loaded = new_vault.list_entries()
        print(f"  ✓ Entries loaded: {entries_loaded}")
        print(f"  ✓ Number of entries: {len(entries_loaded)}")
        
        # VERIFICACIÓN CRÍTICA: ¿Se cargó la entrada específica?
        target_entry = new_vault.get_entry('test_note')
        if target_entry is None:
            print("  ✗ CRITICAL ERROR: get_entry('test_note') returned None!")
            print(f"  All loaded entries: {entries_loaded}")
            
            # Si no hay entradas, el problema está en load_vault
            if len(entries_loaded) == 0:
                print("  ✗ VAULT IS EMPTY AFTER LOAD!")
                print("  Possible causes:")
                print("  1. Wrong key derivation in load_vault()")
                print("  2. Decryption failed silently")
                print("  3. JSON structure mismatch after decryption")
        else:
            # Ahora podemos acceder a .content de forma segura
            is_content_same = target_entry.content == 'Secret note'
            print(f"  ✓ Entry 'test_note' found!")
            print(f"  ✓ Content preserved: {is_content_same}")
            if not is_content_same:
                print(f"    Original: 'Secret note'")
                print(f"    Loaded: '{target_entry.content}'")
    else:
        print("  ✗ ERROR: load_vault() failed (returned False)")
    
    # Test 5: Wrong password
    print("\n[5/5] Testing security...")
    wrong_vault = NeoVault()
    wrong_load = wrong_vault.load_vault(temp_path, "WrongPassword!")
    print(f"  ✓ Wrong password rejected: {not wrong_load}")
    
    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)
        print(f"  ✓ Cleanup: temp file deleted")
    
    print("\n" + "="*60)
    print("✅ VAULT TEST COMPLETE (Check for errors above)")
    print("="*60)


if __name__ == "__main__":
    test_vault_complete()
    