"""
GUI controllers for NeoVault Matrix interface.
Connects UI with backend functionality
"""
import os
import json
import random
import string
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime


class VaultController:
    """Controller for vault operations"""
    
    def __init__(self, vaults_dir: str = "~/.neovault"):
        self.vaults_dir = os.path.expanduser(vaults_dir)
        self.current_vault = None
        self._ensure_vaults_dir()


    def _ensure_vaults_dir(self) -> None:
        """Create vaults directory if it doesn'rt exist"""
        os.makedirs(self.vaults_dir, exist_ok=True)


    def list_vaults(self) -> List[str]:
        """List all vault files in vaults directory"""
        if not os.path.exists(self.vaults_dir):
            return []
        
        vaults = []
        for file in os.listdir(self.vaults_dir):
            if file.endswith('.nvault'):
                vaults.append(file)
        return sorted(vaults)
    

    def create_vault(self, name: str, password: str) -> Dict[str, Any]:
        """Create a new vault (placeholder - will integrate with core)"""
        vault_data = {
            "name": name,
            "created": datetime.now().isoformat(),
            "entries": [],
            "version": "1.0"
        }

        # Save to file (temporary - will be encrypted with core moduel)
        filename = f"{name}.nvault"
        filepath = os.path.join(self.vaults_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(vault_data, f, indent=2)

        return {
            "succes": True,
            "filename": filename,
            "message": f"Vault '{name}' created successfully"
        }
    

    def load_vault(self, filename: str, password: str) -> Dict[str, Any]:
        """Load an existing vault (placeholder)"""
        filepath = os.path.join(self.vaults_dir, filename)

        if not os.path.exists(filepath):
            return {
                "success": False,
                "message": f"Vault file not found: {filename}"
            }
        
        try:
            with open(filepath, 'r') as f:
                vault_data = json.load(f)

            # For now, just validate structure
            if "name" not in vault_data or "entries" not in vault_data:
                return {
                    "success": False,
                    "message": "Invalid vault format"
                }
            
            self.current_vault = vault_data

            return {
                "success": True,
                "name": vault_data["name"],
                "entries": len(vault_data["entries"]),
                "message": f"Vault '{vault_data['name']}' loaded ({len(vault_data['entries'])} entries)"
            }
        
        except json.JSONDecodeError:
            return {
                "success": False,
                "message": "Corrupted vault file"
            }
        

    def get_vault_stats(self) -> Dict[str, Any]:
        """Get statistics about vaults"""
        vaults = self.list_vaults()
        total_size = 0

        for vault in vaults:
            filepath = os.path.join(self.vaults_dir, vault)
            if os.path.exists(filepath):
                total_size += os.path.getsize(filepath)

        return {
            "total_vaults": len(vaults),
            "total_size_kb": total_size / 1024,
            "vaults_list": vaults
        }
    


class PasswordGeneratorController:
    """Controller for password generation"""

    def __init__(self):
        self.generation_history = []

    
    def generate_password(self, length: int = 16,
                          use_upper: bool = True,
                          use_lower: bool = True,
                          use_numbers: bool = True,
                          use_symbols: bool = True) -> Dict[str, Any]:
        """Generate a random password with given parameters"""

        # Validate parameters
        if length < 4:
            length = 4
        elif length > 128:
            length = 128

        # Build character set
        chars = ""
        char_categories = []

        if use_lower:
            chars += string.ascii_lowercase
            char_categories.append("lowecase")
        if use_upper:
            chars += string.ascii_uppercase
            char_categories.append("uppercase")
        if use_numbers:
            chars += string.digits
            char_categories.append("numbers")
        if use_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            char_categories.append("symbols")

        # Ensure at least one character ser is selected
        if not chars:
            chars = string.ascii_letters + string.digits
            char_categories = ["letters", "numbers"]

        # Generate password
        password = ''.join(random.choice(chars) for _ in range(length))

        # Calculate stength (simplified)
        strength = self._calculate_strength(password, length, char_categories)

        # Store in history
        self.generation_history.append({
            "password": password,
            "length": length,
            "categories": char_categories,
            "timestamp": datetime.now().isoformat(),
            "strength": strength
        })

        # Keep only last 50 entries
        if len(self.generation_history) > 50:
            self.generation_history.pop(0)

        return {
            "password": password,
            "length": length,
            "categories": char_categories,
            "strength": strength,
            "strength_text": self._strength_to_text(strength)
        }
    

    def _calculate_strength(self, password: str, length: int, categories: List[str]) -> int:
        """Calculate password strength (0-100)"""
        # Base score from length
        length_score = min(length * 3, 60)

        # Bonus for character variety
        variety_bonus = len(categories) * 10

        # Penalty for simple patterns (basic check)
        penalty = 0
        if password.isnumeric():
            penalty = 20
        elif password.isalpha():
            penalty = 10

        strength = length_score + variety_bonus - penalty
        return max(0, min(100, strength))

    
    def _strength_to_text(self, strength: int) -> str:
        """Convert strength screo to text description"""
        if strength >= 80:
            return "Very Strong"
        elif strength >= 60:
            return "Strong"
        elif strength >= 40:
            return "Good"
        elif strength >= 20:
            return "Weak"
        else:
            return "Very Weak"


    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get password generation history"""
        return self.generation_history[-limit:] if self.generation_history else []



class SearchController:
    """Controller for search operations"""
    def __init__(self):
        self.search_history = []

    
    def search(self, query: str, vault_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Search in vault entries (placeholder)"""
        results = []

        if vault_data and "entries" in vault_data:
            for entry in vault_data["entries"]:
                # Simple text search in name and tags
                if (query.lower() in entry.get("name", "").lower() or
                    query.lower() in " ".join(entry.get("tags", [])).lower()):
                    results.append(entry)

        # Store search
        self.search_history.append({
            "query": query,
            "results": len(results),
            "timestamp": datetime.now().isoformat()
        })

        return {
            "query": query,
            "results_count": len(results),
            "results": results
        }
    


class SystemController:
    """Controller for system information"""

    def get_system_info(self) -> Dict[str, Any]:
        """Get system information for status display"""
        import psutil
        import platform

        return {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "python_version": platform.python_version(),
            "memory_used": psutil.virtual_memory().percent,
            "cpu_usage": psutil.cpu_percent(interval=0.1),
            "timestamp": datetime.now().isoformat()
        }

