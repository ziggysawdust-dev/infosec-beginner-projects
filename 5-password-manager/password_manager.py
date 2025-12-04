"""
Simple Password Manager
Learn about secure password storage, encryption, and credential management.

Learning concepts:
- Encrypted storage
- Key derivation functions
- Secure random password generation
- Password database management
- File encryption basics
"""

import json
import os
import secrets
import string
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import base64
import hashlib


class PasswordManager:
    """A simple encrypted password manager."""
    
    def __init__(self, vault_file: str = "password_vault.json"):
        """
        Initialize password manager.
        
        Args:
            vault_file: Path to encrypted vault file
        """
        self.vault_file = vault_file
        self.cipher = None
        self.master_password = None
    
    def _derive_key(self, password: str, salt: bytes = None) -> tuple:
        """
        Derive encryption key from master password using PBKDF2.
        
        Args:
            password: Master password
            salt: Salt for key derivation
            
        Returns:
            Tuple of (key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def setup_vault(self, master_password: str) -> bool:
        """
        Create new vault with master password.
        
        Args:
            master_password: Master password to protect vault
            
        Returns:
            True if successful
        """
        key, salt = self._derive_key(master_password)
        self.cipher = Fernet(key)
        self.master_password = master_password
        
        # Create empty vault
        vault_data = {
            'salt': base64.b64encode(salt).decode(),
            'passwords': {}
        }
        
        self._save_vault(vault_data)
        print("✅ Vault created successfully!")
        return True
    
    def open_vault(self, master_password: str) -> bool:
        """
        Open existing vault.
        
        Args:
            master_password: Master password
            
        Returns:
            True if password is correct
        """
        if not Path(self.vault_file).exists():
            print("❌ Vault file not found. Create new vault first!")
            return False
        
        try:
            with open(self.vault_file, 'r') as f:
                vault_data = json.load(f)
            
            salt = base64.b64decode(vault_data['salt'])
            key, _ = self._derive_key(master_password, salt)
            self.cipher = Fernet(key)
            self.master_password = master_password
            
            # Test key by trying to decrypt
            for encrypted in vault_data['passwords'].values():
                try:
                    self.cipher.decrypt(encrypted.encode())
                    break
                except:
                    print("❌ Incorrect master password!")
                    return False
            
            print("✅ Vault opened successfully!")
            return True
        
        except Exception as e:
            print(f"❌ Error opening vault: {e}")
            return False
    
    def add_password(self, service: str, username: str, password: str) -> bool:
        """
        Add a password to vault.
        
        Args:
            service: Service/website name
            username: Username or email
            password: Password to store
            
        Returns:
            True if successful
        """
        if not self.cipher:
            print("❌ Vault not open!")
            return False
        
        with open(self.vault_file, 'r') as f:
            vault_data = json.load(f)
        
        # Encrypt password
        encrypted = self.cipher.encrypt(password.encode()).decode()
        
        vault_data['passwords'][service] = {
            'username': username,
            'password': encrypted
        }
        
        self._save_vault(vault_data)
        print(f"✅ Password saved for {service}")
        return True
    
    def get_password(self, service: str) -> dict:
        """
        Retrieve password from vault.
        
        Args:
            service: Service name
            
        Returns:
            Dictionary with username and password
        """
        if not self.cipher:
            print("❌ Vault not open!")
            return None
        
        with open(self.vault_file, 'r') as f:
            vault_data = json.load(f)
        
        if service not in vault_data['passwords']:
            print(f"❌ No password found for {service}")
            return None
        
        entry = vault_data['passwords'][service]
        decrypted = self.cipher.decrypt(entry['password'].encode()).decode()
        
        return {
            'service': service,
            'username': entry['username'],
            'password': decrypted
        }
    
    def list_services(self) -> list:
        """List all stored services."""
        if not self.cipher:
            print("❌ Vault not open!")
            return []
        
        with open(self.vault_file, 'r') as f:
            vault_data = json.load(f)
        
        return list(vault_data['passwords'].keys())
    
    def delete_password(self, service: str) -> bool:
        """Delete a password entry."""
        if not self.cipher:
            print("❌ Vault not open!")
            return False
        
        with open(self.vault_file, 'r') as f:
            vault_data = json.load(f)
        
        if service in vault_data['passwords']:
            del vault_data['passwords'][service]
            self._save_vault(vault_data)
            print(f"✅ Password for {service} deleted")
            return True
        
        print(f"❌ No password found for {service}")
        return False
    
    def _save_vault(self, vault_data: dict):
        """Save vault to file."""
        with open(self.vault_file, 'w') as f:
            json.dump(vault_data, f, indent=2)
    
    @staticmethod
    def generate_password(length: int = 16, 
                         use_special: bool = True) -> str:
        """
        Generate a secure random password.
        
        Args:
            length: Password length
            use_special: Include special characters
            
        Returns:
            Generated password
        """
        chars = string.ascii_letters + string.digits
        if use_special:
            chars += string.punctuation
        
        password = ''.join(secrets.choice(chars) for _ in range(length))
        return password


def main():
    """Main function."""
    print("=" * 60)
    print("🔐 PASSWORD MANAGER")
    print("=" * 60)
    
    manager = PasswordManager()
    
    # Check if vault exists
    if not Path(manager.vault_file).exists():
        print("\nNo vault found. Creating new vault...")
        master_pwd = input("Set master password: ")
        manager.setup_vault(master_pwd)
    else:
        master_pwd = input("Enter master password: ")
        if not manager.open_vault(master_pwd):
            print("❌ Failed to open vault!")
            return
    
    while True:
        print("\n" + "=" * 60)
        print("Options:")
        print("1. Add new password")
        print("2. Retrieve password")
        print("3. List all services")
        print("4. Delete password")
        print("5. Generate strong password")
        print("6. Exit")
        
        choice = input("\nChoose option (1-6): ").strip()
        
        if choice == '1':
            service = input("Service/Website name: ")
            username = input("Username/Email: ")
            password = input("Password (or press Enter to generate): ")
            
            if not password:
                password = PasswordManager.generate_password()
                print(f"Generated password: {password}")
            
            manager.add_password(service, username, password)
        
        elif choice == '2':
            service = input("Service name: ")
            entry = manager.get_password(service)
            if entry:
                print(f"\n📋 {entry['service']}")
                print(f"Username: {entry['username']}")
                print(f"Password: {entry['password']}")
        
        elif choice == '3':
            services = manager.list_services()
            if services:
                print("\n📋 Stored Services:")
                for svc in services:
                    print(f"  • {svc}")
            else:
                print("No passwords stored yet.")
        
        elif choice == '4':
            service = input("Service to delete: ")
            manager.delete_password(service)
        
        elif choice == '5':
            length = int(input("Password length (default 16): ") or "16")
            pwd = PasswordManager.generate_password(length)
            print(f"Generated: {pwd}")
        
        elif choice == '6':
            print("\n✅ Goodbye!")
            break
        
        else:
            print("Invalid option!")


if __name__ == "__main__":
    # Check for required package
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print("❌ Required package 'cryptography' not installed!")
        print("Install with: pip install cryptography")
        exit(1)
    
    main()
