"""
GUI Helper Module for Password Manager

This module provides a clean interface for GUI applications.
It separates business logic from UI, making it easy to build
a tkinter or PyQt GUI later.

Future: This will be imported by gui.py when we build the GUI app.
"""

from password_manager import PasswordManager
from typing import List, Dict, Optional


class PasswordManagerAPI:
    """
    Clean API layer for GUI applications.
    
    This wraps PasswordManager to provide:
    - Data-driven responses (no print statements)
    - Consistent error handling
    - GUI-friendly data structures
    - Type hints for IDE support
    """
    
    def __init__(self, vault_file: str = "password_vault.json"):
        """Initialize the API wrapper."""
        self.manager = PasswordManager(vault_file)
        self.is_authenticated = False
    
    def authenticate(self, master_password: str) -> Dict:
        """
        Authenticate with master password.
        
        Returns:
            {
                'success': bool,
                'message': str,
                'authenticated': bool
            }
        """
        result = self.manager.open_vault(master_password)
        self.is_authenticated = result
        
        return {
            'success': result,
            'message': 'Vault opened successfully' if result else 'Invalid password',
            'authenticated': result
        }
    
    def create_vault(self, master_password: str) -> Dict:
        """
        Create new vault.
        
        Returns:
            {'success': bool, 'message': str}
        """
        try:
            self.manager.setup_vault(master_password)
            self.is_authenticated = True
            return {'success': True, 'message': 'Vault created successfully'}
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    def add_password(self, service: str, username: str, password: str) -> Dict:
        """
        Add password to vault.
        
        Returns:
            {'success': bool, 'message': str}
        """
        if not self.is_authenticated:
            return {'success': False, 'message': 'Not authenticated'}
        
        try:
            self.manager.add_password(service, username, password)
            return {'success': True, 'message': f'Password saved for {service}'}
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    def get_password(self, service: str) -> Dict:
        """
        Get password details.
        
        Returns:
            {
                'success': bool,
                'message': str,
                'service': str (if success),
                'username': str (if success),
                'password': str (if success)
            }
        """
        if not self.is_authenticated:
            return {'success': False, 'message': 'Not authenticated'}
        
        result = self.manager.get_password_details(service)
        return result
    
    def search_services(self, prefix: str) -> Dict:
        """
        Search services by prefix.
        
        Returns:
            {
                'success': bool,
                'count': int,
                'results': List[str],
                'message': str
            }
        """
        if not self.is_authenticated:
            return {
                'success': False,
                'count': 0,
                'results': [],
                'message': 'Not authenticated'
            }
        
        results = self.manager.search_services(prefix)
        
        return {
            'success': True,
            'count': len(results),
            'results': results,
            'message': f'Found {len(results)} match(es)' if results else 'No matches found'
        }
    
    def list_services(self) -> Dict:
        """
        List all services.
        
        Returns:
            {
                'success': bool,
                'count': int,
                'services': List[str],
                'message': str
            }
        """
        if not self.is_authenticated:
            return {
                'success': False,
                'count': 0,
                'services': [],
                'message': 'Not authenticated'
            }
        
        services = self.manager.list_services()
        
        return {
            'success': True,
            'count': len(services),
            'services': services,
            'message': f'{len(services)} service(s) stored'
        }
    
    def delete_password(self, service: str) -> Dict:
        """
        Delete password entry.
        
        Returns:
            {'success': bool, 'message': str}
        """
        if not self.is_authenticated:
            return {'success': False, 'message': 'Not authenticated'}
        
        try:
            self.manager.delete_password(service)
            return {'success': True, 'message': f'Password for {service} deleted'}
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    def generate_password(self, length: int = 16, use_special: bool = True) -> Dict:
        """
        Generate strong password.
        
        Returns:
            {'success': bool, 'password': str, 'message': str}
        """
        try:
            pwd = self.manager.generate_password(length, use_special)
            return {
                'success': True,
                'password': pwd,
                'message': f'Generated {length}-character password'
            }
        except Exception as e:
            return {'success': False, 'password': '', 'message': f'Error: {str(e)}'}


# Example usage (for testing GUI functionality):
if __name__ == "__main__":
    api = PasswordManagerAPI("test_api.json")
    
    # Create vault
    print(api.create_vault("TestPass123!"))
    
    # Add password
    print(api.add_password("example", "user", "pass123"))
    
    # Search
    print(api.search_services("ex"))
    
    # List all
    print(api.list_services())
    
    # Get password
    print(api.get_password("example"))
    
    # Clean up
    import os
    os.remove("test_api.json")
