"""
Simple Cipher Tools
Learn about encryption, the Caesar cipher, and substitution ciphers.

Learning concepts:
- Caesar cipher (shift cipher)
- Substitution cipher
- Encryption/decryption basics
- String manipulation
"""

import string
from typing import Tuple


class CaesarCipher:
    """Implement and break Caesar cipher (shift cipher)."""
    
    @staticmethod
    def encrypt(plaintext: str, shift: int) -> str:
        """
        Encrypt text using Caesar cipher.
        
        Args:
            plaintext: Text to encrypt
            shift: Number of positions to shift (1-25)
            
        Returns:
            Encrypted text
        """
        ciphertext = []
        for char in plaintext:
            if char.isalpha():
                # Determine if uppercase or lowercase
                start = ord('A') if char.isupper() else ord('a')
                # Shift the character
                shifted = (ord(char) - start + shift) % 26
                ciphertext.append(chr(start + shifted))
            else:
                # Keep non-alphabetic characters unchanged
                ciphertext.append(char)
        
        return ''.join(ciphertext)
    
    @staticmethod
    def decrypt(ciphertext: str, shift: int) -> str:
        """
        Decrypt text using Caesar cipher.
        
        Args:
            ciphertext: Text to decrypt
            shift: Number of positions original was shifted
            
        Returns:
            Decrypted text
        """
        return CaesarCipher.encrypt(ciphertext, -shift)
    
    @staticmethod
    def brute_force(ciphertext: str) -> list:
        """
        Brute force attack - try all 26 possible shifts.
        
        Args:
            ciphertext: Text to decrypt
            
        Returns:
            List of all possible decryptions
        """
        results = []
        for shift in range(26):
            decrypted = CaesarCipher.decrypt(ciphertext, shift)
            results.append({
                'shift': shift,
                'text': decrypted
            })
        return results


class VigenereCipher:
    """Simple Vigenère cipher implementation."""
    
    @staticmethod
    def encrypt(plaintext: str, key: str) -> str:
        """
        Encrypt using Vigenère cipher.
        
        Args:
            plaintext: Text to encrypt
            key: Encryption key (must be alphabetic)
            
        Returns:
            Encrypted text
        """
        key = key.upper()
        key_index = 0
        ciphertext = []
        
        for char in plaintext:
            if char.isalpha():
                # Get shift from key
                shift = ord(key[key_index % len(key)]) - ord('A')
                # Encrypt character
                start = ord('A') if char.isupper() else ord('a')
                encrypted = chr((ord(char) - start + shift) % 26 + start)
                ciphertext.append(encrypted)
                key_index += 1
            else:
                ciphertext.append(char)
        
        return ''.join(ciphertext)
    
    @staticmethod
    def decrypt(ciphertext: str, key: str) -> str:
        """Decrypt using Vigenère cipher."""
        key = key.upper()
        key_index = 0
        plaintext = []
        
        for char in ciphertext:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                start = ord('A') if char.isupper() else ord('a')
                decrypted = chr((ord(char) - start - shift) % 26 + start)
                plaintext.append(decrypted)
                key_index += 1
            else:
                plaintext.append(char)
        
        return ''.join(plaintext)


def main():
    """Main function."""
    print("=" * 60)
    print("🔐 CIPHER TOOLS - ENCRYPTION & DECRYPTION")
    print("=" * 60)
    
    print("\nChoose a cipher:")
    print("1. Caesar Cipher (simple shift)")
    print("2. Vigenère Cipher (stronger)")
    
    cipher_choice = input("\nEnter choice (1-2): ").strip()
    
    if cipher_choice == '1':
        print("\n--- Caesar Cipher ---")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Brute force (crack)")
        
        action = input("Choose action (1-3): ").strip()
        
        if action == '1':
            text = input("Enter text to encrypt: ")
            shift = int(input("Enter shift value (1-25): "))
            encrypted = CaesarCipher.encrypt(text, shift)
            print(f"\n✅ Encrypted: {encrypted}")
            
        elif action == '2':
            text = input("Enter text to decrypt: ")
            shift = int(input("Enter shift value: "))
            decrypted = CaesarCipher.decrypt(text, shift)
            print(f"\n✅ Decrypted: {decrypted}")
            
        elif action == '3':
            text = input("Enter ciphertext to crack: ")
            results = CaesarCipher.brute_force(text)
            print("\n--- All Possible Decryptions ---")
            for result in results:
                print(f"Shift {result['shift']:2d}: {result['text']}")
    
    elif cipher_choice == '2':
        print("\n--- Vigenère Cipher ---")
        print("1. Encrypt")
        print("2. Decrypt")
        
        action = input("Choose action (1-2): ").strip()
        key = input("Enter key (password): ")
        
        if action == '1':
            text = input("Enter text to encrypt: ")
            encrypted = VigenereCipher.encrypt(text, key)
            print(f"\n✅ Encrypted: {encrypted}")
            
        elif action == '2':
            text = input("Enter text to decrypt: ")
            decrypted = VigenereCipher.decrypt(text, key)
            print(f"\n✅ Decrypted: {decrypted}")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
