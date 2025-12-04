# Secure Password Manager

## Overview
A Python-based encrypted password manager to learn about secure credential storage and encryption.

## Learning Outcomes
- Encryption with Fernet (symmetric encryption)
- Key derivation functions (PBKDF2)
- Secure password generation
- File encryption
- Database security best practices
- Salt and pepper concepts

## Features
- **Encrypted Storage**: Passwords encrypted with AES-128
- **Master Password**: Single password protects all credentials
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Password Generation**: Secure random password creation
- **CRUD Operations**: Create, read, update, delete passwords
- **Salt**: Unique salt per vault for additional security

## Installation
```bash
# Install required package
pip install cryptography
```

## Usage
```bash
python password_manager.py
```

## First Run
1. Program detects no vault exists
2. You set a master password
3. Vault is created and encrypted

## Subsequent Runs
1. Enter your master password
2. Access your stored credentials
3. Add/retrieve/delete passwords as needed

## Security Features

### Encryption Algorithm
- **Type**: Symmetric encryption (Fernet)
- **Algorithm**: AES-128 in CBC mode
- **Key Size**: 128-bit
- **Authentication**: HMAC-SHA256 (included in Fernet)

### Key Derivation
- **Algorithm**: PBKDF2
- **Hash Function**: SHA-256
- **Iterations**: 100,000 (industry standard)
- **Salt**: 16 random bytes per vault
- **Purpose**: Slows down password cracking

### Password Security
- **Generation**: Uses `secrets` module (cryptographically secure)
- **Entropy**: Maximum randomness
- **Default Length**: 16 characters
- **Character Types**: Letters, digits, special characters

## How It Works

### Initial Setup
```
1. User sets master password
2. Random 16-byte salt generated
3. PBKDF2 derives encryption key from master password + salt
4. Vault created with empty password dictionary
```

### Adding Password
```
1. User provides service, username, password
2. Password encrypted with derived key
3. Encrypted data stored in JSON vault
4. Vault saved to disk
```

### Retrieving Password
```
1. User enters service name
2. Program decrypts password using master key
3. Returns username and password in plaintext
```

## Vault File Structure
```json
{
  "salt": "base64-encoded-16-bytes",
  "passwords": {
    "gmail": {
      "username": "user@gmail.com",
      "password": "fernet-encrypted-string"
    },
    "github": {
      "username": "username",
      "password": "fernet-encrypted-string"
    }
  }
}
```

## Security Best Practices Demonstrated

1. **Never store plaintext passwords**
2. **Use strong master password** (12+ characters, mixed case, numbers, special)
3. **Use unique encryption for each vault** (different salt)
4. **Slow key derivation** (100,000 PBKDF2 iterations)
5. **Authenticate encryption** (HMAC prevents tampering)
6. **Use cryptographically secure randomness** (secrets module)

## Comparison: Amateur vs Professional Password Managers

### Amateur (What NOT to do)
```python
# ❌ BAD: Storing plaintext
passwords = {"gmail": "mypassword"}

# ❌ BAD: Simple encryption
simple_cipher = password * 3

# ❌ BAD: Weak key derivation
key = hashlib.md5(master_pwd).digest()
```

### Professional (This Project)
```python
# ✅ GOOD: Encrypted storage
Fernet(key).encrypt(password)

# ✅ GOOD: Strong key derivation
PBKDF2 with 100,000 iterations

# ✅ GOOD: Authenticated encryption
Fernet includes HMAC-SHA256
```

## Real-World Alternatives
- **1Password**: Professional password manager
- **Bitwarden**: Open source, cloud-based
- **KeePass**: Desktop-based, no cloud
- **LastPass**: Popular commercial option

These use similar concepts but with:
- Multi-factor authentication
- Cloud synchronization
- Browser integration
- Team sharing
- Advanced encryption (AES-256)

## Next Steps
1. Add password strength checking (from project 1)
2. Implement backup/restore functionality
3. Add password change tracking
4. Create export features
5. Add two-factor authentication support
6. Implement password expiration reminders

## Security Warnings

### ⚠️ DO NOT use this for real passwords!
This is educational. For real password management, use:
- 1Password
- Bitwarden
- KeePass
- Professional tools with:
  - Regular security audits
  - Professional development
  - Bug bounty programs
  - Proper threat modeling

### Master Password Tips
- ✅ Make it long (15+ characters)
- ✅ Mix uppercase, lowercase, numbers, special chars
- ✅ Don't use personal information
- ✅ Don't reuse from other services
- ✅ Store in secure location (your memory!)
- ❌ Don't write it down
- ❌ Don't share it
- ❌ Don't use simple passwords

## Learning Path
1. Start with Project 1: Password Strength Checker
2. This Project: Password Manager
3. Add hash generation (Project 2)
4. Integrate cipher (Project 3)
5. Build complete security suite
