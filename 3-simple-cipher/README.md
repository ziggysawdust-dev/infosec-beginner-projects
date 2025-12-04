# Simple Cipher Tools

## Overview
Python tools to learn classical encryption methods: Caesar cipher and Vigenère cipher.

## Learning Outcomes
- Understand classical encryption techniques
- Caesar cipher (shift cipher) and how to break it
- Vigenère cipher for stronger encryption
- Brute force attacks on weak encryption
- Why simple ciphers are insecure for modern use

## Features

### Caesar Cipher
- Encrypt text with any shift (1-25)
- Decrypt with known shift
- Brute force attack (crack without key)
- Only 26 possible keys - very weak!

### Vigenère Cipher
- More complex: uses a key (password)
- Much harder to brute force than Caesar
- Resisted cryptanalysis for centuries
- Still breakable with frequency analysis

## Usage
```bash
python cipher.py
```

## Examples

### Caesar Cipher
```
Plain:  HELLO WORLD
Shift:  3
Cipher: KHOOR ZRUOG
```

### Vigenère Cipher
```
Plain:  HELLO WORLD
Key:    SECRET
Cipher: ZINPR GRLFS
```

## How Caesar Cipher Works
```
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
         ↓ shift by 3
D E F G H I J K L M N O P Q R S T U V W X Y Z A B C
```

## Security Analysis

### Caesar Cipher
- **Strength**: None - easily brute forced
- **Possible keys**: Only 26 (shift 0-25)
- **Attack time**: Milliseconds
- **Real use**: Educational only

### Vigenère Cipher
- **Strength**: Much better than Caesar
- **Key space**: Depends on key length and complexity
- **Attack**: Frequency analysis (Kasiski examination)
- **Real use**: Historical, not for modern systems

## Why These Are Insecure
1. Single character always maps to same cipher character
2. Frequency analysis reveals patterns
3. Only rely on substitution (easily automated)
4. No authentication (can't verify sender)

## Modern Alternatives
- **AES (Advanced Encryption Standard)**: Industry standard
- **ChaCha20**: Fast, secure modern cipher
- **RSA**: Public-key encryption
- **TLS/SSL**: Secure communications

## Historical Context
- Caesar cipher: Used by Julius Caesar (100-44 BC)
- Vigenère: Developed 16th century, used in WWI
- Both broken by modern cryptanalysis
- Important to understand for learning cryptography

## Next Steps
- Implement frequency analysis to break ciphers
- Create AES encryption tool
- Add file encryption capability
- Learn about key derivation functions
