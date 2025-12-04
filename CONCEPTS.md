# Cybersecurity Concepts Reference Guide

Quick reference for concepts covered in your 5 projects.

## 🔐 Project 1: Password Strength Checker

### Key Concepts

**Regular Expressions (Regex)**
```python
import re
re.search(r'[A-Z]', password)  # Find uppercase letter
re.search(r'\d', password)      # Find digit (0-9)
re.search(r'[!@#$%^&*]', text) # Find special characters
```

**Security Requirements**
- ✅ Length: 8+ characters (12+ is better)
- ✅ Uppercase: At least one A-Z
- ✅ Lowercase: At least one a-z
- ✅ Numbers: At least one 0-9
- ✅ Special Characters: !@#$%^&*()

**Why It Matters**
- Weak passwords are cracked in seconds
- Strong passwords protect all your accounts
- Attackers use dictionary attacks and brute force

---

## #️⃣ Project 2: Hash Generator

### Key Concepts

**What is a Hash?**
- One-way function: can't reverse it
- Same input always produces same output
- Different input produces completely different output
- Very sensitive (1 bit change = different hash)

**Algorithm Comparison**

| Algorithm | Size | Speed | Security | Use Case |
|-----------|------|-------|----------|----------|
| MD5       | 128-bit | Fast | ❌ Broken | Legacy only |
| SHA-1     | 160-bit | Fast | ⚠️ Weak | Historical |
| SHA-256   | 256-bit | Good | ✅ Secure | Recommended |
| SHA-512   | 512-bit | Good | ✅ Very Secure | Maximum security |

**Real-World Uses**
```
File Integrity: Download hash = Local hash? ✅ Not modified
Password Storage: hash("password") → store in database
Blockchain: Every block contains SHA-256 hash
Digital Signatures: Hash message before signing
```

**Hash Properties (The 4 Properties)**
1. **Deterministic**: Same input = Same output
2. **Quick**: Fast to compute
3. **Avalanche**: Tiny input change = completely different hash
4. **One-way**: Cannot reverse to find original input

---

## 🔒 Project 3: Simple Cipher

### Key Concepts

**Caesar Cipher**
```
Original alphabet: A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
Shift by 3:       D E F G H I J K L M N O P Q R S T U V W X Y Z A B C

HELLO → KHOOR
```

**Why Caesar is Weak**
- Only 26 possible keys (shift 0-25)
- Can brute force in milliseconds
- Letter frequency analysis breaks it
- Same plaintext letter = same ciphertext letter

**Vigenère Cipher (Stronger)**
```
Plaintext:  H E L L O W O R L D
Key:        S E C R E T S E C R
Ciphertext: Z H P E S P G V N U
```

**Why Vigenère is Better (But Still Weak)**
- Uses a password as key
- Different key letters = different shifts
- Harder to break than Caesar
- But still vulnerable to frequency analysis and known plaintext attacks

**Modern Encryption** (What to use instead)
- AES (Advanced Encryption Standard): Industry standard
- ChaCha20: Fast and modern
- RSA: Public-key encryption
- TLS/SSL: Secure communications

---

## 🌐 Project 4: Port Scanner

### Key Concepts

**Network Basics**
```
Computer A → Router → Internet → Target Server
            ↓
      Port (1-65535) - endpoint for service
```

**TCP/IP Model**
```
7. Application Layer (HTTP, SMTP, SSH)
6. Presentation Layer
5. Session Layer
4. Transport Layer (TCP, UDP)
3. Network Layer (IP)
2. Data Link Layer
1. Physical Layer
```

**Ports Overview**
- Range: 1 to 65,535
- Well-known: 1-1,023 (require admin)
- Registered: 1,024-49,151
- Dynamic: 49,152-65,535

**Common Ports**
- 21: FTP (File Transfer)
- 22: SSH (Secure Shell)
- 80: HTTP (Web)
- 443: HTTPS (Secure Web)
- 3306: MySQL (Database)

**Port Scanning Methods**
```
TCP Connect Scan (Your project)
- Attempts full TCP connection
- Slow but reliable
- Easy to detect in logs

SYN Scan (Advanced)
- Faster, doesn't complete connection
- Requires root privileges
- Harder to detect

UDP Scan
- For UDP services
- Less reliable (stateless)
```

**Socket Programming**
```python
socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# AF_INET = IPv4
# SOCK_STREAM = TCP (reliable)
```

**Legal & Ethical Considerations**
⚠️ **Only scan:**
- Your own systems
- Systems with written permission
- Lab/test environments

---

## 🔑 Project 5: Password Manager

### Key Concepts

**Encryption vs. Hashing**
```
Encryption:
- Input → Algorithm → Output (encrypted)
- Reversible (with key)
- Used for: passwords, files, messages
- CAN decrypt if you have key

Hashing:
- Input → Algorithm → Hash
- NOT reversible
- Used for: verification, integrity
- Cannot decrypt
```

**Symmetric Encryption (Your Project)**
```
One key for both encryption and decryption
Key → Plaintext → Encrypted Data
Key → Encrypted Data → Plaintext

Advantage: Fast
Disadvantage: Must securely share key
```

**Asymmetric Encryption (Reference)**
```
Two keys: Public and Private
- Public key: Encrypt (anyone can use)
- Private key: Decrypt (only you have)

Used for: Digital signatures, key exchange
```

**AES Encryption**
- Advanced Encryption Standard
- 128-bit, 192-bit, or 256-bit keys
- Industry standard
- Fast and secure

**Key Derivation Function (PBKDF2)**
```python
# Purpose: Derive strong key from weak password
Password: "mypassword"
    ↓
PBKDF2 (100,000 iterations)
    ↓
Strong 256-bit key

Why 100,000 iterations?
- Makes brute force attacks slower
- 100,000 × slower = too expensive
- Each iteration takes time
```

**Salt**
```
Random bytes added to password before hashing
- Each vault has unique salt
- Prevents rainbow tables
- Same password = different hash

Without salt: MD5("password") = always same
With salt: MD5("password" + random) = different for each user
```

**Secure Random Generation**
```python
import secrets
secrets.token_bytes(16)  # 16 random bytes
secrets.choice(alphabet)  # Cryptographically secure random

Don't use: random.choice() - not secure!
```

---

## 🧠 Security Principles to Remember

### Defense in Depth
- Multiple layers of security
- If one fails, others still protect
- Example: Password + 2FA + encrypted storage

### Fail Secure
- When system fails, secure state is default
- Not open/allow by default
- "Closed by default" approach

### Least Privilege
- Users get minimum access needed
- Reduce attack surface
- Remove unnecessary permissions

### Separation of Concerns
- Different modules have different jobs
- Easier to audit and secure
- Failure doesn't cascade

### Never Trust User Input
- Always validate and sanitize
- Assume input is malicious
- Use whitelists, not blacklists

### Defense Through Obscurity Doesn't Work
- Security should NOT rely on hiding algorithm
- Use proven, public algorithms
- Secrecy should be in the KEY, not algorithm

---

## 📊 Cryptography Strength Comparison

```
Strength (from weakest to strongest):

❌ No encryption
   → Plaintext password in file

⚠️ Basic encryption
   → Caesar cipher
   → Single XOR

⚠️ Weak encryption
   → MD5 hashing
   → SHA-1 hashing
   → DES encryption

✅ Good encryption
   → SHA-256 hashing
   → AES-128 encryption
   → RSA-2048

✅✅ Excellent encryption
   → SHA-512 hashing
   → AES-256 encryption
   → RSA-4096
   → Quantum-resistant algorithms (future)
```

---

## 🔍 Common Security Vulnerabilities (OWASP Top 10)

Your projects demonstrate protection against:

1. **Injection** - Your cipher shows encryption
2. **Broken Authentication** - Your password manager shows proper storage
3. **Sensitive Data Exposure** - Your encryption protects data
4. **XML External Entities** - Not covered (web-specific)
5. **Broken Access Control** - Master password = access control
6. **Security Misconfiguration** - Your projects use defaults correctly
7. **Cross-Site Scripting** - Not covered (web-specific)
8. **Insecure Deserialization** - Not covered (advanced)
9. **Using Components with Known Vulnerabilities** - Use updated packages
10. **Insufficient Logging** - Consider adding logging to projects

---

## 🎓 Interview Talking Points

### "Tell me about your password strength checker"
"I built a tool that validates passwords against NIST guidelines using regular expressions. It checks for length, character diversity (uppercase, lowercase, numbers, special chars), and provides specific feedback for improvement. This demonstrates understanding of security requirements and regex pattern matching."

### "How does hashing differ from encryption?"
"Hashing is one-way - you can't recover the original data. Encryption is reversible with a key. Hashing is used for verification (passwords, file integrity), while encryption protects data at rest and in transit. Hash collisions are theoretically possible but practically impossible with SHA-256."

### "Why are simple ciphers insecure?"
"Classical ciphers like Caesar cipher have only 26 possible keys, making them trivial to brute force. They also exhibit patterns that allow frequency analysis attacks. Modern encryption like AES uses much larger key spaces (2^128) and is based on mathematical principles that make cryptanalysis infeasible."

### "How does your port scanner work?"
"The port scanner attempts TCP connections to target ports. If the connection succeeds, the port is open. If refused, it's closed. I implemented threading to scan multiple ports simultaneously, making it much faster. I also included service identification mapping common ports to services."

### "What makes your password manager secure?"
"I use AES encryption via Fernet for data at rest, PBKDF2 key derivation from the master password with 100,000 iterations to slow brute force attacks, and cryptographically secure random password generation with the secrets module. Each vault has a unique salt to prevent rainbow table attacks."

---

## 📚 Books to Read

- "Cryptography Engineering" by Schneier, Ferguson, Kohno
- "The Web Application Hacker's Handbook" by Stuttard & Pinto
- "Practical Cryptography" by Schneier & Ferguson
- "Penetration Testing" by Georgia Weidman

---

## 🌐 Websites to Explore

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CyberAces](https://www.cyberaces.org/) - Free tutorials
- [TryHackMe](https://tryhackme.com/) - Interactive labs
- [HackTheBox](https://www.hackthebox.com/) - Challenge labs
- [Cryptography.io](https://cryptography.io/) - Python crypto docs

---

**Good luck with your interviews! 🚀**

Remember: Understanding the "why" is more important than memorizing the "what."
