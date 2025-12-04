# InfoSec Beginner Projects - Learning Path for Cybersecurity

A collection of 5 beginner-friendly infosec projects designed to teach fundamental security concepts while building a portfolio for job applications.

## 📚 Projects Overview

### Project 1: Password Strength Checker ⭐ **START HERE**
Learn regex, string validation, and security requirements.
- **Skills**: Regular expressions, input validation, security best practices
- **Time**: 30 minutes
- **Difficulty**: Easy
```bash
cd 1-password-strength-checker
python password_checker.py
```

### Project 2: Hash Generator
Understand cryptographic hashing, file integrity, and data verification.
- **Skills**: Cryptography basics, MD5/SHA algorithms, file I/O
- **Time**: 45 minutes
- **Difficulty**: Easy-Medium
```bash
cd 2-hash-generator
python hash_generator.py
```

### Project 3: Simple Cipher
Learn classical encryption (Caesar and Vigenère ciphers) and cryptanalysis.
- **Skills**: Encryption fundamentals, brute force attacks, character manipulation
- **Time**: 1 hour
- **Difficulty**: Medium
```bash
cd 3-simple-cipher
python cipher.py
```

### Project 4: Port Scanner
Discover network scanning, service detection, and ethical hacking basics.
- **Skills**: Socket programming, networking, threading, ethics
- **Time**: 1 hour
- **Difficulty**: Medium
```bash
cd 4-port-scanner
python port_scanner.py
```

### Project 5: Password Manager
Master encryption, key derivation, and secure credential storage.
- **Skills**: AES encryption, PBKDF2, secure random generation, database design
- **Time**: 1.5 hours
- **Difficulty**: Hard
```bash
cd 5-password-manager
pip install cryptography
python password_manager.py
```

## 🎯 Learning Path

### Week 1: Foundations
- **Day 1-2**: Project 1 - Password Strength Checker
  - Understand regex and validation
  - Learn security requirements
  
- **Day 3-4**: Project 2 - Hash Generator
  - Understand cryptographic concepts
  - Learn about different algorithms
  
- **Day 5-6**: Project 3 - Simple Cipher
  - Learn encryption basics
  - Understand cipher security

### Week 2: Advanced Topics
- **Day 7-8**: Project 4 - Port Scanner
  - Network programming basics
  - Understand ethical hacking
  - Learn legal considerations
  
- **Day 9-10**: Project 5 - Password Manager
  - Integrate encryption knowledge
  - Build practical security application
  - Understand real-world security patterns

## 💻 Installation & Setup

### Requirements
- Python 3.8+
- Git
- GitHub account

### Install Project Dependencies

```bash
# For most projects (no dependencies)
# Python standard library is sufficient

# For Password Manager (Project 5):
pip install cryptography
```

## 🚀 How to Push to GitHub

### Step 1: Create Repository on GitHub
1. Go to [github.com/new](https://github.com/new)
2. Name it: `infosec-beginner-projects`
3. Add description: "Learning portfolio of beginner-friendly cybersecurity projects"
4. Choose Public (to show employers)
5. Click "Create Repository"

### Step 2: Initialize Git in Your Local Folder

```bash
cd /home/ziggy/Desktop/infosec-beginner-projects

# Initialize git
git init

# Add all files
git add .

# Create initial commit
git commit -m "Initial commit: Add 5 beginner infosec projects"
```

### Step 3: Connect to GitHub

```bash
# Add remote (replace USERNAME with your GitHub username)
git remote add origin https://github.com/USERNAME/infosec-beginner-projects.git

# Rename branch to main (GitHub default)
git branch -M main

# Push to GitHub
git push -u origin main
```

### Step 4: Create Professional README

The main README.md is already created in this folder. To enhance it further, add badges:

```markdown
# Add to the top of README.md:

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
```

## 📝 Tips for Job Applications

### Making This Portfolio Stand Out

1. **Add Tests**
   - Create `test_password_checker.py` for each project
   - Demonstrates quality and professionalism
   - Use `unittest` or `pytest`

2. **Documentation**
   - ✅ Each project has detailed README (already done!)
   - Add docstrings (already done!)
   - Include examples in README

3. **Code Quality**
   - Follow PEP 8 style guide
   - Use type hints (already done!)
   - Handle errors gracefully (already done!)

4. **Enhancements**
   - Add CLI using `argparse`
   - Create logging
   - Add configuration files
   - Build web interface with Flask

### Example Job Interview Talking Points

#### For Project 1:
"I built a password strength checker that validates security criteria using regex. It demonstrates understanding of security requirements and how modern systems evaluate password strength."

#### For Project 2:
"Created a hash generator supporting multiple algorithms. This shows knowledge of cryptographic fundamentals and why different hash algorithms exist for different use cases."

#### For Project 3:
"Implemented both Caesar and Vigenère ciphers with brute force attacks. This demonstrates understanding of encryption fundamentals and why classical ciphers are insecure."

#### For Project 4:
"Built a network port scanner with threading. This shows networking knowledge, ethical hacking understanding, and that I understand the importance of authorization."

#### For Project 5:
"Created an encrypted password manager using AES encryption and PBKDF2 key derivation. This demonstrates advanced cryptography knowledge and secure software development practices."

## 🔄 Future Enhancements

### Short-term (Add these to impress)
- [ ] Add unit tests for all projects
- [ ] Create CLI interface with argparse
- [ ] Add logging to all projects
- [ ] Create requirements.txt

### Medium-term (Portfolio expansion)
- [ ] Implement AES encryption in cipher project
- [ ] Add SQL injection detection tool
- [ ] Create vulnerability scanner
- [ ] Build web scraping with security analysis

### Long-term (Advanced)
- [ ] Create web application with Flask
- [ ] Add API endpoints
- [ ] Implement authentication system
- [ ] Create Docker containers
- [ ] Add CI/CD pipeline (GitHub Actions)

## 📚 Additional Learning Resources

### Python & Coding
- [Real Python - Python Security](https://realpython.com/python-security/)
- [Python Official Documentation](https://docs.python.org/3/)
- [PEP 8 Style Guide](https://pep8.org/)

### Cybersecurity
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CyberAces Tutorials](https://www.cyberaces.org/)
- [TryHackMe Learning Path](https://tryhackme.com/)

### Cryptography
- [Cryptography.io Documentation](https://cryptography.io/)
- ["Cryptography Engineering" Book](https://www.schneier.com/books/cryptography-engineering/)

### Networking
- [Networking Basics](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/116125-qa-pse-00.html)
- [TCP/IP Model Explained](https://en.wikipedia.org/wiki/Internet_protocol_suite)

## ✅ Checklist Before Submitting

- [ ] All 5 projects completed
- [ ] Code runs without errors
- [ ] README files have detailed explanations
- [ ] Code includes comments and docstrings
- [ ] Pushed to GitHub (public repository)
- [ ] GitHub profile is complete (picture, bio, location)
- [ ] Pinned this repository to your GitHub profile

## 🤝 Contributing & Community

### Share Your Projects
- Share on Twitter/LinkedIn with #cybersecurity #python #portfolio
- Contribute improvements to this learning path
- Help others by reviewing their code

### Getting Help
- GitHub Issues: Ask questions
- Stack Overflow: Tag with `python` and `cybersecurity`
- Local security meetups or Discord communities

## 📋 License

MIT License - Feel free to use, modify, and distribute

## 🎓 Next Steps After Completing

1. **Apply to Entry-Level Jobs**
   - Security Analyst
   - SOC Analyst
   - IT Security roles
   - Penetration Tester Trainee

2. **Get Certifications**
   - CompTIA Security+
   - Certified Ethical Hacker (CEH)
   - OSCP (Offensive Security Certified Professional)

3. **Advanced Learning**
   - Build more complex tools
   - Study for certifications
   - Contribute to open source security projects
   - Participate in CTF (Capture The Flag) competitions

## 💡 Remember

> "The best way to learn security is to build things and understand why they work."

These projects teach you:
- How to think like a security professional
- Why certain practices matter
- How to write secure code
- Practical security concepts

Good luck with your journey into cybersecurity! 🚀

---

**Questions?** Create an issue or reach out on GitHub!

**Want to improve these projects?** Fork and submit a pull request!
