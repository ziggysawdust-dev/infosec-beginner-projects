# Simple Port Scanner

## Overview
A Python network scanning tool to learn about ports, services, and network reconnaissance.

## Learning Outcomes
- Socket programming in Python
- Network connections and TCP/IP basics
- Port scanning methodology
- Service identification
- Ethical hacking practices
- Threading for performance

## Features
- Scan specific port ranges
- Scan common ports (faster)
- Hostname resolution
- Service identification
- Threading for parallel scanning
- Clean, informative output

## Usage
```bash
python port_scanner.py
```

## Examples

### Scan localhost
```bash
python port_scanner.py
# Enter: localhost or 127.0.0.1
```

### Scan common ports on a server
```bash
python port_scanner.py
# Enter: example.com
# Choose: Option 1 (common ports)
```

## Common Ports Reference
| Port | Service | Purpose |
|------|---------|---------|
| 21   | FTP     | File transfer |
| 22   | SSH     | Secure shell |
| 23   | Telnet  | Remote login (insecure) |
| 25   | SMTP    | Email sending |
| 53   | DNS     | Domain name resolution |
| 80   | HTTP    | Web traffic |
| 110  | POP3    | Email retrieval |
| 143  | IMAP    | Email protocol |
| 443  | HTTPS   | Secure web traffic |
| 445  | SMB     | File sharing |
| 3306 | MySQL   | Database |
| 3389 | RDP     | Remote desktop |
| 5432 | PostgreSQL | Database |
| 8080 | HTTP-Alt| Alternative HTTP |

## How Port Scanning Works

1. **Connection Attempt**: Try to establish TCP connection to target:port
2. **Response Check**: 
   - Connection successful = Port open
   - Connection refused = Port closed
   - No response = Port filtered (firewall)
3. **Service Identification**: Match port number to known service

## Types of Port Scans

### TCP Connect Scan (Used Here)
- Completes full TCP handshake
- Easy to detect in logs
- Most reliable
- Slower than other methods

### Other Professional Scan Types (Reference)
- **SYN Scan**: Faster, stealthier (requires root)
- **UDP Scan**: For UDP services
- **Stealth Scan**: Tries to avoid detection

## Important Security & Legal Notes

### ⚠️ LEGAL WARNING
- **ONLY** scan:
  - Your own computers
  - Systems you have written permission to test
  - Lab environments you control
  - Professional penetration testing with contract

- **DO NOT** scan:
  - Computers you don't own
  - Systems without explicit permission
  - External internet hosts without authorization

### Unauthorized scanning can result in:
- Criminal charges (felony in many jurisdictions)
- Civil lawsuits
- Prison time
- Heavy fines

## Ethics in Security
As a security professional:
1. Always get written permission
2. Document authorization
3. Define scope clearly
4. Report findings responsibly
5. Never abuse access

## Next Steps
- Add UDP scanning capability
- Implement SYN scanning
- Create vulnerability scanner
- Add OS fingerprinting
- Build automated reporting

## Professional Tools Reference
- **Nmap**: Industry standard port scanner
- **Masscan**: Fast mass port scanner
- **Zmap**: Large-scale network scanner
- **Shodan**: Internet search engine for devices

Study these tools to understand advanced scanning techniques!
