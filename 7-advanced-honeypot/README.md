# Advanced Honeypot with Deception Technology

Learn about **threat detection**, **attacker behavior analysis**, and **deception-based security**.

## What You'll Learn

### Core Concepts
- **Honeypot Design**: Multi-port service emulation to trap attackers
- **Deception Technology**: Canary tokens, decoy files, fake credentials
- **Attack Logging**: Database-driven threat intelligence
- **Threat Analysis**: Pattern detection and attacker profiling
- **Kali Integration**: Tool detection and attack simulation

### Security Skills
- Threat detection and prevention
- Attack attribution and forensics
- Social engineering via deception
- Network monitoring
- Security intelligence gathering

## Project Structure

```
7-advanced-honeypot/
├── honeypot.py              # Core honeypot engine
├── analyzer.py              # Threat intelligence analysis
├── kali_integration.py      # Kali Linux tools integration
├── README.md                # This file
├── QUICKSTART.md            # Quick setup guide
├── DEPLOYMENT.md            # AWS deployment guide
└── honeypot.db              # SQLite database (created at runtime)
```

## Architecture

### 1. Core Honeypot (`honeypot.py`)

**Multi-Port Service Emulator**
- Listens on multiple ports (SSH, Telnet, HTTP, MySQL, RDP, etc.)
- Emulates vulnerable/interesting services
- Logs all connection attempts
- Threads handle concurrent attackers

**Service Handlers**
```
SSH (22)      → Fake SSH server, auth attempt logging
Telnet (23)   → Old protocol, credential capture
HTTP (80/443) → Fake web server, request logging
MySQL (3306)  → Database service, connection logging
RDP (3389)    → Remote desktop, connection logging
```

**Deception Technology**
- **Canary Credentials**: Fake admin/root/mysql passwords
- **Decoy Files**: Fake backup files, config files, SSH keys
- **Honeypot Tokens**: Unique identifiers for tracking

### 2. Threat Intelligence (`analyzer.py`)

**Analysis Features**
- Attack summary (total, successful, failed)
- Top attackers and their techniques
- Attack patterns (brute force, scanning, etc.)
- Deception trap effectiveness
- Timeline visualization
- Comprehensive threat reports

**Database Queries**
```sql
-- Top attacking IPs
SELECT source_ip, COUNT(*) FROM attack_attempts
GROUP BY source_ip ORDER BY COUNT(*) DESC;

-- Deception events triggered
SELECT decoy_name, event_type FROM deception_events
ORDER BY timestamp DESC;

-- Brute force detection
SELECT source_ip, COUNT(*) as attempts
FROM attack_attempts
WHERE attack_type IN ('SSH_AUTH_ATTEMPT', 'TELNET_LOGIN')
GROUP BY source_ip HAVING attempts > 5;
```

### 3. Kali Integration (`kali_integration.py`)

**Nmap Detection**
- Run scans against honeypot
- Parse Nmap output
- Detect tool signatures
- Identify scanning patterns

**Tcpdump Capture**
- Capture network traffic
- PCAP file analysis
- Packet inspection
- Protocol distribution

**Attack Simulation**
- Simulate Nmap scans
- Test brute force attacks (safely)
- Port scanning simulations
- Controlled testing environment

## Database Schema

### connections
```sql
id, timestamp, source_ip, source_port, target_port,
service, protocol, data_sent, data_received, 
duration_seconds, threat_level
```

### attack_attempts
```sql
id, timestamp, source_ip, attack_type, tool_detected,
payload, response, success
```

### deception_events
```sql
id, timestamp, source_ip, event_type, decoy_name,
decoy_type, attacker_action, alert_sent
```

### attacker_profiles
```sql
id, source_ip (UNIQUE), first_seen, last_seen,
attack_count, tools_detected, techniques, 
threat_level, geographic_location
```

## Learning Path

### Phase 1: Local Testing (Kali VM)
1. Start honeypot on localhost
2. Test with your own tools
3. Analyze attack patterns
4. Understand deception effectiveness

### Phase 2: Network Testing
1. Change binding to 0.0.0.0 (or local network)
2. Run Nmap scans
3. Attempt brute force attacks
4. Monitor Tcpdump capture
5. Generate threat reports

### Phase 3: AWS Deployment
1. Deploy to EC2 instance
2. Expose to internet
3. Collect real attack data
4. Build threat intelligence
5. Create resume showcase

## Usage Examples

### Start the Honeypot

```bash
# Localhost only (safe lab environment)
python honeypot.py

# All interfaces (for AWS)
# Edit honeypot.py: bind_address='0.0.0.0'
```

### Run Threat Analysis

```bash
python analyzer.py
# Generates: honeypot_threat_report.txt
```

### Test with Kali Tools

```bash
python kali_integration.py

# Manual Nmap scan
nmap -sT -p 22,23,80,443,3306 127.0.0.1

# SSH brute force attempt
hydra -l admin -P rockyou.txt ssh://127.0.0.1

# Connection attempt simulation
telnet 127.0.0.1 23
```

## Deception Technology Explained

### Canary Tokens
Fake credentials embedded in the honeypot that alert when accessed:

```python
'creds_admin': {
    'username': 'admin',
    'password': 'SuperSecret!2024',
    'honeypot_id': 'unique_token_12345'  # Tracks this canary
}
```

**How it works:**
1. Attacker tries credentials on real systems
2. Alert triggered when honeypot token is detected
3. Attribution: You know which credentials came from this honeypot

### Decoy Files
Fake files that look interesting but are monitored:

```python
'fake_backup': {
    'path': '/home/user/backup_2024.tar.gz',
    'honeypot_id': 'unique_token_67890'
}
```

**Attacker behavior:**
- Finds "backup" file
- Downloads it (caught by honeypot)
- Attempts to open it (honeypot token detected elsewhere)
- You now know their TTPs

### Attack Detection

**Brute Force Pattern**
```
IP 192.168.1.100 attempts SSH login 47 times
→ Severity: HIGH
→ Action: Block or study attack pattern
```

**Port Scanning Pattern**
```
IP 10.0.0.50 connects to ports 22, 23, 80, 443, 3306
→ Pattern: Reconnaissance
→ Tool: Likely Nmap or similar
```

**Deception Trap Trigger**
```
IP 203.0.113.50 accesses /home/user/backup_2024.tar.gz
→ Severity: HIGH (sophisticated attacker)
→ Intent: Exploring after initial compromise
→ TTPs: File exfiltration attempt
```

## Advanced Features

### Threat Levels
- **LOW**: Passive scans, single connection attempts
- **MEDIUM**: Multiple auth attempts, tool usage detected
- **HIGH**: Deception trap triggers, aggressive exploitation

### Attack Attribution
Correlate across:
- IP address
- Tools used (Nmap, Metasploit, etc.)
- Attack techniques
- Timing and patterns
- Deception trap engagement

### Intelligence Generation
```
Timeline: 23:14 - Port scan detected (Nmap)
         23:15 - SSH brute force attempt (Hydra)
         23:16 - Canary credential used on real system (ALERT!)
         23:17 - Decoy file accessed

Conclusion: Sophisticated attacker with multi-stage attack
```

## Security Considerations

### Local Lab (Safe)
✅ Bind to 127.0.0.1 only
✅ Run on Kali VM in isolated network
✅ No risk to production systems
✅ Full control for testing

### AWS Deployment (Exposed)
⚠️ Bind to 0.0.0.0 and expose to internet
⚠️ Real attackers will find and probe honeypot
⚠️ Security groups should limit exposure
⚠️ Monitor AWS costs (DDoS can cause bill shock)

### Best Practices
1. Never use real production credentials
2. Monitor database growth (logging uses disk space)
3. Rotate honeypot location periodically
4. Cordon off honeypot IP in firewall rules
5. Analyze data regularly (detection is useless without action)

## Resume Talking Points

### Technical Skills Demonstrated
- ✅ Multi-threaded network programming
- ✅ Protocol emulation (SSH, Telnet, HTTP, MySQL)
- ✅ SQLite database design and queries
- ✅ Threat intelligence and forensics
- ✅ Deception technology implementation
- ✅ Security tool integration (Nmap, Tcpdump)
- ✅ Attack pattern analysis
- ✅ AWS deployment and management

### Real-World Scenarios
1. **Threat Detection**: "Implemented deception technology that caught sophisticated attackers attempting credential reuse"
2. **Attack Analysis**: "Analyzed 10,000+ attack attempts to identify top 5 attacker signatures"
3. **Social Engineering**: "Used canary tokens to track attacker movement post-exploitation"
4. **Tool Detection**: "Developed Nmap/Hydra signatures to identify attack tools in real-time"

## Next Steps

1. **Run locally** on Kali VM (Phase 1)
2. **Analyze small dataset** to understand patterns
3. **Deploy to AWS** with proper security groups
4. **Monitor for 2-4 weeks** to collect real data
5. **Generate intelligence reports** for portfolio
6. **Present findings**: "Analyzed honeypot that detected 50+ unique attacks from 15 countries"

## Troubleshooting

### Port Already in Use
```bash
# Find process using port
lsof -i :22

# Kill process
kill -9 <PID>
```

### Permission Denied (Tcpdump/Nmap)
```bash
# Run with sudo
sudo python honeypot.py

# Or configure sudoers for specific commands
```

### Database Errors
```bash
# Check database integrity
sqlite3 honeypot.db "PRAGMA integrity_check;"

# Backup and reset
cp honeypot.db honeypot.db.bak
rm honeypot.db  # Will recreate on next run
```

### No Attacks Detected
- Check honeypot is actually listening: `netstat -tlnp`
- Run Nmap scan to test: `nmap -sT -p 22,23,80 localhost`
- Verify database is being written to

## Resources

### Learning Resources
- OWASP Honeypots: https://owasp.org/www-community/Honeypots
- Honeypot Project: https://www.honeypotproject.org/
- Nmap Usage Guide: https://nmap.org/book/
- SQLite Documentation: https://www.sqlite.org/docs.html

### Security Concepts
- Threat Intelligence: https://en.wikipedia.org/wiki/Threat_intelligence
- Canary Tokens: https://canarytokens.org/
- Deception Technology: https://www.deceptiontech.com/

### Tools
- Nmap: Port scanning and OS detection
- Tcpdump: Network packet analysis
- Hydra: Brute force attack simulation
- Metasploit: Exploitation framework

## Summary

This project teaches you to:
1. **Build** a sophisticated security trap
2. **Detect** and analyze real attacks
3. **Understand** attacker behavior
4. **Deploy** to cloud infrastructure
5. **Generate** threat intelligence for security teams

All critical skills for infosec careers in:
- SOC (Security Operations Center)
- Incident Response
- Threat Intelligence
- Penetration Testing
- Security Research
