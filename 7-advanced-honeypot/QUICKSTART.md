# Quick Start Guide - Advanced Honeypot

Get up and running in 5 minutes.

## Installation

### Prerequisites
```bash
# Ensure you have Python 3.8+
python3 --version

# Required Kali tools
sudo apt-get update
sudo apt-get install nmap tcpdump
```

### Setup
```bash
# Navigate to project directory
cd 7-advanced-honeypot

# That's it! No external dependencies needed
# (uses only Python stdlib: socket, threading, sqlite3)
```

## Quick Start (5 minutes)

### 1. Start the Honeypot
```bash
# Terminal 1: Start honeypot
python3 honeypot.py

# Output:
# ======================================================================
# 🍯 ADVANCED HONEYPOT WITH DECEPTION TECHNOLOGY
# ======================================================================
# 
# Binding to: 127.0.0.1
# Monitoring ports: [22, 23, 80, 443, 3306, 8080]
# 
# ✓ Listening on port 22
# ✓ Listening on port 23
# ✓ Listening on port 80
# ...
# ✓ Honeypot started! Waiting for attackers...
```

### 2. Test from Another Terminal
```bash
# Terminal 2: Run Nmap scan
nmap -sT -p 22,23,80,443,3306 127.0.0.1

# Watch honeypot catch the scan:
# 🔍 Connection from 127.0.0.1:12345 → port 22
# 🔍 Connection from 127.0.0.1:12346 → port 23
# ...
```

### 3. Analyze Results
```bash
# Terminal 2: Generate threat report
python3 analyzer.py

# Output: honeypot_threat_report.txt
# View the report:
cat honeypot_threat_report.txt
```

## Learning Path (30 minutes)

### Step 1: Understand the Components (5 min)
```bash
# Read the core files
less honeypot.py       # Multi-port listener + service emulation
less analyzer.py       # Threat intelligence analysis
less kali_integration.py  # Kali tools integration
```

**Key Classes:**
- `HoneypotDatabase`: SQLite logging
- `DeceptionTechnology`: Canaries and decoys
- `ServiceEmulator`: SSH, Telnet, HTTP, MySQL handlers
- `AdvancedHoneypot`: Main orchestrator
- `HoneypotAnalyzer`: Intelligence reporting

### Step 2: Local Lab Testing (10 min)
```bash
# Terminal 1: Start honeypot
python3 honeypot.py

# Terminal 2: Run various tests
python3 kali_integration.py

# This will attempt:
# - Nmap port scan
# - Service detection
# - Tool fingerprinting
```

### Step 3: Simulate Attacks (10 min)
```bash
# Terminal 2: Manual testing

# Test SSH (observe fake SSH server)
telnet 127.0.0.1 22

# Test Telnet (observe login prompt)
telnet 127.0.0.1 23

# Test HTTP (observe web server)
curl http://127.0.0.1:80

# Test connection flooding (observe threat detection)
for i in {1..10}; do nmap -sT -p 80 127.0.0.1; done
```

### Step 4: Analyze Attack Data (5 min)
```bash
# Terminal 2: Generate and view report
python3 analyzer.py

# Key sections:
# 📊 Attack Summary - Total attacks, successful/failed
# 🎯 Top Attackers - Which IPs attacked most
# ⚠️  Suspicious Patterns - Brute force, scanning, etc.
# 🍯 Deception Effectiveness - Traps triggered
# 📈 Attack Timeline - When attacks occurred
```

## Common Commands

### Start/Stop
```bash
# Start honeypot on localhost (safe)
python3 honeypot.py

# Stop: Ctrl+C
# View statistics on exit
```

### Testing
```bash
# Full port scan
nmap -sT -p- 127.0.0.1

# Aggressive scan (OS detection)
nmap -A -sT 127.0.0.1

# UDP scan
nmap -sU -p 53,123 127.0.0.1

# Service version detection
nmap -sV -p 22,23,80 127.0.0.1
```

### Analysis
```bash
# Generate threat report
python3 analyzer.py

# View threat report
cat honeypot_threat_report.txt

# Query database directly
sqlite3 honeypot.db "SELECT * FROM connections LIMIT 10;"

# Count attacks by IP
sqlite3 honeypot.db "SELECT source_ip, COUNT(*) FROM attack_attempts GROUP BY source_ip ORDER BY COUNT(*) DESC;"

# Show deception events
sqlite3 honeypot.db "SELECT * FROM deception_events ORDER BY timestamp DESC;"
```

### Database Management
```bash
# Check database size
ls -lh honeypot.db

# Backup database
cp honeypot.db honeypot.db.backup

# Reset database (recreates on next run)
rm honeypot.db

# Export data to CSV
sqlite3 honeypot.db ".mode csv" "SELECT * FROM attack_attempts;" > attacks.csv
```

## Deception Technology Demo

### Canary Credentials
When attacker tries these fake credentials:
```
Username: admin
Password: SuperSecret!2024

# OR
Username: root
Password: RootPassword123!

# OR
Username: mysql
Password: mysqlpass123
```

The honeypot logs it and alerts you:
```
🚨 CANARY TRIGGERED! Attacker 192.168.1.100 found credential: creds_admin
```

### Decoy Files
When attacker attempts to access:
```
/home/user/backup_2024.tar.gz
/etc/app/config.conf
/home/user/.ssh/id_rsa
/var/run/docker.sock
```

The honeypot logs it:
```
🚨 DECOY ACCESSED! Attacker 192.168.1.100 tried: /home/user/backup_2024.tar.gz
```

## Database Inspection

### Attack Attempts
```bash
sqlite3 honeypot.db
> SELECT * FROM attack_attempts ORDER BY timestamp DESC LIMIT 5;
```

### Connections
```bash
> SELECT source_ip, target_port, service, COUNT(*) as attempts
  FROM connections
  GROUP BY source_ip, target_port
  ORDER BY attempts DESC;
```

### Deception Events
```bash
> SELECT * FROM deception_events ORDER BY timestamp DESC;
```

### Attacker Profiles
```bash
> SELECT * FROM attacker_profiles ORDER BY attack_count DESC;
```

## Ports Explained

| Port | Service | Honeypot Behavior |
|------|---------|-------------------|
| 22 | SSH | Emulates SSH auth, logs credentials |
| 23 | Telnet | Fake login prompt, old protocol |
| 80 | HTTP | Fake web server, captures requests |
| 443 | HTTPS | HTTP over TLS (simplified) |
| 3306 | MySQL | Database server, logs connections |
| 3389 | RDP | Remote desktop (simplified) |
| 8080 | HTTP Alt | Alternative web server |

## Threat Levels

**LOW** 🟢
- Single connection attempts
- Service banners grabbed
- Port scanning activity

**MEDIUM** 🟡
- Multiple auth attempts (5-20)
- Multiple port connections
- Tool usage detected

**HIGH** 🔴
- Deception trap triggered (attacker found fake credentials/files)
- Brute force attack (20+ attempts from one IP)
- Sophisticated multi-stage attack

## Resume Angle

After 2-4 weeks of honeypot running, you can say:

> "Developed and deployed an advanced honeypot with deception technology that:
> - Detected and logged 5,000+ attack attempts across 47 unique attacker IPs
> - Identified 12 distinct attack tools (Nmap, Hydra, Metasploit, etc.)
> - Triggered deception traps 34 times, capturing attacker TTPs
> - Generated threat intelligence reports used for security posture assessment"

## Next: AWS Deployment

Once you're comfortable locally, see `DEPLOYMENT.md` for:
1. Deploying to EC2
2. Exposing to internet
3. Collecting real-world attack data
4. Scaling to multiple honeypots
5. Integration with SIEM systems

## Troubleshooting

### Q: Port already in use
**A:**
```bash
# Find process
lsof -i :22

# Kill it
kill -9 <PID>
```

### Q: Permission denied
**A:**
```bash
# Run with sudo
sudo python3 honeypot.py

# Or change binding to high port (>1024)
# Edit honeypot.py: ports=[8022, 8023, 8080, 8443, 8306, 8389]
```

### Q: No attacks detected
**A:**
```bash
# Verify honeypot is listening
netstat -tlnp | grep python

# Try Nmap scan
nmap -sT 127.0.0.1

# Check if database is being written
ls -l honeypot.db

# Query database
sqlite3 honeypot.db "SELECT COUNT(*) FROM connections;"
```

### Q: Honeypot crashed
**A:**
```bash
# Check error
python3 honeypot.py 2>&1 | head -20

# Check logs
cat honeypot.log

# Database corrupted?
sqlite3 honeypot.db "PRAGMA integrity_check;"
```

## Key Files

| File | Purpose |
|------|---------|
| `honeypot.py` | Main honeypot engine (multi-port listener) |
| `analyzer.py` | Threat intelligence analysis tool |
| `kali_integration.py` | Nmap/Tcpdump integration |
| `honeypot.db` | SQLite database (created at runtime) |
| `honeypot.log` | Honeypot activity log |
| `honeypot_threat_report.txt` | Generated threat intelligence report |

## Learning Objectives Checklist

- [ ] Start honeypot successfully
- [ ] Connect to honeypot from another terminal
- [ ] Run Nmap scan against it
- [ ] View attack logs in database
- [ ] Generate threat report
- [ ] Understand deception technology
- [ ] Identify attack patterns
- [ ] Know how to deploy to AWS (next step)

## Time Investment

| Task | Time |
|------|------|
| Initial setup | 5 min |
| Local lab testing | 15 min |
| Understanding code | 30 min |
| Analysis and reporting | 10 min |
| AWS deployment setup | 20 min |
| **Total** | **~80 min** |

Start now and have a working honeypot in 5 minutes!
