# Testing & Validation Guide

Complete testing procedures to validate your honeypot works correctly.

## Test 1: Basic Startup (2 minutes)

### Objective
Verify honeypot starts and listens on all ports.

### Steps
```bash
# Start honeypot
python3 honeypot.py

# Expected output:
# ======================================================================
# 🍯 ADVANCED HONEYPOT WITH DECEPTION TECHNOLOGY
# ======================================================================
# Binding to: 127.0.0.1
# Monitoring ports: [22, 23, 80, 443, 3306, 8080]
# ✓ Listening on port 22
# ✓ Listening on port 23
# ✓ Listening on port 80
# ✓ Listening on port 443
# ✓ Listening on port 3306
# ✓ Listening on port 8080
# ✓ Honeypot started! Waiting for attackers...
```

### Validation
- ✅ No errors on startup
- ✅ All ports show "Listening"
- ✅ No "Address already in use" errors

**Result:** PASS / FAIL

---

## Test 2: Port Listening (3 minutes)

### Objective
Verify honeypot actually listens on specified ports.

### From Another Terminal
```bash
# Check if ports are listening
netstat -tlnp | grep python

# Expected output:
# tcp  0  0 127.0.0.1:22    0.0.0.0:*  LISTEN  12345/python3
# tcp  0  0 127.0.0.1:23    0.0.0.0:*  LISTEN  12345/python3
# tcp  0  0 127.0.0.1:80    0.0.0.0:*  LISTEN  12345/python3
```

### Validation
- ✅ All 6 ports show LISTEN state
- ✅ Bound to 127.0.0.1
- ✅ PID is same for all ports

**Result:** PASS / FAIL

---

## Test 3: Connection Test (3 minutes)

### Objective
Connect to honeypot and verify service responses.

### Test SSH Connection
```bash
telnet 127.0.0.1 22

# Expected:
# SSH-2.0-OpenSSH_7.4 (Honeypot)
```

### Test HTTP Service
```bash
curl http://127.0.0.1:80

# Expected:
# <html><body>Welcome to Honeypot Server</body></html>
```

### Validation
- ✅ SSH service responds with banner
- ✅ HTTP service responds with HTML
- ✅ All connections handled gracefully

**Result:** PASS / FAIL

---

## Test 4: Nmap Scan (5 minutes)

### Objective
Verify honeypot is detected by Nmap.

### Run Scan
```bash
nmap -sT -p 22,23,80,443,3306,8080 127.0.0.1

# Expected: All ports show as open
```

### Validation
- ✅ Nmap detects all open ports
- ✅ Honeypot logs each connection
- ✅ Connections show in real-time

**Result:** PASS / FAIL

---

## Test 5: Attack Logging (5 minutes)

### Objective
Verify attacks are logged to database.

### Trigger Attacks
```bash
nmap -sT 127.0.0.1
curl http://127.0.0.1/admin
```

### Query Database
```bash
sqlite3 honeypot.db "SELECT COUNT(*) FROM connections;"
sqlite3 honeypot.db "SELECT COUNT(*) FROM attack_attempts;"
```

### Validation
- ✅ Connections table populated
- ✅ Attack attempts table populated
- ✅ Timestamps recorded correctly

**Result:** PASS / FAIL

---

## Test 6: Deception Technology (5 minutes)

### Objective
Verify canary credentials are detected.

### Trigger Canary
```bash
# Try with canary username
timeout 2 telnet 127.0.0.1 23 <<EOF
admin
SuperSecret!2024
EOF

# Watch honeypot terminal for:
# 🚨 CANARY TRIGGERED!
```

### Validation
- ✅ Canary trigger detected
- ✅ Alert shown in console
- ✅ Event logged to database

**Result:** PASS / FAIL

---

## Test 7: Analysis Report (3 minutes)

### Objective
Verify threat analysis generates reports.

### Generate Report
```bash
python3 analyzer.py
```

### Validation
- ✅ Report generated successfully
- ✅ File saved as honeypot_threat_report.txt
- ✅ Contains attack summary

**Result:** PASS / FAIL

---

## Test Summary

| Test | Result |
|------|--------|
| 1. Startup | PASS/FAIL |
| 2. Port Check | PASS/FAIL |
| 3. Services | PASS/FAIL |
| 4. Nmap Scan | PASS/FAIL |
| 5. Logging | PASS/FAIL |
| 6. Deception | PASS/FAIL |
| 7. Reports | PASS/FAIL |

All tests must pass before AWS deployment!
