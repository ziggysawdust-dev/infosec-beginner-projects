# HackTheBox Log Grok Tool

Parse, analyze, and assess HackTheBox forensics logs — including binary wtmp files and text-based logs (syslog, auth, Apache, etc.).

## Features

- **Binary wtmp Parser**: Parses Unix login/logout event logs with IP tracking and session reconstruction
- **Grok-like Pattern Matcher**: Regex-based pattern matching for common log formats (SSH, sudo, Apache, etc.)
- **Log Correlation**: Timeline-based event correlation across multiple log sources
- **Suspicious Pattern Detection**: Automatic detection of brute force, privilege escalation, and multi-source login anomalies
- **Assessment Reports**: JSON and terminal output with detailed event analysis

## What You'll Learn

- Binary file parsing in Python (struct, unpacking)
- Regular expression pattern matching and log parsing
- Security event correlation and timeline reconstruction
- Forensics analysis and threat assessment
- CLI tool design and argument parsing

## Installation

No external dependencies required (uses Python stdlib only).

```bash
cd htb-log-grok
```

## Usage

### Quick View (Human-Readable Format)

View logs in a clean, color-coded table with filtering and export options:

```bash
# View wtmp login records
python3 log_viewer.py wtmp /var/log/wtmp

# View SSH authentication logs
python3 log_viewer.py log /var/log/auth.log --pattern syslog_auth_success

# Filter by username
python3 log_viewer.py log /var/log/auth.log --user root

# Filter by IP address
python3 log_viewer.py log /var/log/auth.log --ip 192.168

# Export to JSON for further analysis
python3 log_viewer.py log /var/log/auth.log --export-json report.json

# Export to CSV for spreadsheet apps
python3 log_viewer.py wtmp /var/log/wtmp --export-csv logins.csv

# Combine filters
python3 log_viewer.py log /var/log/auth.log --user root --ip 10.10 --export-json admin_logins.json
```

### Programmatic Access

```bash
# Parse wtmp file directly
python3 wtmp_parser.py /var/log/wtmp

# Parse text logs with grok patterns
python3 grok_matcher.py /var/log/auth.log syslog_auth_success
python3 grok_matcher.py /var/log/apache2/access.log apache_access
```

### Full Assessment Report

```bash
# Comprehensive analysis (wtmp + multiple logs + threat detection)
python3 htb_assessment.py report /var/log/wtmp /var/log/auth.log /var/log/syslog

# Analyze just wtmp sessions
python3 htb_assessment.py analyze_wtmp /var/log/wtmp

# Analyze just log file with pattern matching
python3 htb_assessment.py analyze_log /var/log/auth.log syslog_auth_failed
```

## Example Output

```
================================================================================
HACKTHEBOX LOG ASSESSMENT REPORT
================================================================================

📊 SUMMARY
  wtmp sessions:        24
  Log entries parsed:   156
  Timeline events:      389
  Unique users (wtmp):  3 - ['admin', 'htb', 'root']
  Unique users (logs):  5 - ['admin', 'htb', 'nobody', 'root', 'www-data']
  Unique IPs:           7 - ['10.10.10.5', '192.168.1.100', ...]
  Suspicious events:    3

📈 EVENTS BY TYPE
  syslog_auth_success         89 events
  syslog_auth_failed          45 events
  sudo_command                12 events
  apache_access               10 events

⚠️  SUSPICIOUS ACTIVITY DETECTED

  [HIGH] brute_force_attack
    ip: 192.168.1.50
    attempt_count: 23
    users_targeted: admin, root
    first_attempt: Dec  8 14:23:45
    last_attempt: Dec  8 14:35:12

  [MEDIUM] multi_source_login
    user: admin
    locations: ['10.10.10.5', '192.168.1.100']
    login_count: 3

  [MEDIUM] privilege_escalation
    user: htb
    target_user: root
    command: cat /root/.ssh/id_rsa
    timestamp: Dec  8 16:45:23
```

## Supported Patterns

### wtmp Parser
- `USER_PROCESS`: Login/logout events
- `BOOT_TIME`: System reboot events
- `DEAD_PROCESS`: Terminated sessions
- IP address extraction and session reconstruction

### Grok Patterns
- `syslog_auth_success`: SSH successful authentication
- `syslog_auth_failed`: SSH failed authentication attempts
- `sudo_command`: Privilege escalation (sudo) commands
- `apache_access`: Web server access logs

## The Tools

### log_viewer.py
**Human-readable log viewer with color-coding, filtering, and export.**

Features:
- Color-coded output (green=success, red=failed, yellow=warning)
- Formatted table view with key fields
- Filtering by user, IP, status, or time
- Export to JSON or CSV
- Summary statistics and top users/IPs

The best tool to quickly view and understand logs.

### wtmp_parser.py
**Binary wtmp file parser.**

- Parses Unix login/logout event logs (296 bytes per entry)
- Handles type codes (USER_PROCESS, BOOT_TIME, etc.)
- Extracts IP addresses and hostnames
- Session duration calculation
- Methods: `parse()`, `get_login_sessions()`, `get_reboot_times()`, `get_summary()`

### grok_matcher.py
**Grok-like pattern matcher for text logs.**

- Pre-defined patterns for common log formats
- Regex-based field extraction with named groups
- Pattern registration system
- Supports custom patterns
- Methods: `match()`, `register_pattern()`

### htb_assessment.py
**Comprehensive forensics analysis tool.**

Combines wtmp + logs with threat detection:
- Timeline correlation across multiple sources
- Brute force detection (3+ failed logins)
- Multi-source login anomaly detection
- Privilege escalation identification
- Incomplete session detection
- JSON export for detailed reporting

## Supported Patterns

### Pre-defined Grok Patterns
- `syslog_auth_success`: SSH successful authentication
- `syslog_auth_failed`: SSH failed authentication attempts
- `sudo_command`: Sudo command execution
- `apache_access`: Apache/Nginx access logs

### Add Custom Patterns

```python
from grok_matcher import GrokMatcher

matcher = GrokMatcher()
matcher.register_pattern(
    'custom_app_log',
    r'(?<timestamp>\d{4}-\d{2}-\d{2})\s+(?<level>\w+)\s+(?<message>.+)'
)
```

## Suspicious Activity Detection

Automatically detects:

1. **Brute Force Attacks**: 3+ failed auth attempts from same IP
2. **Multi-source Login**: User logging in from multiple IPs (impossible travel)
3. **Privilege Escalation**: Sudo commands and user context changes
4. **Failed Sessions**: Logins with no recorded logout

## File Parsing Details

### wtmp Structure (binary)
```
Type (2 bytes) | PID (4) | TTY (32) | ID (4) | User (32) | 
Host (256) | Exit Code (2) | Session (4) | Timestamp (4) | IP (4)
```

### Supported Log Formats
- **syslog**: Standard Unix syslog format
- **SSH**: OpenSSH auth logs (failed/successful)
- **sudo**: Sudo privilege escalation logs
- **Apache**: Apache/Nginx access logs

## Assessment Workflow

### For HackTheBox Challenges:

1. **Collect logs** from compromised system:
   ```bash
   # On target system
   cp /var/log/wtmp /tmp/wtmp.bin
   cp /var/log/auth.log /tmp/auth.log
   cp /var/log/syslog /tmp/syslog
   ```

2. **Run assessment**:
   ```bash
   python3 htb_assessment.py report /tmp/wtmp.bin /tmp/auth.log /tmp/syslog
   ```

3. **Review report**:
   - Check suspicious events section
   - Review timeline of user activity
   - Identify attack vectors
   - Document findings in assessment document

4. **Export findings**:
   ```bash
   # JSON export for further analysis
   cat assessment_report.json
   ```

## Command Reference

| Command | Usage |
|---------|-------|
| `analyze_wtmp` | Parse and report on wtmp file |
| `analyze_log` | Parse and report on single log file |
| `analyze_both` | Combine wtmp + one log file |
| `report` | Full assessment (wtmp + multiple logs, JSON export) |

## Customization

### Add New Grok Pattern

Edit `grok_matcher.py` and add to `GrokPatterns`:

```python
CUSTOM_PATTERN = (
    r'(?<timestamp>\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?<hostname>[\w\-\.]+)\s+'
    r'(?<event_type>\w+):\s+(?<details>.+)$'
)
```

### Customize Suspicious Pattern Detection

Edit `htb_assessment.py` `analyze_suspicious_patterns()` method to add your own detection logic.

## Output Formats

### Terminal Report
- Summary statistics
- Event count by type
- Suspicious activity with severity levels
- Recommended actions

### JSON Export
```json
{
  "timestamp": "2025-12-11T14:23:45.123456",
  "summary": {
    "wtmp_sessions": 24,
    "log_entries": 156,
    "unique_users": ["admin", "htb", "root"]
  },
  "suspicious_events": [...],
  "wtmp_sessions": [...],
  "log_matches": [...]
}
```

## Tips for HackTheBox

1. **Binary files**: Run `hexdump -C wtmp | head -20` to verify file format
2. **Timestamp interpretation**: wtmp uses Unix epoch (seconds since 1970-01-01)
3. **IP addresses**: Stored as 4 bytes in network byte order
4. **Missing data**: Some fields may be empty (0x00) — tool handles gracefully
5. **Assessment doc**: Use exported JSON as evidence in your writeup

## Limitations

- Does not parse `utmp` (current logins only) — use `wtmp` for history
- Grok patterns are simplified (not full Elasticsearch Grok)
- Timestamps must match pattern exactly
- No automatic log rotation handling

## Career Relevance

This tool demonstrates:
- ✅ Binary file format parsing
- ✅ Log analysis and pattern matching
- ✅ Forensics and timeline reconstruction
- ✅ Event correlation and threat assessment
- ✅ CLI tool design
- ✅ Python security programming

Perfect for **incident response**, **threat hunting**, and **forensics** interviews.

## Portfolio Usage

Add to your security portfolio:
```
HTB Log Grok Tool
- Parsed binary wtmp files for login event extraction
- Implemented grok-like pattern matching for 5+ log formats
- Detected suspicious patterns: brute force, privilege escalation, anomalous access
- Generated forensics reports for HackTheBox challenges
- Technologies: Python, binary parsing, regex, JSON export
```

## Example HackTheBox Scenario

**Challenge**: Analyze a compromised web server and identify attacker activity.

1. Recover logs from system:
   - `/var/log/wtmp` (login history)
   - `/var/log/auth.log` (authentication events)
   - `/var/log/apache2/access.log` (web requests)

2. Run assessment:
   ```bash
   python3 htb_assessment.py report wtmp auth.log access.log
   ```

3. Answer challenge questions:
   - **How many unique users accessed the system?** ✓ From summary
   - **What IPs were used for attacks?** ✓ From suspicious events
   - **Were there privilege escalation attempts?** ✓ From sudo commands
   - **Timeline of attacker activity?** ✓ From events_by_type

## Support & Notes

- Tested with Python 3.8+
- Handles malformed log entries gracefully
- Large files (100MB+) may take time but will complete
- Use `grep` + tool for specific user: `grep admin auth.log | python3 ...`

---

**Status**: Production-ready for HackTheBox forensics challenges.

Ready to assess? Run: `python3 htb_assessment.py report <wtmp> <logs...>`
