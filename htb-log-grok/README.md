# HackTheBox Log Grok Tool

Interactive forensics timeline viewer for HTB Sherlock challenges. Combines wtmp binary files and text logs into a searchable timeline with color-coded events.

**Philosophy:** Show data, don't analyze it. You make the conclusions.

## Features

- **Interactive Timeline**: Htop-style interface for event exploration
- **Merged Timeline**: wtmp and log files combined chronologically  
- **Fast Search**: Find events by user, IP, hostname, or event type
- **Color-Coded**: Green=success, Red=failed, Yellow=warnings, Cyan=info
- **Full Details**: No truncation—see complete event information
- **Binary Parser**: Handles Unix wtmp 384-byte entries
- **Grok Matching**: Pre-defined patterns for SSH, sudo, Apache logs
- **Keyboard-Driven**: Quick navigation with j/k, /, d, q

## Quick Start

```bash
# View wtmp and auth logs together
python3 interactive_viewer.py --wtmp ./wtmp --log ./auth.log

# Just wtmp
python3 interactive_viewer.py --wtmp /var/log/wtmp

# With specific pattern
python3 interactive_viewer.py --wtmp ./wtmp --log ./auth.log --pattern syslog_auth_failed
```

## Keyboard Controls

```
j/k or ↑/↓      Scroll through events
/               Search (user, IP, hostname, event type)
n / N           Jump to next/previous search result
d               Show full details of selected event
?               Help screen
q               Quit
```

## Color Legend

- **🟢 GREEN**: Successful logins (Accepted, USER_PROCESS)
- **🔴 RED**: Failed attempts (Invalid user, Failed password)
- **🟡 YELLOW**: Warnings (sudo commands, reboots, system events)
- **🔵 CYAN**: Info events (sessions, BOOT_TIME, RUN_LVL)

## HTB Sherlock Workflow

1. Launch tool with your challenge files:
   ```bash
   python3 interactive_viewer.py --wtmp ./wtmp --log ./auth.log
   ```

2. See merged timeline of all events

3. Search for suspicious activity (press `/`):
   - Search for attacker IP
   - Search for usernames
   - Look for patterns

4. Identify key events:
   - Failed login attempts (RED)
   - Successful login after failures (GREEN)
   - Privilege escalation (YELLOW)

5. Press `d` on events to see full details with exact timestamps and session info

## Core Modules

### interactive_viewer.py
Main tool—interactive timeline viewer combining wtmp + logs

### wtmp_parser.py
Binary wtmp parser:
```python
from wtmp_parser import WtmpParser
parser = WtmpParser('/var/log/wtmp')
for entry in parser.parse():
    print(f"{entry.timestamp} | {entry.user} | {entry.ip_str}")
```

### grok_matcher.py
Log pattern matcher with built-in patterns:
- `syslog_auth_success`: SSH successful logins
- `syslog_auth_failed`: SSH failed attempts
- `sudo_command`: Privilege escalation
- `apache_access`: Web server logs

```python
from grok_matcher import GrokMatcher
grok = GrokMatcher()
match = grok.match(log_line, 'syslog_auth_success')
if match.matched:
    print(match.fields)  # timestamp, user, ip, port, auth_type, etc.
```

## Supported Patterns

When using `--pattern`:
- `syslog_auth_success`: "Accepted publickey for user X from IP"
- `syslog_auth_failed`: "Invalid user X from IP" or "Failed password"
- `sudo_command`: Privilege escalation with full command details
- `apache_access`: Web server access logs with status codes

## Examples

### Find Brute Force Attempts
```bash
python3 interactive_viewer.py --log ./auth.log --pattern syslog_auth_failed

# Search for attacker IP to see all failed attempts from that source
```

### Track Specific User
```bash
python3 interactive_viewer.py --wtmp ./wtmp --log ./auth.log

# Search for username to see login/logout and activity
```

### Investigate Privilege Escalation
```bash
python3 interactive_viewer.py --log ./auth.log --pattern sudo_command

# See who ran what with sudo
```

## Installation

No external dependencies required (Python stdlib only).

```bash
cd htb-log-grok
python3 interactive_viewer.py --help
```

## Documentation

See `claude.md` for:
- Complete architecture documentation
- Customization and configuration guide
- Troubleshooting tips
- Performance notes
- Development reference

## What You'll Learn

- Binary file format parsing (struct, unpacking)
- Regular expression pattern matching
- Forensics timeline reconstruction
- Interactive terminal UI with curses
- Unix log file formats
- Security event investigation methodology

## Career Relevance

Perfect for **incident response**, **threat hunting**, and **forensics** interviews. Demonstrates:
- ✅ Binary analysis
- ✅ Log analysis
- ✅ Timeline reconstruction
- ✅ Python security tools
- ✅ CLI/UI design
- ✅ Investigation methodology

## Quick Reference

```bash
# Interactive investigation
python3 interactive_viewer.py --wtmp /path/to/wtmp --log /path/to/auth.log

# Parse wtmp programmatically
python3 -c "from wtmp_parser import WtmpParser; \
p = WtmpParser('./wtmp'); \
[print(e.timestamp, e.user, e.ip_str) for e in p.parse()]"

# Test grok pattern
python3 -c "from grok_matcher import GrokMatcher; \
m = GrokMatcher(); \
r = m.match('YOUR_LOG_LINE', 'syslog_auth_success'); \
print('Matched:', r.matched, r.fields)"
```

## Troubleshooting

**"No events loaded"**
- Check file paths: `ls -la <file>`
- Try with `--pattern syslog_auth_success` first

**"No search results"**
- Search is case-insensitive
- Try shorter search term (e.g., `192.168` instead of full IP)
- Press `d` on an event to see exact format

**"Weird timestamps"**
- Corrupted wtmp entries are expected in HTB challenges
- Focus on relative timing and sequences

---

**Ready to investigate?** Run `python3 interactive_viewer.py --help` to get started.
