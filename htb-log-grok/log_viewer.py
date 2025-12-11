#!/usr/bin/env python3
"""
Human-readable log and wtmp file viewer with filtering and formatting.

Provides formatted output for:
- wtmp binary login records
- Syslog auth logs
- System logs
- Apache access logs

Features:
- Color-coded output (success/failure/warning)
- Flexible filtering (by date, user, IP, event type)
- Sortable columns
- Summary statistics
- Export to CSV/JSON
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import argparse
import json

# Import our modules
from wtmp_parser import WtmpParser, UtmpEntry
from grok_matcher import GrokMatcher


# ANSI color codes
class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


@dataclass
class LogEntry:
    """Unified log entry for display."""
    timestamp: str
    event_type: str
    user: str
    source_ip: str
    hostname: str
    status: str  # success, failed, warning, info
    details: str
    raw_line: str = ""


class LogViewer:
    """Human-readable log and wtmp viewer."""
    
    def __init__(self, use_colors: bool = True):
        """Initialize viewer."""
        self.use_colors = use_colors
        self.grok = GrokMatcher()
        self.entries: List[LogEntry] = []
    
    def _colorize(self, text: str, color: str) -> str:
        """Apply color to text if colors enabled."""
        if not self.use_colors:
            return text
        return f"{color}{text}{Colors.RESET}"
    
    def _get_status_color(self, status: str) -> str:
        """Get color for status."""
        status_map = {
            'success': Colors.GREEN,
            'failed': Colors.RED,
            'warning': Colors.YELLOW,
            'info': Colors.CYAN,
            'unknown': Colors.DIM,
        }
        return status_map.get(status, Colors.WHITE)
    
    def load_wtmp_file(self, filepath: str) -> None:
        """Load and display wtmp binary file."""
        print(f"\n{self._colorize('═══ WTMP LOGIN RECORDS ═══', Colors.BOLD)}\n")
        print(f"File: {filepath}")
        
        try:
            parser = WtmpParser(filepath)
            entries = parser.parse()
            
            if not entries:
                print("No login records found.")
                return
            
            # Convert to LogEntry format for display
            for entry in entries:
                status = self._get_entry_status(entry)
                log_entry = LogEntry(
                    timestamp=entry.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    event_type='LOGIN' if entry.type_name == 'USER_PROCESS' else entry.type_name,
                    user=entry.user or '(none)',
                    source_ip=entry.ip_str or '(local)',
                    hostname=entry.host or entry.id or '?',
                    status=status,
                    details=f"PID: {entry.pid} | TTY: {entry.line}",
                    raw_line=f"Type: {entry.type_name} | Exit: {entry.exit_status}"
                )
                self.entries.append(log_entry)
            
            self._display_table(self.entries)
            self._display_summary(self.entries)
            
        except Exception as e:
            print(f"{self._colorize('ERROR', Colors.RED)}: {e}")
    
    def load_log_file(self, filepath: str, pattern: str = 'syslog_auth_success') -> None:
        """Load and display log file with grok pattern matching."""
        print(f"\n{self._colorize('═══ SYSTEM LOG ═══', Colors.BOLD)}\n")
        print(f"File: {filepath}")
        print(f"Pattern: {pattern}\n")
        
        try:
            with open(filepath, 'r', errors='ignore') as f:
                lines = f.readlines()
            
            matched = 0
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Try to match with specified pattern first
                match = self.grok.match(line, pattern)
                
                # If no match and pattern is a specific auth pattern, try the other
                if not match.matched:
                    if pattern == 'syslog_auth_success':
                        match = self.grok.match(line, 'syslog_auth_failed')
                    elif pattern == 'syslog_auth_failed':
                        match = self.grok.match(line, 'syslog_auth_success')
                
                if match.matched:
                    matched += 1
                    status = 'success' if pattern == 'syslog_auth_success' else 'failed'
                    
                    fields = match.fields
                    log_entry = LogEntry(
                        timestamp=fields.get('timestamp', '?'),
                        event_type='SSH_AUTH',
                        user=fields.get('user', '?'),
                        source_ip=fields.get('ip', '?'),
                        hostname=fields.get('hostname', '?'),
                        status=status,
                        details=f"Auth Type: {fields.get('auth_type', '?')} | Port: {fields.get('port', '?')}",
                        raw_line=line[:100]
                    )
                    self.entries.append(log_entry)
            
            if self.entries:
                self._display_table(self.entries)
                self._display_summary(self.entries)
                print(f"\nMatched {matched}/{len(lines)} lines with pattern '{pattern}'")
            else:
                print(f"No matches found for pattern '{pattern}'")
                print(f"Scanned {len(lines)} lines")
        
        except FileNotFoundError:
            print(f"{self._colorize('ERROR', Colors.RED)}: File not found: {filepath}")
        except Exception as e:
            print(f"{self._colorize('ERROR', Colors.RED)}: {e}")
    
    def _get_entry_status(self, entry: UtmpEntry) -> str:
        """Determine status of login entry."""
        if entry.exit_status != 0:
            return 'failed'
        elif entry.type_name == 'USER_PROCESS':
            return 'success'
        elif entry.type_name == 'BOOT_TIME':
            return 'info'
        else:
            return 'unknown'
    
    def _display_table(self, entries: List[LogEntry]) -> None:
        """Display entries in formatted table."""
        # Table headers
        headers = ['TIMESTAMP', 'USER', 'EVENT', 'SOURCE IP', 'STATUS', 'HOSTNAME']
        col_widths = [19, 12, 12, 15, 10, 15]
        
        # Print header
        header_line = ' | '.join(h.ljust(w) for h, w in zip(headers, col_widths))
        print(self._colorize(header_line, Colors.BOLD))
        print(self._colorize('─' * (sum(col_widths) + len(headers) * 3 - 1), Colors.DIM))
        
        # Print rows
        for entry in entries:
            status_color = self._get_status_color(entry.status)
            status_colored = self._colorize(entry.status.upper(), status_color)
            
            row = [
                entry.timestamp[:19],
                entry.user[:12],
                entry.event_type[:12],
                entry.source_ip[:15],
                status_colored,
                entry.hostname[:15],
            ]
            
            row_line = ' | '.join(
                (r if i == 4 else r.ljust(w))
                for i, (r, w) in enumerate(zip(row, col_widths))
            )
            print(row_line)
            
            # Print details line
            if entry.details:
                print(f"  └─ {self._colorize(entry.details, Colors.DIM)}")
    
    def _display_summary(self, entries: List[LogEntry]) -> None:
        """Display summary statistics."""
        if not entries:
            return
        
        print(f"\n{self._colorize('─── SUMMARY ───', Colors.DIM)}")
        
        # Count by status
        status_counts = {}
        for entry in entries:
            status_counts[entry.status] = status_counts.get(entry.status, 0) + 1
        
        for status, count in sorted(status_counts.items()):
            color = self._get_status_color(status)
            print(f"  {self._colorize(status.upper(), color)}: {count}")
        
        # Count by user
        user_counts = {}
        for entry in entries:
            user = entry.user
            user_counts[user] = user_counts.get(user, 0) + 1
        
        if len(user_counts) > 1:
            print(f"\n  {self._colorize('Users:', Colors.CYAN)}")
            for user, count in sorted(user_counts.items(), key=lambda x: -x[1])[:5]:
                print(f"    {user}: {count}")
        
        # Count by source IP
        ip_counts = {}
        for entry in entries:
            ip = entry.source_ip
            if ip != '(local)' and ip != '?':
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        if ip_counts:
            print(f"\n  {self._colorize('Top Source IPs:', Colors.CYAN)}")
            for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:5]:
                print(f"    {ip}: {count}")
        
        print()
    
    def filter_entries(self, 
                      user: Optional[str] = None,
                      ip: Optional[str] = None,
                      status: Optional[str] = None,
                      since: Optional[str] = None) -> List[LogEntry]:
        """Filter entries by criteria."""
        filtered = self.entries
        
        if user:
            filtered = [e for e in filtered if user.lower() in e.user.lower()]
        
        if ip:
            filtered = [e for e in filtered if ip in e.source_ip]
        
        if status:
            filtered = [e for e in filtered if e.status == status.lower()]
        
        if since:
            try:
                since_time = datetime.fromisoformat(since)
                filtered = [e for e in filtered if datetime.fromisoformat(e.timestamp) >= since_time]
            except ValueError:
                print(f"Invalid datetime format: {since}. Use YYYY-MM-DD HH:MM:SS")
        
        return filtered
    
    def export_json(self, filepath: str, entries: Optional[List[LogEntry]] = None) -> None:
        """Export entries to JSON."""
        to_export = entries or self.entries
        
        data = [
            {
                'timestamp': e.timestamp,
                'event_type': e.event_type,
                'user': e.user,
                'source_ip': e.source_ip,
                'hostname': e.hostname,
                'status': e.status,
                'details': e.details,
            }
            for e in to_export
        ]
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Exported {len(data)} entries to {filepath}")
    
    def export_csv(self, filepath: str, entries: Optional[List[LogEntry]] = None) -> None:
        """Export entries to CSV."""
        to_export = entries or self.entries
        
        import csv
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=['timestamp', 'event_type', 'user', 'source_ip', 'hostname', 'status', 'details']
            )
            writer.writeheader()
            
            for e in to_export:
                writer.writerow({
                    'timestamp': e.timestamp,
                    'event_type': e.event_type,
                    'user': e.user,
                    'source_ip': e.source_ip,
                    'hostname': e.hostname,
                    'status': e.status,
                    'details': e.details,
                })
        
        print(f"Exported {len(to_export)} entries to {filepath}")


def main():
    """Command-line interface."""
    parser = argparse.ArgumentParser(
        description='Human-readable log and wtmp file viewer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # View wtmp file
  python3 log_viewer.py wtmp /var/log/wtmp
  
  # View syslog auth file
  python3 log_viewer.py log /var/log/auth.log --pattern syslog_auth_success
  
  # View and filter by user
  python3 log_viewer.py log /var/log/auth.log --user root
  
  # View and filter by IP
  python3 log_viewer.py log /var/log/auth.log --ip 192.168
  
  # Export to JSON
  python3 log_viewer.py log /var/log/auth.log --export-json report.json
        '''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Wtmp command
    wtmp_parser = subparsers.add_parser('wtmp', help='View wtmp file')
    wtmp_parser.add_argument('file', help='Path to wtmp file')
    wtmp_parser.add_argument('--user', help='Filter by username')
    wtmp_parser.add_argument('--ip', help='Filter by source IP')
    wtmp_parser.add_argument('--status', choices=['success', 'failed'], help='Filter by status')
    wtmp_parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    wtmp_parser.add_argument('--export-json', help='Export to JSON file')
    wtmp_parser.add_argument('--export-csv', help='Export to CSV file')
    
    # Log command
    log_parser = subparsers.add_parser('log', help='View log file with pattern matching')
    log_parser.add_argument('file', help='Path to log file')
    log_parser.add_argument('--pattern', default='syslog_auth_success',
                           choices=['syslog_auth_success', 'syslog_auth_failed', 'sudo_command', 'apache_access'],
                           help='Grok pattern to use')
    log_parser.add_argument('--user', help='Filter by username')
    log_parser.add_argument('--ip', help='Filter by source IP')
    log_parser.add_argument('--status', choices=['success', 'failed'], help='Filter by status')
    log_parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    log_parser.add_argument('--export-json', help='Export to JSON file')
    log_parser.add_argument('--export-csv', help='Export to CSV file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize viewer
    viewer = LogViewer(use_colors=not args.no_color)
    
    # Load file
    if args.command == 'wtmp':
        viewer.load_wtmp_file(args.file)
    elif args.command == 'log':
        viewer.load_log_file(args.file, args.pattern)
    
    # Apply filters
    filtered_entries = viewer.filter_entries(
        user=getattr(args, 'user', None),
        ip=getattr(args, 'ip', None),
        status=getattr(args, 'status', None)
    )
    
    if filtered_entries != viewer.entries:
        print(f"\n{Colors.CYAN}Filtered to {len(filtered_entries)} entries{Colors.RESET}\n")
        viewer._display_table(filtered_entries)
    
    # Export if requested
    if hasattr(args, 'export_json') and args.export_json:
        viewer.export_json(args.export_json, filtered_entries or viewer.entries)
    
    if hasattr(args, 'export_csv') and args.export_csv:
        viewer.export_csv(args.export_csv, filtered_entries or viewer.entries)


if __name__ == '__main__':
    main()
