#!/usr/bin/env python3
"""
Interactive Forensics Timeline Viewer

A htop-style interactive tool for investigating wtmp and log files.
Perfect for HTB Sherlock challenges - shows data, doesn't analyze it.

Features:
- Merged timeline view (wtmp + auth logs)
- Keyboard-driven navigation (j/k, search, details)
- Color-coded by event type
- Full data display (no truncation)
- Search/filter by IP, user, timestamp
- Forensics-focused (YOU make conclusions)
"""

import curses
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import argparse
from dataclasses import dataclass

from wtmp_parser import WtmpParser
from grok_matcher import GrokMatcher


@dataclass
class TimelineEvent:
    """Unified timeline event from wtmp or logs."""
    timestamp: datetime
    source: str  # 'wtmp' or 'auth' or 'syslog'
    event_type: str  # 'USER_PROCESS', 'Failed password', etc.
    user: str
    ip: str
    hostname: str
    pid: str
    details: str
    raw: str = ""  # Full original line


class Colors:
    """Color pair constants."""
    DEFAULT = 0
    SUCCESS = 1      # Green - successful logins
    FAILED = 2       # Red - failed attempts
    WARNING = 3      # Yellow - sudo, reboots
    INFO = 4         # Cyan - system events
    SEARCH = 5       # Inverse - search results
    HEADER = 6       # Bold white


class ForensicsViewer:
    """Interactive forensics timeline viewer."""
    
    def __init__(self, stdscr):
        """Initialize viewer."""
        self.stdscr = stdscr
        self.events: List[TimelineEvent] = []
        self.filtered_events: List[TimelineEvent] = []
        
        # UI state
        self.scroll_pos = 0
        self.selected_idx = 0
        self.search_query = ""
        self.search_results = []
        self.search_idx = 0
        self.show_details = False
        self.detail_scroll = 0
        
        # Setup colors
        self._setup_colors()
    
    def _setup_colors(self):
        """Initialize color pairs."""
        curses.init_pair(Colors.SUCCESS, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.FAILED, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(Colors.WARNING, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(Colors.INFO, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(Colors.SEARCH, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(Colors.HEADER, curses.COLOR_WHITE, curses.COLOR_BLUE)
    
    def load_wtmp(self, filepath: str) -> None:
        """Load wtmp file into timeline."""
        try:
            parser = WtmpParser(filepath)
            entries = parser.parse()
            
            for entry in entries:
                if not entry.timestamp:
                    continue
                
                event_type = entry.type_name
                
                event = TimelineEvent(
                    timestamp=entry.timestamp,
                    source='wtmp',
                    event_type=event_type,
                    user=entry.user or '(none)',
                    ip=entry.ip_str or '(local)',
                    hostname=entry.host or entry.id or '?',
                    pid=str(entry.pid) if entry.pid else '?',
                    details=f"TTY: {entry.line} | Type: {event_type}",
                    raw=f"[wtmp] {event_type} - {entry.user}@{entry.host}"
                )
                self.events.append(event)
        except Exception as e:
            raise Exception(f"Error loading wtmp: {e}")
    
    def load_logs(self, filepath: str, pattern: str) -> None:
        """Load log file with grok pattern."""
        try:
            grok = GrokMatcher()
            
            with open(filepath, 'r', errors='ignore') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Try specified pattern first
                match = grok.match(line, pattern)
                
                # Try alternate if auth pattern
                if not match.matched and pattern == 'syslog_auth_success':
                    match = grok.match(line, 'syslog_auth_failed')
                elif not match.matched and pattern == 'syslog_auth_failed':
                    match = grok.match(line, 'syslog_auth_success')
                
                if match.matched:
                    fields = match.fields
                    
                    try:
                        ts_str = fields.get('timestamp', '')
                        # Parse timestamp - handle various formats
                        if ts_str:
                            # Try parsing common syslog format
                            ts = datetime.strptime(ts_str, '%b %d %H:%M:%S') if ' ' in ts_str else None
                            if not ts:
                                ts = datetime.now()
                        else:
                            ts = datetime.now()
                    except:
                        ts = datetime.now()
                    
                    event = TimelineEvent(
                        timestamp=ts,
                        source='auth.log',
                        event_type=pattern,
                        user=fields.get('user', '?'),
                        ip=fields.get('ip', '?'),
                        hostname=fields.get('hostname', '?'),
                        pid=fields.get('pid', '?'),
                        details=f"Auth: {fields.get('auth_type', '?')} | Port: {fields.get('port', '?')}",
                        raw=line
                    )
                    self.events.append(event)
        except Exception as e:
            raise Exception(f"Error loading logs: {e}")
    
    def finalize(self) -> None:
        """Sort events by timestamp and prepare for display."""
        self.events.sort(key=lambda x: x.timestamp)
        self.filtered_events = self.events.copy()
    
    def _get_event_color(self, event: TimelineEvent) -> int:
        """Determine color for event."""
        if 'Accepted' in event.event_type or 'USER_PROCESS' in event.event_type:
            return Colors.SUCCESS
        elif 'Failed' in event.event_type or 'Invalid' in event.event_type:
            return Colors.FAILED
        elif 'sudo' in event.event_type or 'BOOT' in event.event_type or 'RUN_LVL' in event.event_type:
            return Colors.WARNING
        else:
            return Colors.INFO
    
    def search(self, query: str) -> None:
        """Search for events matching query."""
        self.search_query = query.lower()
        self.search_results = []
        
        for idx, event in enumerate(self.filtered_events):
            if (query.lower() in event.user.lower() or
                query.lower() in event.ip.lower() or
                query.lower() in event.hostname.lower() or
                query.lower() in event.event_type.lower()):
                self.search_results.append(idx)
        
        self.search_idx = 0
        if self.search_results:
            self.selected_idx = self.search_results[0]
            self._ensure_visible()
    
    def next_search_result(self) -> None:
        """Jump to next search result."""
        if self.search_results:
            self.search_idx = (self.search_idx + 1) % len(self.search_results)
            self.selected_idx = self.search_results[self.search_idx]
            self._ensure_visible()
    
    def prev_search_result(self) -> None:
        """Jump to previous search result."""
        if self.search_results:
            self.search_idx = (self.search_idx - 1) % len(self.search_results)
            self.selected_idx = self.search_results[self.search_idx]
            self._ensure_visible()
    
    def _ensure_visible(self) -> None:
        """Ensure selected event is visible on screen."""
        height = self.stdscr.getmaxyx()[0] - 4
        if self.selected_idx < self.scroll_pos:
            self.scroll_pos = self.selected_idx
        elif self.selected_idx >= self.scroll_pos + height:
            self.scroll_pos = self.selected_idx - height + 1
    
    def render(self) -> None:
        """Render the entire screen."""
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()
        
        # Minimum width check
        if width < 60 or height < 10:
            self.stdscr.addstr(0, 0, "Terminal too small (need 60x10 minimum)")
            self.stdscr.refresh()
            return
        
        # Header
        header = f" Forensics Timeline Viewer | Events: {len(self.filtered_events)} | Search: {self.search_query or '(none)'}"
        try:
            self.stdscr.attron(curses.color_pair(Colors.HEADER) | curses.A_BOLD)
            self.stdscr.addstr(0, 0, header[:width-1].ljust(width-1))
            self.stdscr.attroff(curses.color_pair(Colors.HEADER) | curses.A_BOLD)
        except:
            pass
        
        # Column headers
        col_header = "  TIMESTAMP         | SRC    | EVENT TYPE       | USER             | IP"
        try:
            self.stdscr.attron(curses.A_BOLD)
            self.stdscr.addstr(1, 0, col_header[:width-1])
            self.stdscr.attroff(curses.A_BOLD)
        except:
            pass
        
        self.stdscr.addstr(2, 0, "─" * min(width, len(col_header)))
        
        # Events
        event_height = height - 4
        for i in range(event_height):
            idx = self.scroll_pos + i
            if idx >= len(self.filtered_events):
                break
            
            event = self.filtered_events[idx]
            is_selected = (idx == self.selected_idx)
            is_search_result = (idx in self.search_results)
            
            # Format event line
            ts = event.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            src = event.source.replace('\x00', '')[:6]
            evt = event.event_type.replace('\x00', '')[:16]
            user = event.user.replace('\x00', '')[:16]
            ip = event.ip.replace('\x00', '')[:15]
            
            line = f"  {ts} | {src:<6} | {evt:<16} | {user:<16} | {ip}"
            line = line[:width-1].ljust(width-1)
            
            # Apply colors
            color_pair = self._get_event_color(event)
            
            try:
                if is_search_result:
                    self.stdscr.attron(curses.color_pair(Colors.SEARCH))
                else:
                    self.stdscr.attron(curses.color_pair(color_pair))
                
                if is_selected:
                    self.stdscr.attron(curses.A_BOLD)
                
                self.stdscr.addstr(3 + i, 0, line)
                
                if is_selected:
                    self.stdscr.attroff(curses.A_BOLD)
                
                if is_search_result:
                    self.stdscr.attroff(curses.color_pair(Colors.SEARCH))
                else:
                    self.stdscr.attroff(curses.color_pair(color_pair))
            except:
                pass  # Silently ignore rendering errors for edge cases
        
        # Footer (use ASCII only, no unicode)
        footer = " j/k:scroll  up/dn:select  /:search  n/N:next/prev  d:details  q:quit  ?:help"
        self.stdscr.attron(curses.A_DIM)
        # Safely write footer, ensuring we don't exceed width
        footer_display = (footer[:width-1]).ljust(width-1)
        try:
            self.stdscr.addstr(height - 1, 0, footer_display)
        except:
            pass  # Silently fail if footer can't be written (edge cases)
        self.stdscr.attroff(curses.A_DIM)
        
        self.stdscr.refresh()
    
    def show_event_details(self) -> None:
        """Show detailed view of selected event."""
        if not self.filtered_events or self.selected_idx >= len(self.filtered_events):
            return
        
        event = self.filtered_events[self.selected_idx]
        height, width = self.stdscr.getmaxyx()
        
        self.stdscr.clear()
        
        # Title
        title = " Event Details (Press q to close)"
        self.stdscr.attron(curses.A_BOLD)
        self.stdscr.addstr(0, 0, title)
        self.stdscr.attroff(curses.A_BOLD)
        
        self.stdscr.addstr(1, 0, "─" * width)
        
        # Event details (strip null bytes from binary data)
        details = [
            f"Timestamp:   {event.timestamp.isoformat()}",
            f"Source:      {event.source.replace(chr(0), '')}",
            f"Event Type:  {event.event_type.replace(chr(0), '')}",
            f"User:        {event.user.replace(chr(0), '')}",
            f"IP Address:  {event.ip.replace(chr(0), '')}",
            f"Hostname:    {event.hostname.replace(chr(0), '')}",
            f"PID:         {event.pid}",
            f"Details:     {event.details.replace(chr(0), '')}",
            "",
            f"Raw Event:   {event.raw.replace(chr(0), '')}",
        ]
        
        for i, line in enumerate(details):
            if 3 + i < height - 1:
                self.stdscr.addstr(3 + i, 2, line[:width-4])
        
        self.stdscr.refresh()
        self.stdscr.getch()
    
    def run(self) -> None:
        """Main event loop."""
        curses.curs_set(0)  # Hide cursor
        
        while True:
            self.render()
            
            key = self.stdscr.getch()
            
            if key == ord('q'):
                break
            elif key == ord('j') or key == curses.KEY_DOWN:
                self.selected_idx = min(self.selected_idx + 1, len(self.filtered_events) - 1)
                self._ensure_visible()
            elif key == ord('k') or key == curses.KEY_UP:
                self.selected_idx = max(self.selected_idx - 1, 0)
                self._ensure_visible()
            elif key == ord('/'):
                curses.curs_set(1)
                self.stdscr.nodelay(0)
                query = self._get_input("Search: ")
                self.stdscr.nodelay(1)
                curses.curs_set(0)
                if query:
                    self.search(query)
            elif key == ord('n'):
                self.next_search_result()
            elif key == ord('N'):
                self.prev_search_result()
            elif key == ord('d'):
                self.show_event_details()
            elif key == ord('?'):
                self._show_help()
    
    def _get_input(self, prompt: str) -> str:
        """Get user input."""
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, prompt)
        self.stdscr.refresh()
        
        input_str = ""
        while True:
            key = self.stdscr.getch()
            if key == 10:  # Enter
                break
            elif key == 27:  # Escape
                return ""
            elif key == curses.KEY_BACKSPACE or key == 8:
                input_str = input_str[:-1]
            elif 32 <= key <= 126:
                input_str += chr(key)
            
            self.stdscr.clear()
            self.stdscr.addstr(0, 0, prompt + input_str)
            self.stdscr.refresh()
        
        return input_str
    
    def _show_help(self) -> None:
        """Show help screen."""
        help_text = [
            "Keyboard Controls:",
            "",
            "j/k or ↑↓          Scroll through events",
            "/                  Search by user, IP, hostname, or event type",
            "n / N              Jump to next/previous search result",
            "d                  Show full details of selected event",
            "?                  Show this help screen",
            "q                  Quit",
            "",
            "Color Legend:",
            "🟢 Green           Successful logins / USER_PROCESS",
            "🔴 Red             Failed attempts / Invalid users",
            "🟡 Yellow          Sudo commands / System events",
            "🔵 Cyan            Info events / Reboots",
        ]
        
        height, width = self.stdscr.getmaxyx()
        self.stdscr.clear()
        
        title = " Help (Press q to close)"
        self.stdscr.attron(curses.A_BOLD)
        self.stdscr.addstr(0, 0, title)
        self.stdscr.attroff(curses.A_BOLD)
        
        for i, line in enumerate(help_text):
            if 2 + i < height - 1:
                self.stdscr.addstr(2 + i, 2, line[:width-4])
        
        self.stdscr.refresh()
        self.stdscr.getch()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Interactive Forensics Timeline Viewer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # View wtmp and auth logs
  python3 interactive_viewer.py --wtmp /path/to/wtmp --log /var/log/auth.log
  
  # View with specific pattern
  python3 interactive_viewer.py --wtmp ./wtmp --log ./auth.log --pattern syslog_auth_failed
  
  # Just wtmp
  python3 interactive_viewer.py --wtmp /var/log/wtmp

Keyboard Controls:
  j/k or arrows    Scroll events
  /                Search (user, IP, hostname, type)
  n / N            Next/previous search result
  d                Show event details
  ?                Help
  q                Quit
        '''
    )
    
    parser.add_argument('--wtmp', help='Path to wtmp file')
    parser.add_argument('--log', help='Path to log file (auth.log, syslog, etc.)')
    parser.add_argument('--pattern', default='syslog_auth_success',
                       choices=['syslog_auth_success', 'syslog_auth_failed', 'sudo_command', 'apache_access'],
                       help='Grok pattern for log file')
    
    args = parser.parse_args()
    
    if not args.wtmp and not args.log:
        parser.print_help()
        sys.exit(1)
    
    def run_viewer(stdscr):
        viewer = ForensicsViewer(stdscr)
        
        try:
            if args.wtmp:
                viewer.load_wtmp(args.wtmp)
            if args.log:
                viewer.load_logs(args.log, args.pattern)
            
            viewer.finalize()
            
            if not viewer.events:
                stdscr.clear()
                stdscr.addstr(0, 0, "No events loaded. Check file paths and patterns.")
                stdscr.refresh()
                stdscr.getch()
                return
            
            viewer.run()
        except Exception as e:
            stdscr.clear()
            stdscr.addstr(0, 0, f"Error: {e}")
            stdscr.refresh()
            stdscr.getch()
    
    curses.wrapper(run_viewer)


if __name__ == '__main__':
    main()
