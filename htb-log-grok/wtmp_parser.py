"""
Binary wtmp file parser for HackTheBox log assessment.

The wtmp file is a binary log of all user logins/logouts, session durations, 
and connection information. This parser extracts structured event data.

Learning concepts:
- Binary file parsing in Python
- struct unpacking for C-style data
- Unix utmp/wtmp file format
- Session tracking and timeline reconstruction
"""

import struct
import socket
import socket as socket_module
from datetime import datetime
from typing import List, Dict, Tuple
from pathlib import Path


class UtmpEntry:
    """Represents a single utmp/wtmp entry."""
    
    # utmp struct format (Linux 384-byte entry)
    # Offsets: type(0-2), pid(2-6), line(6-38), id(38-42), user(42-74), 
    #          host(74-330), exit(330-334), session(334-338), padding(338-340),
    #          timestamp(340-344), addr(344-348), reserved(348-384)
    
    UTMP_FORMAT = '=hI32s4s32s256sII2sII36s'
    UTMP_SIZE = struct.calcsize(UTMP_FORMAT)
    
    # utmp type constants
    EMPTY = 0
    RUN_LVL = 1
    BOOT_TIME = 2
    NEW_TIME = 3
    OLD_TIME = 4
    INIT_PROCESS = 5
    LOGIN_PROCESS = 6
    USER_PROCESS = 7
    DEAD_PROCESS = 8
    ACCOUNTING = 9
    
    TYPE_NAMES = {
        0: 'EMPTY',
        1: 'RUN_LVL',
        2: 'BOOT_TIME',
        3: 'NEW_TIME',
        4: 'OLD_TIME',
        5: 'INIT_PROCESS',
        6: 'LOGIN_PROCESS',
        7: 'USER_PROCESS',
        8: 'DEAD_PROCESS',
        9: 'ACCOUNTING'
    }
    
    def __init__(self, raw_bytes: bytes):
        """Parse raw wtmp entry bytes."""
        if len(raw_bytes) < self.UTMP_SIZE:
            raise ValueError(f"Entry too small: {len(raw_bytes)} < {self.UTMP_SIZE}")
        
        # Unpack binary data
        data = struct.unpack(self.UTMP_FORMAT, raw_bytes[:self.UTMP_SIZE])
        
        self.type = data[0]
        self.pid = data[1]
        self.line = data[2].rstrip(b'\x00').decode('utf-8', errors='replace')
        self.id = data[3].rstrip(b'\x00').decode('utf-8', errors='replace')
        self.user = data[4].rstrip(b'\x00').decode('utf-8', errors='replace')
        self.host = data[5].rstrip(b'\x00').decode('utf-8', errors='replace')
        self.exit_code = data[6]
        self.session = data[7]
        # data[8] is 2-byte padding
        self.timestamp_raw = data[9]
        addr_int = data[10]
        # data[11] is reserved padding, ignored
        
        # Timestamp (32-bit Unix epoch)
        self.timestamp = datetime.fromtimestamp(self.timestamp_raw) if self.timestamp_raw else None
        
        # IPv4 address (convert from uint32 to dotted notation)
        self.ipaddr = self._int_to_ip(addr_int)
    
    @staticmethod
    def _int_to_ip(ip_int: int) -> str:
        """Convert uint32 to dotted IP notation (little-endian)."""
        if ip_int == 0:
            return '0.0.0.0'
        # Extract bytes in order they appear (little-endian storage)
        return '.'.join(str((ip_int >> (i*8)) & 0xFF) for i in range(4))
    
    @staticmethod
    def _bytes_to_ip(addr_bytes: bytes) -> str:
        """Convert 4 bytes to dotted IP notation."""
        if len(addr_bytes) < 4:
            return '0.0.0.0'
        try:
            return '.'.join(str(b) for b in addr_bytes[:4])
        except (TypeError, ValueError):
            return '0.0.0.0'
    
    @property
    def type_name(self) -> str:
        """Get type name for this entry."""
        return self.TYPE_NAMES.get(self.type, 'UNKNOWN')
    
    @property
    def ip_str(self) -> str:
        """Get IP address as string."""
        return self.ipaddr
    
    def to_dict(self) -> Dict:
        """Convert entry to dictionary."""
        return {
            'type': self.type,
            'type_name': self.TYPE_NAMES.get(self.type, 'UNKNOWN'),
            'pid': self.pid,
            'line': self.line,
            'id': self.id,
            'user': self.user,
            'host': self.host,
            'exit_code': self.exit_code,
            'exit_signal': self.exit_signal,
            'session': self.session,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'ipaddr': self.ipaddr
        }
    
    def __repr__(self):
        return (f"UtmpEntry(user='{self.user}', host='{self.host}', "
                f"type={self.TYPE_NAMES.get(self.type, self.type)}, "
                f"time={self.timestamp})")


class WtmpParser:
    """Parse binary wtmp files."""
    
    def __init__(self, wtmp_file: str):
        """Initialize parser with wtmp file path."""
        self.file_path = Path(wtmp_file)
        if not self.file_path.exists():
            raise FileNotFoundError(f"wtmp file not found: {wtmp_file}")
    
    def parse(self) -> List[UtmpEntry]:
        """Parse all entries from wtmp file."""
        entries = []
        
        try:
            with open(self.file_path, 'rb') as f:
                while True:
                    # Read one entry (UTMP_SIZE bytes)
                    chunk = f.read(UtmpEntry.UTMP_SIZE)
                    if not chunk or len(chunk) < UtmpEntry.UTMP_SIZE:
                        break
                    
                    try:
                        entry = UtmpEntry(chunk)
                        entries.append(entry)
                    except Exception as e:
                        print(f"Warning: Failed to parse entry at offset {f.tell()}: {e}")
        
        except IOError as e:
            print(f"Error reading wtmp file: {e}")
        
        return entries
    
    def get_login_sessions(self) -> List[Dict]:
        """Extract login sessions (LOGIN_PROCESS + USER_PROCESS pairs)."""
        entries = self.parse()
        sessions = []
        
        for i, entry in enumerate(entries):
            # USER_PROCESS: active login
            if entry.type == UtmpEntry.USER_PROCESS and entry.user:
                session = {
                    'user': entry.user,
                    'host': entry.host,
                    'ipaddr': entry.ipaddr,
                    'line': entry.line,
                    'login_time': entry.timestamp,
                    'logout_time': None,
                    'duration_seconds': None,
                    'session_id': entry.session,
                    'pid': entry.pid
                }
                
                # Look for DEAD_PROCESS entry to find logout
                for j in range(i + 1, len(entries)):
                    if (entries[j].type == UtmpEntry.DEAD_PROCESS and
                        entries[j].session == entry.session):
                        session['logout_time'] = entries[j].timestamp
                        if entry.timestamp and entries[j].timestamp:
                            session['duration_seconds'] = (
                                entries[j].timestamp - entry.timestamp
                            ).total_seconds()
                        break
                
                sessions.append(session)
        
        return sessions
    
    def get_reboot_times(self) -> List[Dict]:
        """Extract system reboot events."""
        entries = self.parse()
        reboots = []
        
        for entry in entries:
            if entry.type == UtmpEntry.BOOT_TIME:
                reboots.append({
                    'event': 'BOOT',
                    'timestamp': entry.timestamp,
                    'host': entry.host
                })
            elif entry.type == UtmpEntry.RUN_LVL:
                reboots.append({
                    'event': 'RUN_LEVEL_CHANGE',
                    'timestamp': entry.timestamp,
                    'line': entry.line
                })
        
        return reboots
    
    def get_failed_logins(self) -> List[Dict]:
        """Identify suspicious patterns (incomplete sessions, rapid connects)."""
        sessions = self.get_login_sessions()
        failed = []
        
        for session in sessions:
            # No logout recorded = session still active or abruptly ended
            if session['logout_time'] is None:
                failed.append({
                    'user': session['user'],
                    'host': session['host'],
                    'ip': session['ipaddr'],
                    'login_time': session['login_time'],
                    'reason': 'No logout recorded (still active or abrupt termination)',
                    'session_id': session['session_id']
                })
        
        return failed
    
    def get_summary(self) -> Dict:
        """Get statistical summary of wtmp file."""
        entries = self.parse()
        sessions = self.get_login_sessions()
        reboots = self.get_reboot_times()
        
        # Unique users
        unique_users = set(e.user for e in entries if e.user and e.type == UtmpEntry.USER_PROCESS)
        
        # Unique hosts
        unique_hosts = set(e.host for e in entries if e.host and e.type == UtmpEntry.USER_PROCESS)
        
        # Unique IPs
        unique_ips = set(e.ipaddr for e in entries if e.ipaddr != '0.0.0.0' and e.type == UtmpEntry.USER_PROCESS)
        
        return {
            'total_entries': len(entries),
            'total_sessions': len(sessions),
            'unique_users': len(unique_users),
            'users': sorted(list(unique_users)),
            'unique_hosts': len(unique_hosts),
            'hosts': sorted(list(unique_hosts)),
            'unique_ips': len(unique_ips),
            'ips': sorted(list(unique_ips)),
            'reboot_count': len(reboots),
            'file_size_bytes': self.file_path.stat().st_size
        }


def main():
    """Demo usage."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python wtmp_parser.py <wtmp_file>")
        print("\nExample:")
        print("  python wtmp_parser.py /var/log/wtmp")
        print("  python wtmp_parser.py ./wtmp")
        return
    
    wtmp_file = sys.argv[1]
    
    try:
        parser = WtmpParser(wtmp_file)
        
        # Print summary
        summary = parser.get_summary()
        print("\n=== WTMP Summary ===")
        print(f"Total entries: {summary['total_entries']}")
        print(f"Login sessions: {summary['total_sessions']}")
        print(f"Unique users: {summary['unique_users']} - {summary['users']}")
        print(f"Unique hosts: {summary['unique_hosts']} - {summary['hosts']}")
        print(f"Unique IPs: {summary['unique_ips']} - {summary['ips']}")
        print(f"Reboots detected: {summary['reboot_count']}")
        
        # Print sessions
        print("\n=== Login Sessions ===")
        for session in parser.get_login_sessions()[:10]:
            print(f"User: {session['user']:12} | Host: {session['host']:20} | "
                  f"IP: {session['ipaddr']:15} | Login: {session['login_time']}")
        
        # Print suspicious activity
        print("\n=== Suspicious Activity ===")
        failed = parser.get_failed_logins()
        if failed:
            for event in failed[:10]:
                print(f"User: {event['user']} | Host: {event['host']} | "
                      f"IP: {event['ip']} | {event['reason']}")
        else:
            print("No suspicious patterns detected.")
    
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error parsing wtmp file: {e}")


if __name__ == "__main__":
    main()
