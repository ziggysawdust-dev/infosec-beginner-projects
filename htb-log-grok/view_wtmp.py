#!/usr/bin/env python3
"""
Simple wtmp file viewer - reads and displays binary wtmp entries.
"""

import struct
import sys
from datetime import datetime
from pathlib import Path


def parse_wtmp(filepath):
    """Parse and display wtmp file."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # wtmp entry size on Linux
        # Try common sizes
        entry_size = 384
        
        print(f"\n{'TIMESTAMP':<20} {'USER':<12} {'TYPE':<15} {'HOST':<20} {'IP':<15}")
        print("─" * 82)
        
        # Parse entries
        offset = 0
        entry_count = 0
        
        while offset + entry_size <= len(data):
            try:
                entry = data[offset:offset+entry_size]
                
                # Extract fields based on Linux utmp structure
                # Offset: type(2), pid(4), line(32), id(4), user(32), host(256), exit(2+2), session(4), time(4), addr(4), reserved(20)
                ut_type = struct.unpack('=H', entry[0:2])[0]
                ut_pid = struct.unpack('=I', entry[2:6])[0]
                ut_line = entry[6:38].rstrip(b'\x00').decode('utf-8', errors='replace')
                ut_id = entry[38:42].rstrip(b'\x00').decode('utf-8', errors='replace')
                ut_user = entry[42:74].rstrip(b'\x00').decode('utf-8', errors='replace')
                ut_host = entry[74:330].rstrip(b'\x00').decode('utf-8', errors='replace')
                
                # Time is at offset 344 (after exit codes, session, and padding)
                time_offset = 344
                ut_time = struct.unpack('=I', entry[time_offset:time_offset+4])[0]
                
                # IP address (4 bytes)
                ip_offset = 348
                ip_bytes = entry[ip_offset:ip_offset+4]
                ip = '.'.join(str(b) for b in ip_bytes)
                
                # Type names
                type_names = {
                    0: 'EMPTY', 1: 'RUN_LVL', 2: 'BOOT_TIME', 3: 'NEW_TIME',
                    4: 'OLD_TIME', 5: 'INIT_PROCESS', 6: 'LOGIN_PROCESS',
                    7: 'USER_PROCESS', 8: 'DEAD_PROCESS', 9: 'ACCOUNTING'
                }
                type_name = type_names.get(ut_type, f'UNKNOWN({ut_type})')
                
                # Skip empty entries
                if ut_type == 0:
                    offset += entry_size
                    continue
                
                # Parse timestamp
                if ut_time > 0:
                    try:
                        timestamp = datetime.fromtimestamp(ut_time)
                        ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                    except (ValueError, OSError):
                        ts_str = '(invalid)'
                        offset += entry_size
                        continue
                    
                    # Display entry if it has a user
                    if ut_user:
                        print(f"{ts_str:<20} {ut_user:<12} {type_name:<15} {ut_host:<20} {ip:<15}")
                        entry_count += 1
                
            except struct.error:
                break
            
            offset += entry_size
        
        if entry_count == 0:
            print("(No valid login records found)")
        else:
            print(f"\n{entry_count} login records displayed")
        
    except Exception as e:
        print(f"Error parsing wtmp: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: view_wtmp.py <wtmp_file>")
        print(f"Example: view_wtmp.py /var/log/wtmp")
        sys.exit(1)
    
    wtmp_file = sys.argv[1]
    if not Path(wtmp_file).exists():
        print(f"Error: File not found: {wtmp_file}", file=sys.stderr)
        sys.exit(1)
    
    parse_wtmp(wtmp_file)
