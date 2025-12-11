"""
HackTheBox Log Assessment Tool

Unified tool for analyzing:
- Binary wtmp files (login/logout events)
- Text logs (syslog, auth, Apache, etc.)
- Timeline reconstruction
- Security event correlation
- Assessment reporting

Learning concepts:
- Log aggregation and correlation
- Timeline-based analysis
- Event classification
- Threat/risk assessment
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from collections import defaultdict

from wtmp_parser import WtmpParser, UtmpEntry
from grok_matcher import LogParser, GrokPatterns


class LogAssessmentTool:
    """Unified log assessment and analysis tool for HackTheBox."""
    
    def __init__(self, skip_db: bool = True):
        """Initialize assessment tool.
        
        Args:
            skip_db: If True, don't create/use SQLite database (safer for HTB files)
        """
        self.log_parser = LogParser()
        self.grok_matches: List = []
        self.wtmp_sessions: List = []
        self.timeline: List[Dict] = []
        self.events_by_type: Dict = defaultdict(list)
        self.suspicious_events: List = []
        self.skip_db = skip_db
    
    def load_wtmp(self, wtmp_file: str) -> bool:
        """Load and parse wtmp file."""
        try:
            parser = WtmpParser(wtmp_file)
            self.wtmp_sessions = parser.get_login_sessions()
            
            # Add wtmp events to timeline
            for session in self.wtmp_sessions:
                if session['login_time']:
                    self.timeline.append({
                        'timestamp': session['login_time'],
                        'type': 'login',
                        'source': 'wtmp',
                        'user': session['user'],
                        'host': session['host'],
                        'ip': session['ipaddr'],
                        'details': session
                    })
                
                if session['logout_time']:
                    self.timeline.append({
                        'timestamp': session['logout_time'],
                        'type': 'logout',
                        'source': 'wtmp',
                        'user': session['user'],
                        'host': session['host'],
                        'ip': session['ipaddr'],
                        'details': session
                    })
            
            print(f"✓ Loaded wtmp: {len(self.wtmp_sessions)} sessions")
            return True
        
        except Exception as e:
            print(f"✗ Error loading wtmp: {e}")
            return False
    
    def load_log_file(self, log_file: str, pattern_name: Optional[str] = None) -> int:
        """Load and parse text log file."""
        try:
            if pattern_name:
                results = self.log_parser.parse_file(log_file, pattern_name)
            else:
                results = self.log_parser.parse_auto(log_file)
            
            # Add grok matches to timeline
            for result in results:
                self.grok_matches.append(result)
                self.events_by_type[result.pattern_name].append(result)
                
                # Try to extract timestamp
                timestamp_str = result.fields.get('timestamp')
                event = {
                    'timestamp': timestamp_str,
                    'type': result.pattern_name,
                    'source': 'log',
                    'fields': result.fields,
                    'line': result.raw_line
                }
                self.timeline.append(event)
            
            print(f"✓ Loaded {log_file}: {len(results)} matches")
            return len(results)
        
        except Exception as e:
            print(f"✗ Error loading log file: {e}")
            return 0
    
    def analyze_suspicious_patterns(self):
        """Detect suspicious activity patterns."""
        suspicious = []
        
        # Pattern 1: Brute force detection (multiple failed auth attempts from same IP)
        failed_attempts = defaultdict(list)
        for result in self.grok_matches:
            if 'syslog_auth_failed' in result.pattern_name:
                ip = result.fields.get('ip', 'unknown')
                failed_attempts[ip].append(result)
        
        for ip, attempts in failed_attempts.items():
            if len(attempts) > 3:
                suspicious.append({
                    'type': 'brute_force_attack',
                    'severity': 'HIGH',
                    'ip': ip,
                    'attempt_count': len(attempts),
                    'users_targeted': list(set(a.fields.get('user') for a in attempts)),
                    'first_attempt': attempts[0].fields.get('timestamp'),
                    'last_attempt': attempts[-1].fields.get('timestamp')
                })
        
        # Pattern 2: Multiple login sources (impossible travel)
        user_logins = defaultdict(list)
        for session in self.wtmp_sessions:
            user = session['user']
            user_logins[user].append(session)
        
        for user, logins in user_logins.items():
            if len(set(l['ipaddr'] for l in logins)) > 2:
                suspicious.append({
                    'type': 'multi_source_login',
                    'severity': 'MEDIUM',
                    'user': user,
                    'locations': list(set(l['ipaddr'] for l in logins)),
                    'login_count': len(logins)
                })
        
        # Pattern 3: Privilege escalation (sudo commands)
        for result in self.grok_matches:
            if 'sudo_command' in result.pattern_name:
                suspicious.append({
                    'type': 'privilege_escalation',
                    'severity': 'MEDIUM',
                    'user': result.fields.get('user'),
                    'target_user': result.fields.get('target_user'),
                    'command': result.fields.get('command'),
                    'timestamp': result.fields.get('timestamp')
                })
        
        self.suspicious_events = suspicious
        return suspicious
    
    def get_summary(self) -> Dict:
        """Generate assessment summary."""
        # Unique users from wtmp
        wtmp_users = set(s['user'] for s in self.wtmp_sessions if s['user'])
        
        # Unique users from logs
        log_users = set()
        for result in self.grok_matches:
            user = result.fields.get('user')
            if user:
                log_users.add(user)
        
        # Unique IPs
        unique_ips = set()
        for session in self.wtmp_sessions:
            if session['ipaddr'] != '0.0.0.0':
                unique_ips.add(session['ipaddr'])
        
        for result in self.grok_matches:
            ip = result.fields.get('ip')
            if ip:
                unique_ips.add(ip)
        
        return {
            'wtmp_sessions': len(self.wtmp_sessions),
            'log_entries': len(self.grok_matches),
            'timeline_events': len(self.timeline),
            'unique_users_wtmp': sorted(list(wtmp_users)),
            'unique_users_logs': sorted(list(log_users)),
            'unique_ips': sorted(list(unique_ips)),
            'suspicious_events': len(self.suspicious_events),
            'events_by_type': {k: len(v) for k, v in self.events_by_type.items()}
        }
    
    def print_report(self):
        """Print formatted assessment report."""
        summary = self.get_summary()
        suspicious = self.analyze_suspicious_patterns()
        
        print("\n" + "="*80)
        print("HACKTHEBOX LOG ASSESSMENT REPORT")
        print("="*80)
        
        print("\n📊 SUMMARY")
        print(f"  wtmp sessions:        {summary['wtmp_sessions']}")
        print(f"  Log entries parsed:   {summary['log_entries']}")
        print(f"  Timeline events:      {summary['timeline_events']}")
        print(f"  Unique users (wtmp):  {len(summary['unique_users_wtmp'])} - {summary['unique_users_wtmp']}")
        print(f"  Unique users (logs):  {len(summary['unique_users_logs'])} - {summary['unique_users_logs']}")
        print(f"  Unique IPs:           {len(summary['unique_ips'])} - {summary['unique_ips']}")
        print(f"  Suspicious events:    {summary['suspicious_events']}")
        
        print("\n📈 EVENTS BY TYPE")
        for event_type, count in sorted(summary['events_by_type'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {event_type:30} {count:4} events")
        
        if suspicious:
            print("\n⚠️  SUSPICIOUS ACTIVITY DETECTED")
            for event in suspicious:
                event_type = event['type']
                severity = event['severity']
                print(f"\n  [{severity}] {event_type}")
                for key, value in event.items():
                    if key not in ['type', 'severity']:
                        if isinstance(value, list):
                            print(f"    {key}: {', '.join(str(v) for v in value)}")
                        else:
                            print(f"    {key}: {value}")
        else:
            print("\n✓ No suspicious activity detected")
        
        print("\n" + "="*80)
    
    def export_json(self, output_file: str):
        """Export assessment results as JSON."""
        summary = self.get_summary()
        suspicious = self.analyze_suspicious_patterns()
        
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'summary': summary,
            'suspicious_events': suspicious,
            'wtmp_sessions': self.wtmp_sessions,
            'log_matches': [
                {
                    'pattern': r.pattern_name,
                    'fields': r.fields,
                    'line': r.raw_line
                }
                for r in self.grok_matches
            ]
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            print(f"\n✓ Exported to {output_file}")
        except Exception as e:
            print(f"\n✗ Error exporting: {e}")


def main():
    """Main CLI interface."""
    if len(sys.argv) < 2:
        print("Usage: python htb_assessment.py <command> [options]")
        print("\nCommands:")
        print("  analyze_wtmp <wtmp_file>")
        print("  analyze_log <log_file> [pattern]")
        print("  analyze_both <wtmp_file> <log_file>")
        print("  report <wtmp_file> <log_files...>")
        return
    
    command = sys.argv[1]
    tool = LogAssessmentTool()
    
    if command == "analyze_wtmp" and len(sys.argv) > 2:
        tool.load_wtmp(sys.argv[2])
        tool.print_report()
    
    elif command == "analyze_log" and len(sys.argv) > 2:
        pattern = sys.argv[3] if len(sys.argv) > 3 else None
        tool.load_log_file(sys.argv[2], pattern)
        tool.print_report()
    
    elif command == "analyze_both" and len(sys.argv) > 3:
        tool.load_wtmp(sys.argv[2])
        tool.load_log_file(sys.argv[3])
        tool.print_report()
    
    elif command == "report" and len(sys.argv) > 2:
        tool.load_wtmp(sys.argv[2])
        for log_file in sys.argv[3:]:
            tool.load_log_file(log_file)
        tool.print_report()
        tool.export_json("assessment_report.json")
    
    else:
        print("Invalid command or missing arguments")


if __name__ == "__main__":
    main()
