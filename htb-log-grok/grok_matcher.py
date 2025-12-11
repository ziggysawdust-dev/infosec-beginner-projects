"""
Grok-like pattern matcher for HackTheBox log assessment.

Implements simplified grok pattern matching for common log formats:
- syslog (auth.log, syslog)
- Apache/Nginx access/error logs
- Application-specific logs
- Custom regex patterns

Learning concepts:
- Regular expression matching and extraction
- Pattern definition and composition
- Structured log parsing
- Event classification
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Pattern
from dataclasses import dataclass


@dataclass
class GrokMatch:
    """Result of a grok pattern match."""
    matched: bool
    fields: Dict[str, str]
    raw_line: str
    pattern_name: str
    
    def __repr__(self):
        return f"GrokMatch(pattern={self.pattern_name}, matched={self.matched}, fields={len(self.fields)})"


class GrokPatterns:
    """Pre-defined grok patterns for common log formats."""
    
    # Time patterns
    TIMESTAMP_ISO8601 = r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)'
    TIMESTAMP_SYSLOG = r'(?P<timestamp>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
    TIMESTAMP_UNIX = r'(?P<timestamp>\d{10})'
    
    # Network patterns
    IP_ADDRESS = r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    HOSTNAME = r'(?P<hostname>[\w\-\.]+)'
    PORT = r'(?P<port>\d{1,5})'
    
    # Auth patterns
    USER = r'(?P<user>[\w\-\.]+)'
    PASSWORD = r'(?P<password>[\S]+)'
    
    # HTTP patterns
    HTTP_METHOD = r'(?P<http_method>GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)'
    HTTP_STATUS = r'(?P<http_status>\d{3})'
    URL_PATH = r'(?P<url_path>/[\S]*)'
    
    # Custom patterns
    TTY = r'(?P<tty>tty\d+|pts/\d+|console|unknown)'
    
    # Pre-built common patterns
    SYSLOG_AUTH_SUCCESS = (
        r'(?P<timestamp>\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>[\w\-\.]+)\s+'
        r'sshd\[(?P<pid>\d+)\]:\s+'
        r'Accepted (?P<auth_type>\w+) for (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<port>\d+)'
    )
    
    SYSLOG_AUTH_FAILED = (
        r'(?P<timestamp>\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>[\w\-\.]+)\s+'
        r'sshd\[(?P<pid>\d+)\]:\s+'
        r'Invalid user (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<port>\d+)'
    )
    
    SUDO_COMMAND = (
        r'(?P<timestamp>\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>[\w\-\.]+)\s+'
        r'sudo:\s+(?P<user>\w+)\s+:\s+TTY=(?P<tty>[\w/\-]+)\s+;\s+PWD=(?P<pwd>[^\s]+)\s+;\s+'
        r'USER=(?P<target_user>\w+)\s+;\s+COMMAND=(?P<command>.+)$'
    )
    
    APACHE_ACCESS = (
        r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
        r'(?P<ident>\S+)\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<url_path>\S+)\s+(?P<http_version>HTTP/[\d\.]+)"\s+'
        r'(?P<http_status>\d{3})\s+(?P<bytes>\d+)'
    )
    
    @classmethod
    def get_all_patterns(cls) -> Dict[str, str]:
        """Return all pre-defined patterns."""
        return {
            'syslog_auth_success': cls.SYSLOG_AUTH_SUCCESS,
            'syslog_auth_failed': cls.SYSLOG_AUTH_FAILED,
            'sudo_command': cls.SUDO_COMMAND,
            'apache_access': cls.APACHE_ACCESS,
        }


class GrokMatcher:
    """Grok pattern matcher for log parsing."""
    
    def __init__(self):
        """Initialize matcher with predefined patterns."""
        self.patterns: Dict[str, Pattern] = {}
        self.register_patterns(GrokPatterns.get_all_patterns())
    
    def register_pattern(self, name: str, pattern: str):
        """Register a new grok pattern."""
        try:
            compiled = re.compile(pattern)
            self.patterns[name] = compiled
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{name}': {e}")
    
    def register_patterns(self, patterns: Dict[str, str]):
        """Register multiple patterns."""
        for name, pattern in patterns.items():
            self.register_pattern(name, pattern)
    
    def match(self, line: str, pattern_name: str) -> GrokMatch:
        """Match a line against a registered pattern."""
        if pattern_name not in self.patterns:
            return GrokMatch(matched=False, fields={}, raw_line=line, pattern_name=pattern_name)
        
        pattern = self.patterns[pattern_name]
        match = pattern.search(line)
        
        if match:
            return GrokMatch(
                matched=True,
                fields=match.groupdict(),
                raw_line=line,
                pattern_name=pattern_name
            )
        else:
            return GrokMatch(matched=False, fields={}, raw_line=line, pattern_name=pattern_name)
    
    def match_any(self, line: str, pattern_names: List[str]) -> Optional[GrokMatch]:
        """Try to match against multiple patterns, return first match."""
        for pattern_name in pattern_names:
            result = self.match(line, pattern_name)
            if result.matched:
                return result
        return None
    
    def match_all(self, line: str) -> List[GrokMatch]:
        """Try to match against all registered patterns."""
        results = []
        for pattern_name in self.patterns.keys():
            result = self.match(line, pattern_name)
            if result.matched:
                results.append(result)
        return results


class LogParser:
    """Parse and analyze log files using grok patterns."""
    
    def __init__(self):
        """Initialize log parser."""
        self.matcher = GrokMatcher()
        self.events: List[Dict] = []
    
    def parse_file(self, log_file: str, pattern_name: str) -> List[GrokMatch]:
        """Parse log file with a specific pattern."""
        results = []
        
        try:
            with open(log_file, 'r', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    result = self.matcher.match(line.strip(), pattern_name)
                    if result.matched:
                        result.fields['_line_num'] = str(line_num)
                        results.append(result)
        except FileNotFoundError:
            print(f"Error: File not found - {log_file}")
        except IOError as e:
            print(f"Error reading file: {e}")
        
        return results
    
    def parse_auto(self, log_file: str) -> List[GrokMatch]:
        """Auto-detect log format and parse."""
        results = []
        
        # Try to auto-detect format by sampling first few lines
        try:
            with open(log_file, 'r', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Try all patterns
                    for pattern_name in self.matcher.patterns.keys():
                        result = self.matcher.match(line, pattern_name)
                        if result.matched:
                            result.fields['_line_num'] = str(line_num)
                            results.append(result)
        
        except Exception as e:
            print(f"Error parsing file: {e}")
        
        return results
    
    def filter_events(self, results: List[GrokMatch], filter_key: str, 
                     filter_value: str) -> List[GrokMatch]:
        """Filter parsed events by field value."""
        filtered = []
        for result in results:
            if result.fields.get(filter_key) == filter_value:
                filtered.append(result)
        return filtered
    
    def extract_field(self, results: List[GrokMatch], field_name: str) -> List[str]:
        """Extract specific field from all matches."""
        values = []
        for result in results:
            if field_name in result.fields:
                values.append(result.fields[field_name])
        return values
    
    def get_unique_values(self, results: List[GrokMatch], field_name: str) -> set:
        """Get unique values for a field."""
        return set(self.extract_field(results, field_name))


def main():
    """Demo usage."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python grok_matcher.py <log_file> [pattern_name]")
        print("\nAvailable patterns:")
        for name in GrokPatterns.get_all_patterns().keys():
            print(f"  - {name}")
        return
    
    log_file = sys.argv[1]
    pattern_name = sys.argv[2] if len(sys.argv) > 2 else None
    
    parser = LogParser()
    
    if pattern_name:
        # Parse with specific pattern
        results = parser.parse_file(log_file, pattern_name)
        print(f"\n=== Parsed with '{pattern_name}' ===")
        print(f"Matched {len(results)} lines\n")
        
        for result in results[:10]:
            print(f"Line {result.fields.get('_line_num')}: {result.fields}")
    else:
        # Auto-detect and parse
        results = parser.parse_auto(log_file)
        print(f"\n=== Auto-detected patterns ===")
        print(f"Total matches: {len(results)}\n")
        
        # Show stats
        pattern_stats = {}
        for result in results:
            pattern_name = result.pattern_name
            pattern_stats[pattern_name] = pattern_stats.get(pattern_name, 0) + 1
        
        print("Matches by pattern:")
        for pattern, count in sorted(pattern_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {pattern}: {count}")
        
        print("\nFirst 10 matches:")
        for result in results[:10]:
            print(f"  {result.pattern_name}: {result.fields}")


if __name__ == "__main__":
    main()
