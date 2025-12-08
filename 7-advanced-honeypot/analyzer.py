"""
Honeypot Analysis & Threat Intelligence Tool
Analyze attack data, generate reports, and identify threat patterns.

Learning concepts:
- Data analysis and pattern detection
- Threat intelligence extraction
- Attack attribution and profiling
- Security intelligence reporting
"""

import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from collections import Counter
import json


class HoneypotAnalyzer:
    """Analyze honeypot attack data and generate intelligence reports."""
    
    def __init__(self, db_file: str = "honeypot.db"):
        """Initialize analyzer."""
        self.db_file = db_file
    
    def _get_connection(self):
        """Get database connection."""
        return sqlite3.connect(self.db_file)
    
    def get_attack_summary(self) -> Dict:
        """Get overall attack summary."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Total attacks
        cursor.execute('SELECT COUNT(*) FROM attack_attempts')
        total_attacks = cursor.fetchone()[0]
        
        # Successful vs failed
        cursor.execute('SELECT success, COUNT(*) FROM attack_attempts GROUP BY success')
        success_stats = dict(cursor.fetchall())
        
        # Date range
        cursor.execute('SELECT MIN(timestamp), MAX(timestamp) FROM attack_attempts')
        date_range = cursor.fetchone()
        
        # Top attack types
        cursor.execute('SELECT attack_type, COUNT(*) as count FROM attack_attempts GROUP BY attack_type ORDER BY count DESC')
        top_attacks = cursor.fetchall()
        
        conn.close()
        
        return {
            'total_attacks': total_attacks,
            'successful': success_stats.get(1, 0),
            'failed': success_stats.get(0, 0),
            'first_attack': date_range[0],
            'last_attack': date_range[1],
            'top_attack_types': top_attacks[:5]
        }
    
    def get_top_attackers(self, limit: int = 10) -> List[Dict]:
        """Get most active attacking IPs."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT source_ip, COUNT(*) as attempt_count
            FROM attack_attempts
            GROUP BY source_ip
            ORDER BY attempt_count DESC
            LIMIT ?
        ''', (limit,))
        
        attackers = []
        for ip, count in cursor.fetchall():
            # Get details for this IP
            cursor.execute('''
                SELECT attack_type, tool_detected, COUNT(*) 
                FROM attack_attempts 
                WHERE source_ip = ?
                GROUP BY attack_type, tool_detected
            ''', (ip,))
            
            details = cursor.fetchall()
            
            # Get deception events for this IP
            cursor.execute('''
                SELECT COUNT(*) FROM deception_events WHERE source_ip = ?
            ''', (ip,))
            deception_count = cursor.fetchone()[0]
            
            attackers.append({
                'ip': ip,
                'total_attempts': count,
                'deception_traps_triggered': deception_count,
                'attack_methods': details
            })
        
        conn.close()
        return attackers
    
    def get_deception_intelligence(self) -> Dict:
        """Analyze deception technology effectiveness."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Canaries triggered
        cursor.execute('''
            SELECT decoy_name, COUNT(*) as count
            FROM deception_events
            WHERE event_type = 'CANARY_TRIGGERED'
            GROUP BY decoy_name
            ORDER BY count DESC
        ''')
        
        canaries = cursor.fetchall()
        
        # Decoys accessed
        cursor.execute('''
            SELECT decoy_name, COUNT(*) as count
            FROM deception_events
            WHERE event_type = 'DECOY_ACCESSED'
            GROUP BY decoy_name
            ORDER BY count DESC
        ''')
        
        decoys = cursor.fetchall()
        
        # Total deception events
        cursor.execute('SELECT COUNT(*) FROM deception_events')
        total_deceptions = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_deception_events': total_deceptions,
            'canaries_triggered': canaries,
            'decoys_accessed': decoys
        }
    
    def get_attack_timeline(self, hours: int = 24) -> List[Tuple]:
        """Get attack timeline for last N hours."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        cursor.execute('''
            SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as count
            FROM attack_attempts
            WHERE timestamp > ?
            GROUP BY hour
            ORDER BY hour
        ''', (cutoff_time.isoformat(),))
        
        timeline = cursor.fetchall()
        conn.close()
        
        return timeline
    
    def detect_attack_patterns(self) -> List[Dict]:
        """Detect suspicious attack patterns."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        patterns = []
        
        # Pattern 1: Multiple failed logins from same IP
        cursor.execute('''
            SELECT source_ip, COUNT(*) as attempts
            FROM attack_attempts
            WHERE attack_type IN ('SSH_AUTH_ATTEMPT', 'TELNET_LOGIN')
            GROUP BY source_ip
            HAVING attempts > 5
            ORDER BY attempts DESC
        ''')
        
        brute_forces = cursor.fetchall()
        if brute_forces:
            patterns.append({
                'pattern': 'Brute Force Attack',
                'severity': 'HIGH',
                'details': brute_forces,
                'description': 'Multiple failed login attempts from same IP'
            })
        
        # Pattern 2: Port scanning (connection to multiple ports)
        cursor.execute('''
            SELECT source_ip, COUNT(DISTINCT target_port) as port_count
            FROM connections
            GROUP BY source_ip
            HAVING port_count > 3
            ORDER BY port_count DESC
        ''')
        
        scanners = cursor.fetchall()
        if scanners:
            patterns.append({
                'pattern': 'Port Scanning',
                'severity': 'MEDIUM',
                'details': scanners,
                'description': 'Single IP scanning multiple ports'
            })
        
        # Pattern 3: Deception trap triggers (sophisticated attacker)
        cursor.execute('''
            SELECT source_ip, COUNT(*) as trap_count
            FROM deception_events
            GROUP BY source_ip
            HAVING trap_count > 0
            ORDER BY trap_count DESC
        ''')
        
        trap_triggers = cursor.fetchall()
        if trap_triggers:
            patterns.append({
                'pattern': 'Deception Trap Engagement',
                'severity': 'HIGH',
                'details': trap_triggers,
                'description': 'Attacker discovered and interacted with decoys'
            })
        
        conn.close()
        return patterns
    
    def get_geo_threat_assessment(self) -> Dict:
        """Assess geographic threat distribution (requires GeoIP data)."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Get unique IPs and their attack counts
        cursor.execute('''
            SELECT source_ip, COUNT(*) as attempts
            FROM attack_attempts
            GROUP BY source_ip
            ORDER BY attempts DESC
        ''')
        
        ips = cursor.fetchall()
        
        # Note: In production, would integrate with GeoIP2, MaxMind, or IP2Location
        # For now, we'll return raw IP data
        
        conn.close()
        
        return {
            'note': 'Integrate with GeoIP database for full geographic analysis',
            'total_unique_ips': len(ips),
            'top_attacking_ips': ips[:10]
        }
    
    def generate_threat_report(self) -> str:
        """Generate comprehensive threat intelligence report."""
        report = []
        report.append("="*80)
        report.append("HONEYPOT THREAT INTELLIGENCE REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("="*80)
        
        # Summary
        report.append("\n📊 ATTACK SUMMARY")
        report.append("-" * 80)
        summary = self.get_attack_summary()
        report.append(f"Total Attacks:              {summary['total_attacks']}")
        report.append(f"Successful Attacks:         {summary['successful']}")
        report.append(f"Failed Attacks:             {summary['failed']}")
        if summary['first_attack']:
            report.append(f"Attack Period:              {summary['first_attack']} to {summary['last_attack']}")
        report.append(f"\nTop Attack Methods:")
        for attack_type, count in summary['top_attack_types']:
            report.append(f"  • {attack_type}: {count} attempts")
        
        # Top Attackers
        report.append("\n\n🎯 TOP ATTACKERS")
        report.append("-" * 80)
        attackers = self.get_top_attackers(limit=5)
        for i, attacker in enumerate(attackers, 1):
            report.append(f"\n{i}. IP: {attacker['ip']}")
            report.append(f"   Total Attempts: {attacker['total_attempts']}")
            report.append(f"   Deception Traps Triggered: {attacker['deception_traps_triggered']}")
            if attacker['attack_methods']:
                report.append(f"   Attack Methods:")
                for method, tool, count in attacker['attack_methods']:
                    report.append(f"     - {method} ({tool}): {count}x")
        
        # Attack Patterns
        report.append("\n\n⚠️  SUSPICIOUS PATTERNS DETECTED")
        report.append("-" * 80)
        patterns = self.detect_attack_patterns()
        if patterns:
            for pattern in patterns:
                report.append(f"\nPattern: {pattern['pattern']}")
                report.append(f"Severity: {pattern['severity']}")
                report.append(f"Description: {pattern['description']}")
                report.append(f"Affected IPs: {len(pattern['details'])}")
                for detail in pattern['details'][:3]:  # Show top 3
                    report.append(f"  • {detail[0]}: {detail[1]} occurrences")
        else:
            report.append("No suspicious patterns detected.")
        
        # Deception Intelligence
        report.append("\n\n🍯 DECEPTION TECHNOLOGY EFFECTIVENESS")
        report.append("-" * 80)
        deception = self.get_deception_intelligence()
        report.append(f"Total Deception Events: {deception['total_deception_events']}")
        
        if deception['canaries_triggered']:
            report.append("\nCanaries Triggered (Fake Credentials):")
            for canary, count in deception['canaries_triggered']:
                report.append(f"  • {canary}: {count}x")
        
        if deception['decoys_accessed']:
            report.append("\nDecoys Accessed (Fake Files/Paths):")
            for decoy, count in deception['decoys_accessed']:
                report.append(f"  • {decoy}: {count}x")
        
        # Attack Timeline
        report.append("\n\n📈 ATTACK TIMELINE (Last 24 Hours)")
        report.append("-" * 80)
        timeline = self.get_attack_timeline(hours=24)
        if timeline:
            for hour, count in timeline:
                bar = "█" * min(count, 40)
                report.append(f"{hour}: {bar} {count} attacks")
        else:
            report.append("No attacks in last 24 hours")
        
        # Recommendations
        report.append("\n\n💡 RECOMMENDATIONS")
        report.append("-" * 80)
        
        top_attack = summary['top_attack_types'][0][0] if summary['top_attack_types'] else "Unknown"
        report.append(f"1. Most Common Attack: {top_attack}")
        report.append("   → Recommendation: Review logs and patch vulnerable services")
        report.append("\n2. Deception Technology Engagement:")
        if deception['total_deception_events'] > 0:
            report.append(f"   → {deception['total_deception_events']} traps triggered")
            report.append("   → Attackers are exploring the system; monitor for escalation")
        else:
            report.append("   → No traps triggered; attackers not probing deep")
        
        report.append("\n3. Geographic Distribution:")
        report.append("   → Consider implementing GeoIP-based rules")
        report.append("   → Review whitelisting policies")
        
        report.append("\n" + "="*80)
        
        return "\n".join(report)


def main():
    """Run analysis."""
    analyzer = HoneypotAnalyzer()
    
    # Print comprehensive report
    print(analyzer.generate_threat_report())
    
    # Save report to file
    report = analyzer.generate_threat_report()
    with open('honeypot_threat_report.txt', 'w') as f:
        f.write(report)
    print("\n✓ Report saved to honeypot_threat_report.txt")


if __name__ == "__main__":
    main()
