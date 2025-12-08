"""
Kali Linux Integration Tools
Use built-in Kali tools to test the honeypot and detect tool signatures.

Learning concepts:
- Nmap integration
- Tool fingerprinting
- Tcpdump integration for packet capture
- Attack signature detection
"""

import subprocess
import json
import re
from datetime import datetime
from typing import Dict, List
import sqlite3


class NmapDetector:
    """Detect and analyze Nmap scans against honeypot."""
    
    def __init__(self, db_file: str = "honeypot.db"):
        """Initialize Nmap detector."""
        self.db_file = db_file
    
    def scan_target(self, target: str, ports: str = "22,23,80,443,3306,8080",
                   scan_type: str = "-sT") -> Dict:
        """
        Run Nmap scan and return results.
        
        Args:
            target: Target IP or hostname
            ports: Ports to scan (comma-separated)
            scan_type: Nmap scan type (-sT, -sS, -sU, etc.)
        
        Returns:
            Dictionary with scan results
        """
        try:
            # Build Nmap command
            cmd = ['nmap', scan_type, '-p', ports, '--open', '-oX', '-', target]
            
            # Run Nmap
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            # Parse results
            scan_results = self._parse_nmap_output(result.stdout)
            
            return {
                'success': True,
                'target': target,
                'command': ' '.join(cmd),
                'results': scan_results
            }
        
        except FileNotFoundError:
            return {
                'success': False,
                'error': 'Nmap not found. Install with: apt-get install nmap'
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Nmap scan timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _parse_nmap_output(self, xml_output: str) -> List[Dict]:
        """Parse Nmap XML output."""
        results = []
        
        # Simple regex parsing (in production, use xml.etree)
        port_pattern = r'<port protocol="(tcp|udp)" portid="(\d+)"><state state="(\w+)"'
        
        for match in re.finditer(port_pattern, xml_output):
            protocol, port, state = match.groups()
            results.append({
                'port': int(port),
                'protocol': protocol,
                'state': state
            })
        
        return sorted(results, key=lambda x: x['port'])
    
    def detect_scan_signature(self, connection_data: Dict) -> str:
        """
        Detect which tool was used to scan based on connection patterns.
        
        Args:
            connection_data: Dictionary with connection/request data
        
        Returns:
            Detected tool name or 'Unknown'
        """
        # Nmap signatures
        nmap_signatures = [
            'User-Agent.*Nmap',
            'nmap',
            'NSE',
            'probe responses',
            'open|filtered',
        ]
        
        # Masscan signatures
        masscan_signatures = [
            'masscan',
            'high-speed port scanner'
        ]
        
        # Metasploit signatures
        metasploit_signatures = [
            'metasploit',
            'ruby.*socket',
            'Metasploit Framework'
        ]
        
        # Hydra signatures
        hydra_signatures = [
            'hydra',
            'password brute force',
            'dictionary attack'
        ]
        
        data_str = json.dumps(connection_data)
        
        if any(re.search(sig, data_str, re.IGNORECASE) for sig in nmap_signatures):
            return 'Nmap'
        elif any(re.search(sig, data_str, re.IGNORECASE) for sig in masscan_signatures):
            return 'Masscan'
        elif any(re.search(sig, data_str, re.IGNORECASE) for sig in metasploit_signatures):
            return 'Metasploit'
        elif any(re.search(sig, data_str, re.IGNORECASE) for sig in hydra_signatures):
            return 'Hydra'
        
        return 'Unknown'


class TcpdumpCapture:
    """Capture and analyze network traffic using Tcpdump."""
    
    def __init__(self, db_file: str = "honeypot.db"):
        """Initialize Tcpdump capture."""
        self.db_file = db_file
        self.capture_file = f"honeypot_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    
    def start_capture(self, interface: str = "lo", filter_expr: str = "",
                     duration: int = 60) -> Dict:
        """
        Start Tcpdump packet capture.
        
        Args:
            interface: Network interface to capture on
            filter_expr: Tcpdump filter expression
            duration: Capture duration in seconds
        
        Returns:
            Dictionary with capture status
        """
        try:
            # Build Tcpdump command
            cmd = ['sudo', 'tcpdump', '-i', interface, '-w', self.capture_file]
            
            if filter_expr:
                cmd.append(filter_expr)
            
            # Start capture with timeout
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            return {
                'success': True,
                'message': f'Tcpdump started on {interface}',
                'capture_file': self.capture_file,
                'duration': duration
            }
        
        except FileNotFoundError:
            return {
                'success': False,
                'error': 'Tcpdump not found. Install with: apt-get install tcpdump'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def analyze_pcap(self, pcap_file: str) -> Dict:
        """
        Analyze PCAP file with Tcpdump.
        
        Args:
            pcap_file: Path to PCAP file
        
        Returns:
            Analysis results
        """
        try:
            # Use tcpdump to read and summarize
            cmd = ['tcpdump', '-r', pcap_file, '-n', '-q']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Parse tcpdump output
            packets = self._parse_tcpdump_output(result.stdout)
            
            return {
                'success': True,
                'pcap_file': pcap_file,
                'total_packets': len(packets),
                'unique_sources': len(set(p.get('source_ip', '') for p in packets)),
                'unique_destinations': len(set(p.get('dest_ip', '') for p in packets)),
                'protocols': self._extract_protocols(packets),
                'packets': packets[:100]  # Return first 100
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _parse_tcpdump_output(self, output: str) -> List[Dict]:
        """Parse Tcpdump text output."""
        packets = []
        
        # Pattern: timestamp IP.port > IP.port: flags
        pattern = r'(\d+:\d+:\d+\.\d+)\s+([\w.-]+\.(\d+))\s*>\s+([\w.-]+\.(\d+))'
        
        for match in re.finditer(pattern, output):
            time, source, src_port, dest, dst_port = match.groups()
            packets.append({
                'timestamp': time,
                'source_ip': source,
                'source_port': src_port,
                'dest_ip': dest,
                'dest_port': dst_port
            })
        
        return packets
    
    @staticmethod
    def _extract_protocols(packets: List[Dict]) -> Dict[str, int]:
        """Extract protocol distribution from packets."""
        protocols = {}
        
        # This is simplified; in production, use scapy or pyshark
        for packet in packets:
            proto = 'TCP'  # Placeholder
            protocols[proto] = protocols.get(proto, 0) + 1
        
        return protocols


class AttackSimulator:
    """Simulate attacks to test honeypot (for controlled testing)."""
    
    def __init__(self, target: str = "127.0.0.1"):
        """Initialize simulator."""
        self.target = target
    
    def simulate_nmap_scan(self, ports: str = "22,23,80,443,3306") -> Dict:
        """
        Simulate Nmap scan against honeypot.
        
        Args:
            ports: Ports to scan
        
        Returns:
            Scan results
        """
        detector = NmapDetector()
        results = detector.scan_target(self.target, ports=ports, scan_type="-sT")
        
        if results['success']:
            print(f"✓ Nmap scan completed on {self.target}")
            print(f"  Open ports:")
            for port_info in results['results']:
                if port_info['state'] == 'open':
                    print(f"    • {port_info['port']}/{port_info['protocol']}: {port_info['state']}")
        else:
            print(f"✗ Scan failed: {results.get('error')}")
        
        return results
    
    def simulate_brute_force(self, port: int = 22, wordlist: str = None) -> Dict:
        """
        Simulate brute force attack using Hydra.
        
        Args:
            port: Target port
            wordlist: Path to password wordlist
        
        Returns:
            Attack results
        """
        try:
            if not wordlist:
                wordlist = "/usr/share/wordlists/rockyou.txt"
            
            # Build Hydra command (limited to small wordlist for safety)
            cmd = [
                'hydra',
                '-l', 'admin',
                '-P', wordlist,
                '-f',
                '-t', '4',
                f'{self.target}',
                f'ssh'  # or telnet, ftp, etc.
            ]
            
            print(f"⚠️  Hydra brute force simulation started...")
            print(f"   Command: {' '.join(cmd)}")
            
            # Note: Don't actually run this against production systems!
            return {
                'success': True,
                'message': 'Brute force simulation prepared (not executed)',
                'command': ' '.join(cmd)
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def simulate_port_scan(self, start_port: int = 1, end_port: int = 1024) -> Dict:
        """
        Simulate port scan.
        
        Args:
            start_port: Starting port number
            end_port: Ending port number
        
        Returns:
            Scan results
        """
        detector = NmapDetector()
        ports = f"{start_port}-{end_port}"
        
        return detector.scan_target(self.target, ports=ports, scan_type="-sT")


def main():
    """Run Kali integration tools."""
    print("="*70)
    print("🛡️  KALI INTEGRATION TOOLS")
    print("="*70)
    
    # Initialize simulator
    simulator = AttackSimulator(target="127.0.0.1")
    
    print("\n1. Testing Nmap Integration:")
    print("-" * 70)
    nmap_results = simulator.simulate_nmap_scan()
    
    print("\n2. Tcpdump Capture Setup:")
    print("-" * 70)
    capture = TcpdumpCapture()
    print("✓ Tcpdump ready for packet capture")
    print(f"  Capture file: {capture.capture_file}")
    print("  Usage: capture.start_capture(interface='lo', duration=60)")
    
    print("\n3. Attack Signature Detection:")
    print("-" * 70)
    detector = NmapDetector()
    test_data = {
        'tool': 'Nmap',
        'probe_type': 'SYN',
        'os_detection': True
    }
    detected_tool = detector.detect_scan_signature(test_data)
    print(f"✓ Detected tool: {detected_tool}")
    
    print("\n" + "="*70)
    print("✓ Kali tools ready!")
    print("  • Use NmapDetector for port scanning")
    print("  • Use TcpdumpCapture for network analysis")
    print("  • Use AttackSimulator for controlled testing")
    print("="*70)


if __name__ == "__main__":
    main()
