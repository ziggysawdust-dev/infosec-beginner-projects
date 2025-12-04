"""
Simple Port Scanner
Learn about network security, port scanning, and service detection.

Learning concepts:
- Socket programming
- Network connections
- Port scanning basics
- Service identification
- Ethical hacking fundamentals
"""

import socket
import sys
from datetime import datetime
import threading
from typing import List, Dict


class PortScanner:
    """A simple port scanner for learning network security."""
    
    def __init__(self, host: str, timeout: float = 1.0):
        """
        Initialize scanner.
        
        Args:
            host: Hostname or IP address to scan
            timeout: Connection timeout in seconds
        """
        self.host = host
        self.timeout = timeout
        self.open_ports = []
        self.common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
        }
    
    def resolve_hostname(self) -> str:
        """Resolve hostname to IP address."""
        try:
            ip = socket.gethostbyname(self.host)
            return ip
        except socket.gaierror:
            print(f"❌ Cannot resolve hostname: {self.host}")
            sys.exit(1)
    
    def scan_port(self, port: int) -> bool:
        """
        Scan a single port.
        
        Args:
            port: Port number to scan
            
        Returns:
            True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, port))
            sock.close()
            
            if result == 0:
                return True
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
        
        return False
    
    def scan_ports(self, start_port: int = 1, end_port: int = 1024, 
                   use_threading: bool = False) -> List[Dict]:
        """
        Scan a range of ports.
        
        Args:
            start_port: Starting port number
            end_port: Ending port number
            use_threading: Use threading for faster scanning
            
        Returns:
            List of open ports with service names
        """
        print(f"\n🔍 Scanning {self.host}...")
        print(f"Scanning ports {start_port}-{end_port}")
        print("-" * 50)
        
        results = []
        
        if use_threading:
            threads = []
            for port in range(start_port, end_port + 1):
                thread = threading.Thread(target=self._thread_scan, 
                                        args=(port, results))
                threads.append(thread)
                thread.start()
            
            for thread in threads:
                thread.join()
        else:
            for port in range(start_port, end_port + 1):
                if self.scan_port(port):
                    service = self.common_ports.get(port, "Unknown")
                    results.append({
                        'port': port,
                        'service': service,
                        'status': 'open'
                    })
                    print(f"✅ Port {port:5d} is open - {service}")
        
        return sorted(results, key=lambda x: x['port'])
    
    def _thread_scan(self, port: int, results: List[Dict]):
        """Helper method for threading."""
        if self.scan_port(port):
            service = self.common_ports.get(port, "Unknown")
            results.append({
                'port': port,
                'service': service,
                'status': 'open'
            })
            print(f"✅ Port {port:5d} is open - {service}")
    
    def scan_common_ports(self) -> List[Dict]:
        """Scan only commonly used ports (faster)."""
        print(f"\n🔍 Scanning {self.host} - Common Ports")
        print("-" * 50)
        
        results = []
        for port, service in self.common_ports.items():
            if self.scan_port(port):
                results.append({
                    'port': port,
                    'service': service,
                    'status': 'open'
                })
                print(f"✅ Port {port:5d} is open - {service}")
        
        return results


def main():
    """Main function."""
    print("=" * 60)
    print("🔍 SIMPLE PORT SCANNER")
    print("=" * 60)
    print("\n⚠️  LEGAL WARNING: Only scan computers you own or have")
    print("    explicit permission to scan. Unauthorized scanning is illegal!")
    
    host = input("\nEnter hostname or IP address: ").strip()
    
    if not host:
        print("❌ No host specified!")
        sys.exit(1)
    
    scanner = PortScanner(host, timeout=1.0)
    
    # Resolve and display IP
    print(f"\n📍 Resolving {host}...")
    ip = scanner.resolve_hostname()
    print(f"📍 Target IP: {ip}")
    
    print("\nScan Options:")
    print("1. Scan common ports (faster)")
    print("2. Scan port range")
    
    choice = input("Choose option (1-2): ").strip()
    
    if choice == '1':
        results = scanner.scan_common_ports()
    elif choice == '2':
        start = int(input("Start port (1-65535): ") or "1")
        end = int(input("End port (1-65535): ") or "1024")
        results = scanner.scan_ports(start, end, use_threading=True)
    else:
        print("Invalid choice!")
        sys.exit(1)
    
    # Display results
    print("\n" + "=" * 60)
    print("📊 SCAN RESULTS")
    print("=" * 60)
    
    if results:
        print(f"\n✅ Found {len(results)} open port(s):\n")
        print(f"{'Port':<8} {'Service':<15} {'Status':<10}")
        print("-" * 40)
        for result in results:
            print(f"{result['port']:<8} {result['service']:<15} {result['status']:<10}")
    else:
        print("\n❌ No open ports found or target is unreachable.")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
