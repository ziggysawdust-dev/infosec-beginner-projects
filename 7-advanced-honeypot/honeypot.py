"""
Advanced Honeypot with Deception Technology
Learn about threat detection, attacker behavior analysis, and deception tactics.

Learning concepts:
- Multi-port service emulation
- Attack detection and logging
- Deception technology (canaries, decoys, fake data)
- Threat intelligence extraction
- Attack pattern analysis
- Network security monitoring
"""

import socket
import threading
import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
import hashlib
import random
import string


class HoneypotDatabase:
    """Manage honeypot attack data storage and queries."""
    
    def __init__(self, db_file: str = "honeypot.db"):
        """Initialize honeypot database."""
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Create database schema."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Connection attempts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                target_port INTEGER,
                service TEXT,
                protocol TEXT,
                data_sent TEXT,
                data_received TEXT,
                duration_seconds REAL,
                threat_level TEXT
            )
        ''')
        
        # Attack attempts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_attempts (
                id INTEGER PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                attack_type TEXT,
                tool_detected TEXT,
                payload TEXT,
                response TEXT,
                success BOOLEAN
            )
        ''')
        
        # Deception events (canaries triggered)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS deception_events (
                id INTEGER PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                event_type TEXT,
                decoy_name TEXT,
                decoy_type TEXT,
                attacker_action TEXT,
                alert_sent BOOLEAN
            )
        ''')
        
        # Attacker profiles
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacker_profiles (
                id INTEGER PRIMARY KEY,
                source_ip TEXT UNIQUE,
                first_seen DATETIME,
                last_seen DATETIME,
                attack_count INTEGER DEFAULT 1,
                tools_detected TEXT,
                techniques TEXT,
                threat_level TEXT,
                geographic_location TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_connection(self, source_ip: str, source_port: int, target_port: int,
                      service: str, protocol: str, data_sent: str, 
                      data_received: str, duration: float, threat_level: str):
        """Log a connection attempt."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO connections 
            (source_ip, source_port, target_port, service, protocol, 
             data_sent, data_received, duration_seconds, threat_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (source_ip, source_port, target_port, service, protocol,
              data_sent, data_received, duration, threat_level))
        
        conn.commit()
        conn.close()
    
    def log_attack(self, source_ip: str, attack_type: str, tool_detected: str,
                  payload: str, response: str, success: bool):
        """Log an attack attempt."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO attack_attempts
            (source_ip, attack_type, tool_detected, payload, response, success)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (source_ip, attack_type, tool_detected, payload, response, success))
        
        conn.commit()
        conn.close()
    
    def log_deception_event(self, source_ip: str, event_type: str, 
                           decoy_name: str, decoy_type: str, 
                           attacker_action: str, alert_sent: bool = True):
        """Log when a deception trap (canary) is triggered."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO deception_events
            (source_ip, event_type, decoy_name, decoy_type, attacker_action, alert_sent)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (source_ip, event_type, decoy_name, decoy_type, attacker_action, alert_sent))
        
        conn.commit()
        conn.close()
    
    def update_attacker_profile(self, source_ip: str, tool: str = None, technique: str = None):
        """Update or create attacker profile."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM attacker_profiles WHERE source_ip = ?', (source_ip,))
        existing = cursor.fetchone()
        
        if existing:
            attack_count = existing[4] + 1
            cursor.execute('''
                UPDATE attacker_profiles
                SET last_seen = CURRENT_TIMESTAMP,
                    attack_count = ?
                WHERE source_ip = ?
            ''', (attack_count, source_ip))
        else:
            cursor.execute('''
                INSERT INTO attacker_profiles
                (source_ip, first_seen, last_seen, tools_detected, threat_level)
                VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, 'MEDIUM')
            ''', (source_ip, tool or "Unknown"))
        
        conn.commit()
        conn.close()


class DeceptionTechnology:
    """Implement deception tactics to trap and analyze attackers."""
    
    def __init__(self, db: HoneypotDatabase):
        """Initialize deception tech."""
        self.db = db
        self.canaries = self._create_canaries()
        self.decoys = self._create_decoys()
    
    def _create_canaries(self) -> Dict:
        """Create fake credentials and sensitive data to detect access."""
        return {
            'creds_admin': {
                'username': 'admin',
                'password': 'SuperSecret!2024',
                'type': 'credential',
                'honeypot_id': self._generate_token(),
                'created': datetime.now().isoformat()
            },
            'creds_root': {
                'username': 'root',
                'password': 'RootPassword123!',
                'type': 'credential',
                'honeypot_id': self._generate_token(),
                'created': datetime.now().isoformat()
            },
            'creds_mysql': {
                'username': 'mysql',
                'password': 'mysqlpass123',
                'type': 'credential',
                'honeypot_id': self._generate_token(),
                'created': datetime.now().isoformat()
            },
            'api_key_aws': {
                'key': 'AKIAIOSFODNN7EXAMPLE',
                'secret': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                'type': 'api_key',
                'honeypot_id': self._generate_token(),
                'created': datetime.now().isoformat()
            },
            'api_key_github': {
                'token': 'ghp_' + ''.join(random.choices(string.ascii_letters + string.digits, k=36)),
                'type': 'token',
                'honeypot_id': self._generate_token(),
                'created': datetime.now().isoformat()
            }
        }
    
    def _create_decoys(self) -> Dict:
        """Create fake files and directories to detect exploration."""
        return {
            'fake_backup': {
                'path': '/home/user/backup_2024.tar.gz',
                'type': 'file',
                'description': 'Fake database backup',
                'honeypot_id': self._generate_token()
            },
            'fake_config': {
                'path': '/etc/app/config.conf',
                'type': 'file',
                'description': 'Fake app configuration with credentials',
                'honeypot_id': self._generate_token()
            },
            'fake_private_key': {
                'path': '/home/user/.ssh/id_rsa',
                'type': 'file',
                'description': 'Fake SSH private key',
                'honeypot_id': self._generate_token()
            },
            'fake_docker_socket': {
                'path': '/var/run/docker.sock',
                'type': 'socket',
                'description': 'Fake Docker socket',
                'honeypot_id': self._generate_token()
            }
        }
    
    def check_canary_triggered(self, data: str, source_ip: str) -> bool:
        """Detect if a canary (fake credential) was accessed."""
        triggered = False
        
        for canary_name, canary_data in self.canaries.items():
            # Check if any canary identifier appears in data
            if canary_data['password'] in data or canary_data['username'] in data:
                self.db.log_deception_event(
                    source_ip=source_ip,
                    event_type='CANARY_TRIGGERED',
                    decoy_name=canary_name,
                    decoy_type='credential',
                    attacker_action=f'Accessed fake credential: {canary_name}'
                )
                triggered = True
                print(f"🚨 CANARY TRIGGERED! Attacker {source_ip} found credential: {canary_name}")
        
        return triggered
    
    def check_decoy_accessed(self, path: str, source_ip: str) -> bool:
        """Detect if a decoy file/directory was accessed."""
        accessed = False
        
        for decoy_name, decoy_data in self.decoys.items():
            if decoy_data['path'] in path:
                self.db.log_deception_event(
                    source_ip=source_ip,
                    event_type='DECOY_ACCESSED',
                    decoy_name=decoy_name,
                    decoy_type=decoy_data['type'],
                    attacker_action=f'Accessed decoy: {decoy_data["path"]}'
                )
                accessed = True
                print(f"🚨 DECOY ACCESSED! Attacker {source_ip} tried: {decoy_data['path']}")
        
        return accessed
    
    @staticmethod
    def _generate_token() -> str:
        """Generate unique honeypot token for tracking."""
        return hashlib.sha256(
            (datetime.now().isoformat() + str(random.random())).encode()
        ).hexdigest()[:16]


class ServiceEmulator:
    """Emulate vulnerable/interesting services to trap attackers."""
    
    def __init__(self, db: HoneypotDatabase, deception: DeceptionTechnology):
        """Initialize service emulator."""
        self.db = db
        self.deception = deception
    
    def handle_ssh(self, client_socket: socket.socket, source_ip: str):
        """Emulate SSH service."""
        try:
            client_socket.send(b"SSH-2.0-OpenSSH_7.4 (Honeypot)\r\n")
            
            # Read client banner
            client_banner = client_socket.recv(1024).decode('utf-8', errors='ignore')
            
            # Simulate key exchange (simplified)
            client_socket.send(b"SSH-2.0-OpenSSH_7.4\r\n")
            
            # Simulate authentication prompt
            client_socket.send(b"root@honeypot:~$ ")
            
            # Receive potential username
            username = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Log authentication attempt
            self.db.log_attack(
                source_ip=source_ip,
                attack_type='SSH_AUTH_ATTEMPT',
                tool_detected='Manual or SSH Client',
                payload=f'Username: {username}',
                response='Auth Failed (fake)',
                success=False
            )
            
            # Check for canary credentials
            self.deception.check_canary_triggered(username, source_ip)
            
            client_socket.send(b"Permission denied (publickey).\r\n")
        
        except Exception as e:
            print(f"SSH handler error: {e}")
        finally:
            client_socket.close()
    
    def handle_telnet(self, client_socket: socket.socket, source_ip: str):
        """Emulate Telnet service (old, insecure)."""
        try:
            client_socket.send(b"Welcome to Linux Honeypot\r\nLogin: ")
            
            login = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            client_socket.send(b"Password: ")
            
            password = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Log attempt
            self.db.log_attack(
                source_ip=source_ip,
                attack_type='TELNET_LOGIN',
                tool_detected='Telnet/Automated',
                payload=f'{login}:{password}',
                response='Login failed',
                success=False
            )
            
            # Check canaries
            self.deception.check_canary_triggered(f'{login}:{password}', source_ip)
            
            client_socket.send(b"Login incorrect\r\n")
        
        except Exception as e:
            print(f"Telnet handler error: {e}")
        finally:
            client_socket.close()
    
    def handle_http(self, client_socket: socket.socket, source_ip: str):
        """Emulate HTTP service."""
        try:
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')
            
            # Parse request
            lines = request.split('\r\n')
            request_line = lines[0] if lines else ''
            
            # Log HTTP request
            self.db.log_attack(
                source_ip=source_ip,
                attack_type='HTTP_REQUEST',
                tool_detected='Web Browser/Scanner',
                payload=request_line,
                response='200 OK (fake)',
                success=False
            )
            
            # Check for common exploitation paths
            if '/admin' in request or '/shell.php' in request or '/wp-admin' in request:
                self.deception.check_decoy_accessed(request, source_ip)
            
            # Send fake response
            html = b"""HTTP/1.1 200 OK\r
Content-Type: text/html\r
Content-Length: 50\r
\r
<html><body>Welcome to Honeypot Server</body></html>"""
            client_socket.send(html)
        
        except Exception as e:
            print(f"HTTP handler error: {e}")
        finally:
            client_socket.close()
    
    def handle_mysql(self, client_socket: socket.socket, source_ip: str):
        """Emulate MySQL service."""
        try:
            # MySQL handshake packet (simplified)
            client_socket.send(b'\x0a5.7.0-Honeypot\x00')
            
            auth_packet = client_socket.recv(1024)
            
            self.db.log_attack(
                source_ip=source_ip,
                attack_type='MYSQL_CONNECTION',
                tool_detected='MySQL Client',
                payload='Connection attempt',
                response='Auth failed',
                success=False
            )
            
            # Send error response
            error = b'\xff\x15\x04Access denied for user'
            client_socket.send(error)
        
        except Exception as e:
            print(f"MySQL handler error: {e}")
        finally:
            client_socket.close()


class AdvancedHoneypot:
    """Main honeypot orchestrator with deception technology."""
    
    def __init__(self, ports: List[int] = None, bind_address: str = '0.0.0.0'):
        """
        Initialize honeypot.
        
        Args:
            ports: List of ports to monitor
            bind_address: Address to bind to (0.0.0.0 for all interfaces, 127.0.0.1 for localhost)
        """
        self.ports = ports or [22, 23, 80, 443, 3306, 3389, 8080]
        self.bind_address = bind_address
        self.db = HoneypotDatabase()
        self.deception = DeceptionTechnology(self.db)
        self.emulator = ServiceEmulator(self.db, self.deception)
        self.threads = []
        
        # Setup logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup honeypot logging."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('honeypot.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _get_service_handler(self, port: int):
        """Get appropriate handler for port."""
        handlers = {
            22: self.emulator.handle_ssh,
            23: self.emulator.handle_telnet,
            80: self.emulator.handle_http,
            443: self.emulator.handle_http,  # HTTPS (simplified)
            3306: self.emulator.handle_mysql,
            3389: self.emulator.handle_telnet,  # RDP (simplified)
            8080: self.emulator.handle_http,
        }
        return handlers.get(port, self.emulator.handle_http)
    
    def _listen_on_port(self, port: int):
        """Listen on a specific port and accept connections."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.bind_address, port))
            server_socket.listen(5)
            print(f"✓ Listening on port {port}")
            
            while True:
                try:
                    client_socket, (source_ip, source_port) = server_socket.accept()
                    
                    # Get service-specific handler
                    handler = self._get_service_handler(port)
                    
                    # Log connection
                    self.db.log_connection(
                        source_ip=source_ip,
                        source_port=source_port,
                        target_port=port,
                        service=self._get_service_name(port),
                        protocol='TCP',
                        data_sent='',
                        data_received='',
                        duration=0.0,
                        threat_level='MEDIUM'
                    )
                    
                    # Update attacker profile
                    self.db.update_attacker_profile(source_ip)
                    
                    print(f"🔍 Connection from {source_ip}:{source_port} → port {port}")
                    
                    # Handle in thread
                    client_thread = threading.Thread(
                        target=handler,
                        args=(client_socket, source_ip)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                
                except Exception as e:
                    print(f"Connection error on port {port}: {e}")
        
        except OSError as e:
            print(f"❌ Cannot bind to port {port}: {e}")
        finally:
            server_socket.close()
    
    @staticmethod
    def _get_service_name(port: int) -> str:
        """Get service name for port."""
        services = {
            22: 'SSH',
            23: 'Telnet',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            8080: 'HTTP-Alt'
        }
        return services.get(port, 'Unknown')
    
    def start(self):
        """Start the honeypot on all configured ports."""
        print("\n" + "="*70)
        print("🍯 ADVANCED HONEYPOT WITH DECEPTION TECHNOLOGY")
        print("="*70)
        print(f"\nBinding to: {self.bind_address}")
        print(f"Monitoring ports: {self.ports}\n")
        
        for port in self.ports:
            thread = threading.Thread(target=self._listen_on_port, args=(port,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        print(f"\n✓ Honeypot started! Waiting for attackers...\n")
        
        try:
            # Keep main thread alive
            while True:
                pass
        except KeyboardInterrupt:
            print("\n\n👋 Shutting down honeypot...")
    
    def print_statistics(self):
        """Print attack statistics."""
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        
        # Total connections
        cursor.execute('SELECT COUNT(*) FROM connections')
        total_connections = cursor.fetchone()[0]
        
        # Unique IPs
        cursor.execute('SELECT COUNT(DISTINCT source_ip) FROM connections')
        unique_ips = cursor.fetchone()[0]
        
        # Attack types
        cursor.execute('SELECT attack_type, COUNT(*) FROM attack_attempts GROUP BY attack_type')
        attack_types = cursor.fetchall()
        
        # Deception events
        cursor.execute('SELECT COUNT(*) FROM deception_events')
        deception_events = cursor.fetchone()[0]
        
        conn.close()
        
        print("\n" + "="*70)
        print("📊 HONEYPOT STATISTICS")
        print("="*70)
        print(f"Total Connections: {total_connections}")
        print(f"Unique Attackers: {unique_ips}")
        print(f"Deception Traps Triggered: {deception_events}")
        print("\nAttack Types Detected:")
        for attack_type, count in attack_types:
            print(f"  • {attack_type}: {count}")
        print("="*70 + "\n")


def main():
    """Main function."""
    # Create honeypot
    # Use '127.0.0.1' for localhost only (safe lab)
    # Use '0.0.0.0' for all interfaces (real deployment)
    honeypot = AdvancedHoneypot(
        ports=[22, 23, 80, 443, 3306, 8080],
        bind_address='127.0.0.1'  # Change to '0.0.0.0' for AWS
    )
    
    try:
        honeypot.start()
    except KeyboardInterrupt:
        honeypot.print_statistics()


if __name__ == "__main__":
    main()
